package eth

import (
	"context"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

const (
	// hostWebhookMaxBlockAge skips HOST requests in blocks older than this,
	// e.g. while a validator catches up after downtime.
	hostWebhookMaxBlockAge = time.Hour

	// hostWebhookMaxCatchup bounds how many blocks are scanned for a single
	// head advance (about one hour of 5 second blocks).
	hostWebhookMaxCatchup = 720
)

// hostWebhookWatcher delivers HOST precompile webhooks for canonical blocks.
//
// The HOST precompile only emits a HostRequested log; the log survives only if
// its call frame and transaction did not revert and only reaches receipts once
// the block is written. The watcher follows ChainHeadEvent, which is emitted
// both for imported blocks and for blocks sealed by the local miner, walks
// every newly canonical block (including the new branch after a reorg), scans
// its receipts for HostRequested logs and, if this node holds a validator key,
// re-reads the HostRequests registry against that block's post-state to build,
// sign and send the webhook. Each requestId fires at most once per node
// (in-memory deduplication), so a request re-included after a reorg does not
// fire again. Webhooks already sent for blocks that are later reorged out
// cannot be recalled.
type hostWebhookWatcher struct {
	chain *core.BlockChain
	fire  func(context.Context, *vm.HostWebhook)

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup // loop goroutine
	fireWg sync.WaitGroup // in-flight deliveries

	last *types.Header // last canonical block scanned
}

func newHostWebhookWatcher(chain *core.BlockChain) *hostWebhookWatcher {
	ctx, cancel := context.WithCancel(context.Background())
	return &hostWebhookWatcher{
		chain:  chain,
		fire:   vm.FireHostWebhook,
		ctx:    ctx,
		cancel: cancel,
	}
}

// start begins following the chain from the current head. Blocks already in
// the chain at startup are not scanned.
func (w *hostWebhookWatcher) start() {
	w.last = w.chain.CurrentBlock()
	headCh := make(chan core.ChainHeadEvent, 16)
	sub := w.chain.SubscribeChainHeadEvent(headCh)
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		defer sub.Unsubscribe()
		for {
			select {
			case <-headCh:
				w.advance()
			case <-sub.Err():
				return
			case <-w.ctx.Done():
				return
			}
		}
	}()
}

// stop terminates the watcher and aborts pending delivery retries.
func (w *hostWebhookWatcher) stop() {
	w.cancel()
	w.wg.Wait()
	w.fireWg.Wait()
}

// advance scans all blocks that became canonical since the last call.
func (w *hostWebhookWatcher) advance() {
	head := w.chain.CurrentBlock()
	if head == nil {
		return
	}
	// Find the most recent scanned block that is still canonical; after a
	// reorg this is the common ancestor of the old and new branch.
	anc := w.last
	for anc != nil && w.chain.GetCanonicalHash(anc.Number.Uint64()) != anc.Hash() {
		if anc.Number.Sign() == 0 {
			anc = nil
			break
		}
		anc = w.chain.GetHeader(anc.ParentHash, anc.Number.Uint64()-1)
	}
	if anc == nil {
		w.last = head
		return
	}
	w.last = anc

	from, to := anc.Number.Uint64()+1, head.Number.Uint64()
	if from > to {
		return
	}
	if to-from+1 > hostWebhookMaxCatchup {
		from = to - hostWebhookMaxCatchup + 1
	}
	for n := from; n <= to; n++ {
		if w.ctx.Err() != nil {
			return
		}
		block := w.chain.GetBlockByNumber(n)
		if block == nil {
			return
		}
		w.processBlock(block)
		w.last = block.Header()
	}
}

// processBlock fires webhooks for the HostRequested logs in a canonical block.
func (w *hostWebhookWatcher) processBlock(block *types.Block) {
	key := crypto.GlobalValidatorKey
	if key == nil {
		return
	}
	if age := time.Since(time.Unix(int64(block.Time()), 0)); age > hostWebhookMaxBlockAge {
		return
	}
	var ids []*big.Int
	seen := make(map[string]bool)
	for _, receipt := range w.chain.GetReceiptsByHash(block.Hash()) {
		if receipt.Status != types.ReceiptStatusSuccessful {
			continue
		}
		for _, l := range receipt.Logs {
			id, ok := vm.HostRequestIDFromLog(l)
			if !ok || seen[id.String()] || vm.HostRequestFired(id) {
				continue
			}
			seen[id.String()] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return
	}
	statedb, err := w.chain.StateAt(block.Root())
	if err != nil {
		log.Warn("HOST: State unavailable for webhook lookup", "number", block.Number(), "hash", block.Hash(), "err", err)
		return
	}
	header := block.Header()
	evm := vm.NewEVM(core.NewEVMBlockContext(header, w.chain, nil), vm.TxContext{GasPrice: new(big.Int)}, statedb, w.chain.Config(), vm.Config{NoBaseFee: true})

	for _, id := range ids {
		hook, err := vm.LookupHostWebhook(evm, id, key)
		if err != nil {
			log.Warn("HOST: Webhook lookup failed", "id", id, "number", block.Number(), "err", err)
			continue
		}
		if hook == nil {
			continue // not assigned to this validator
		}
		if !vm.MarkHostRequestFired(id) {
			log.Info("HOST WEBHOOK: Skipped duplicate", "id", id)
			continue
		}
		w.fireWg.Add(1)
		go func() {
			defer w.fireWg.Done()
			w.fire(w.ctx, hook)
		}()
	}
}
