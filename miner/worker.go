// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package miner

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rebase"
	"github.com/ethereum/go-ethereum/trie"
)

const (
	// resultQueueSize is the size of channel listening to sealing result.
	resultQueueSize = 10

	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	txChanSize = 4096

	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	chainHeadChanSize = 10

	// resubmitAdjustChanSize is the size of resubmitting interval adjustment channel.
	resubmitAdjustChanSize = 10

	// minRecommitInterval is the minimal time interval to recreate the sealing block with
	// any newly arrived transactions.
	minRecommitInterval = 1 * time.Second

	// maxRecommitInterval is the maximum time interval to recreate the sealing block with
	// any newly arrived transactions.
	maxRecommitInterval = 15 * time.Second

	// intervalAdjustRatio is the impact a single interval adjustment has on sealing work
	// resubmitting interval.
	intervalAdjustRatio = 0.1

	// intervalAdjustBias is applied during the new resubmit interval calculation in favor of
	// increasing upper limit or decreasing lower limit so that the limit can be reachable.
	intervalAdjustBias = 200 * 1000.0 * 1000.0

	// staleThreshold is the maximum depth of the acceptable stale block.
	staleThreshold = 7
)

var (
	errBlockInterruptedByNewHead  = errors.New("new head arrived while building block")
	errBlockInterruptedByRecommit = errors.New("recommit interrupt while building block")
	errBlockInterruptedByTimeout  = errors.New("timeout while building block")
)

// environment is the worker's current environment and holds all
// information of the sealing block generation.
type environment struct {
	signer   types.Signer
	state    *state.StateDB // apply state changes here
	tcount   int            // tx count in cycle
	gasPool  *core.GasPool  // available gas used to pack transactions
	coinbase common.Address

	header   *types.Header
	txs      []*types.Transaction
	receipts []*types.Receipt
	sidecars []*types.BlobTxSidecar
	blobs    int
}

// copy creates a deep copy of environment.
func (env *environment) copy() *environment {
	cpy := &environment{
		signer:   env.signer,
		state:    env.state.Copy(),
		tcount:   env.tcount,
		coinbase: env.coinbase,
		header:   types.CopyHeader(env.header),
		receipts: copyReceipts(env.receipts),
	}
	if env.gasPool != nil {
		gasPool := *env.gasPool
		cpy.gasPool = &gasPool
	}
	cpy.txs = make([]*types.Transaction, len(env.txs))
	copy(cpy.txs, env.txs)

	cpy.sidecars = make([]*types.BlobTxSidecar, len(env.sidecars))
	copy(cpy.sidecars, env.sidecars)

	return cpy
}

// discard terminates the background prefetcher go-routine. It should
// always be called for all created environment instances otherwise
// the go-routine leak can happen.
func (env *environment) discard() {
	if env.state == nil {
		return
	}
	env.state.StopPrefetcher()
}

// task contains all information for consensus engine sealing and result submitting.
type task struct {
	receipts  []*types.Receipt
	state     *state.StateDB
	block     *types.Block
	createdAt time.Time
}

const (
	commitInterruptNone int32 = iota
	commitInterruptNewHead
	commitInterruptResubmit
	commitInterruptTimeout
)

// newWorkReq represents a request for new sealing work submitting with relative interrupt notifier.
type newWorkReq struct {
	interrupt *atomic.Int32
	timestamp int64
}

// newPayloadResult is the result of payload generation.
type newPayloadResult struct {
	err      error
	block    *types.Block
	fees     *big.Int               // total block fees
	sidecars []*types.BlobTxSidecar // collected blobs of blob transactions
}

// getWorkReq represents a request for getting a new sealing work with provided parameters.
type getWorkReq struct {
	params *generateParams
	result chan *newPayloadResult // non-blocking channel
}

// intervalAdjust represents a resubmitting interval adjustment.
type intervalAdjust struct {
	ratio float64
	inc   bool
}

// worker is the main object which takes care of submitting new work to consensus engine
// and gathering the sealing result.
type worker struct {
	config      *Config
	chainConfig *params.ChainConfig
	engine      consensus.Engine
	eth         Backend
	chain       *core.BlockChain

	// Feeds
	pendingLogsFeed event.Feed

	// Subscriptions
	mux          *event.TypeMux
	txsCh        chan core.NewTxsEvent
	txsSub       event.Subscription
	chainHeadCh  chan core.ChainHeadEvent
	chainHeadSub event.Subscription

	// Channels
	newWorkCh          chan *newWorkReq
	getWorkCh          chan *getWorkReq
	taskCh             chan *task
	resultCh           chan *types.Block
	startCh            chan struct{}
	exitCh             chan struct{}
	resubmitIntervalCh chan time.Duration
	resubmitAdjustCh   chan *intervalAdjust

	wg sync.WaitGroup

	current *environment // An environment for current running cycle.

	mu       sync.RWMutex // The lock used to protect the coinbase and extra fields
	coinbase common.Address
	extra    []byte

	pendingMu    sync.RWMutex
	pendingTasks map[common.Hash]*task

	snapshotMu       sync.RWMutex // The lock used to protect the snapshots below
	snapshotBlock    *types.Block
	snapshotReceipts types.Receipts
	snapshotState    *state.StateDB

	// atomic status counters
	running atomic.Bool  // The indicator whether the consensus engine is running or not.
	newTxs  atomic.Int32 // New arrival transaction count since last sealing work submitting.
	syncing atomic.Bool  // The indicator whether the node is still syncing.

	// newpayloadTimeout is the maximum timeout allowance for creating payload.
	// The default value is 2 seconds but node operator can set it to arbitrary
	// large value. A large timeout allowance may cause Geth to fail creating
	// a non-empty payload within the specified time and eventually miss the slot
	// in case there are some computation expensive transactions in txpool.
	newpayloadTimeout time.Duration

	// recommit is the time interval to re-create sealing work or to re-build
	// payload in proof-of-stake stage.
	recommit time.Duration

	// External functions
	isLocalBlock func(header *types.Header) bool // Function used to determine whether the specified block is mined by local miner.

	// Test hooks
	newTaskHook  func(*task)                        // Method to call upon receiving a new sealing task.
	skipSealHook func(*task) bool                   // Method to decide whether skipping the sealing.
	fullTaskHook func()                             // Method to call before pushing the full sealing task.
	resubmitHook func(time.Duration, time.Duration) // Method to call upon updating resubmitting interval.
}

func newWorker(config *Config, chainConfig *params.ChainConfig, engine consensus.Engine, eth Backend, mux *event.TypeMux, isLocalBlock func(header *types.Header) bool, init bool) *worker {
	worker := &worker{
		config:             config,
		chainConfig:        chainConfig,
		engine:             engine,
		eth:                eth,
		chain:              eth.BlockChain(),
		mux:                mux,
		isLocalBlock:       isLocalBlock,
		coinbase:           config.Etherbase,
		extra:              config.ExtraData,
		pendingTasks:       make(map[common.Hash]*task),
		txsCh:              make(chan core.NewTxsEvent, txChanSize),
		chainHeadCh:        make(chan core.ChainHeadEvent, chainHeadChanSize),
		newWorkCh:          make(chan *newWorkReq),
		getWorkCh:          make(chan *getWorkReq),
		taskCh:             make(chan *task),
		resultCh:           make(chan *types.Block, resultQueueSize),
		startCh:            make(chan struct{}, 1),
		exitCh:             make(chan struct{}),
		resubmitIntervalCh: make(chan time.Duration),
		resubmitAdjustCh:   make(chan *intervalAdjust, resubmitAdjustChanSize),
	}
	// Subscribe NewTxsEvent for tx pool
	worker.txsSub = eth.TxPool().SubscribeNewTxsEvent(worker.txsCh)
	// Subscribe events for blockchain
	worker.chainHeadSub = eth.BlockChain().SubscribeChainHeadEvent(worker.chainHeadCh)

	// Sanitize recommit interval if the user-specified one is too short.
	recommit := worker.config.Recommit
	if recommit < minRecommitInterval {
		log.Warn("Sanitizing miner recommit interval", "provided", recommit, "updated", minRecommitInterval)
		recommit = minRecommitInterval
	}
	worker.recommit = recommit

	// Sanitize the timeout config for creating payload.
	newpayloadTimeout := worker.config.NewPayloadTimeout
	if newpayloadTimeout == 0 {
		log.Warn("Sanitizing new payload timeout to default", "provided", newpayloadTimeout, "updated", DefaultConfig.NewPayloadTimeout)
		newpayloadTimeout = DefaultConfig.NewPayloadTimeout
	}
	if newpayloadTimeout < time.Millisecond*100 {
		log.Warn("Low payload timeout may cause high amount of non-full blocks", "provided", newpayloadTimeout, "default", DefaultConfig.NewPayloadTimeout)
	}
	worker.newpayloadTimeout = newpayloadTimeout

	worker.wg.Add(4)
	go worker.mainLoop()
	go worker.newWorkLoop(recommit)
	go worker.resultLoop()
	go worker.taskLoop()

	// Submit first work to initialize pending state.
	if init {
		worker.startCh <- struct{}{}
	}
	return worker
}

// setEtherbase sets the etherbase used to initialize the block coinbase field.
func (w *worker) setEtherbase(addr common.Address) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.coinbase = addr
}

// etherbase retrieves the configured etherbase address.
func (w *worker) etherbase() common.Address {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.coinbase
}

func (w *worker) setGasCeil(ceil uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.config.GasCeil = ceil
}

// setExtra sets the content used to initialize the block extra field.
func (w *worker) setExtra(extra []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.extra = extra
}

// setRecommitInterval updates the interval for miner sealing work recommitting.
func (w *worker) setRecommitInterval(interval time.Duration) {
	select {
	case w.resubmitIntervalCh <- interval:
	case <-w.exitCh:
	}
}

// pending returns the pending state and corresponding block. The returned
// values can be nil in case the pending block is not initialized.
func (w *worker) pending() (*types.Block, *state.StateDB) {
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	if w.snapshotState == nil {
		return nil, nil
	}
	return w.snapshotBlock, w.snapshotState.Copy()
}

// pendingBlock returns pending block. The returned block can be nil in case the
// pending block is not initialized.
func (w *worker) pendingBlock() *types.Block {
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	return w.snapshotBlock
}

// pendingBlockAndReceipts returns pending block and corresponding receipts.
// The returned values can be nil in case the pending block is not initialized.
func (w *worker) pendingBlockAndReceipts() (*types.Block, types.Receipts) {
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	return w.snapshotBlock, w.snapshotReceipts
}

// start sets the running status as 1 and triggers new work submitting.
func (w *worker) start() {
	w.running.Store(true)
	w.startCh <- struct{}{}
}

// stop sets the running status as 0.
func (w *worker) stop() {
	w.running.Store(false)
}

// isRunning returns an indicator whether worker is running or not.
func (w *worker) isRunning() bool {
	return w.running.Load()
}

// close terminates all background threads maintained by the worker.
// Note the worker does not support being closed multiple times.
func (w *worker) close() {
	w.running.Store(false)
	close(w.exitCh)
	w.wg.Wait()
}

// recalcRecommit recalculates the resubmitting interval upon feedback.
func recalcRecommit(minRecommit, prev time.Duration, target float64, inc bool) time.Duration {
	var (
		prevF = float64(prev.Nanoseconds())
		next  float64
	)
	if inc {
		next = prevF*(1-intervalAdjustRatio) + intervalAdjustRatio*(target+intervalAdjustBias)
		max := float64(maxRecommitInterval.Nanoseconds())
		if next > max {
			next = max
		}
	} else {
		next = prevF*(1-intervalAdjustRatio) + intervalAdjustRatio*(target-intervalAdjustBias)
		min := float64(minRecommit.Nanoseconds())
		if next < min {
			next = min
		}
	}
	return time.Duration(int64(next))
}

// newWorkLoop is a standalone goroutine to submit new sealing work upon received events.
func (w *worker) newWorkLoop(recommit time.Duration) {
	defer w.wg.Done()
	var (
		interrupt   *atomic.Int32
		minRecommit = recommit // minimal resubmit interval specified by user.
		timestamp   int64      // timestamp for each round of sealing.
	)

	timer := time.NewTimer(0)
	defer timer.Stop()
	<-timer.C // discard the initial tick

	// commit aborts in-flight transaction execution with given signal and resubmits a new one.
	commit := func(s int32) {
		if interrupt != nil {
			interrupt.Store(s)
		}
		interrupt = new(atomic.Int32)
		select {
		case w.newWorkCh <- &newWorkReq{interrupt: interrupt, timestamp: timestamp}:
		case <-w.exitCh:
			return
		}
		timer.Reset(recommit)
		w.newTxs.Store(0)
	}
	// clearPending cleans the stale pending tasks.
	clearPending := func(number uint64) {
		w.pendingMu.Lock()
		for h, t := range w.pendingTasks {
			if t.block.NumberU64()+staleThreshold <= number {
				delete(w.pendingTasks, h)
			}
		}
		w.pendingMu.Unlock()
	}

	for {
		select {
		case <-w.startCh:
			clearPending(w.chain.CurrentBlock().Number.Uint64())
			timestamp = time.Now().Unix()
			commit(commitInterruptNewHead)

		case head := <-w.chainHeadCh:
			clearPending(head.Block.NumberU64())
			timestamp = time.Now().Unix()
			commit(commitInterruptNewHead)

		case <-timer.C:
			// If sealing is running resubmit a new work cycle periodically to pull in
			// higher priced transactions. Disable this overhead for pending blocks.
			if w.isRunning() && (w.chainConfig.Clique == nil || w.chainConfig.Clique.Period > 0) {
				// Short circuit if no new transaction arrives.
				if w.newTxs.Load() == 0 {
					timer.Reset(recommit)
					continue
				}
				commit(commitInterruptResubmit)
			}

		case interval := <-w.resubmitIntervalCh:
			// Adjust resubmit interval explicitly by user.
			if interval < minRecommitInterval {
				log.Warn("Sanitizing miner recommit interval", "provided", interval, "updated", minRecommitInterval)
				interval = minRecommitInterval
			}
			log.Info("Miner recommit interval update", "from", minRecommit, "to", interval)
			minRecommit, recommit = interval, interval

			if w.resubmitHook != nil {
				w.resubmitHook(minRecommit, recommit)
			}

		case adjust := <-w.resubmitAdjustCh:
			// Adjust resubmit interval by feedback.
			if adjust.inc {
				before := recommit
				target := float64(recommit.Nanoseconds()) / adjust.ratio
				recommit = recalcRecommit(minRecommit, recommit, target, true)
				log.Trace("Increase miner recommit interval", "from", before, "to", recommit)
			} else {
				before := recommit
				recommit = recalcRecommit(minRecommit, recommit, float64(minRecommit.Nanoseconds()), false)
				log.Trace("Decrease miner recommit interval", "from", before, "to", recommit)
			}

			if w.resubmitHook != nil {
				w.resubmitHook(minRecommit, recommit)
			}

		case <-w.exitCh:
			return
		}
	}
}

// mainLoop is responsible for generating and submitting sealing work based on
// the received event. It can support two modes: automatically generate task and
// submit it or return task according to given parameters for various proposes.
func (w *worker) mainLoop() {
	defer w.wg.Done()
	defer w.txsSub.Unsubscribe()
	defer w.chainHeadSub.Unsubscribe()
	defer func() {
		if w.current != nil {
			w.current.discard()
		}
	}()

	for {
		select {
		case req := <-w.newWorkCh:
			w.commitWork(req.interrupt, req.timestamp)

		case req := <-w.getWorkCh:
			req.result <- w.generateWork(req.params)

		case ev := <-w.txsCh:
			// Apply transactions to the pending state if we're not sealing
			//
			// Note all transactions received may not be continuous with transactions
			// already included in the current sealing block. These transactions will
			// be automatically eliminated.
			if !w.isRunning() && w.current != nil {
				// If block is already full, abort
				if gp := w.current.gasPool; gp != nil && gp.Gas() < params.TxGas {
					continue
				}
				txs := make(map[common.Address][]*txpool.LazyTransaction, len(ev.Txs))
				for _, tx := range ev.Txs {
					acc, _ := types.Sender(w.current.signer, tx)
					txs[acc] = append(txs[acc], &txpool.LazyTransaction{
						Hash:      tx.Hash(),
						Tx:        tx.WithoutBlobTxSidecar(),
						Time:      tx.Time(),
						GasFeeCap: tx.GasFeeCap(),
						GasTipCap: tx.GasTipCap(),
					})
				}
				txset := newTransactionsByPriceAndNonce(w.current.signer, txs, w.current.header.BaseFee)
				tcount := w.current.tcount
				w.commitTransactions(w.current, txset, nil)

				// Only update the snapshot if any new transactions were added
				// to the pending block
				if tcount != w.current.tcount {
					w.updateSnapshot(w.current)
				}
			} else {
				// Special case, if the consensus engine is 0 period clique(dev mode),
				// submit sealing work here since all empty submission will be rejected
				// by clique. Of course the advance sealing(empty submission) is disabled.
				if w.chainConfig.Clique != nil && w.chainConfig.Clique.Period == 0 {
					w.commitWork(nil, time.Now().Unix())
				}
			}
			w.newTxs.Add(int32(len(ev.Txs)))

		// System stopped
		case <-w.exitCh:
			return
		case <-w.txsSub.Err():
			return
		case <-w.chainHeadSub.Err():
			return
		}
	}
}

// taskLoop is a standalone goroutine to fetch sealing task from the generator and
// push them to consensus engine.
func (w *worker) taskLoop() {
	defer w.wg.Done()
	var (
		stopCh chan struct{}
		prev   common.Hash
	)

	// interrupt aborts the in-flight sealing task.
	interrupt := func() {
		if stopCh != nil {
			close(stopCh)
			stopCh = nil
		}
	}
	for {
		select {
		case task := <-w.taskCh:
			if w.newTaskHook != nil {
				w.newTaskHook(task)
			}
			// Reject duplicate sealing work due to resubmitting.
			sealHash := w.engine.SealHash(task.block.Header())
			if sealHash == prev {
				continue
			}
			// Interrupt previous sealing operation
			interrupt()
			stopCh, prev = make(chan struct{}), sealHash

			if w.skipSealHook != nil && w.skipSealHook(task) {
				continue
			}
			w.pendingMu.Lock()
			w.pendingTasks[sealHash] = task
			w.pendingMu.Unlock()

			if err := w.engine.Seal(w.chain, task.block, w.resultCh, stopCh); err != nil {
				log.Warn("Block sealing failed", "err", err)
				w.pendingMu.Lock()
				delete(w.pendingTasks, sealHash)
				w.pendingMu.Unlock()
			}
		case <-w.exitCh:
			interrupt()
			return
		}
	}
}

// resultLoop is a standalone goroutine to handle sealing result submitting
// and flush relative data to the database.
func (w *worker) resultLoop() {
	defer w.wg.Done()
	for {
		select {
		case block := <-w.resultCh:
			// Short circuit when receiving empty result.
			if block == nil {
				continue
			}
			// Short circuit when receiving duplicate result caused by resubmitting.
			if w.chain.HasBlock(block.Hash(), block.NumberU64()) {
				continue
			}
			var (
				sealhash = w.engine.SealHash(block.Header())
				hash     = block.Hash()
			)
			w.pendingMu.RLock()
			task, exist := w.pendingTasks[sealhash]
			w.pendingMu.RUnlock()
			if !exist {
				log.Error("Block found but no relative pending task", "number", block.Number(), "sealhash", sealhash, "hash", hash)
				continue
			}
			// Different block could share same sealhash, deep copy here to prevent write-write conflict.
			var (
				receipts = make([]*types.Receipt, len(task.receipts))
				logs     []*types.Log
			)
			for i, taskReceipt := range task.receipts {
				receipt := new(types.Receipt)
				receipts[i] = receipt
				*receipt = *taskReceipt

				// add block location fields
				receipt.BlockHash = hash
				receipt.BlockNumber = block.Number()
				receipt.TransactionIndex = uint(i)

				// Update the block hash in all logs since it is now available and not when the
				// receipt/log of individual transactions were created.
				receipt.Logs = make([]*types.Log, len(taskReceipt.Logs))
				for i, taskLog := range taskReceipt.Logs {
					log := new(types.Log)
					receipt.Logs[i] = log
					*log = *taskLog
					log.BlockHash = hash
				}
				logs = append(logs, receipt.Logs...)
			}
			// Commit block and state to database.
			_, err := w.chain.WriteBlockAndSetHead(block, receipts, logs, task.state, true)
			if err != nil {
				log.Error("Failed writing block to chain", "err", err)
				continue
			}
			log.Info("Successfully sealed new block", "number", block.Number(), "sealhash", sealhash, "hash", hash,
				"elapsed", common.PrettyDuration(time.Since(task.createdAt)))

			// Broadcast the block and announce chain insertion event
			w.mux.Post(core.NewMinedBlockEvent{Block: block})

		case <-w.exitCh:
			return
		}
	}
}

// makeEnv creates a new environment for the sealing block.
func (w *worker) makeEnv(parentHeader *types.Header, header *types.Header, coinbase common.Address) (*environment, error) {
	// Retrieve the parentHeader state to execute on top and start a prefetcher for
	// the miner to speed block sealing up a bit.
	state, err := w.chain.StateAt(parentHeader.Root)
	if err != nil {
		return nil, err
	}
	state.StartPrefetcher("miner")

	// Note the passed coinbase may be different with header.Coinbase.
	env := &environment{
		signer:   types.MakeSigner(w.chainConfig, header.Number, header.Time),
		state:    state,
		coinbase: coinbase,
		header:   header,
	}
	// Keep track of transactions which return errors so they can be removed
	env.tcount = 0
	return env, nil
}

// updateSnapshot updates pending snapshot block, receipts and state.
func (w *worker) updateSnapshot(env *environment) {
	w.snapshotMu.Lock()
	defer w.snapshotMu.Unlock()

	w.snapshotBlock = types.NewBlock(
		w.chain.CurrentHeader(),
		env.header,
		env.txs,
		nil,
		env.receipts,
		trie.NewStackTrie(nil),
	)
	w.snapshotReceipts = copyReceipts(env.receipts)
	w.snapshotState = env.state.Copy()
}

func (w *worker) commitTransaction(env *environment, tx *types.Transaction) ([]*types.Log, error) {
	if tx.Type() == types.BlobTxType {
		return w.commitBlobTransaction(env, tx)
	}

	receipt, err := w.applyTransaction(env, tx)
	if err != nil {
		return nil, err
	}
	env.txs = append(env.txs, tx)
	env.receipts = append(env.receipts, receipt)
	return receipt.Logs, nil
}

func (w *worker) commitBlobTransaction(env *environment, tx *types.Transaction) ([]*types.Log, error) {
	sc := tx.BlobTxSidecar()
	if sc == nil {
		panic("blob transaction without blobs in miner")
	}
	// Checking against blob gas limit: It's kind of ugly to perform this check here, but there
	// isn't really a better place right now. The blob gas limit is checked at block validation time
	// and not during execution. This means core.ApplyTransaction will not return an error if the
	// tx has too many blobs. So we have to explicitly check it here.
	if (env.blobs+len(sc.Blobs))*params.BlobTxBlobGasPerBlob > params.MaxBlobGasPerBlock {
		return nil, errors.New("max data blobs reached")
	}

	receipt, err := w.applyTransaction(env, tx)
	if err != nil {
		return nil, err
	}
	env.txs = append(env.txs, tx.WithoutBlobTxSidecar())
	env.receipts = append(env.receipts, receipt)
	env.sidecars = append(env.sidecars, sc)
	env.blobs += len(sc.Blobs)
	*env.header.BlobGasUsed += receipt.BlobGasUsed
	return receipt.Logs, nil
}

// applyTransaction runs the transaction. If execution fails, state and gas pool are reverted.
func (w *worker) applyTransaction(env *environment, tx *types.Transaction) (*types.Receipt, error) {
	var (
		snap = env.state.Snapshot()
		gp   = env.gasPool.Gas()
	)
	
	// CRITICAL FIX FOR REBASE: Create a local copy of Rbx at the start of transaction processing
	// This ensures that this specific transaction uses a consistent value even if the header is
	// modified by another goroutine during rebase
	txRbx := env.header.Rbx
	
	// CRITICAL CHANGE: Always ensure header.Rbx is properly set before any transaction processing
	// This is the most important fix to ensure consistency throughout the entire block processing pipeline
	if txRbx == 0 {
		// Log this as an error - it should never happen with our fixes, but we need to handle it
		log.Error("CRITICAL: Zero Rbx value in header during transaction application", 
			"block", env.header.Number, "hash", env.header.Hash())
			
		// Try to recover from chain state first (most reliable during normal operation)
		currentChainState := w.chain.CurrentHeader()
		if currentChainState != nil && currentChainState.Rbx > 0 {
			txRbx = currentChainState.Rbx
			// Also update header for future operations
			env.header.Rbx = txRbx 
			log.Error("Emergency Rbx recovery from chain state", 
				"block", env.header.Number, 
				"rbx", txRbx)
		} else {
			// Try to get from parentHeader block as fallback
			blockNumber := env.header.Number.Uint64()
			prevBlockNumber := blockNumber - 1
			
			var prevBlock *types.Block
			for attempt := 0; attempt < 5; attempt++ { // Limit search depth
				prevBlock = w.chain.GetBlockByNumber(prevBlockNumber)
				if prevBlock != nil && prevBlock.Header().Rbx > 0 {
					txRbx = prevBlock.Header().Rbx
					// Also update header for future operations
					env.header.Rbx = txRbx
					log.Error("Emergency Rbx recovery from parentHeader block", 
						"block", env.header.Number, 
						"parentHeaderBlock", prevBlockNumber,
						"rbx", txRbx)
					break
				}
				if prevBlockNumber <= 2 {
					break
				}
				prevBlockNumber--
			}
			
			// Last resort - use default value
			if txRbx == 0 {
				txRbx = 100000000 // rebase.DIVISOR.Uint64()
				// Also update header for future operations
				env.header.Rbx = txRbx
				log.Error("SEVERE: Using default Rbx value - this will likely cause merkle root errors", 
					"block", env.header.Number, 
					"default_rbx", txRbx)
			}
		}
	}

	// Log Rbx value and transaction info to trace the exact transaction processing
	// Only log at Info level during rebase transitions to help with debugging
	if env.header.Number.Uint64() > 0 && env.header.Number.Uint64() % rebase.BLOCKS_PER_EPOCH.Uint64() == 0 {
		log.Info("Transaction processing at epoch boundary", 
			"block", env.header.Number, 
			"txHash", tx.Hash().String(), 
			"rbx", txRbx,
			"epoch", env.header.Epoch,
			"rbxEpoch", env.header.RbxEpoch)
	} else {
		log.Debug("Transaction processing", 
			"block", env.header.Number, 
			"txHash", tx.Hash().String(), 
			"rbx", txRbx)
	}
	
	// CRITICAL FIX FOR REBASE: Use the captured txRbx value consistently for this transaction
	// This ensures that even if header.Rbx changes during a rebase in another goroutine,
	// this specific transaction will complete with a consistent value
	receipt, err := core.ApplyTransaction(w.chainConfig, w.chain, &env.coinbase, env.gasPool, env.state, env.header, tx, &env.header.GasUsed, *w.chain.GetVMConfig(), txRbx)
	if err != nil {
		env.state.RevertToSnapshot(snap)
		env.gasPool.SetGas(gp)
	}
	return receipt, err
}

func (w *worker) commitTransactions(env *environment, txs *transactionsByPriceAndNonce, interrupt *atomic.Int32) error {
	gasLimit := env.header.GasLimit
	if env.gasPool == nil {
		env.gasPool = new(core.GasPool).AddGas(gasLimit)
	}
	var coalescedLogs []*types.Log

	// CRITICAL FIX: Capture the current Rbx value at the start of transaction batch processing
	// This helps prevent inconsistencies if a rebase happens during transaction processing
	batchRbx := env.header.Rbx
	
	// Log the initial Rbx state for this batch of transactions, especially useful for rebase debugging
	if env.header.Number.Uint64() > 0 && env.header.Number.Uint64() % rebase.BLOCKS_PER_EPOCH.Uint64() == 0 {
		log.Info("Starting transaction batch at epoch boundary", 
			"block", env.header.Number, 
			"rbx", batchRbx,
			"epoch", env.header.Epoch,
			"rbxEpoch", env.header.RbxEpoch,
			"txCount", len(env.txs))
	}

	for {
		// Check interruption signal and abort building if it's fired.
		if interrupt != nil {
			if signal := interrupt.Load(); signal != commitInterruptNone {
				return signalToErr(signal)
			}
		}
		// If we don't have enough gas for any further transactions then we're done.
		if env.gasPool.Gas() < params.TxGas {
			log.Trace("Not enough gas for further transactions", "have", env.gasPool, "want", params.TxGas)
			break
		}
		// Retrieve the next transaction and abort if all done.
		ltx := txs.Peek()
		if ltx == nil {
			break
		}
		tx := ltx.Resolve()
		if tx == nil {
			log.Warn("Ignoring evicted transaction")
			txs.Pop()
			continue
		}

		// Error may be ignored here. The error has already been checked
		// during transaction acceptance is the transaction pool.
		from, _ := types.Sender(env.signer, tx)

		// Check whether the tx is replay protected. If we're not in the EIP155 hf
		// phase, start ignoring the sender until we do.
		if tx.Protected() && !w.chainConfig.IsEIP155(env.header.Number) {
			log.Trace("Ignoring replay protected transaction", "hash", tx.Hash(), "eip155", w.chainConfig.EIP155Block)
			txs.Pop()
			continue
		}

		// Start executing the transaction
		env.state.SetTxContext(tx.Hash(), env.tcount)

		// IMPORTANT: Check if env.header.Rbx has changed since we started processing this batch
		// This could happen if a rebase was triggered in another goroutine
		if env.header.Rbx != batchRbx {
			// We detected a potential rebase in the middle of processing transactions
			log.Warn("Rbx value changed during transaction processing - potential rebase detected", 
				"block", env.header.Number,
				"original_rbx", batchRbx,
				"current_rbx", env.header.Rbx,
				"txHash", tx.Hash())
				
			// This is critical - we must ensure all transactions in this batch use the same Rbx value
			// Force the header back to the original value to maintain consistency
			env.header.Rbx = batchRbx
			log.Info("Forced Rbx back to original value for transaction consistency", 
				"block", env.header.Number,
				"rbx", batchRbx)
		}

		logs, err := w.commitTransaction(env, tx)
		switch {
		case errors.Is(err, core.ErrNonceTooLow):
			// New head notification data race between the transaction pool and miner, shift
			log.Trace("Skipping transaction with low nonce", "sender", from, "nonce", tx.Nonce())
			txs.Shift()

		case errors.Is(err, nil):
			// Everything ok, collect the logs and shift in the next transaction from the same account
			coalescedLogs = append(coalescedLogs, logs...)
			env.tcount++
			txs.Shift()

		default:
			// Transaction is regarded as invalid, drop all consecutive transactions from
			// the same sender because of `nonce-too-high` clause.
			log.Debug("Transaction failed, account skipped", "hash", tx.Hash(), "err", err)
			txs.Pop()
		}
	}
	if !w.isRunning() && len(coalescedLogs) > 0 {
		// We don't push the pendingLogsEvent while we are sealing. The reason is that
		// when we are sealing, the worker will regenerate a sealing block every 3 seconds.
		// In order to avoid pushing the repeated pendingLog, we disable the pending log pushing.

		// make a copy, the state caches the logs and these logs get "upgraded" from pending to mined
		// logs by filling in the block hash when the block was mined by the local miner. This can
		// cause a race condition if a log was "upgraded" before the PendingLogsEvent is processed.
		cpy := make([]*types.Log, len(coalescedLogs))
		for i, l := range coalescedLogs {
			cpy[i] = new(types.Log)
			*cpy[i] = *l
		}
		w.pendingLogsFeed.Send(cpy)
	}
	return nil
}

// generateParams wraps various of settings for generating sealing task.
type generateParams struct {
	timestamp   uint64            // The timstamp for sealing task
	forceTime   bool              // Flag whether the given timestamp is immutable or not
	parentHeaderHash  common.Hash       // Parent block hash, empty means the latest chain head
	coinbase    common.Address    // The fee recipient address for including transaction
	random      common.Hash       // The randomness generated by beacon chain, empty before the merge
	withdrawals types.Withdrawals // List of withdrawals to include in block.
	beaconRoot  *common.Hash      // The beacon root (cancun field).
	noTxs       bool              // Flag whether an empty block without any transaction is expected
}

// prepareWork constructs the sealing task according to the given parameters,
// either based on the last chain head or specified parentHeader. In this function
// the pending transactions are not filled yet, only the empty task returned.
func (w *worker) prepareWork(genParams *generateParams) (*environment, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	// Find the parentHeader block for sealing task
	parentHeader := w.chain.CurrentBlock()
	if genParams.parentHeaderHash != (common.Hash{}) {
		block := w.chain.GetBlockByHash(genParams.parentHeaderHash)
		if block == nil {
			return nil, fmt.Errorf("missing parentHeader")
		}
		parentHeader = block.Header()
	}
	// Sanity check the timestamp correctness, recap the timestamp
	// to parentHeader+1 if the mutation is allowed.
	timestamp := genParams.timestamp
	if parentHeader.Time >= timestamp {
		if genParams.forceTime {
			return nil, fmt.Errorf("invalid timestamp, parentHeader %d given %d", parentHeader.Time, timestamp)
		}
		timestamp = parentHeader.Time + 1
	}
	// Construct the sealing block header.
	header := &types.Header{
		ParentHash: parentHeader.Hash(),
		Number:     new(big.Int).Add(parentHeader.Number, common.Big1),
		GasLimit:   core.CalcGasLimit(parentHeader.GasLimit, w.config.GasCeil),
		Time:       timestamp,
		Coinbase:   genParams.coinbase,
		Epoch:      parentHeader.Epoch,
		EpochTx:    parentHeader.EpochTx,
		Rbx:        parentHeader.Rbx, // Initialize with parentHeader Rbx value to avoid zero values
		RbxEpoch:   parentHeader.RbxEpoch,
		Supply:     new(big.Int).Set(parentHeader.Supply),
		Perks:      big.NewInt(0),
	}
	
	// Verify Rbx value is set
	if header.Rbx == 0 {
		header.Rbx = 100000000
		log.Warn("Parent had zero Rbx value in prepareWork, using default", 
			"block", header.Number, 
			"parentHeaderNumber", parentHeader.Number)
	}
	// Set the extra field.
	if len(w.extra) != 0 {
		header.Extra = w.extra
	}
	// Set the randomness field from the beacon chain if it's available.
	if genParams.random != (common.Hash{}) {
		header.MixDigest = genParams.random
	}
	// Set baseFee and GasLimit if we are on an EIP-1559 chain
	if w.chainConfig.IsLondon(header.Number) {
		header.BaseFee = eip1559.CalcBaseFee(w.chainConfig, parentHeader)
		if !w.chainConfig.IsLondon(parentHeader.Number) {
			parentHeaderGasLimit := parentHeader.GasLimit * w.chainConfig.ElasticityMultiplier()
			header.GasLimit = core.CalcGasLimit(parentHeaderGasLimit, w.config.GasCeil)
		}
	}
	// Apply EIP-4844, EIP-4788.
	if w.chainConfig.IsCancun(header.Number, header.Time) {
		var excessBlobGas uint64
		if w.chainConfig.IsCancun(parentHeader.Number, parentHeader.Time) {
			excessBlobGas = eip4844.CalcExcessBlobGas(*parentHeader.ExcessBlobGas, *parentHeader.BlobGasUsed)
		} else {
			// For the first post-fork block, both parentHeader.data_gas_used and parentHeader.excess_data_gas are evaluated as 0
			excessBlobGas = eip4844.CalcExcessBlobGas(0, 0)
		}
		header.BlobGasUsed = new(uint64)
		header.ExcessBlobGas = &excessBlobGas
		header.ParentBeaconRoot = genParams.beaconRoot
	}
	// Run the consensus preparation with the default or customized consensus engine.
	if err := w.engine.Prepare(w.chain, header); err != nil {
		log.Error("Failed to prepare header for sealing", "err", err)
		return nil, err
	}
	// Could potentially happen if starting to mine in an odd state.
	// Note genParams.coinbase can be different with header.Coinbase
	// since clique algorithm can modify the coinbase field in header.
	env, err := w.makeEnv(parentHeader, header, genParams.coinbase)
	if err != nil {
		log.Error("Failed to create sealing context", "err", err)
		return nil, err
	}
	if header.ParentBeaconRoot != nil {
		context := core.NewEVMBlockContext(header, w.chain, nil)
		vmenv := vm.NewEVM(context, vm.TxContext{}, env.state, w.chainConfig, vm.Config{})
		core.ProcessBeaconBlockRoot(*header.ParentBeaconRoot, vmenv, env.state)
	}
	return env, nil
}

// fillTransactions retrieves the pending transactions from the txpool and fills them
// into the given sealing block. The transaction selection and ordering strategy can
// be customized with the plugin in the future.
func (w *worker) fillTransactions(interrupt *atomic.Int32, env *environment) error {
	pending := w.eth.TxPool().Pending(true)

	// Split the pending transactions into locals and remotes.
	localTxs, remoteTxs := make(map[common.Address][]*txpool.LazyTransaction), pending
	for _, account := range w.eth.TxPool().Locals() {
		if txs := remoteTxs[account]; len(txs) > 0 {
			delete(remoteTxs, account)
			localTxs[account] = txs
		}
	}

	// Fill the block with all available pending transactions.
	if len(localTxs) > 0 {
		txs := newTransactionsByPriceAndNonce(env.signer, localTxs, env.header.BaseFee)
		if err := w.commitTransactions(env, txs, interrupt); err != nil {
			return err
		}
	}
	if len(remoteTxs) > 0 {
		txs := newTransactionsByPriceAndNonce(env.signer, remoteTxs, env.header.BaseFee)
		if err := w.commitTransactions(env, txs, interrupt); err != nil {
			return err
		}
	}
	return nil
}

// generateWork generates a sealing block based on the given parameters.
func (w *worker) generateWork(params *generateParams) *newPayloadResult {
	work, err := w.prepareWork(params)
	if err != nil {
		return &newPayloadResult{err: err}
	}
	defer work.discard()

	// CRITICAL CHANGE: First thing, ensure Rbx value is set and valid BEFORE any other operations
	// This is the primary source of truth for the Rbx value used in the entire assembly process
	// Record the original header Rbx value - we'll use this to detect rebases
	originalRbx := work.header.Rbx
	
	// Verify the Rbx value is non-zero - this is the most important check
	if work.header.Rbx == 0 {
		log.Error("CRITICAL: Zero Rbx detected in generateWork - this will cause merkle root issues", 
			"block", work.header.Number)
		
		// First try to get from current chain state (most accurate for current block)
		parentHeader := w.chain.CurrentHeader()
		if parentHeader != nil && parentHeader.Rbx > 0 {
			work.header.Rbx = parentHeader.Rbx
			log.Error("Emergency Rbx recovery from chain state", 
				"block", work.header.Number, 
				"rbx", work.header.Rbx)
		} else {
			// Last resort - use default value if nothing else works
			work.header.Rbx = 100000000 // rebase.DIVISOR.Uint64()
			log.Error("SEVERE: Using default Rbx value - certain to cause merkle root errors", 
				"block", work.header.Number)
		}
	}
	
	// Now that we have established a valid Rbx value, we can process transactions
	if !params.noTxs {
		interrupt := new(atomic.Int32)
		timer := time.AfterFunc(w.newpayloadTimeout, func() {
			interrupt.Store(commitInterruptTimeout)
		})
		defer timer.Stop()

		err := w.fillTransactions(interrupt, work)
		if errors.Is(err, errBlockInterruptedByTimeout) {
			log.Warn("Block building is interrupted", "allowance", common.PrettyDuration(w.newpayloadTimeout))
		}
	}
	
	// CRITICAL: After transaction processing, check if we're at an epoch boundary
	// This is where rebases happen and we need to ensure consistency
	parentHeader := w.chain.CurrentHeader()
	if parentHeader != nil {
		isRebaseTransition := false
		
		// Check if this block crosses an epoch boundary
		if work.header.Number.Uint64() > 0 && work.header.Number.Uint64() % rebase.BLOCKS_PER_EPOCH.Uint64() == 0 {
			isRebaseTransition = true
			log.Info("Detected potential rebase at epoch boundary", 
				"block", work.header.Number,
				"parentHeaderEpoch", parentHeader.Epoch,
				"prevRbx", originalRbx,
				"currentRbx", work.header.Rbx)
		}
		
		// Also check if epoch or rbxEpoch has changed directly
		if parentHeader.Epoch < work.header.Epoch || parentHeader.RbxEpoch < work.header.RbxEpoch {
			isRebaseTransition = true
			log.Info("Detected rebase by epoch change", 
				"block", work.header.Number, 
				"parentHeaderEpoch", parentHeader.Epoch,
				"headerEpoch", work.header.Epoch, 
				"parentHeaderRbxEpoch", parentHeader.RbxEpoch,
				"headerRbxEpoch", work.header.RbxEpoch)
		}
		
		// If a rebase is happening, we need to ensure the correct Rbx value is used
		if isRebaseTransition {
			// CRITICAL FIX: Special handling for rebase transitions
			log.Info("Processing rebase transition in generateWork", 
				"block", work.header.Number, 
				"parentEpoch", parentHeader.Epoch,
				"headerEpoch", work.header.Epoch,
				"parentRbx", parentHeader.Rbx,
				"headerRbx", work.header.Rbx,
				"hasTxs", len(work.txs) > 0)
			
			// Create rebase info structures for computation
			chainRebaseInfo := rebase.RebaseInfo{
				Epoch:    parentHeader.Epoch,
				EpochTx:  parentHeader.EpochTx,
				Rbx:      parentHeader.Rbx,
				RbxEpoch: parentHeader.RbxEpoch,
				Supply:   parentHeader.Supply,
				Perks:    parentHeader.Perks,
				Tx:       uint64(len(work.txs)),
			}
			
			// Get current values from the work header
			currentRebaseInfo := rebase.RebaseInfo{
				Epoch:    work.header.Epoch,
				EpochTx:  work.header.EpochTx,
				Rbx:      work.header.Rbx,
				RbxEpoch: work.header.RbxEpoch,
				Supply:   work.header.Supply,
				Perks:    work.header.Perks,
				Tx:       uint64(len(work.txs)),
			}
			
			// CRITICAL FIX: If we have transactions AND we're at an epoch boundary,
			// we need to be extra careful with the rebase to avoid merkle root issues
			isAtEpochBoundary := work.header.Number.Uint64() > 0 && 
							work.header.Number.Uint64() % rebase.BLOCKS_PER_EPOCH.Uint64() == 0
							
			if len(work.txs) > 0 && isAtEpochBoundary {
				log.Warn("Rebase at epoch boundary with transactions - extra care needed", 
					"block", work.header.Number,
					"txCount", len(work.txs),
					"currentRbx", work.header.Rbx)
					
				// Get the pre-rebase Rbx value from the parent block
				preRebaseRbx := parentHeader.Rbx
				
				// Process rebase to get the post-rebase values
				epoch, epochTx, postRebaseRbx, rbxEpoch, supply, perks := 
					rebase.ProcessRebase(work.header.Number, chainRebaseInfo, currentRebaseInfo)
				
				// Log detailed information about the rebase
				log.Warn("Rebase Success 🎉🎉🎉", 
					"Epoch", epoch, 
					"RbxEpoch", rbxEpoch, 
					"Rbx", postRebaseRbx, 
					"Ratio", 125,
					"Supply", supply)
					
				// CRITICAL FIX: If the transactions have already been processed with the
				// pre-rebase Rbx value, we need to keep it consistent for this block to
				// avoid merkle root mismatches!
				if originalRbx == preRebaseRbx {
					log.Warn("Transactions already processed with pre-rebase Rbx - keeping consistent", 
						"block", work.header.Number,
						"originalRbx", originalRbx,
						"newRbx", postRebaseRbx)
						
					// We still want to update epoch, rbxEpoch, and supply information
					// but keep the Rbx value consistent for this block's transactions
					work.header.Epoch = epoch 
					work.header.EpochTx = epochTx
					work.header.RbxEpoch = rbxEpoch
					work.header.Supply = supply
					work.header.Perks = perks
					
					// SPECIAL CASE: Do NOT update the Rbx value since transactions were
					// already processed with the pre-rebase value. The next block will
					// use the post-rebase value.
					log.Info("Keeping pre-rebase Rbx for transaction consistency", 
						"block", work.header.Number,
						"rbx", work.header.Rbx)
				} else {
					// Normal case - we can update all fields including Rbx
					work.header.Epoch = epoch
					work.header.EpochTx = epochTx
					work.header.RbxEpoch = rbxEpoch
					work.header.Rbx = postRebaseRbx
					work.header.Supply = supply
					work.header.Perks = perks
					
					log.Info("Updated all rebase fields including Rbx", 
						"block", work.header.Number,
						"old_rbx", originalRbx,
						"new_rbx", postRebaseRbx)
				}
				
				log.Info("Rebase occurred - Rbx value updated", 
					"block", work.header.Number, 
					"old_rbx", originalRbx, 
					"new_rbx", work.header.Rbx)
			} else {
				// Standard rebase processing without transactions, or outside epoch boundary
				epoch, epochTx, rbx, rbxEpoch, supply, perks := 
					rebase.ProcessRebase(work.header.Number, chainRebaseInfo, currentRebaseInfo)
				
				// Update all fields
				oldRbx := work.header.Rbx
				work.header.Epoch = epoch
				work.header.EpochTx = epochTx
				work.header.RbxEpoch = rbxEpoch
				work.header.Rbx = rbx
				work.header.Supply = supply
				work.header.Perks = perks
				
				// Log the rebase details
				if oldRbx != work.header.Rbx {
					log.Warn("Rebase Success 🎉🎉🎉", 
						"Epoch", epoch, 
						"RbxEpoch", rbxEpoch, 
						"Rbx", rbx, 
						"Ratio", 125)
					
					log.Info("Rebase occurred - Rbx value updated", 
						"block", work.header.Number, 
						"old_rbx", oldRbx, 
						"new_rbx", work.header.Rbx)
				}
			}
		}
	}
	
	// Final safety check - we must NEVER let a zero Rbx value reach FinalizeAndAssemble
	if work.header.Rbx == 0 {
		log.Error("CRITICAL FAILURE: Zero Rbx detected just before block assembly", 
			"block", work.header.Number)
		
		// Emergency fallback as last resort
		work.header.Rbx = 100000000 // rebase.DIVISOR.Uint64()
		log.Error("EMERGENCY FALLBACK: Using default Rbx value for block assembly",
			"block", work.header.Number,
			"rbx", work.header.Rbx)
	}
	
	// Log final values before FinalizeAndAssemble for debugging
	log.Info("Final header values before block assembly", 
		"block", work.header.Number, 
		"hash", work.header.Hash().String(),
		"rbx", work.header.Rbx, 
		"epoch", work.header.Epoch,
		"rbxEpoch", work.header.RbxEpoch,
		"txs", len(work.txs))
	
	block, err := w.engine.FinalizeAndAssemble(w.chain, work.header, work.state, work.txs, nil, work.receipts, params.withdrawals)
	if err != nil {
		return &newPayloadResult{err: err}
	}
	return &newPayloadResult{
		block:    block,
		fees:     totalFees(block, work.receipts),
		sidecars: work.sidecars,
	}
}

// commitWork generates several new sealing tasks based on the parentHeader block
// and submit them to the sealer.
func (w *worker) commitWork(interrupt *atomic.Int32, timestamp int64) {
	// Abort committing if node is still syncing
	if w.syncing.Load() {
		return
	}
	start := time.Now()

	// Set the coinbase if the worker is running or it's required
	var coinbase common.Address
	if w.isRunning() {
		coinbase = w.etherbase()
		if coinbase == (common.Address{}) {
			log.Error("Refusing to mine without etherbase")
			return
		}
	}
	work, err := w.prepareWork(&generateParams{
		timestamp: uint64(timestamp),
		coinbase:  coinbase,
	})
	if err != nil {
		return
	}
	// Fill pending transactions from the txpool into the block.
	err = w.fillTransactions(interrupt, work)
	switch {
	case err == nil:
		// The entire block is filled, decrease resubmit interval in case
		// of current interval is larger than the user-specified one.
		w.resubmitAdjustCh <- &intervalAdjust{inc: false}

	case errors.Is(err, errBlockInterruptedByRecommit):
		// Notify resubmit loop to increase resubmitting interval if the
		// interruption is due to frequent commits.
		gaslimit := work.header.GasLimit
		ratio := float64(gaslimit-work.gasPool.Gas()) / float64(gaslimit)
		if ratio < 0.1 {
			ratio = 0.1
		}
		w.resubmitAdjustCh <- &intervalAdjust{
			ratio: ratio,
			inc:   true,
		}

	case errors.Is(err, errBlockInterruptedByNewHead):
		// If the block building is interrupted by newhead event, discard it
		// totally. Committing the interrupted block introduces unnecessary
		// delay, and possibly causes miner to mine on the previous head,
		// which could result in higher uncle rate.
		work.discard()
		return
	}
	// Submit the generated block for consensus sealing.
	w.commit(work.copy(), w.fullTaskHook, true, start)

	// Swap out the old work with the new one, terminating any leftover
	// prefetcher processes in the mean time and starting a new one.
	if w.current != nil {
		w.current.discard()
	}
	w.current = work
}

// commit runs any post-transaction state modifications, assembles the final block
// and commits new work if consensus engine is running.
// Note the assumption is held that the mutation is allowed to the passed env, do
// the deep copy first.
func (w *worker) commit(env *environment, interval func(), update bool, start time.Time) error {
	if w.isRunning() {
		if interval != nil {
			interval()
		}
		// Create a local environment copy, avoid the data race with snapshot state.
		// https://github.com/ethereum/go-ethereum/issues/24299
		env := env.copy()
		
		// CRITICAL CHANGE: First store the original Rbx value to detect changes
		originalRbx := env.header.Rbx
		
		// Always ensure header.Rbx is properly set before any processing
		// This is vital for merkle root consistency
		if env.header.Rbx == 0 {
			// Log this as a critical error since it should never happen with our fixes
			log.Error("CRITICAL: Zero Rbx value in commit function - will cause merkle root errors", 
				"block", env.header.Number, "hash", env.header.Hash().String())
				
			// Try to recover from chain state first (most reliable)
			parentHeader := w.chain.CurrentHeader()
			if parentHeader != nil && parentHeader.Rbx > 0 {
				env.header.Rbx = parentHeader.Rbx
				log.Error("Emergency Rbx recovery from chain state in commit", 
					"block", env.header.Number, 
					"rbx", env.header.Rbx)
			} else {
				// Try parentHeader blocks as fallback with limited search depth
				blockNumber := env.header.Number.Uint64()
				if blockNumber > 0 {
					parentHeaderNumber := blockNumber - 1
					for attempt := 0; attempt < 3; attempt++ {
						if parentHeaderNumber <= 2 {
							break
						}
						
						parentHeaderBlock := w.chain.GetBlockByNumber(parentHeaderNumber)
						if parentHeaderBlock != nil && parentHeaderBlock.Header().Rbx > 0 {
							env.header.Rbx = parentHeaderBlock.Header().Rbx
							log.Error("Recovered Rbx from parentHeader block in commit", 
								"block", env.header.Number,
								"parentHeaderBlock", parentHeaderNumber,
								"rbx", env.header.Rbx)
							break
						}
						parentHeaderNumber--
					}
				}
				
				// Last resort fallback to avoid complete failure
				if env.header.Rbx == 0 {
					env.header.Rbx = 100000000 // rebase.DIVISOR.Uint64()
					log.Error("SEVERE: Using default Rbx value in commit - high risk of merkle errors", 
						"block", env.header.Number,
						"defaultRbx", env.header.Rbx)
				}
			}
		}

		// Check if this block is at an epoch boundary (when rebases happen)
		isEpochBoundary := false
		if env.header.Number.Uint64() > 0 && env.header.Number.Uint64() % rebase.BLOCKS_PER_EPOCH.Uint64() == 0 {
			isEpochBoundary = true
			log.Info("Block is at epoch boundary in commit function", 
				"block", env.header.Number,
				"rbx", env.header.Rbx)
		}

			// Always check for rebase transition by comparing epochs
			parentHeader := w.chain.CurrentHeader()
			if parentHeader != nil && 
				(isEpochBoundary || (parentHeader.Epoch < env.header.Epoch) || (parentHeader.RbxEpoch < env.header.RbxEpoch)) {
				
				log.Info("Processing potential rebase in commit function", 
					"block", env.header.Number, 
					"parentHeaderEpoch", parentHeader.Epoch, 
					"headerEpoch", env.header.Epoch,
					"parentHeaderRbxEpoch", parentHeader.RbxEpoch,
					"headerRbxEpoch", env.header.RbxEpoch,
					"currentRbx", env.header.Rbx)
					
				// Create rebase info from chain state
				lastRebaseInfo := rebase.RebaseInfo{
					Epoch:    parentHeader.Epoch,
					EpochTx:  parentHeader.EpochTx,
					Rbx:      parentHeader.Rbx,
					RbxEpoch: parentHeader.RbxEpoch,
					Supply:   parentHeader.Supply,
					Perks:    parentHeader.Perks,
					Tx:       0,
				}
				currentRebaseInfo := rebase.RebaseInfo{
					Epoch:    env.header.Epoch,
					EpochTx:  env.header.EpochTx,
					Rbx:      env.header.Rbx,
					RbxEpoch: env.header.RbxEpoch,
					Supply:   env.header.Supply,
					Perks:    env.header.Perks,
					Tx:       uint64(len(env.txs)),
				}
				
				// Recalculate rebase values to ensure consistency across all components
				epoch, epochTx, rbx, rbxEpoch, supply, perks := 
					rebase.ProcessRebase(env.header.Number, lastRebaseInfo, currentRebaseInfo)
					
				// Update all rebase fields in the header with the values from ProcessRebase
				env.header.Epoch = epoch
				env.header.EpochTx = epochTx
				env.header.RbxEpoch = rbxEpoch
				env.header.Rbx = rbx
				env.header.Supply = supply
				env.header.Perks = perks
				
				// Log if Rbx value changed due to rebase
				if originalRbx != env.header.Rbx {
					log.Warn("Rebase Success 🎉🎉🎉", 
						"Epoch", epoch, 
						"RbxEpoch", rbxEpoch, 
						"Rbx", rbx, 
						"Ratio", 125)
					
					log.Info("Rebase occurred - Rbx value updated", 
						"block", env.header.Number, 
						"old_rbx", originalRbx, 
						"new_rbx", env.header.Rbx)
				}
				
				log.Info("Rebase field values synchronized in commit function", 
					"block", env.header.Number, 
					"epoch", epoch, 
					"rbxEpoch", rbxEpoch, 
					"rbx", rbx)
			}
		
		// Additional logging and safety check right before block assembly
		log.Debug("Rbx value before FinalizeAndAssemble in commit function", 
			"block", env.header.Number, 
			"hash", env.header.Hash().String(),
			"rbx", env.header.Rbx, 
			"epoch", env.header.Epoch,
			"rbxEpoch", env.header.RbxEpoch,
			"txs", len(env.txs))
			
		// MANDATORY FINAL CHECK: Never allow a zero Rbx value to reach FinalizeAndAssemble
		if env.header.Rbx == 0 {
			log.Error("CRITICAL FAILURE: Zero Rbx detected right before block assembly", 
				"block", env.header.Number)
			
			// Emergency fallback to prevent merkle root errors
			parentHeader := w.chain.CurrentHeader()
			if parentHeader != nil && parentHeader.Rbx > 0 {
				env.header.Rbx = parentHeader.Rbx
				log.Error("Emergency Rbx recovery from parentHeader", 
					"block", env.header.Number, 
					"rbx", env.header.Rbx)
			} else {
				env.header.Rbx = rebase.DIVISOR.Uint64()
				log.Error("Emergency Rbx recovery using DIVISOR", 
					"block", env.header.Number, 
					"rbx", env.header.Rbx)
			}
		}
		
		// Final logging before FinalizeAndAssemble
		log.Info("Final header values before block assembly", 
			"block", env.header.Number, 
			"hash", env.header.Hash().String(),
			"rbx", env.header.Rbx, 
			"epoch", env.header.Epoch,
			"rbxEpoch", env.header.RbxEpoch,
			"txs", len(env.txs))
		
		// Withdrawals are set to nil here, because this is only called in PoW.
		block, err := w.engine.FinalizeAndAssemble(w.chain, env.header, env.state, env.txs, nil, env.receipts, nil)
		if err != nil {
			return err
		}
		// If we're post merge, just ignore
		if !w.isTTDReached(block.Header()) {
			select {
			case w.taskCh <- &task{receipts: env.receipts, state: env.state, block: block, createdAt: time.Now()}:
				fees := totalFees(block, env.receipts)
				feesInEther := new(big.Float).Quo(new(big.Float).SetInt(fees), big.NewFloat(params.Ether))
				log.Info("Commit new sealing work", "number", block.Number(), "sealhash", w.engine.SealHash(block.Header()),
					"txs", env.tcount, "gas", block.GasUsed(), "fees", feesInEther,
					"elapsed", common.PrettyDuration(time.Since(start)))

			case <-w.exitCh:
				log.Info("Worker has exited")
			}
		}
	}
	if update {
		w.updateSnapshot(env)
	}
	return nil
}

// getSealingBlock generates the sealing block based on the given parameters.
// The generation result will be passed back via the given channel no matter
// the generation itself succeeds or not.
func (w *worker) getSealingBlock(params *generateParams) *newPayloadResult {
	req := &getWorkReq{
		params: params,
		result: make(chan *newPayloadResult, 1),
	}
	select {
	case w.getWorkCh <- req:
		return <-req.result
	case <-w.exitCh:
		return &newPayloadResult{err: errors.New("miner closed")}
	}
}

// isTTDReached returns the indicator if the given block has reached the total
// terminal difficulty for The Merge transition.
func (w *worker) isTTDReached(header *types.Header) bool {
	td, ttd := w.chain.GetTd(header.ParentHash, header.Number.Uint64()-1), w.chain.Config().TerminalTotalDifficulty
	return td != nil && ttd != nil && td.Cmp(ttd) >= 0
}

// copyReceipts makes a deep copy of the given receipts.
func copyReceipts(receipts []*types.Receipt) []*types.Receipt {
	result := make([]*types.Receipt, len(receipts))
	for i, l := range receipts {
		cpy := *l
		result[i] = &cpy
	}
	return result
}

// totalFees computes total consumed miner fees in Wei. Block transactions and receipts have to have the same order.
func totalFees(block *types.Block, receipts []*types.Receipt) *big.Int {
	feesWei := new(big.Int)
	for i, tx := range block.Transactions() {
		minerFee, _ := tx.EffectiveGasTip(block.BaseFee())
		feesWei.Add(feesWei, new(big.Int).Mul(new(big.Int).SetUint64(receipts[i].GasUsed), minerFee))
	}
	return feesWei
}

// signalToErr converts the interruption signal to a concrete error type for return.
// The given signal must be a valid interruption signal.
func signalToErr(signal int32) error {
	switch signal {
	case commitInterruptNewHead:
		return errBlockInterruptedByNewHead
	case commitInterruptResubmit:
		return errBlockInterruptedByRecommit
	case commitInterruptTimeout:
		return errBlockInterruptedByTimeout
	default:
		panic(fmt.Errorf("undefined signal %d", signal))
	}
}
