// Package txmanager implements transaction batching for rebasing periods
package txmanager

import (
	"context"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

// BackendWithTxManager extends a Backend with transaction batching
type BackendWithTxManager struct {
	// The actual backend
	backend *txpool.TxPool
	
	// Our transaction manager
	txManager *TxManager
}

// NewBackendWithTxManager creates a new backend with transaction batching
func NewBackendWithTxManager(backend *txpool.TxPool, blockchain *core.BlockChain, config Config) *BackendWithTxManager {
	txManager := New(backend, blockchain, config)
	txManager.Start()
	
	return &BackendWithTxManager{
		backend:    backend,
		txManager:  txManager,
	}
}

// Stop stops the transaction manager
func (b *BackendWithTxManager) Stop() {
	b.txManager.Stop()
}

// Add adds new transactions to the pool
func (b *BackendWithTxManager) Add(txs []*types.Transaction, local bool, sync bool) []error {
	// If we're not near rebasing, pass through to backend
	if !b.txManager.isNearRebasing() {
		return b.backend.Add(txs, local, sync)
	}
	
	// Use the transaction manager for batching
	errs := make([]error, len(txs))
	for i, tx := range txs {
		errs[i] = b.txManager.AddTransaction(tx)
	}
	
	return errs
}

// SendTx is a convenience method that adds a transaction to the pool
func (b *BackendWithTxManager) SendTx(ctx context.Context, tx *types.Transaction) error {
	// If we're not near rebasing, pass through
	if !b.txManager.isNearRebasing() {
		return b.backend.Add([]*types.Transaction{tx}, true, false)[0]
	}
	
	// Use the transaction manager for batching
	err := b.txManager.AddTransaction(tx)
	if err != nil {
		log.Warn("Transaction rejected", "hash", tx.Hash(), "err", err)
	} else {
		log.Debug("Transaction accepted", "hash", tx.Hash())
	}
	return err
}

// Nonce returns the next nonce of an account, with all known transactions included
func (b *BackendWithTxManager) Nonce(addr common.Address) uint64 {
	return b.backend.Nonce(addr)
}