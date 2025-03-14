// Package txmanager implements transaction batching for rebasing periods
package txmanager

import (
	"context"
	"sync"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/log"
)

// Integration provides methods to integrate the TxManager with the Ethereum node
type Integration struct {
	ethereum  *eth.Ethereum
	txManager *TxManager
	enabled   bool
	lock      sync.RWMutex
}

// NewIntegration creates a new integration between TxManager and Ethereum node
func NewIntegration(eth *eth.Ethereum, config Config) *Integration {
	txManager := New(eth.TxPool(), eth.BlockChain(), config)
	
	return &Integration{
		ethereum:  eth,
		txManager: txManager,
		enabled:   false,
	}
}

// Start initializes the TxManager and enables transaction batching
func (i *Integration) Start() error {
	i.lock.Lock()
	defer i.lock.Unlock()
	
	log.Info("Starting Transaction Manager for rebasing periods")
	
	err := i.txManager.Start()
	if err != nil {
		return err
	}
	
	i.enabled = true
	return nil
}

// Stop stops the TxManager
func (i *Integration) Stop() {
	i.lock.Lock()
	defer i.lock.Unlock()
	
	if i.enabled {
		i.txManager.Stop()
		i.enabled = false
		log.Info("Transaction Manager stopped")
	}
}

// IsEnabled returns whether the TxManager is currently enabled
func (i *Integration) IsEnabled() bool {
	i.lock.RLock()
	defer i.lock.RUnlock()
	return i.enabled
}

// HandleTransaction intercepts transaction submissions and routes them through the TxManager when near rebasing
func (i *Integration) HandleTransaction(ctx context.Context, tx *types.Transaction) error {
	i.lock.RLock()
	enabled := i.enabled
	i.lock.RUnlock()
	
	// If not enabled, pass through to normal tx pool
	if !enabled || !i.txManager.isNearRebasing() {
		return i.ethereum.TxPool().Add([]*types.Transaction{tx}, true, false)[0]
	}
	
	// Use transaction manager for batching when near rebasing
	return i.txManager.AddTransaction(tx)
}

// RegisterWithNode registers the TxManager with the Ethereum node
func RegisterWithNode(eth *eth.Ethereum) *Integration {
	config := DefaultConfig()
	integration := NewIntegration(eth, config)
	integration.Start()
	
	return integration
}