package txmanager

import (
	"context"
	
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
)

// RegisterTxManager registers the TxManager with the Ethereum service
func RegisterTxManager(stack *node.Node, backend *eth.Ethereum) error {
	log.Info("Registering transaction manager for rebasing periods")
	
	// Create and start the transaction manager
	config := DefaultConfig()
	integration := NewIntegration(backend, config)
	err := integration.Start()
	if err != nil {
		return err
	}
	
	// Install API hooks
	integration.InstallAPIHook(stack)
	
	// Register a hook for the transaction manager
	stack.RegisterLifecycle(&TxManagerHook{integration: integration})
	
	return nil
}

// TxManagerHook is a node.Lifecycle implementation for the TxManager
type TxManagerHook struct {
	integration *Integration
}

// Start implements node.Lifecycle
func (h *TxManagerHook) Start() error {
	return nil // Already started in RegisterTxManager
}

// Stop implements node.Lifecycle
func (h *TxManagerHook) Stop() error {
	h.integration.Stop()
	return nil
}

// Initialize our txmanager when imported
func init() {
	log.Info("Transaction manager for rebasing periods initialized")
	
	// Register a hook to be called after eth.New
	eth.RegisterLifecycleHook(func(stack *node.Node, backend *eth.Ethereum) {
		err := RegisterTxManager(stack, backend)
		if err != nil {
			log.Warn("Failed to register transaction manager", "err", err)
		}
	})
}