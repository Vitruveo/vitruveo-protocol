package txmanager

import (
	"context"
	
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
)

// APIBackendHook wraps the EthAPIBackend to intercept SendTx calls
type APIBackendHook struct {
	backend     *eth.EthAPIBackend
	integration *Integration
}

// NewAPIBackendHook creates a new hook for the EthAPIBackend
func NewAPIBackendHook(backend *eth.EthAPIBackend, integration *Integration) *APIBackendHook {
	return &APIBackendHook{
		backend:     backend,
		integration: integration,
	}
}

// SendTx intercepts transaction submissions and routes them through TxManager when near rebasing
func (h *APIBackendHook) SendTx(ctx context.Context, tx *types.Transaction) error {
	if h.integration != nil && h.integration.IsEnabled() && h.integration.txManager.isNearRebasing() {
		log.Debug("Routing transaction through TxManager", "hash", tx.Hash())
		return h.integration.txManager.AddTransaction(tx)
	}
	
	// Otherwise, pass through to the original backend
	return h.backend.SendTx(ctx, tx)
}

// Install hooks the integration with the backend
func (i *Integration) InstallAPIHook(stack *node.Node) {
	// For now we just set the active integration, but in the future
	// we may want to implement a more direct hook into the SendTx method
	SetActiveIntegration(i)
	log.Info("Transaction manager API hook installed")
}