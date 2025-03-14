package txmanager

import (
	"context"
	"sync"
	
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/log"
)

var (
	activeIntegration     *Integration
	activeIntegrationLock sync.RWMutex
)

// SetActiveIntegration sets the active TxManager integration
func SetActiveIntegration(integration *Integration) {
	activeIntegrationLock.Lock()
	defer activeIntegrationLock.Unlock()
	activeIntegration = integration
}

// GetActiveIntegration returns the active TxManager integration
func GetActiveIntegration() *Integration {
	activeIntegrationLock.RLock()
	defer activeIntegrationLock.RUnlock()
	return activeIntegration
}

// Custom patching mechanism through the API hook
func init() {
	log.Info("Initializing transaction manager patcher for rebasing periods")
}