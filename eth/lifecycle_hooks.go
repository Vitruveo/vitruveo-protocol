// Copyright 2023 The go-ethereum Authors
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

package eth

import (
	"sync"

	"github.com/ethereum/go-ethereum/node"
)

// LifecycleHook is a function that can be registered to be called after eth.New
type LifecycleHook func(stack *node.Node, backend *Ethereum)

var (
	lifecycleHooks     []LifecycleHook
	lifecycleHooksLock sync.RWMutex
)

// RegisterLifecycleHook registers a function to be called after eth.New
func RegisterLifecycleHook(hook LifecycleHook) {
	lifecycleHooksLock.Lock()
	defer lifecycleHooksLock.Unlock()
	lifecycleHooks = append(lifecycleHooks, hook)
}

// runLifecycleHooks runs all registered lifecycle hooks
func runLifecycleHooks(stack *node.Node, backend *Ethereum) {
	lifecycleHooksLock.RLock()
	defer lifecycleHooksLock.RUnlock()
	for _, hook := range lifecycleHooks {
		hook(stack, backend)
	}
}