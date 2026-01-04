// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.

package vm

import (
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	RNGBaseGas = 100
)

// RunRNG generates pseudo-random bytes using block context and caller-provided seed.
// Input: arbitrary bytes (seed)
// Output: 32 bytes of keccak256(block.timestamp || block.number || prevrandao || origin || seed)
func RunRNG(evm *EVM, input []byte, gas uint64) ([]byte, uint64, error) {
	if gas < RNGBaseGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= RNGBaseGas

	// Build entropy from multiple sources
	data := make([]byte, 0, 128+len(input))

	// Block timestamp (8 bytes)
	timestamp := evm.Context.Time
	for i := 7; i >= 0; i-- {
		data = append(data, byte(timestamp>>(i*8)))
	}

	// Block number (32 bytes)
	data = append(data, evm.Context.BlockNumber.Bytes()...)

	// PREVRANDAO if available (post-merge), otherwise difficulty
	if evm.Context.Random != nil {
		data = append(data, evm.Context.Random.Bytes()...)
	} else if evm.Context.Difficulty != nil {
		data = append(data, evm.Context.Difficulty.Bytes()...)
	}

	// Transaction origin (20 bytes)
	data = append(data, evm.TxContext.Origin.Bytes()...)

	// User-provided seed
	data = append(data, input...)

	// Hash everything
	result := crypto.Keccak256(data)

	return result, gas, nil
}