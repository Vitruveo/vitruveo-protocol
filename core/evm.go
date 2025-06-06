// Copyright 2016 The go-ethereum Authors
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

package core

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rebase"
)

// ChainContext supports retrieving headers and consensus parameters from the
// current blockchain to be used during transaction processing.
type ChainContext interface {
	// Engine retrieves the chain's consensus engine.
	Engine() consensus.Engine

	// GetHeader returns the header corresponding to the hash/number argument pair.
	GetHeader(common.Hash, uint64) *types.Header
}

// NewEVMBlockContext creates a new context for use in the EVM.
func NewEVMBlockContext(header *types.Header, chain ChainContext, author *common.Address) vm.BlockContext {
	var (
		beneficiary common.Address
		baseFee     *big.Int
		random      *common.Hash
	)

	// If we don't have an explicit author (i.e. not mining), extract from the header
	if author == nil {
		beneficiary, _ = chain.Engine().Author(header) // Ignore error, we're past header validation
	} else {
		beneficiary = *author
	}
	if header.BaseFee != nil {
		baseFee = new(big.Int).Set(header.BaseFee)
	}
	if header.Difficulty.Cmp(common.Big0) == 0 {
		random = &header.MixDigest
	}
	
	// Ensure the header has a valid Rbx value
	rbxValue := header.Rbx
	if rbxValue == 0 {
		// This should never happen in normal operation, but we'll add a fallback
		// to ensure consistent merkle roots across the network
		log.Error("Header with zero Rbx value detected in NewEVMBlockContext", 
			"block", header.Number, 
			"hash", header.Hash(),
			"epoch", header.Epoch,
			"rbxEpoch", header.RbxEpoch)
			
		// Try to recover from chain state first
		parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
		if parent != nil && parent.Rbx > 0 {
			rbxValue = parent.Rbx
			log.Error("Recovered Rbx from parent block in NewEVMBlockContext", 
				"block", header.Number, 
				"parentBlock", parent.Number, 
				"rbx", rbxValue)
		} else {
			// Last resort fallback
			rbxValue = rebase.DIVISOR.Uint64() // Use default value from rebase package
			log.Error("Using default Rbx value in NewEVMBlockContext", 
				"block", header.Number, 
				"rbx", rbxValue)
		}
	} else if header.Epoch > 0 || header.RbxEpoch > 0 {
		// Extra logging for blocks with rebase data to track merkle root issues
		log.Debug("Creating EVM block context with rebase data", 
			"block", header.Number, 
			"hash", header.Hash(),
			"rbx", rbxValue,
			"epoch", header.Epoch,
			"rbxEpoch", header.RbxEpoch)
	}

	return vm.BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     GetHashFn(header, chain),
		Coinbase:    beneficiary,
		BlockNumber: new(big.Int).Set(header.Number),
		Time:        header.Time,
		Difficulty:  new(big.Int).Set(header.Difficulty),
		BaseFee:     baseFee,
		GasLimit:    header.GasLimit,
		Rbx:         rbxValue,
		Random:      random,
		ExcessBlobGas: header.ExcessBlobGas,
	}
}

// NewEVMTxContext creates a new transaction context for a single transaction.
func NewEVMTxContext(msg *Message) vm.TxContext {
	return vm.TxContext{
		Origin:     msg.From,
		GasPrice:   new(big.Int).Set(msg.GasPrice),
		BlobHashes: msg.BlobHashes,
	}
}

// GetHashFn returns a GetHashFunc which retrieves header hashes by number
func GetHashFn(ref *types.Header, chain ChainContext) func(n uint64) common.Hash {
	// Cache will initially contain [refHash.parent],
	// Then fill up with [refHash.p, refHash.pp, refHash.ppp, ...]
	var cache []common.Hash

	return func(n uint64) common.Hash {
		if ref.Number.Uint64() <= n {
			// This situation can happen if we're doing tracing and using
			// block overrides.
			return common.Hash{}
		}
		// If there's no hash cache yet, make one
		if len(cache) == 0 {
			cache = append(cache, ref.ParentHash)
		}
		if idx := ref.Number.Uint64() - n - 1; idx < uint64(len(cache)) {
			return cache[idx]
		}
		// No luck in the cache, but we can start iterating from the last element we already know
		lastKnownHash := cache[len(cache)-1]
		lastKnownNumber := ref.Number.Uint64() - uint64(len(cache))

		for {
			header := chain.GetHeader(lastKnownHash, lastKnownNumber)
			if header == nil {
				break
			}
			cache = append(cache, header.ParentHash)
			lastKnownHash = header.ParentHash
			lastKnownNumber = header.Number.Uint64() - 1
			if n == lastKnownNumber {
				return lastKnownHash
			}
		}
		return common.Hash{}
	}
}

// CanTransfer checks whether there are enough funds in the address' account to make a transfer.
// This does not take the necessary gas in to account to make the transfer valid.
func CanTransfer(db vm.StateDB, rbx uint64, addr common.Address, amount *big.Int) bool {
	rebasedBalance := rebase.GetRebasedAmount(db.GetBalance(addr), rbx)
	//log.Warn("CanTransfer", "amount", amount, "rebased", rebasedBalance, "compare", rebasedBalance.Cmp(amount))
	return rebasedBalance.Cmp(amount) >= 0

}

// Transfer subtracts amount from sender and adds amount to recipient using the given Db
func Transfer(db vm.StateDB, rbx uint64, sender, recipient common.Address, amount *big.Int) {
	//log.Warn("EVM Transfer with Rebasing", "rbx", rbx, "sender", sender)
	// Rebased transfer
	transferAmount := rebase.GetTransferAmount(amount, rbx)

	db.SubBalance(sender, transferAmount)
	db.AddBalance(recipient, transferAmount)
}
