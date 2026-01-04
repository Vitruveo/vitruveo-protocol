// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.

package vm

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

const (
	BatchSendBaseGas        = 200
	BatchSendPerTransferGas = 50000
)

var transferFromSelector = []byte{0x23, 0xb8, 0x72, 0xdd} // transferFrom(address,address,uint256)

// RunBatchSendNative sends native currency to multiple recipients.
// NOTE: Direct state transfers - no recipient fallback/receive code executes.
// Input: (recipient(20) | amount(32))[]
// Output: 32 bytes - number of successful transfers (uint256)
// Reverts on malformed input.
func RunBatchSendNative(evm *EVM, input []byte, gas uint64) ([]byte, uint64, error) {
	if gas < BatchSendBaseGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= BatchSendBaseGas

	if len(input) < 52 || len(input)%52 != 0 {
		return nil, gas, ErrExecutionReverted
	}

	transferCount := len(input) / 52

	requiredGas := uint64(transferCount) * BatchSendPerTransferGas
	if gas < requiredGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= requiredGas

	caller := evm.TxContext.Origin
	successCount := uint256.NewInt(0)
	one := uint256.NewInt(1)

	for i := 0; i < transferCount; i++ {
		offset := i * 52
		recipient := common.BytesToAddress(input[offset : offset+20])
		amount := uint256.NewInt(0).SetBytes(input[offset+20 : offset+52])

		if evm.Context.CanTransfer(evm.StateDB, caller, amount) {
			evm.Context.Transfer(evm.StateDB, caller, recipient, amount)
			successCount.Add(successCount, one)
		}
	}

	result := make([]byte, 32)
	successCount.WriteToSlice(result)
	return result, gas, nil
}

// RunBatchSendERC20 sends a single ERC20 token to multiple recipients.
// Input: token(20) | (recipient(20) | amount(32))[]
// Output: 32 bytes - number of successful transfers (uint256)
// Reverts on malformed input.
func RunBatchSendERC20(evm *EVM, input []byte, gas uint64) ([]byte, uint64, error) {
	if gas < BatchSendBaseGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= BatchSendBaseGas

	if len(input) < 72 || (len(input)-20)%52 != 0 {
		return nil, gas, ErrExecutionReverted
	}

	tokenAddr := common.BytesToAddress(input[0:20])
	transferData := input[20:]
	transferCount := len(transferData) / 52

	requiredGas := uint64(transferCount) * BatchSendPerTransferGas
	if gas < requiredGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= requiredGas

	caller := AccountRef(BatchSendERC20Address)
	origin := evm.TxContext.Origin
	successCount := uint256.NewInt(0)
	one := uint256.NewInt(1)
	zeroValue := uint256.NewInt(0)

	callData := make([]byte, 100)
	copy(callData[0:4], transferFromSelector)
	copy(callData[16:36], origin.Bytes())

	for i := 0; i < transferCount; i++ {
		offset := i * 52
		recipient := common.BytesToAddress(transferData[offset : offset+20])
		amount := transferData[offset+20 : offset+52]

		for j := 36; j < 68; j++ {
			callData[j] = 0
		}
		copy(callData[48:68], recipient.Bytes())
		copy(callData[68:100], amount)

		ret, _, err := evm.Call(
			caller,
			tokenAddr,
			callData,
			BatchSendPerTransferGas,
			zeroValue,
		)

		if err == nil && (len(ret) == 0 || (len(ret) >= 32 && !isZeroSlice(ret[0:32]))) {
			successCount.Add(successCount, one)
		}
	}

	result := make([]byte, 32)
	successCount.WriteToSlice(result)
	return result, gas, nil
}

func isZeroSlice(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}