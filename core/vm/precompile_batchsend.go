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

var (
    // We now use transfer(address,uint256) instead of transferFrom
    transferSelector = []byte{0xa9, 0x05, 0x9c, 0xbb} 
)

// RunBatchSendNative sends native currency to multiple recipients.
// NOTE: Direct state transfers - no recipient fallback/receive code executes.
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
// Protocol Privilege: This impersonates the user to call 'transfer', skipping allowance.
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

	// IMPOSTER MODE: We act as the Transaction Origin (the user)
	// This tricks the ERC20 into thinking the user called 'transfer' directly.
	caller := AccountRef(evm.TxContext.Origin)
	
	successCount := uint256.NewInt(0)
	one := uint256.NewInt(1)
	zeroValue := uint256.NewInt(0)

	// Prepare calldata for transfer(address,uint256) -> 4 + 32 + 32 = 68 bytes
	callData := make([]byte, 68)
	copy(callData[0:4], transferSelector)

	for i := 0; i < transferCount; i++ {
		offset := i * 52
		recipient := common.BytesToAddress(transferData[offset : offset+20])
		amount := transferData[offset+20 : offset+52]

		// Pack args: recipient (padded), amount (padded)
		// recipient is 20 bytes, needs left padding to 32
		copy(callData[4:16], make([]byte, 12)) // zero pad
		copy(callData[16:36], recipient.Bytes())
		copy(callData[36:68], amount)

		// Execute Call acting as the User
		ret, _, err := evm.Call(
			caller,     // <--- We are impersonating the user here
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