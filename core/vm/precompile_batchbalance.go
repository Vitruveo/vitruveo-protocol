// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.

package vm

import (
	"github.com/ethereum/go-ethereum/common"
)

const (
	BatchBalanceBaseGas     = 100
	BatchBalancePerTokenGas = 30000
)

var balanceOfSelector = []byte{0x70, 0xa0, 0x82, 0x31}

// RunBatchBalance returns multiple ERC20 balances in a single call.
// Input: owner(20) | token1(20) | token2(20) | ...
// Output: balance1(32) | balance2(32) | ...
// Reverts on malformed input.
func RunBatchBalance(evm *EVM, input []byte, gas uint64) ([]byte, uint64, error) {
	if gas < BatchBalanceBaseGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= BatchBalanceBaseGas

	if len(input) < 40 || (len(input)-20)%20 != 0 {
		return nil, gas, ErrExecutionReverted
	}

	owner := common.BytesToAddress(input[0:20])
	tokenData := input[20:]
	tokenCount := len(tokenData) / 20

	requiredGas := uint64(tokenCount) * BatchBalancePerTokenGas
	if gas < requiredGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= requiredGas

	result := make([]byte, tokenCount*32)

	callData := make([]byte, 36)
	copy(callData[0:4], balanceOfSelector)
	copy(callData[16:36], owner.Bytes())

	caller := AccountRef(BatchBalancePrecompileAddress)

	for i := 0; i < tokenCount; i++ {
		tokenAddr := common.BytesToAddress(tokenData[i*20 : (i+1)*20])

		ret, _, err := evm.StaticCall(
			caller,
			tokenAddr,
			callData,
			BatchBalancePerTokenGas,
		)

		if err == nil && len(ret) >= 32 {
			copy(result[i*32:(i+1)*32], ret[0:32])
		}
	}

	return abiEncodeUint256Array(result), gas, nil
}

// RunBatchBalanceNative returns native + ERC20 balances.
// Input: owner(20) | includeNative(1) | token1(20) | token2(20) | ...
// Output: [nativeBalance(32) if includeNative] | balance1(32) | balance2(32) | ...
// Reverts on malformed input.
func RunBatchBalanceNative(evm *EVM, input []byte, gas uint64) ([]byte, uint64, error) {
	if gas < BatchBalanceBaseGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= BatchBalanceBaseGas

	if len(input) < 21 || (len(input)-21)%20 != 0 {
		return nil, gas, ErrExecutionReverted
	}

	owner := common.BytesToAddress(input[0:20])
	includeNative := input[20] == 1
	tokenData := input[21:]
	tokenCount := len(tokenData) / 20

	requiredGas := uint64(tokenCount) * BatchBalancePerTokenGas
	if gas < requiredGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= requiredGas

	resultSize := tokenCount * 32
	if includeNative {
		resultSize += 32
	}
	result := make([]byte, resultSize)

	offset := 0

	if includeNative {
		nativeBal := evm.StateDB.GetBalance(owner)
		balBytes := nativeBal.Bytes()
		copy(result[32-len(balBytes):32], balBytes)
		offset = 32
	}

	if tokenCount == 0 {
		return result, gas, nil
	}

	callData := make([]byte, 36)
	copy(callData[0:4], balanceOfSelector)
	copy(callData[16:36], owner.Bytes())

	caller := AccountRef(BatchBalanceNativePrecompileAddress)

	for i := 0; i < tokenCount; i++ {
		tokenAddr := common.BytesToAddress(tokenData[i*20 : (i+1)*20])

		ret, _, err := evm.StaticCall(
			caller,
			tokenAddr,
			callData,
			BatchBalancePerTokenGas,
		)

		if err == nil && len(ret) >= 32 {
			copy(result[offset+i*32:offset+(i+1)*32], ret[0:32])
		}
	}

	return abiEncodeUint256Array(result), gas, nil
}