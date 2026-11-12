// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.

package vm

import (
	"encoding/binary"
	"github.com/ethereum/go-ethereum/common"
)

// GlobalValidatorSigner is a function variable that allows the VM
// to request a signature from the node's running wallet.
var GlobalValidatorSigner func(data []byte) ([]byte, error)

// EVM-dependent precompile addresses
var (
	HOSTPrecompileAddress               = common.HexToAddress("0x0000000000000000000000000000000000000099")
	PasskeyPrecompileAddress            = common.HexToAddress("0x00000000000000000000000000000000000000AA")
	ShufflePrecompileAddress            = common.HexToAddress("0x00000000000000000000000000000000000000AB")
	BatchBalancePrecompileAddress       = common.HexToAddress("0x00000000000000000000000000000000000000BB")
	BatchBalanceNativePrecompileAddress = common.HexToAddress("0x00000000000000000000000000000000000000BC")
	CompoundInterestPrecompileAddress   = common.HexToAddress("0x00000000000000000000000000000000000000CC")
	MerklePrecompileAddress             = common.HexToAddress("0x00000000000000000000000000000000000000DD")
	RNGPrecompileAddress                = common.HexToAddress("0x00000000000000000000000000000000000000FF")
	TrendPrecompileAddress              = common.HexToAddress("0x00000000000000000000000000000000000000DC")
	ProtobufPrecompileAddress           = common.HexToAddress("0x00000000000000000000000000000000000000B0")
	MultisigPrecompileAddress           = common.HexToAddress("0x00000000000000000000000000000000000000AC")
	FileStorePrecompileAddress          = common.HexToAddress("0x00000000000000000000000000000000000000F1")
	C2PAPrecompileAddress               = common.HexToAddress("0x00000000000000000000000000000000000000CA")
)

// RunEVMDependentPrecompile checks and runs precompiles that need EVM context.
// Returns (result, gasLeft, handled, error). If handled is false, continue with normal execution.
// static is true when entered via STATICCALL; precompiles that write state
// must reject writes then, or when already inside a read-only frame.
func (evm *EVM) RunEVMDependentPrecompile(caller ContractRef, addr common.Address, input []byte, gas uint64, static bool) ([]byte, uint64, bool, error) {
	switch addr {
	case HOSTPrecompileAddress:
		ret, leftOver, err := RunHOST(evm, caller.Address(), input, gas)
		return ret, leftOver, true, err
	case RNGPrecompileAddress:
		ret, leftOver, err := RunRNG(evm, caller.Address(), input, gas, static)
		return ret, leftOver, true, err
	case PasskeyPrecompileAddress:
		ret, leftOver, err := RunPasskey(evm, input, gas)
		return ret, leftOver, true, err
	case ShufflePrecompileAddress:
		ret, leftOver, err := RunShuffle(evm, caller.Address(), input, gas, static)
		return ret, leftOver, true, err
	case BatchBalancePrecompileAddress:
		ret, leftOver, err := RunBatchBalance(evm, input, gas)
		return ret, leftOver, true, err
	case BatchBalanceNativePrecompileAddress:
		ret, leftOver, err := RunBatchBalanceNative(evm, input, gas)
		return ret, leftOver, true, err
	case ProtobufPrecompileAddress:
		ret, leftOver, err := RunProtobuf(evm, caller.Address(), input, gas, static)
		return ret, leftOver, true, err
	case MultisigPrecompileAddress:
		ret, leftOver, err := RunMultisig(evm, caller.Address(), input, gas, static)
		return ret, leftOver, true, err
	case FileStorePrecompileAddress:
		ret, leftOver, err := RunFileStore(evm, caller.Address(), input, gas, static)
		return ret, leftOver, true, err
	case C2PAPrecompileAddress:
		ret, leftOver, err := RunC2PA(evm, caller.Address(), input, gas, static)
		return ret, leftOver, true, err
	case CompoundInterestPrecompileAddress:
		ret, leftOver, err := RunCompoundInterest(evm, input, gas)
		return ret, leftOver, true, err
	case MerklePrecompileAddress:
		ret, leftOver, err := RunMerkleProof(evm, input, gas)
		return ret, leftOver, true, err
	case TrendPrecompileAddress:
		ret, leftOver, err := RunTrend(evm, input, gas)
		return ret, leftOver, true, err
	default:
		return nil, gas, false, nil
	}
}

// abiEncodeUint256Array wraps a contiguous byte slice of 32-byte words
// into a standard Solidity uint256[] dynamic array.
// Format: [Offset(32)][Length(32)][Data...]
func abiEncodeUint256Array(packedData []byte) []byte {
	// 1. Header size: 32 bytes (Offset) + 32 bytes (Length)
	output := make([]byte, 64+len(packedData))

	// 2. Offset: Always 0x20 (32) because the length is immediately after the offset word
	// We write to the end of the first 32-byte word.
	output[31] = 0x20

	// 3. Length: Number of 32-byte words
	count := uint64(len(packedData) / 32)
	binary.BigEndian.PutUint64(output[56:64], count)

	// 4. Payload
	copy(output[64:], packedData)

	return output
}
