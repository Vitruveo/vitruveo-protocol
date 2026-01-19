// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.

package vm

import "github.com/ethereum/go-ethereum/common"

// GlobalValidatorSigner is a function variable that allows the VM 
// to request a signature from the node's running wallet.
var GlobalValidatorSigner func(data []byte) ([]byte, error)

// EVM-dependent precompile addresses
var (
	HOSTPrecompileAddress 		  	  = common.HexToAddress("0x0000000000000000000000000000000000000099")
	PasskeyPrecompileAddress 	  	  = common.HexToAddress("0x00000000000000000000000000000000000000AA")
	ShufflePrecompileAddress 	  	  = common.HexToAddress("0x00000000000000000000000000000000000000AB")
	BatchBalancePrecompileAddress 	  			 = common.HexToAddress("0x00000000000000000000000000000000000000BB")
	BatchBalanceNativePrecompileAddress     	  = common.HexToAddress("0x00000000000000000000000000000000000000BC")
	CompoundInterestPrecompileAddress = common.HexToAddress("0x00000000000000000000000000000000000000CC")
	MerklePrecompileAddress			  = common.HexToAddress("0x00000000000000000000000000000000000000DD")
	BatchSendERC20PrecompileAddress         	  = common.HexToAddress("0x00000000000000000000000000000000000000EE")
	BatchSendNativePrecompileAddress        	  = common.HexToAddress("0x00000000000000000000000000000000000000EC")
	RNGPrecompileAddress  		  	  = common.HexToAddress("0x00000000000000000000000000000000000000FF")
	IBCPrecompileAddress  		  	  = common.HexToAddress("0x00000000000000000000000000000000000001BC")
	TrendPrecompileAddress  		  	  = common.HexToAddress("0x00000000000000000000000000000000000000DC")
)

// RunEVMDependentPrecompile checks and runs precompiles that need EVM context.
// Returns (result, gasLeft, handled, error). If handled is false, continue with normal execution.
// RunEVMDependentPrecompile checks and runs precompiles that need EVM context.
func (evm *EVM) RunEVMDependentPrecompile(addr common.Address, input []byte, gas uint64) ([]byte, uint64, bool, error) {
	switch addr {
	case HOSTPrecompileAddress:
		ret, leftOver, err := RunHOST(evm, input, gas)
		return ret, leftOver, true, err
	case IBCPrecompileAddress:
		ret, leftOver, err := RunIBCVerifier(evm, input, gas)
		return ret, leftOver, true, err
	case RNGPrecompileAddress:
		ret, leftOver, err := RunRNG(evm, input, gas)
		return ret, leftOver, true, err
	case PasskeyPrecompileAddress:
		ret, leftOver, err := RunPasskey(evm, input, gas)
		return ret, leftOver, true, err
	case ShufflePrecompileAddress:
		ret, leftOver, err := RunShuffle(evm, input, gas)
		return ret, leftOver, true, err
	case BatchBalancePrecompileAddress:
		ret, leftOver, err := RunBatchBalance(evm, input, gas)
		return ret, leftOver, true, err
	case BatchBalanceNativePrecompileAddress:
		ret, leftOver, err := RunBatchBalanceNative(evm, input, gas)
		return ret, leftOver, true, err
	case BatchSendNativePrecompileAddress:
		ret, leftOver, err := RunBatchSendNative(evm, input, gas)
		return ret, leftOver, true, err
	case BatchSendERC20PrecompileAddress:
		ret, leftOver, err := RunBatchSendERC20(evm, input, gas)
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