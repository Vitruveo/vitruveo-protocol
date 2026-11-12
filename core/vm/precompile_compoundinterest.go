package vm

import (
	"math/big"
)

const (
	CompoundBaseGas    = 500
	CompoundPerBitGas  = 60
	CompoundPerMulGas  = 40
	CompoundInputLen   = 96
	CompoundMaxPeriods = 10000
	CompoundMaxBitLen  = 256
)

var (
	compoundScale = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
)

// compoundMaxBaseBitLen bounds the squared multiplier. Since result >= 1 and
// every multiplication by base >= scale is non-decreasing, a base with more
// than 256+60 bits (2^60 > 1e18) guarantees result*base/scale > 2^256, so the
// final result cannot fit. Smaller bases are allowed even above 256 bits so a
// small principal is not rejected spuriously.
const compoundMaxBaseBitLen = CompoundMaxBitLen + 60

// RunCompoundInterest computes principal * (1 + rate/1e18)^periods with
// per-step truncation (1e18 fixed point).
// Input (96 bytes, abi.encode(uint256 principal, uint256 rate, uint256 periods)):
//
//	principal (32) || rate (32, 1e18-scaled per period) || periods (32)
//
// Output: ABI-encoded uint256 (32 bytes). A zero principal returns 0 and zero
// periods returns principal. Reverts with ErrExecutionReverted when the input
// is not exactly 96 bytes, periods exceeds CompoundMaxPeriods, or the result
// overflows uint256.
func RunCompoundInterest(evm *EVM, input []byte, gas uint64) ([]byte, uint64, error) {
	_ = evm

	if gas < CompoundBaseGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= CompoundBaseGas

	if len(input) != CompoundInputLen {
		return nil, gas, ErrExecutionReverted
	}

	principal := new(big.Int).SetBytes(input[0:32])
	rate := new(big.Int).SetBytes(input[32:64])
	periods := new(big.Int).SetBytes(input[64:96])

	if periods.Cmp(big.NewInt(CompoundMaxPeriods)) > 0 {
		return nil, gas, ErrExecutionReverted
	}

	if principal.Sign() == 0 {
		return make([]byte, 32), gas, nil
	}

	p := periods.Uint64()

	var bitGas uint64
	tmp := p
	for tmp > 0 {
		bitGas += CompoundPerBitGas
		tmp >>= 1
	}

	if bitGas > gas {
		return nil, 0, ErrOutOfGas
	}
	gas -= bitGas

	multiplier := new(big.Int).Add(compoundScale, rate)

	result := new(big.Int).Set(principal)
	base := new(big.Int).Set(multiplier)

	for p > 0 {
		if p&1 == 1 {
			if gas < CompoundPerMulGas {
				return nil, 0, ErrOutOfGas
			}
			gas -= CompoundPerMulGas

			result.Mul(result, base)
			result.Div(result, compoundScale)

			if result.BitLen() > CompoundMaxBitLen {
				return nil, gas, ErrExecutionReverted
			}
		}

		p >>= 1
		if p == 0 {
			break
		}

		if gas < CompoundPerMulGas {
			return nil, 0, ErrOutOfGas
		}
		gas -= CompoundPerMulGas

		base.Mul(base, base)
		base.Div(base, compoundScale)

		if base.BitLen() > compoundMaxBaseBitLen {
			return nil, gas, ErrExecutionReverted
		}
	}

	if result.BitLen() > CompoundMaxBitLen {
		return nil, gas, ErrExecutionReverted
	}
	out := make([]byte, 32)
	result.FillBytes(out)

	return out, gas, nil
}
