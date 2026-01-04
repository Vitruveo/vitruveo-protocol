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

func RunCompoundInterest(evm *EVM, input []byte, gas uint64) ([]byte, uint64, error) {
	_ = evm

	if gas < CompoundBaseGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= CompoundBaseGas

	if len(input) != CompoundInputLen {
		return nil, gas, nil
	}

	principal := new(big.Int).SetBytes(input[0:32])
	rate := new(big.Int).SetBytes(input[32:64])
	periods := new(big.Int).SetBytes(input[64:96])

	if principal.Sign() < 0 || rate.Sign() < 0 || periods.Sign() < 0 {
		return nil, gas, nil
	}

	if principal.Sign() == 0 {
		return make([]byte, 32), gas, nil
	}

	if periods.Cmp(big.NewInt(CompoundMaxPeriods)) > 0 {
		return nil, gas, nil
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
				return nil, gas, nil
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

		if base.BitLen() > CompoundMaxBitLen {
			return nil, gas, nil
		}
	}

	out := make([]byte, 32)
	b := result.Bytes()
	if len(b) > 32 {
		return nil, gas, nil
	}
	copy(out[32-len(b):], b)

	return out, gas, nil
}