// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.

package vm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
)

const (
	PasskeyBaseGas     = 3450
	PasskeyInputMinLen = 160 // hash(32) | r(32) | s(32) | x(32) | y(32)
)

// RunPasskey verifies a secp256r1 (P-256) ECDSA signature.
// Input layout: hash(32) | r(32) | s(32) | x(32) | y(32)
// Output: 32 bytes, 0x...01 if valid else 0x00
func RunPasskey(evm *EVM, input []byte, gas uint64) ([]byte, uint64, error) {
	_ = evm // currently unused; kept for consistency with other EVM-dependent precompiles

	if gas < PasskeyBaseGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= PasskeyBaseGas

	// Strict length to avoid ambiguity / malleable encodings
	if len(input) != PasskeyInputMinLen {
		return passkeyFail(), gas, nil
	}

	// Parse fields (big-endian)
	hash := input[0:32]
	r := new(big.Int).SetBytes(input[32:64])
	s := new(big.Int).SetBytes(input[64:96])
	x := new(big.Int).SetBytes(input[96:128])
	y := new(big.Int).SetBytes(input[128:160])

	curve := elliptic.P256()
	params := curve.Params()
	N := params.N

	// r, s must be in [1, N-1]
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return passkeyFail(), gas, nil
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return passkeyFail(), gas, nil
	}

	// Enforce low-S to prevent signature malleability: s <= N/2
	halfN := new(big.Int).Rsh(new(big.Int).Set(N), 1)
	if s.Cmp(halfN) > 0 {
		return passkeyFail(), gas, nil
	}

	// Public key must be on curve
	if !curve.IsOnCurve(x, y) {
		return passkeyFail(), gas, nil
	}

	pubKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	if ecdsa.Verify(pubKey, hash, r, s) {
		return passkeySuccess(), gas, nil
	}
	return passkeyFail(), gas, nil
}

func passkeySuccess() []byte {
	out := make([]byte, 32)
	out[31] = 1
	return out
}

func passkeyFail() []byte {
	return make([]byte, 32)
}