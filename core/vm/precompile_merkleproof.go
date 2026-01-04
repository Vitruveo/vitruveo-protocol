package vm

import (
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	MerkleBaseGas     = 1000
	MerklePerHashGas  = 50
	MerkleInputMinLen = 64 // 32 (root) + 32 (leaf)
)

// RunMerkleProof verifies a Merkle proof.
// Input:
//   root (32) || leaf (32) || proof[0] (32) || ... || proof[n-1] (32)
// Output: 32 bytes = 1 if valid; empty if invalid or malformed input.
func RunMerkleProof(evm *EVM, input []byte, gas uint64) ([]byte, uint64, error) {
	_ = evm

	if gas < MerkleBaseGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= MerkleBaseGas

	if len(input) < MerkleInputMinLen {
		return nil, gas, nil
	}

	proofBytes := len(input) - 64
	if proofBytes%32 != 0 {
		return nil, gas, nil
	}
	proofLen := proofBytes / 32

	hashGas := uint64(proofLen) * MerklePerHashGas
	if gas < hashGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= hashGas

	root := input[0:32]
	leaf := input[32:64]

	var computed [32]byte
	copy(computed[:], leaf)

	for i := 0; i < proofLen; i++ {
		proofElement := input[64+i*32 : 64+(i+1)*32]
		computed = hashPair32(computed, proofElement)
	}

	if bytesEqual32(computed[:], root) {
		out := make([]byte, 32)
		out[31] = 1
		return out, gas, nil
	}

	return nil, gas, nil
}

// hashPair32 hashes two 32-byte values in sorted order (OpenZeppelin style).
// IMPORTANT: avoids append-on-subslice aliasing by using a fixed 64-byte buffer.
func hashPair32(a [32]byte, b []byte) [32]byte {
	var buf [64]byte
	if bytesLess32(a[:], b) {
		copy(buf[0:32], a[:])
		copy(buf[32:64], b)
	} else {
		copy(buf[0:32], b)
		copy(buf[32:64], a[:])
	}

	h := crypto.Keccak256(buf[:])

	var out [32]byte
	copy(out[:], h)
	return out
}

func bytesLess32(a, b []byte) bool {
	for i := 0; i < 32; i++ {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return false
}

func bytesEqual32(a, b []byte) bool {
	for i := 0; i < 32; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}