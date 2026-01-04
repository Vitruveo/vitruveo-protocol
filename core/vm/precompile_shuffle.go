// precompile_shuffle.go
// Canonical ASCII deck shuffle precompile
//
// Output format: 104 bytes
// Each card = 2 bytes: [SHDC][A23456789TJQK]
// Order = shuffled deck
//
// Deterministic given seed.
//
// NOTE:
// - No lookup tables required by the caller
// - Fixed-width, no separators
// - Human-readable, debuggable
//
// Gas: fixed (recommended)

package vm

import (
	"bytes"
	"crypto/sha256"
)

const (
	ShuffleBaseGas = 5000
	ShuffleInputLen = 32 // bytes32 seed
	DeckSize       = 52
	OutputLen      = 104
)

var (
	suits = []byte{'S', 'H', 'D', 'C'}
	ranks = []byte{'A', '2', '3', '4', '5', '6', '7', '8', '9', 'T', 'J', 'Q', 'K'}
)

// RunShuffle returns a shuffled ASCII deck (104 bytes)
func RunShuffle(evm *EVM, input []byte, gas uint64) ([]byte, uint64, error) {
	_ = evm
	if len(input) != ShuffleInputLen {
		return nil, 0, nil
	}
	if gas < ShuffleBaseGas {
		return nil, 0, ErrOutOfGas
	}

	// Build ordered deck as 52 cards (2 bytes each)
	deck := make([][2]byte, DeckSize)
	idx := 0
	for _, s := range suits {
		for _, r := range ranks {
			deck[idx][0] = s
			deck[idx][1] = r
			idx++
		}
	}

	// Fisher–Yates shuffle using hash stream
	seed := input
	counter := uint64(0)
	hashBuf := []byte{}

	nextUint16 := func() uint16 {
		if len(hashBuf) < 2 {
			h := sha256.Sum256(append(seed, byte(counter)))
			hashBuf = h[:]
			counter++
		}
		v := uint16(hashBuf[0])<<8 | uint16(hashBuf[1])
		hashBuf = hashBuf[2:]
		return v
	}

	for i := DeckSize - 1; i > 0; i-- {
		// rejection sampling to avoid modulo bias
		m := uint16(i + 1)
		limit := (uint16(0xFFFF) / m) * m

		var r uint16
		for {
			r = nextUint16()
			if r < limit {
				break
			}
		}

		j := int(r % m)
		deck[i], deck[j] = deck[j], deck[i]
	}

	// Flatten to output bytes
	var out bytes.Buffer
	out.Grow(OutputLen)
	for i := 0; i < DeckSize; i++ {
		out.WriteByte(deck[i][0])
		out.WriteByte(deck[i][1])
	}

	return out.Bytes(), gas - ShuffleBaseGas, nil
}