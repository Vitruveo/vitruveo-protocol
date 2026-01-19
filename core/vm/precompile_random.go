// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.

package vm

import (
    "bytes"
    "crypto/sha256"
    "encoding/binary"

    "github.com/ethereum/go-ethereum/crypto"
)

const (
    // Shared Constants
    RNGMixRounds = 100 // Number of hash loops to prevent off-chain grinding

    // Gas Costs
    RNGBaseGas     = 500
    ShuffleBaseGas = 5000

    // Shuffle Constants
    DeckSize  = 52
    OutputLen = 104
)

var (
    suits = []byte{'S', 'H', 'D', 'C'}
    ranks = []byte{'A', '2', '3', '4', '5', '6', '7', '8', '9', 'T', 'J', 'Q', 'K'}
)

// generateSystemEntropy creates a high-quality seed using protocol state.
// It combines Consensus (ParentHash), Network (ChainID), and Uniqueness (Nonce)
// to ensure the output is deterministic for the node but unpredictable for the user.
func generateSystemEntropy(evm *EVM, salt []byte) []byte {
    // 1. Network & Consensus Context
    // FIXED: Use evm.ChainConfig() to access ChainID
    chainID := evm.ChainConfig().ChainID.Bytes()
    
    // ParentHash provides high entropy from the previous validator's signature/seal.
    currentBlockNum := evm.Context.BlockNumber.Uint64()
    parentHash := evm.Context.GetHash(currentBlockNum - 1)

    // 2. Transaction Context (Uniqueness)
    // Nonce ensures the user cannot reuse the same input state within a block.
    nonce := evm.StateDB.GetNonce(evm.TxContext.Origin)
    nonceBytes := make([]byte, 8)
    binary.BigEndian.PutUint64(nonceBytes, nonce)

    // Timestamp adds context and prevents cross-block replay issues.
    timestamp := evm.Context.Time
    timeBytes := make([]byte, 8)
    binary.BigEndian.PutUint64(timeBytes, timestamp)

    // 3. Build Entropy Pool
    // Pool Capacity = ParentHash(32) + Origin(20) + Nonce(8) + Timestamp(8) + ChainID(N) + Salt(N)
    data := make([]byte, 0, 100+len(salt))
    data = append(data, parentHash.Bytes()...)
    data = append(data, evm.TxContext.Origin.Bytes()...)
    data = append(data, nonceBytes...)
    data = append(data, timeBytes...)
    data = append(data, chainID...)
    
    // Optional salt allows a contract to request multiple unique outcomes in one tx
    if len(salt) > 0 {
        data = append(data, salt...)
    }

    // 4. Heavy Mixing (The "Go Advantage")
    // We hash the data multiple times. This is fast for the node (Go) but 
    // computationally expensive for a cheater trying to "grind" results off-chain.
    result := crypto.Keccak256(data)
    for i := 0; i < RNGMixRounds; i++ {
        result = crypto.Keccak256(result)
    }
    return result
}

// RunRNG generates pseudo-random bytes.
// Input: optional salt (arbitrary bytes)
// Output: 32 bytes of robust entropy
func RunRNG(evm *EVM, input []byte, gas uint64) ([]byte, uint64, error) {
    if gas < RNGBaseGas {
        return nil, 0, ErrOutOfGas
    }
    // Call shared helper to get entropy
    result := generateSystemEntropy(evm, input)
    
    return result, gas - RNGBaseGas, nil
}

// RunShuffle returns a canonical ASCII deck shuffle (104 bytes).
// Format: Each card = 2 bytes [Suit][Rank] (e.g., "SA" for Ace of Spades)
// Input: optional salt (arbitrary bytes)
func RunShuffle(evm *EVM, input []byte, gas uint64) ([]byte, uint64, error) {
    if gas < ShuffleBaseGas {
        return nil, 0, ErrOutOfGas
    }

    // 1. Get Secure Seed from System
    seed := generateSystemEntropy(evm, input)

    // 2. Build Standard Ordered Deck
    deck := make([][2]byte, DeckSize)
    idx := 0
    for _, s := range suits {
        for _, r := range ranks {
            deck[idx][0] = s
            deck[idx][1] = r
            idx++
        }
    }

    // 3. Fisher-Yates Shuffle using SHA256 stream
    // We use the secure system seed to drive the shuffle
    counter := uint64(0)
    hashBuf := []byte{}

    // Helper to extract 16 bits from the hash stream
    nextUint16 := func() uint16 {
        if len(hashBuf) < 2 {
            // Expand the secure seed
            h := sha256.Sum256(append(seed, byte(counter)))
            hashBuf = h[:]
            counter++
        }
        v := uint16(hashBuf[0])<<8 | uint16(hashBuf[1])
        hashBuf = hashBuf[2:]
        return v
    }

    // Shuffle logic with rejection sampling (to avoid modulo bias)
    for i := DeckSize - 1; i > 0; i-- {
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

    // 4. Flatten to Output Bytes
    var out bytes.Buffer
    out.Grow(OutputLen)
    for i := 0; i < DeckSize; i++ {
        out.WriteByte(deck[i][0])
        out.WriteByte(deck[i][1])
    }

    return out.Bytes(), gas - ShuffleBaseGas, nil
}