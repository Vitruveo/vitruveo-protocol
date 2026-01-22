package vm

import (
	
	"crypto/rand"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"

)

func RunEncrypt(evm *EVM, input []byte, suppliedGas uint64) ([]byte, uint64, error) {
	const gasCost = 10000
	if suppliedGas < gasCost {
		return nil, 0, ErrOutOfGas
	}
	
	// Input: [32 bytes pubkey X][32 bytes pubkey Y][plaintext]
	if len(input) < 65 {
		return nil, suppliedGas - gasCost, nil
	}
	
	// Parse public key (uncompressed: 04 + X + Y)
	pubBytes := make([]byte, 65)
	pubBytes[0] = 0x04
	copy(pubBytes[1:33], input[0:32])
	copy(pubBytes[33:65], input[32:64])
	
	pubKey, err := crypto.UnmarshalPubkey(pubBytes)
	if err != nil {
		return nil, suppliedGas - gasCost, nil
	}
	
	eciesPub := ecies.ImportECDSAPublic(pubKey)
	plaintext := input[64:]
	
	ciphertext, err := ecies.Encrypt(rand.Reader, eciesPub, plaintext, nil, nil)
	if err != nil {
		return nil, suppliedGas - gasCost, nil
	}
	
	return ciphertext, suppliedGas - gasCost, nil
}