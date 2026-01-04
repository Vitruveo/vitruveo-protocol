// core/vm/contracts_ibc.go

package vm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	ics23 "github.com/cosmos/ics23/go"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"

	"github.com/gogo/protobuf/proto"
	"github.com/tendermint/tendermint/light"
	tmmath "github.com/tendermint/tendermint/libs/math"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tmtypes "github.com/tendermint/tendermint/types"
)

var (
	IBCVerifierAddress = common.HexToAddress("0x00000000000000000000000000000000000001BC")
	IBCStorageAddress = common.HexToAddress("0x1dbe97231e0bd613EDD58b05A70287DEb84a63C4")

	setSlotSelector   = crypto.Keccak256([]byte("setSlot(bytes32,bytes32)"))[:4]
	getSlotSelector   = crypto.Keccak256([]byte("getSlot(bytes32)"))[:4]

	slotClientStatePrefix    = byte(0x01)
	slotConsensusStatePrefix = byte(0x02)

	selectorCreateClient        = crypto.Keccak256([]byte("createClient(bytes32,bytes,bytes)"))[:4]
	selectorUpdateClient        = crypto.Keccak256([]byte("updateClient(bytes32,bytes,bytes,bytes,bytes)"))[:4]
	selectorVerifyMembership    = crypto.Keccak256([]byte("verifyMembership(bytes32,uint64,bytes,bytes,bytes)"))[:4]
	selectorVerifyNonMembership = crypto.Keccak256([]byte("verifyNonMembership(bytes32,uint64,bytes,bytes)"))[:4]
	selectorGetClientState      = crypto.Keccak256([]byte("getClientState(bytes32)"))[:4]
	selectorGetConsensusState   = crypto.Keccak256([]byte("getConsensusState(bytes32,uint64)"))[:4]

	ErrClientNotFound        = errors.New("client not found")
	ErrClientFrozen          = errors.New("client is frozen")
	ErrClientExists          = errors.New("client already exists")
	ErrConsensusNotFound     = errors.New("consensus state not found")
	ErrConsensusExists       = errors.New("consensus state already exists at height")
	ErrInvalidProof          = errors.New("invalid proof")
	ErrInputTooShort         = errors.New("input too short")
	ErrInputTooLong          = errors.New("input exceeds max size")
	ErrInvalidABI            = errors.New("invalid ABI encoding")
	ErrHeaderMismatch        = errors.New("header does not match stored consensus state")
	ErrHeightNotMonotonic    = errors.New("new height must be greater than trusted height")
	ErrChainIDMismatch       = errors.New("chain ID mismatch")
	ErrValidatorHashMismatch = errors.New("validator set hash mismatch")
	ErrHeaderInFuture        = errors.New("header time too far in future")
	ErrTimeNotMonotonic      = errors.New("untrusted header time must be after trusted header time")
	ErrTrustingPeriodExpired = errors.New("trusted consensus state has expired")
	ErrBootstrapTooOld       = errors.New("bootstrap consensus state already expired")
	ErrTimestampOverflow     = errors.New("timestamp overflows int64")
	ErrOutputTooLarge        = errors.New("output data too large to encode")
	ErrInvalidBytes32        = errors.New("bytes32 must be exactly 32 bytes")

	// MaxInputSize is a policy cap for both input AND output data.
	// Input exceeding this returns ErrInputTooLong.
	// Output exceeding this returns ErrOutputTooLarge.
	// This bounds memory allocation and ensures gas costs stay predictable.
	// If a future method needs larger input/output, bump this only with:
	// (1) security audit of the new method, and (2) gas cost recalibration.
	MaxInputSize = 1 << 20

	MaxChainIDLength    = 128
	MaxProofSize        = 512 * 1024
	MaxSignedHeaderSize = 256 * 1024
	MaxValidatorSetSize = 256 * 1024
	MaxValidatorCount   = 400
	MaxPathSize         = 1024
	MaxValueSize        = 128 * 1024

	// MaxClientStateSize bounds the ABI-encoded client state blob.
	// Calculated from: 2 (chainID length) + MaxChainIDLength + 56 (fixed fields)
	// Update this if you add fields to ClientState binary encoding.
	MaxClientStateSize = 2 + MaxChainIDLength + 56 // = 186 bytes

	// ConsensusStateBinarySize is the exact size of encoded consensus state.
	// 8 (timestamp) + 32 (root) + 32 (validatorsHash) + 32 (nextValidatorsHash)
	ConsensusStateBinarySize = 104
)

type ClientState struct {
	ChainID         string
	TrustLevelNumer uint64
	TrustLevelDenom uint64
	TrustingPeriod  uint64
	UnbondingPeriod uint64
	MaxClockDrift   uint64
	LatestHeight    uint64
	FrozenHeight    uint64
}

type ConsensusState struct {
	Timestamp          uint64
	Root               []byte
	ValidatorsHash     []byte
	NextValidatorsHash []byte
}

type IBCVerifier struct{}

// RequiredGas returns a defensive gas estimate for IBC precompile operations.
//
// These are NOT tight bounds. They are deliberately overestimated because:
// - Proto unmarshal CPU cost varies with message structure
// - light.Verify does signature verification (expensive, scales with validator count)
// - ICS23 proof verification is tree-depth dependent
//
// The per-byte scaling factors are chosen to make adversarial calldata expensive
// without making normal operations prohibitive. If you tune these, err on the
// side of overcharging rather than undercharging.
func (c *IBCVerifier) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return 0
	}
	selector := input[:4]
	inputLen := uint64(len(input))

	switch {
	case bytes.Equal(selector, selectorCreateClient):
		return 100000
	case bytes.Equal(selector, selectorUpdateClient):
		// Two headers + two validator sets + signature verification
		return 200000 + (inputLen * 8)
	case bytes.Equal(selector, selectorVerifyMembership),
		bytes.Equal(selector, selectorVerifyNonMembership):
		// Proto unmarshal + ICS23 tree traversal
		return 50000 + (inputLen * 25)
	case bytes.Equal(selector, selectorGetClientState),
		bytes.Equal(selector, selectorGetConsensusState):
		return 3000
	default:
		return 5000
	}
}

// RunIBCVerifier executes the IBC verifier precompile with EVM context
func RunIBCVerifier(evm *EVM, input []byte, gas uint64) ([]byte, uint64, error) {
	verifier := &IBCVerifier{}
	
	// Check gas
	requiredGas := verifier.RequiredGas(input)
	if gas < requiredGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= requiredGas
	
	// Run
	result, err := verifier.RunIBC(evm, input)
	if err != nil {
		return nil, 0, err
	}
	
	return result, gas, nil
}


func (c *IBCVerifier) RunIBC(evm *EVM, input []byte) ([]byte, error) {
	if len(input) > MaxInputSize {
		return nil, ErrInputTooLong
	}
	if len(input) < 4 {
		return nil, ErrInputTooShort
	}

	selector := input[:4]
	payload := input[4:]

	var result []byte
	var err error

	switch {
	case bytes.Equal(selector, selectorCreateClient):
		result, err = c.createClient(evm, payload)
	case bytes.Equal(selector, selectorUpdateClient):
		result, err = c.updateClient(evm, payload)
	case bytes.Equal(selector, selectorVerifyMembership):
		result, err = c.verifyMembership(evm, payload)
	case bytes.Equal(selector, selectorVerifyNonMembership):
		result, err = c.verifyNonMembership(evm, payload)
	case bytes.Equal(selector, selectorGetClientState):
		result, err = c.getClientStateABI(evm, payload)
	case bytes.Equal(selector, selectorGetConsensusState):
		result, err = c.getConsensusStateABI(evm, payload)
	default:
		return nil, errors.New("unknown selector")
	}

	if err != nil {
		return nil, err
	}

	// Enforce output cap (matches MaxInputSize policy)
	if len(result) > MaxInputSize {
		return nil, ErrOutputTooLarge
	}

	return result, nil
}

// ============================================
// Time Helpers
// ============================================

func safeUnixTime(ts uint64) (time.Time, error) {
	if ts > uint64(math.MaxInt64) {
		return time.Time{}, ErrTimestampOverflow
	}
	return time.Unix(int64(ts), 0), nil
}

// ============================================
// Strict ABI Decoding
//
// INTENTIONAL DESIGN CHOICE: uint64-only decoding.
//
// Standard ABI uses uint256 for offsets and lengths. We deliberately reject
// any value that doesn't fit in uint64, even if it would be "valid" ABI.
// This is acceptable for a precompile because:
// - MaxInputSize hard-caps all data to 1MB anyway
// - Rejecting huge offsets/lengths fails fast on malformed calldata
// - Avoids big.Int allocation overhead on every decode
//
// Do NOT "fix" this to be spec-compliant uint256 without reconsidering
// the security implications and gas costs.
// ============================================

func ceil32Uint64(n uint64) uint64 {
	return ((n + 31) / 32) * 32
}

func decodeUint64FromWord(word []byte) (uint64, error) {
	if len(word) != 32 {
		return 0, ErrInvalidABI
	}
	for i := 0; i < 24; i++ {
		if word[i] != 0 {
			return 0, fmt.Errorf("%w: value exceeds uint64", ErrInvalidABI)
		}
	}
	return binary.BigEndian.Uint64(word[24:32]), nil
}

func decodeABIBytes(payload []byte, headStart int, numHeadWords int) ([]byte, error) {
	headSize := numHeadWords * 32

	if len(payload) < headStart+32 {
		return nil, ErrInputTooShort
	}

	off64, err := decodeUint64FromWord(payload[headStart : headStart+32])
	if err != nil {
		return nil, fmt.Errorf("offset: %w", err)
	}

	if off64 < uint64(headSize) {
		return nil, fmt.Errorf("%w: offset %d < headSize %d", ErrInvalidABI, off64, headSize)
	}
	if off64%32 != 0 {
		return nil, fmt.Errorf("%w: offset %d not 32-byte aligned", ErrInvalidABI, off64)
	}
	if off64 > uint64(len(payload)) {
		return nil, fmt.Errorf("%w: offset %d beyond payload", ErrInvalidABI, off64)
	}
	if uint64(len(payload)) < off64+32 {
		return nil, fmt.Errorf("%w: no room for length word", ErrInvalidABI)
	}

	off := int(off64)

	dataLen64, err := decodeUint64FromWord(payload[off : off+32])
	if err != nil {
		return nil, fmt.Errorf("length: %w", err)
	}

	if dataLen64 > uint64(MaxInputSize) {
		return nil, fmt.Errorf("%w: length %d exceeds max input size", ErrInvalidABI, dataLen64)
	}

	remainingSpace := uint64(len(payload) - off - 32)
	if dataLen64 > remainingSpace {
		return nil, fmt.Errorf("%w: length %d exceeds remaining payload %d", ErrInvalidABI, dataLen64, remainingSpace)
	}

	dataLen := int(dataLen64)
	paddedLen64 := ceil32Uint64(dataLen64)
	paddedEnd := off + 32 + int(paddedLen64)
	if paddedEnd > len(payload) {
		return nil, fmt.Errorf("%w: padded data extends beyond payload", ErrInvalidABI)
	}

	for i := off + 32 + dataLen; i < paddedEnd; i++ {
		if payload[i] != 0 {
			return nil, fmt.Errorf("%w: non-zero padding byte at %d", ErrInvalidABI, i)
		}
	}

	return payload[off+32 : off+32+dataLen], nil
}

func decodeABIBytesWithLimit(payload []byte, headStart int, numHeadWords int, maxSize int) ([]byte, error) {
	data, err := decodeABIBytes(payload, headStart, numHeadWords)
	if err != nil {
		return nil, err
	}
	if len(data) > maxSize {
		return nil, fmt.Errorf("%w: decoded bytes %d > max %d", ErrInputTooLong, len(data), maxSize)
	}
	return data, nil
}

func decodeABIBytesExact(payload []byte, headStart int, numHeadWords int, exactSize int) ([]byte, error) {
	data, err := decodeABIBytes(payload, headStart, numHeadWords)
	if err != nil {
		return nil, err
	}
	if len(data) != exactSize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidABI, exactSize, len(data))
	}
	return data, nil
}

func decodeABIBytes32(payload []byte, start int) ([]byte, error) {
	if len(payload) < start+32 {
		return nil, ErrInputTooShort
	}
	result := make([]byte, 32)
	copy(result, payload[start:start+32])
	return result, nil
}

func decodeABIUint64(payload []byte, start int) (uint64, error) {
	if len(payload) < start+32 {
		return 0, ErrInputTooShort
	}
	return decodeUint64FromWord(payload[start : start+32])
}

// ============================================
// Canonical ABI Encoding
// ============================================

func abiEncodeBool(val bool) []byte {
	result := make([]byte, 32)
	if val {
		result[31] = 1
	}
	return result
}

func abiEncodeBytes32(data []byte) ([]byte, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidBytes32, len(data))
	}
	result := make([]byte, 32)
	copy(result, data)
	return result, nil
}

func abiEncodeBytes(data []byte) ([]byte, error) {
	if uint64(len(data)) > uint64(MaxInputSize) {
		return nil, fmt.Errorf("%w: %d bytes", ErrOutputTooLarge, len(data))
	}

	paddedLen64 := ceil32Uint64(uint64(len(data)))
	if paddedLen64 > uint64(MaxInputSize) {
		return nil, fmt.Errorf("%w: padded size %d", ErrOutputTooLarge, paddedLen64)
	}
	paddedLen := int(paddedLen64)

	result := make([]byte, 32+32+paddedLen)
	binary.BigEndian.PutUint64(result[24:32], 32)
	binary.BigEndian.PutUint64(result[56:64], uint64(len(data)))
	copy(result[64:], data)

	return result, nil
}

// ============================================
// Core Methods
// ============================================

func (c *IBCVerifier) createClient(evm *EVM, payload []byte) ([]byte, error) {
	const numArgs = 3

	clientId, err := decodeABIBytes32(payload, 0)
	if err != nil {
		return nil, fmt.Errorf("clientId: %w", err)
	}

	clientStateBytes, err := decodeABIBytesWithLimit(payload, 32, numArgs, MaxClientStateSize)
	if err != nil {
		return nil, fmt.Errorf("clientState: %w", err)
	}

	consensusStateBytes, err := decodeABIBytesExact(payload, 64, numArgs, ConsensusStateBinarySize)
	if err != nil {
		return nil, fmt.Errorf("consensusState: %w", err)
	}

	if c.getClientState(evm, clientId) != nil {
		return nil, ErrClientExists
	}

	clientState, err := decodeClientStateBytes(clientStateBytes)
	if err != nil {
		return nil, fmt.Errorf("decode clientState: %w", err)
	}

	if err := validateClientState(clientState); err != nil {
		return nil, err
	}

	consensusState, err := decodeConsensusStateBytes(consensusStateBytes)
	if err != nil {
		return nil, fmt.Errorf("decode consensusState: %w", err)
	}

	if err := validateConsensusState(consensusState); err != nil {
		return nil, err
	}

	currentTime, err := safeUnixTime(evm.Context.Time)
	if err != nil {
		return nil, fmt.Errorf("current time: %w", err)
	}

	consensusTime, err := safeUnixTime(consensusState.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("consensus timestamp: %w", err)
	}

	maxClockDrift := time.Duration(clientState.MaxClockDrift) * time.Second
	trustingPeriod := time.Duration(clientState.TrustingPeriod) * time.Second
	maxAllowedTime := currentTime.Add(maxClockDrift)

	if consensusTime.After(maxAllowedTime) {
		return nil, fmt.Errorf("%w: bootstrap timestamp %v > max %v", ErrHeaderInFuture, consensusTime, maxAllowedTime)
	}

	if currentTime.After(consensusTime) {
		elapsed := currentTime.Sub(consensusTime)
		if elapsed >= trustingPeriod {
			return nil, fmt.Errorf("%w: bootstrap timestamp %v is %v old, trusting period is %v", ErrBootstrapTooOld, consensusTime, elapsed, trustingPeriod)
		}
	}

	c.setClientState(evm, clientId, clientState)
	c.setConsensusState(evm, clientId, clientState.LatestHeight, consensusState)

	return abiEncodeBool(true), nil
}

func validateClientState(cs *ClientState) error {
	if len(cs.ChainID) == 0 || len(cs.ChainID) > MaxChainIDLength {
		return errors.New("invalid chainID length")
	}
	if cs.TrustLevelDenom == 0 {
		return errors.New("trust level denominator is zero")
	}
	if cs.TrustLevelNumer == 0 || cs.TrustLevelNumer > cs.TrustLevelDenom {
		return errors.New("invalid trust level")
	}
	if 3*cs.TrustLevelNumer <= cs.TrustLevelDenom {
		return errors.New("trust level must be > 1/3")
	}
	if cs.TrustingPeriod == 0 {
		return errors.New("trusting period is zero")
	}
	if cs.UnbondingPeriod == 0 {
		return errors.New("unbonding period is zero")
	}
	if cs.TrustingPeriod >= cs.UnbondingPeriod {
		return errors.New("trusting period must be < unbonding period")
	}
	if cs.LatestHeight == 0 {
		return errors.New("latest height must be > 0")
	}
	// FrozenHeight: 0 means not frozen, otherwise must be >= LatestHeight.
	// Runtime checks in updateClient/verify* enforce that operations at or
	// above FrozenHeight are rejected. Callers bootstrapping a pre-frozen
	// client (unusual) can set FrozenHeight to any height >= LatestHeight.
	if cs.FrozenHeight != 0 && cs.FrozenHeight < cs.LatestHeight {
		return errors.New("frozen height must be 0 or >= latest height")
	}
	return nil
}

func validateConsensusState(cs *ConsensusState) error {
	if len(cs.Root) != 32 {
		return errors.New("root must be 32 bytes")
	}
	if len(cs.ValidatorsHash) != 32 {
		return errors.New("validatorsHash must be 32 bytes")
	}
	if len(cs.NextValidatorsHash) != 32 {
		return errors.New("nextValidatorsHash must be 32 bytes")
	}
	if cs.Timestamp == 0 {
		return errors.New("timestamp is zero")
	}
	if cs.Timestamp > uint64(math.MaxInt64) {
		return ErrTimestampOverflow
	}
	return nil
}

// updateClient advances the light client to a new height.
//
// INTENTIONAL DESIGN CHOICE: Single trust anchor model.
//
// trustedHeight MUST equal clientState.LatestHeight. This is deliberate:
// - Disallows multi-anchor or delayed/out-of-order relayer updates
// - Prevents back-anchoring attacks where attacker picks a favorable old height
// - Simplifies security reasoning (one trust root, not a forest)
//
// Operational implication: Relayers must update continuously. If you miss
// updates and LatestHeight expires, you cannot "catch up" from an older
// trusted height—you must re-bootstrap the client.
//
// If you need multi-anchor support (e.g., for redundant relayers or
// delayed packet processing), this design must change. Do NOT remove
// the trustedHeight == LatestHeight check without a security review.
func (c *IBCVerifier) updateClient(evm *EVM, payload []byte) ([]byte, error) {
	const numArgs = 5

	clientId, err := decodeABIBytes32(payload, 0)
	if err != nil {
		return nil, err
	}

	trustedHeaderBytes, err := decodeABIBytesWithLimit(payload, 32, numArgs, MaxSignedHeaderSize)
	if err != nil {
		return nil, fmt.Errorf("trustedHeader: %w", err)
	}

	trustedValSetBytes, err := decodeABIBytesWithLimit(payload, 64, numArgs, MaxValidatorSetSize)
	if err != nil {
		return nil, fmt.Errorf("trustedValSet: %w", err)
	}

	untrustedHeaderBytes, err := decodeABIBytesWithLimit(payload, 96, numArgs, MaxSignedHeaderSize)
	if err != nil {
		return nil, fmt.Errorf("untrustedHeader: %w", err)
	}

	untrustedValSetBytes, err := decodeABIBytesWithLimit(payload, 128, numArgs, MaxValidatorSetSize)
	if err != nil {
		return nil, fmt.Errorf("untrustedValSet: %w", err)
	}

	clientState := c.getClientState(evm, clientId)
	if clientState == nil {
		return nil, ErrClientNotFound
	}
	if clientState.FrozenHeight > 0 {
		return nil, ErrClientFrozen
	}

	trustedHeader, err := decodeSignedHeaderProto(trustedHeaderBytes)
	if err != nil {
		return nil, fmt.Errorf("decode trustedHeader: %w", err)
	}

	trustedVals, err := decodeValidatorSetProto(trustedValSetBytes)
	if err != nil {
		return nil, fmt.Errorf("decode trustedVals: %w", err)
	}
	if trustedVals.Size() > MaxValidatorCount {
		return nil, errors.New("trusted validator set too large")
	}

	untrustedHeader, err := decodeSignedHeaderProto(untrustedHeaderBytes)
	if err != nil {
		return nil, fmt.Errorf("decode untrustedHeader: %w", err)
	}

	untrustedVals, err := decodeValidatorSetProto(untrustedValSetBytes)
	if err != nil {
		return nil, fmt.Errorf("decode untrustedVals: %w", err)
	}
	if untrustedVals.Size() > MaxValidatorCount {
		return nil, errors.New("untrusted validator set too large")
	}

	trustedHeight := uint64(trustedHeader.Header.Height)
	newHeight := uint64(untrustedHeader.Header.Height)

	currentTime, err := safeUnixTime(evm.Context.Time)
	if err != nil {
		return nil, fmt.Errorf("current time: %w", err)
	}

	maxClockDrift := time.Duration(clientState.MaxClockDrift) * time.Second
	trustingPeriod := time.Duration(clientState.TrustingPeriod) * time.Second
	maxAllowedTime := currentTime.Add(maxClockDrift)

	// Single trust anchor enforcement (see function comment)
	if trustedHeight != clientState.LatestHeight {
		return nil, fmt.Errorf("trusted height %d != latest height %d", trustedHeight, clientState.LatestHeight)
	}

	if newHeight <= trustedHeight {
		return nil, fmt.Errorf("%w: newHeight %d <= trustedHeight %d", ErrHeightNotMonotonic, newHeight, trustedHeight)
	}

	if c.getConsensusState(evm, clientId, newHeight) != nil {
		return nil, fmt.Errorf("%w: height %d", ErrConsensusExists, newHeight)
	}

	if trustedHeader.Header.ChainID != clientState.ChainID {
		return nil, fmt.Errorf("%w: trusted header", ErrChainIDMismatch)
	}
	if untrustedHeader.Header.ChainID != clientState.ChainID {
		return nil, fmt.Errorf("%w: untrusted header", ErrChainIDMismatch)
	}

	if trustedHeader.Header.Time.After(maxAllowedTime) {
		return nil, fmt.Errorf("%w: trusted header time %v > max %v", ErrHeaderInFuture, trustedHeader.Header.Time, maxAllowedTime)
	}

	if untrustedHeader.Header.Time.After(maxAllowedTime) {
		return nil, fmt.Errorf("%w: untrusted header time %v > max %v", ErrHeaderInFuture, untrustedHeader.Header.Time, maxAllowedTime)
	}

	if !untrustedHeader.Header.Time.After(trustedHeader.Header.Time) {
		return nil, fmt.Errorf("%w: untrusted %v <= trusted %v", ErrTimeNotMonotonic, untrustedHeader.Header.Time, trustedHeader.Header.Time)
	}

	if !bytes.Equal(trustedVals.Hash(), trustedHeader.Header.ValidatorsHash) {
		return nil, fmt.Errorf("%w: trusted validators don't match trusted header", ErrValidatorHashMismatch)
	}
	if !bytes.Equal(untrustedVals.Hash(), untrustedHeader.Header.ValidatorsHash) {
		return nil, fmt.Errorf("%w: untrusted validators don't match untrusted header", ErrValidatorHashMismatch)
	}

	trustedConsState := c.getConsensusState(evm, clientId, trustedHeight)
	if trustedConsState == nil {
		return nil, ErrConsensusNotFound
	}

	if !bytes.Equal(trustedHeader.Header.AppHash, trustedConsState.Root) {
		return nil, fmt.Errorf("%w: appHash", ErrHeaderMismatch)
	}
	if uint64(trustedHeader.Header.Time.Unix()) != trustedConsState.Timestamp {
		return nil, fmt.Errorf("%w: timestamp", ErrHeaderMismatch)
	}
	if !bytes.Equal(trustedHeader.Header.ValidatorsHash, trustedConsState.ValidatorsHash) {
		return nil, fmt.Errorf("%w: validatorsHash", ErrHeaderMismatch)
	}
	if !bytes.Equal(trustedHeader.Header.NextValidatorsHash, trustedConsState.NextValidatorsHash) {
		return nil, fmt.Errorf("%w: nextValidatorsHash", ErrHeaderMismatch)
	}

	storedTrustedTime, err := safeUnixTime(trustedConsState.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("stored trusted time: %w", err)
	}

	var elapsed time.Duration
	if currentTime.After(storedTrustedTime) {
		elapsed = currentTime.Sub(storedTrustedTime)
	} else {
		elapsed = 0
	}

	if elapsed >= trustingPeriod {
		return nil, fmt.Errorf("%w: elapsed %v >= trusting period %v", ErrTrustingPeriodExpired, elapsed, trustingPeriod)
	}

	trustLevel := tmmath.Fraction{
		Numerator:   clientState.TrustLevelNumer,
		Denominator: clientState.TrustLevelDenom,
	}

	err = light.Verify(
		trustedHeader,
		trustedVals,
		untrustedHeader,
		untrustedVals,
		trustingPeriod,
		currentTime,
		maxClockDrift,
		trustLevel,
	)
	if err != nil {
		return nil, fmt.Errorf("light client verification failed: %w", err)
	}

	newConsState := &ConsensusState{
		Timestamp:          uint64(untrustedHeader.Header.Time.Unix()),
		Root:               untrustedHeader.Header.AppHash,
		ValidatorsHash:     untrustedHeader.Header.ValidatorsHash,
		NextValidatorsHash: untrustedHeader.Header.NextValidatorsHash,
	}

	clientState.LatestHeight = newHeight
	c.setClientState(evm, clientId, clientState)
	c.setConsensusState(evm, clientId, newHeight, newConsState)

	return abiEncodeBytes32(newConsState.Root)
}

// verifyMembership verifies a membership proof against a stored consensus state.
//
// Tries both IAVL and Tendermint proof specs. This is practical for early
// deployment but means a proof could validate under either spec. For stricter
// guarantees, store the proof spec per-client in ClientState and enforce it.
func (c *IBCVerifier) verifyMembership(evm *EVM, payload []byte) ([]byte, error) {
	const numArgs = 5

	clientId, err := decodeABIBytes32(payload, 0)
	if err != nil {
		return nil, err
	}

	height, err := decodeABIUint64(payload, 32)
	if err != nil {
		return nil, err
	}

	proofBytes, err := decodeABIBytesWithLimit(payload, 64, numArgs, MaxProofSize)
	if err != nil {
		return nil, err
	}

	path, err := decodeABIBytesWithLimit(payload, 96, numArgs, MaxPathSize)
	if err != nil {
		return nil, err
	}

	value, err := decodeABIBytesWithLimit(payload, 128, numArgs, MaxValueSize)
	if err != nil {
		return nil, err
	}

	clientState := c.getClientState(evm, clientId)
	if clientState == nil {
		return nil, ErrClientNotFound
	}
	if clientState.FrozenHeight > 0 && height >= clientState.FrozenHeight {
		return nil, ErrClientFrozen
	}

	consState := c.getConsensusState(evm, clientId, height)
	if consState == nil {
		return nil, ErrConsensusNotFound
	}

	var proof ics23.CommitmentProof
	if err := proto.Unmarshal(proofBytes, &proof); err != nil {
		return nil, fmt.Errorf("unmarshal proof: %w", err)
	}

	if ics23.VerifyMembership(ics23.IavlSpec, consState.Root, &proof, path, value) {
		return abiEncodeBool(true), nil
	}

	if ics23.VerifyMembership(ics23.TendermintSpec, consState.Root, &proof, path, value) {
		return abiEncodeBool(true), nil
	}

	return nil, ErrInvalidProof
}

// verifyNonMembership verifies a non-membership proof against a stored consensus state.
// See verifyMembership for notes on dual proof spec handling.
func (c *IBCVerifier) verifyNonMembership(evm *EVM, payload []byte) ([]byte, error) {
	const numArgs = 4

	clientId, err := decodeABIBytes32(payload, 0)
	if err != nil {
		return nil, err
	}

	height, err := decodeABIUint64(payload, 32)
	if err != nil {
		return nil, err
	}

	proofBytes, err := decodeABIBytesWithLimit(payload, 64, numArgs, MaxProofSize)
	if err != nil {
		return nil, err
	}

	path, err := decodeABIBytesWithLimit(payload, 96, numArgs, MaxPathSize)
	if err != nil {
		return nil, err
	}

	clientState := c.getClientState(evm, clientId)
	if clientState == nil {
		return nil, ErrClientNotFound
	}
	if clientState.FrozenHeight > 0 && height >= clientState.FrozenHeight {
		return nil, ErrClientFrozen
	}

	consState := c.getConsensusState(evm, clientId, height)
	if consState == nil {
		return nil, ErrConsensusNotFound
	}

	var proof ics23.CommitmentProof
	if err := proto.Unmarshal(proofBytes, &proof); err != nil {
		return nil, fmt.Errorf("unmarshal proof: %w", err)
	}

	if ics23.VerifyNonMembership(ics23.IavlSpec, consState.Root, &proof, path) {
		return abiEncodeBool(true), nil
	}

	if ics23.VerifyNonMembership(ics23.TendermintSpec, consState.Root, &proof, path) {
		return abiEncodeBool(true), nil
	}

	return nil, ErrInvalidProof
}

func (c *IBCVerifier) getClientStateABI(evm *EVM, payload []byte) ([]byte, error) {
	clientId, err := decodeABIBytes32(payload, 0)
	if err != nil {
		return nil, err
	}

	cs := c.getClientState(evm, clientId)
	if cs == nil {
		return nil, ErrClientNotFound
	}

	return abiEncodeBytes(encodeClientStateBytes(cs))
}

func (c *IBCVerifier) getConsensusStateABI(evm *EVM, payload []byte) ([]byte, error) {
	clientId, err := decodeABIBytes32(payload, 0)
	if err != nil {
		return nil, err
	}

	height, err := decodeABIUint64(payload, 32)
	if err != nil {
		return nil, err
	}

	cs := c.getConsensusState(evm, clientId, height)
	if cs == nil {
		return nil, ErrConsensusNotFound
	}

	return abiEncodeBytes(encodeConsensusStateBytes(cs))
}

// ============================================
// Protobuf Decoding
// ============================================

func decodeSignedHeaderProto(data []byte) (*tmtypes.SignedHeader, error) {
	var pb tmproto.SignedHeader
	if err := proto.Unmarshal(data, &pb); err != nil {
		return nil, err
	}
	return tmtypes.SignedHeaderFromProto(&pb)
}

func decodeValidatorSetProto(data []byte) (*tmtypes.ValidatorSet, error) {
	var pb tmproto.ValidatorSet
	if err := proto.Unmarshal(data, &pb); err != nil {
		return nil, err
	}
	return tmtypes.ValidatorSetFromProto(&pb)
}

// ============================================
// Binary Encoding (for ABI input/output only)
//
// FORMAT WARNING: This encoding is versionless.
// Adding, removing, or reordering fields is a BREAKING CHANGE for any
// caller that persists these blobs off-chain (e.g., relayer state, indexers).
// If you need to evolve the format, either:
// - Add a version byte prefix and support both formats, or
// - Coordinate a hard cutover with all known consumers.
//
// Current clientState format (2 + len(chainID) + 56 bytes):
//   [2 bytes]  chainID length (big-endian uint16)
//   [N bytes]  chainID (UTF-8, N = chainID length)
//   [8 bytes]  TrustLevelNumer
//   [8 bytes]  TrustLevelDenom
//   [8 bytes]  TrustingPeriod (seconds)
//   [8 bytes]  UnbondingPeriod (seconds)
//   [8 bytes]  MaxClockDrift (seconds)
//   [8 bytes]  LatestHeight
//   [8 bytes]  FrozenHeight (0 = not frozen)
//
// Current consensusState format (104 bytes, fixed):
//   [8 bytes]  Timestamp (unix seconds)
//   [32 bytes] Root (app hash / commitment root)
//   [32 bytes] ValidatorsHash
//   [32 bytes] NextValidatorsHash
// ============================================

func decodeClientStateBytes(data []byte) (*ClientState, error) {
	if len(data) < 2 {
		return nil, errors.New("too short for chainID length")
	}

	chainIDLen := int(binary.BigEndian.Uint16(data[0:2]))
	if chainIDLen == 0 || chainIDLen > MaxChainIDLength {
		return nil, errors.New("invalid chainID length")
	}
	if len(data) < 2+chainIDLen+56 {
		return nil, errors.New("client state truncated")
	}

	cs := &ClientState{
		ChainID: string(data[2 : 2+chainIDLen]),
	}
	pos := 2 + chainIDLen

	cs.TrustLevelNumer = binary.BigEndian.Uint64(data[pos : pos+8])
	pos += 8
	cs.TrustLevelDenom = binary.BigEndian.Uint64(data[pos : pos+8])
	pos += 8
	cs.TrustingPeriod = binary.BigEndian.Uint64(data[pos : pos+8])
	pos += 8
	cs.UnbondingPeriod = binary.BigEndian.Uint64(data[pos : pos+8])
	pos += 8
	cs.MaxClockDrift = binary.BigEndian.Uint64(data[pos : pos+8])
	pos += 8
	cs.LatestHeight = binary.BigEndian.Uint64(data[pos : pos+8])
	pos += 8
	cs.FrozenHeight = binary.BigEndian.Uint64(data[pos : pos+8])

	return cs, nil
}

func encodeClientStateBytes(cs *ClientState) []byte {
	chainID := []byte(cs.ChainID)
	result := make([]byte, 2+len(chainID)+56)

	binary.BigEndian.PutUint16(result[0:2], uint16(len(chainID)))
	copy(result[2:], chainID)
	pos := 2 + len(chainID)

	binary.BigEndian.PutUint64(result[pos:pos+8], cs.TrustLevelNumer)
	pos += 8
	binary.BigEndian.PutUint64(result[pos:pos+8], cs.TrustLevelDenom)
	pos += 8
	binary.BigEndian.PutUint64(result[pos:pos+8], cs.TrustingPeriod)
	pos += 8
	binary.BigEndian.PutUint64(result[pos:pos+8], cs.UnbondingPeriod)
	pos += 8
	binary.BigEndian.PutUint64(result[pos:pos+8], cs.MaxClockDrift)
	pos += 8
	binary.BigEndian.PutUint64(result[pos:pos+8], cs.LatestHeight)
	pos += 8
	binary.BigEndian.PutUint64(result[pos:pos+8], cs.FrozenHeight)

	return result
}

func decodeConsensusStateBytes(data []byte) (*ConsensusState, error) {
	if len(data) != ConsensusStateBinarySize {
		return nil, fmt.Errorf("consensus state must be %d bytes, got %d", ConsensusStateBinarySize, len(data))
	}

	return &ConsensusState{
		Timestamp:          binary.BigEndian.Uint64(data[0:8]),
		Root:               append([]byte(nil), data[8:40]...),
		ValidatorsHash:     append([]byte(nil), data[40:72]...),
		NextValidatorsHash: append([]byte(nil), data[72:104]...),
	}, nil
}

func encodeConsensusStateBytes(cs *ConsensusState) []byte {
	result := make([]byte, ConsensusStateBinarySize)
	binary.BigEndian.PutUint64(result[0:8], cs.Timestamp)
	copy(result[8:40], cs.Root)
	copy(result[40:72], cs.ValidatorsHash)
	copy(result[72:104], cs.NextValidatorsHash)
	return result
}

// ============================================
// Storage
// ============================================

func (c *IBCVerifier) storageSet(evm *EVM, key, value common.Hash) bool {
	input := make([]byte, 4+32+32)
	copy(input[0:4], setSlotSelector)
	copy(input[4:36], key[:])
	copy(input[36:68], value[:])

	_, _, err := evm.Call(AccountRef(IBCVerifierAddress), IBCStorageAddress, input, 50000, uint256.NewInt(0))
	return err == nil
}

func (c *IBCVerifier) storageGet(evm *EVM, key common.Hash) common.Hash {
	input := make([]byte, 4+32)
	copy(input[0:4], getSlotSelector)
	copy(input[4:36], key[:])

	ret, _, err := evm.StaticCall(AccountRef(IBCVerifierAddress), IBCStorageAddress, input, 50000)
	if err != nil || len(ret) < 32 {
		return common.Hash{}
	}
	return common.BytesToHash(ret[:32])
}

func (c *IBCVerifier) clientStateSlot(clientId []byte) common.Hash {
	buf := make([]byte, 1+len(clientId))
	buf[0] = slotClientStatePrefix
	copy(buf[1:], clientId)
	return crypto.Keccak256Hash(buf)
}

func (c *IBCVerifier) consensusStateSlot(clientId []byte, height uint64) common.Hash {
	buf := make([]byte, 1+len(clientId)+8)
	buf[0] = slotConsensusStatePrefix
	copy(buf[1:], clientId)
	binary.BigEndian.PutUint64(buf[1+len(clientId):], height)
	return crypto.Keccak256Hash(buf)
}

func incrementSlot(slot common.Hash, n uint64) common.Hash {
	var slotCopy [32]byte
	copy(slotCopy[:], slot[:])

	slotBig := new(big.Int).SetBytes(slotCopy[:])
	slotBig.Add(slotBig, new(big.Int).SetUint64(n))
	return common.BigToHash(slotBig)
}

func (c *IBCVerifier) getClientState(evm *EVM, clientId []byte) *ClientState {
	baseSlot := c.clientStateSlot(clientId)

	slot0 := c.storageGet(evm, baseSlot)
	if slot0 == (common.Hash{}) {
		return nil
	}

	chainIDLen := int(binary.BigEndian.Uint16(slot0[0:2]))
	if chainIDLen == 0 || chainIDLen > MaxChainIDLength {
		return nil
	}

	cs := &ClientState{}

	if chainIDLen <= 30 {
		cs.ChainID = string(slot0[2 : 2+chainIDLen])
	} else {
		chainIDBytes := make([]byte, 0, chainIDLen)
		chainIDBytes = append(chainIDBytes, slot0[2:32]...)

		remaining := chainIDLen - 30
		slotIdx := uint64(1)
		for remaining > 0 {
			slotN := c.storageGet(evm, incrementSlot(baseSlot, slotIdx))
			take := remaining
			if take > 32 {
				take = 32
			}
			chainIDBytes = append(chainIDBytes, slotN[:take]...)
			remaining -= take
			slotIdx++
		}
		cs.ChainID = string(chainIDBytes)
	}

	extraChainIDSlots := uint64(0)
	if chainIDLen > 30 {
		extraChainIDSlots = uint64((chainIDLen - 30 + 31) / 32)
	}
	numericSlot := incrementSlot(baseSlot, 1+extraChainIDSlots)

	num0 := c.storageGet(evm, numericSlot)
	cs.TrustLevelNumer = binary.BigEndian.Uint64(num0[0:8])
	cs.TrustLevelDenom = binary.BigEndian.Uint64(num0[8:16])
	cs.TrustingPeriod = binary.BigEndian.Uint64(num0[16:24])
	cs.UnbondingPeriod = binary.BigEndian.Uint64(num0[24:32])

	num1 := c.storageGet(evm, incrementSlot(numericSlot, 1))
	cs.MaxClockDrift = binary.BigEndian.Uint64(num1[0:8])
	cs.LatestHeight = binary.BigEndian.Uint64(num1[8:16])
	cs.FrozenHeight = binary.BigEndian.Uint64(num1[16:24])

	return cs
}

func (c *IBCVerifier) setClientState(evm *EVM, clientId []byte, cs *ClientState) {
	baseSlot := c.clientStateSlot(clientId)
	chainIDBytes := []byte(cs.ChainID)
	chainIDLen := len(chainIDBytes)

	var slot0 [32]byte
	binary.BigEndian.PutUint16(slot0[0:2], uint16(chainIDLen))
	if chainIDLen <= 30 {
		copy(slot0[2:], chainIDBytes)
	} else {
		copy(slot0[2:32], chainIDBytes[:30])
	}
	c.storageSet(evm, baseSlot, common.BytesToHash(slot0[:]))

	extraChainIDSlots := uint64(0)
	if chainIDLen > 30 {
		remaining := chainIDBytes[30:]
		slotIdx := uint64(1)
		for len(remaining) > 0 {
			var slotN [32]byte
			take := len(remaining)
			if take > 32 {
				take = 32
			}
			copy(slotN[:], remaining[:take])
			c.storageSet(evm, incrementSlot(baseSlot, slotIdx), common.BytesToHash(slotN[:]))
			remaining = remaining[take:]
			slotIdx++
		}
		extraChainIDSlots = slotIdx - 1
	}

	numericSlot := incrementSlot(baseSlot, 1+extraChainIDSlots)

	var num0 [32]byte
	binary.BigEndian.PutUint64(num0[0:8], cs.TrustLevelNumer)
	binary.BigEndian.PutUint64(num0[8:16], cs.TrustLevelDenom)
	binary.BigEndian.PutUint64(num0[16:24], cs.TrustingPeriod)
	binary.BigEndian.PutUint64(num0[24:32], cs.UnbondingPeriod)
	c.storageSet(evm, numericSlot, common.BytesToHash(num0[:]))

	var num1 [32]byte
	binary.BigEndian.PutUint64(num1[0:8], cs.MaxClockDrift)
	binary.BigEndian.PutUint64(num1[8:16], cs.LatestHeight)
	binary.BigEndian.PutUint64(num1[16:24], cs.FrozenHeight)
	c.storageSet(evm, incrementSlot(numericSlot, 1), common.BytesToHash(num1[:]))
}

func (c *IBCVerifier) getConsensusState(evm *EVM, clientId []byte, height uint64) *ConsensusState {
	baseSlot := c.consensusStateSlot(clientId, height)

	slot0 := c.storageGet(evm, baseSlot)
	if slot0 == (common.Hash{}) {
		return nil
	}

	cs := &ConsensusState{
		Timestamp: binary.BigEndian.Uint64(slot0[24:32]),
	}

	slot1 := c.storageGet(evm, incrementSlot(baseSlot, 1))
	cs.Root = append([]byte(nil), slot1[:]...)

	slot2 := c.storageGet(evm, incrementSlot(baseSlot, 2))
	cs.ValidatorsHash = append([]byte(nil), slot2[:]...)

	slot3 := c.storageGet(evm, incrementSlot(baseSlot, 3))
	cs.NextValidatorsHash = append([]byte(nil), slot3[:]...)

	return cs
}

func (c *IBCVerifier) setConsensusState(evm *EVM, clientId []byte, height uint64, cs *ConsensusState) {
	baseSlot := c.consensusStateSlot(clientId, height)

	var slot0 [32]byte
	binary.BigEndian.PutUint64(slot0[24:32], cs.Timestamp)
	c.storageSet(evm, baseSlot, common.BytesToHash(slot0[:]))

	var slot1 [32]byte
	copy(slot1[:], cs.Root)
	c.storageSet(evm, incrementSlot(baseSlot, 1), common.BytesToHash(slot1[:]))

	var slot2 [32]byte
	copy(slot2[:], cs.ValidatorsHash)
	c.storageSet(evm, incrementSlot(baseSlot, 2), common.BytesToHash(slot2[:]))

	var slot3 [32]byte
	copy(slot3[:], cs.NextValidatorsHash)
	c.storageSet(evm, incrementSlot(baseSlot, 3), common.BytesToHash(slot3[:]))
}