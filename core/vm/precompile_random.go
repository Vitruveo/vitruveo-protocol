// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.

package vm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// Random number precompiles. See contracts/random/IRandom.sol.
//
// RNG (0x...FF) has two modes.
//
// Plain call (backward compatible, NOT secure against simulation):
//
//	input:  [count uint8][salt bytes...]   (empty input = 1 word, no salt)
//	output: ABI-encoded uint256[] with `count` words
//
// The seed mixes the parent hash, Random/Difficulty, origin, origin nonce,
// timestamp, chain ID, the calling address, a per-transaction call counter
// and the salt. Under Clique, Random is nil and Difficulty is 1 or 2, so every
// input is known to the sender before the transaction is mined: anyone can
// compute the result ahead of time, and a contract can simulate and revert on
// an unfavorable outcome. Use it only where that does not matter.
//
// Commit-reveal (opt-in, ABI): a call whose input is exactly 36 bytes and
// starts with one of the selectors below is an ABI call; any other input is a
// plain call.
//
//	commit(bytes32 salt) returns (uint256 id)
//	reveal(uint256 id) returns (bytes32 randomness)
//	getRandomness(uint256 id) view returns (bool ready, bytes32 randomness)
//	getRequest(uint256 id) view returns (address owner, uint256 commitBlock, uint256 revealBlock, uint256 status)
//
// commit() in block N records a request whose result is
// keccak256(requestSeed, blockhash(N+1)). The hash of block N+1 does not exist
// when the commit is mined, so neither the requester nor a simulating contract
// can know the result at commit time. reveal() can be called by anyone from
// block N+2 until block N+1+256 (the BLOCKHASH window); it stores the result
// permanently and emits RandomnessRevealed. A request not revealed within the
// window expires. The sealer of block N+1 can still bias the result by
// choosing that block's contents; this protects against users, not against a
// colluding validator.
//
// Per-call uniqueness: each plain RNG or Shuffle call increments a counter
// kept in transient storage on the precompile's own address (cleared per
// transaction, reverted with the calling frame), so repeated calls within one
// transaction return different values. In a static context (STATICCALL or a
// read-only frame) nothing can be written: the counter is read but not
// advanced and the call depth and available gas are mixed in instead, no log
// is emitted, and identical static calls with the same gas can return the same
// value; pass a distinct salt to separate them.
//
// Shuffle (0x...AB): input is an optional salt, output is a 104-byte deck
// (52 cards, [suit][rank] ASCII). It uses the same entropy as a plain RNG call
// and has the same predictability. For an unpredictable shuffle, pass a value
// revealed through RNG commit-reveal as the salt.
//
// All inputs are consensus data; no validator-local data is used.

const (
	RNGMixRounds = 100 // Number of hash loops to prevent off-chain grinding

	// Gas Costs
	RNGBaseGas        = 500   // every call
	RNGWordGas        = 100   // per word after the first
	RNGSaltWordGas    = 6     // per 32-byte word of salt
	RNGCounterGas     = 100   // per transient counter read or write (TLOAD/TSTORE)
	RNGCommitGas      = 50000 // per commit (four storage writes)
	RNGRevealGas      = 25000 // per reveal that stores a result
	RNGReadGas        = 2600  // per request lookup
	RNGRevealWindow   = 256   // blocks during which blockhash(revealBlock) is available
	ShuffleBaseGas    = 5000
	rngWordsLogData   = 64 // seed, count
	rngShuffleLogData = 32 // seed

	// Request status reported by getRequest
	RNGStatusNone     = 0
	RNGStatusPending  = 1 // reveal block not yet reached
	RNGStatusReady    = 2 // can be revealed now
	RNGStatusRevealed = 3
	RNGStatusExpired  = 4

	// Shuffle Constants
	DeckSize  = 52
	OutputLen = 104
)

var (
	suits = []byte{'S', 'H', 'D', 'C'}
	ranks = []byte{'A', '2', '3', '4', '5', '6', '7', '8', '9', 'T', 'J', 'Q', 'K'}

	rngSelCommit        = pbSelector("commit(bytes32)")
	rngSelReveal        = pbSelector("reveal(uint256)")
	rngSelGetRandomness = pbSelector("getRandomness(uint256)")
	rngSelGetRequest    = pbSelector("getRequest(uint256)")

	rngArgsReady   = abi.Arguments{{Type: pbTypeBool}, {Type: pbTypeBytes32}}
	rngArgsRequest = abi.Arguments{{Type: pbTypeAddress}, {Type: pbTypeUint256}, {Type: pbTypeUint256}, {Type: pbTypeUint256}}

	rngEvWords     = crypto.Keccak256Hash([]byte("RandomWords(address,uint256,bytes32,uint256)"))
	rngEvShuffled  = crypto.Keccak256Hash([]byte("Shuffled(address,uint256,bytes32)"))
	rngEvCommitted = crypto.Keccak256Hash([]byte("RandomnessRequested(uint256,address,uint256)"))
	rngEvRevealed  = crypto.Keccak256Hash([]byte("RandomnessRevealed(uint256,address,bytes32)"))

	rngCounterSlot   = crypto.Keccak256Hash([]byte("vtru.rng.callcounter"))
	rngDomainWords   = []byte("vtru.rng.words")
	rngDomainShuffle = []byte("vtru.rng.shuffle")
	rngDomainCommit  = []byte("vtru.rng.commit")
)

// rngLogGas is the LOG gas for a log with n topics and size bytes of data.
func rngLogGas(topics, size uint64) uint64 {
	return params.LogGas + topics*params.LogTopicGas + size*params.LogDataGas
}

func rngWords(n int) uint64 { return (uint64(n) + 31) / 32 }

// rngReadOnly reports whether the call cannot modify state.
func rngReadOnly(evm *EVM, static bool) bool {
	return static || (evm.interpreter != nil && evm.interpreter.readOnly)
}

// rngCallUniqueness returns bytes that differ between calls to the precompile
// at self within one transaction, and the call index used. Outside a static
// context the transient counter is advanced; inside one it is only read and
// depth and gas are mixed in instead.
func rngCallUniqueness(evm *EVM, self, caller common.Address, readOnly bool, gas uint64) ([]byte, uint64) {
	cur := evm.StateDB.GetTransientState(self, rngCounterSlot)
	index := binary.BigEndian.Uint64(cur[24:])

	data := make([]byte, 0, 20+8+1+16)
	data = append(data, caller.Bytes()...)
	data = binary.BigEndian.AppendUint64(data, index)
	if readOnly {
		data = append(data, 1)
		data = binary.BigEndian.AppendUint64(data, uint64(evm.depth))
		data = binary.BigEndian.AppendUint64(data, gas)
	} else {
		data = append(data, 0)
		evm.StateDB.SetTransientState(self, rngCounterSlot, msWord(index+1))
	}
	return data, index
}

// generateSystemEntropy creates a seed from consensus data only. It combines
// block context (parent hash, Random or Difficulty, timestamp), network (chain
// ID), transaction (origin and its nonce) and call (caller, call counter)
// context with an optional salt. Every node computes the same value. Under
// Clique all of these are known to the sender in advance; see the file comment.
func generateSystemEntropy(evm *EVM, domain, unique, salt []byte) []byte {
	chainID := common.BigToHash(evm.ChainConfig().ChainID)

	currentBlockNum := evm.Context.BlockNumber.Uint64()
	var parentHash common.Hash
	if currentBlockNum > 0 {
		parentHash = evm.Context.GetHash(currentBlockNum - 1)
	}

	nonce := evm.StateDB.GetNonce(evm.TxContext.Origin)

	var randomness common.Hash
	if evm.Context.Random != nil {
		randomness = *evm.Context.Random
	} else if evm.Context.Difficulty != nil {
		randomness = common.BigToHash(evm.Context.Difficulty)
	}

	data := make([]byte, 0, len(domain)+32+32+20+8+8+32+len(unique)+len(salt))
	data = append(data, domain...)
	data = append(data, parentHash.Bytes()...)
	data = append(data, randomness.Bytes()...)
	data = append(data, evm.TxContext.Origin.Bytes()...)
	data = binary.BigEndian.AppendUint64(data, nonce)
	data = binary.BigEndian.AppendUint64(data, evm.Context.Time)
	data = append(data, chainID.Bytes()...)
	data = append(data, unique...)
	data = append(data, salt...)

	// Repeated hashing raises the cost of grinding salts off-chain.
	result := crypto.Keccak256(data)
	for i := 0; i < RNGMixRounds; i++ {
		result = crypto.Keccak256(result)
	}
	return result
}

// RunRNG dispatches an RNG call: commit-reveal ABI calls or a plain call.
func RunRNG(evm *EVM, caller common.Address, input []byte, gas uint64, static bool) ([]byte, uint64, error) {
	if len(input) == 36 {
		sel := input[:4]
		if bytes.Equal(sel, rngSelCommit) || bytes.Equal(sel, rngSelReveal) ||
			bytes.Equal(sel, rngSelGetRandomness) || bytes.Equal(sel, rngSelGetRequest) {
			return runRNGRequest(evm, caller, input, gas, static)
		}
	}
	return runRNGPlain(evm, caller, input, gas, static)
}

// runRNGPlain generates 'count' pseudo-random 32-byte words.
// Input: [1 byte count][optional salt]
// Output: uint256[] (ABI Encoded)
func runRNGPlain(evm *EVM, caller common.Address, input []byte, gas uint64, static bool) ([]byte, uint64, error) {
	m := &pbMeter{left: gas}
	if m.use(RNGBaseGas) != nil {
		return nil, 0, ErrOutOfGas
	}

	count := 1
	var salt []byte
	if len(input) > 0 {
		count = int(input[0])
		salt = input[1:]
	}
	if count == 0 {
		return abiEncodeUint256Array(nil), m.left, nil
	}

	readOnly := rngReadOnly(evm, static)
	cost := uint64(count-1)*RNGWordGas + rngWords(len(salt))*RNGSaltWordGas + RNGCounterGas
	if !readOnly {
		cost += RNGCounterGas + rngLogGas(3, rngWordsLogData)
	}
	if m.use(cost) != nil {
		return nil, 0, ErrOutOfGas
	}

	unique, index := rngCallUniqueness(evm, RNGPrecompileAddress, caller, readOnly, gas)
	baseSeed := generateSystemEntropy(evm, rngDomainWords, unique, salt)

	// Word i = Keccak(baseSeed || i)
	output := make([]byte, 0, count*32)
	mix := make([]byte, 40)
	copy(mix, baseSeed)
	for i := 0; i < count; i++ {
		binary.BigEndian.PutUint64(mix[32:], uint64(i))
		output = append(output, crypto.Keccak256(mix)...)
	}

	if !readOnly {
		data := make([]byte, 0, rngWordsLogData)
		data = append(data, baseSeed...)
		data = append(data, msWord(uint64(count)).Bytes()...)
		evm.StateDB.AddLog(&types.Log{
			Address:     RNGPrecompileAddress,
			Topics:      []common.Hash{rngEvWords, common.BytesToHash(caller.Bytes()), msWord(index)},
			Data:        data,
			BlockNumber: evm.Context.BlockNumber.Uint64(),
		})
	}
	return abiEncodeUint256Array(output), m.left, nil
}

// RunShuffle returns a canonical ASCII deck shuffle (104 bytes).
// Format: Each card = 2 bytes [Suit][Rank] (e.g., "SA" for Ace of Spades)
// Input: optional salt (arbitrary bytes)
func RunShuffle(evm *EVM, caller common.Address, input []byte, gas uint64, static bool) ([]byte, uint64, error) {
	m := &pbMeter{left: gas}
	readOnly := rngReadOnly(evm, static)
	cost := uint64(ShuffleBaseGas) + rngWords(len(input))*RNGSaltWordGas + RNGCounterGas
	if !readOnly {
		cost += RNGCounterGas + rngLogGas(3, rngShuffleLogData)
	}
	if m.use(cost) != nil {
		return nil, 0, ErrOutOfGas
	}

	unique, index := rngCallUniqueness(evm, ShufflePrecompileAddress, caller, readOnly, gas)
	seed := generateSystemEntropy(evm, rngDomainShuffle, unique, input)

	// Build Standard Ordered Deck
	deck := make([][2]byte, DeckSize)
	idx := 0
	for _, s := range suits {
		for _, r := range ranks {
			deck[idx][0] = s
			deck[idx][1] = r
			idx++
		}
	}

	// Fisher-Yates Shuffle driven by a SHA256 stream over the seed
	counter := uint64(0)
	hashBuf := []byte{}
	block := make([]byte, 33)
	copy(block, seed)

	nextUint16 := func() uint16 {
		if len(hashBuf) < 2 {
			block[32] = byte(counter)
			h := sha256.Sum256(block)
			hashBuf = h[:]
			counter++
		}
		v := uint16(hashBuf[0])<<8 | uint16(hashBuf[1])
		hashBuf = hashBuf[2:]
		return v
	}

	// Rejection sampling avoids modulo bias
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

	var out bytes.Buffer
	out.Grow(OutputLen)
	for i := 0; i < DeckSize; i++ {
		out.WriteByte(deck[i][0])
		out.WriteByte(deck[i][1])
	}

	if !readOnly {
		evm.StateDB.AddLog(&types.Log{
			Address:     ShufflePrecompileAddress,
			Topics:      []common.Hash{rngEvShuffled, common.BytesToHash(caller.Bytes()), msWord(index)},
			Data:        common.CopyBytes(seed),
			BlockNumber: evm.Context.BlockNumber.Uint64(),
		})
	}

	// Shuffle returns raw bytes because it's a fixed blob (104 bytes).
	return out.Bytes(), m.left, nil
}

// ---------------------------------------------------------------------------
// Commit-reveal
// ---------------------------------------------------------------------------

type rngCtx struct {
	evm      *EVM
	caller   common.Address
	readOnly bool
	m        *pbMeter
}

func runRNGRequest(evm *EVM, caller common.Address, input []byte, gas uint64, static bool) ([]byte, uint64, error) {
	m := &pbMeter{left: gas}
	if m.use(RNGBaseGas) != nil {
		return nil, 0, ErrOutOfGas
	}
	snapshot := evm.StateDB.Snapshot()
	c := &rngCtx{evm: evm, caller: caller, readOnly: rngReadOnly(evm, static), m: m}
	sel, data := input[:4], input[4:]

	var (
		out []byte
		err error
	)
	switch {
	case bytes.Equal(sel, rngSelCommit):
		out, err = c.commit(data)
	case bytes.Equal(sel, rngSelReveal):
		out, err = c.reveal(new(big.Int).SetBytes(data))
	case bytes.Equal(sel, rngSelGetRandomness):
		out, err = c.getRandomness(new(big.Int).SetBytes(data))
	default:
		out, err = c.getRequest(new(big.Int).SetBytes(data))
	}
	if err == nil {
		return out, m.left, nil
	}

	evm.StateDB.RevertToSnapshot(snapshot)
	var rev *msRevert
	switch {
	case err == errPBOutOfGas:
		return nil, 0, ErrOutOfGas
	case err == errMSWrite:
		return nil, 0, ErrWriteProtection
	case errors.As(err, &rev):
		return rev.revertData(), m.left, ErrExecutionReverted
	default:
		return nil, m.left, ErrExecutionReverted
	}
}

func rngSlot(label string, id *big.Int) common.Hash {
	return crypto.Keccak256Hash([]byte("vtru.rng."+label), common.BigToHash(id).Bytes())
}

var rngNextSlot = crypto.Keccak256Hash([]byte("vtru.rng.next"))

func (c *rngCtx) get(slot common.Hash) common.Hash {
	return c.evm.StateDB.GetState(RNGPrecompileAddress, slot)
}

func (c *rngCtx) set(slot, v common.Hash) {
	c.evm.StateDB.SetState(RNGPrecompileAddress, slot, v)
}

// rngRequest is a stored commit.
type rngRequest struct {
	owner       common.Address
	revealBlock uint64
	seed        common.Hash
	result      common.Hash
	revealed    bool
}

func (c *rngCtx) load(id *big.Int) (*rngRequest, bool) {
	if id.Sign() == 0 || id.BitLen() > 64 {
		return nil, false
	}
	owner := common.BytesToAddress(c.get(rngSlot("owner", id)).Bytes())
	if owner == (common.Address{}) {
		return nil, false
	}
	r := &rngRequest{
		owner:       owner,
		revealBlock: c.get(rngSlot("block", id)).Big().Uint64(),
		seed:        c.get(rngSlot("seed", id)),
	}
	if c.get(rngSlot("revealed", id)) != (common.Hash{}) {
		r.revealed = true
		r.result = c.get(rngSlot("result", id))
	}
	return r, true
}

// status reports the request state and, when ready or revealed, its result.
func (c *rngCtx) status(r *rngRequest) (uint64, common.Hash) {
	if r.revealed {
		return RNGStatusRevealed, r.result
	}
	current := c.evm.Context.BlockNumber.Uint64()
	if current <= r.revealBlock {
		return RNGStatusPending, common.Hash{}
	}
	if current-r.revealBlock > RNGRevealWindow {
		return RNGStatusExpired, common.Hash{}
	}
	bh := c.evm.Context.GetHash(r.revealBlock)
	if bh == (common.Hash{}) {
		return RNGStatusPending, common.Hash{}
	}
	return RNGStatusReady, crypto.Keccak256Hash(r.seed.Bytes(), bh.Bytes())
}

func (c *rngCtx) emit(topic common.Hash, id *big.Int, owner common.Address, data common.Hash) {
	c.evm.StateDB.AddLog(&types.Log{
		Address:     RNGPrecompileAddress,
		Topics:      []common.Hash{topic, common.BigToHash(id), common.BytesToHash(owner.Bytes())},
		Data:        data.Bytes(),
		BlockNumber: c.evm.Context.BlockNumber.Uint64(),
	})
}

func (c *rngCtx) commit(salt []byte) ([]byte, error) {
	if c.readOnly {
		return nil, errMSWrite
	}
	if err := c.m.use(RNGCommitGas + rngLogGas(3, 32)); err != nil {
		return nil, err
	}
	db := c.evm.StateDB
	if db.GetNonce(RNGPrecompileAddress) == 0 {
		db.SetNonce(RNGPrecompileAddress, 1) // keeps the account from being pruned as empty
	}
	next := c.get(rngNextSlot).Big().Uint64() + 1
	c.set(rngNextSlot, msWord(next))
	id := new(big.Int).SetUint64(next)

	commitBlock := c.evm.Context.BlockNumber.Uint64()
	revealBlock := commitBlock + 1
	seed := crypto.Keccak256Hash(
		rngDomainCommit,
		common.BigToHash(c.evm.ChainConfig().ChainID).Bytes(),
		common.BigToHash(id).Bytes(),
		c.caller.Bytes(),
		salt,
		msWord(commitBlock).Bytes(),
	)
	c.set(rngSlot("owner", id), common.BytesToHash(c.caller.Bytes()))
	c.set(rngSlot("block", id), msWord(revealBlock))
	c.set(rngSlot("seed", id), seed)

	c.emit(rngEvCommitted, id, c.caller, msWord(revealBlock))
	return msArgsUint.Pack(id)
}

func (c *rngCtx) reveal(id *big.Int) ([]byte, error) {
	if err := c.m.use(RNGReadGas); err != nil {
		return nil, err
	}
	r, ok := c.load(id)
	if !ok {
		return nil, msFail("unknown request")
	}
	st, result := c.status(r)
	switch st {
	case RNGStatusRevealed:
		return msArgsBytes32.Pack([32]byte(result))
	case RNGStatusPending:
		return nil, msFail("reveal block not reached")
	case RNGStatusExpired:
		return nil, msFail("request expired")
	}
	if c.readOnly {
		return nil, errMSWrite
	}
	if err := c.m.use(RNGRevealGas + rngLogGas(3, 32)); err != nil {
		return nil, err
	}
	c.set(rngSlot("result", id), result)
	c.set(rngSlot("revealed", id), msWord(1))
	c.emit(rngEvRevealed, id, r.owner, result)
	return msArgsBytes32.Pack([32]byte(result))
}

func (c *rngCtx) getRandomness(id *big.Int) ([]byte, error) {
	if err := c.m.use(RNGReadGas); err != nil {
		return nil, err
	}
	r, ok := c.load(id)
	if !ok {
		return rngArgsReady.Pack(false, [32]byte{})
	}
	st, result := c.status(r)
	ready := st == RNGStatusReady || st == RNGStatusRevealed
	return rngArgsReady.Pack(ready, [32]byte(result))
}

func (c *rngCtx) getRequest(id *big.Int) ([]byte, error) {
	if err := c.m.use(RNGReadGas); err != nil {
		return nil, err
	}
	r, ok := c.load(id)
	if !ok {
		return rngArgsRequest.Pack(common.Address{}, new(big.Int), new(big.Int), new(big.Int))
	}
	st, _ := c.status(r)
	return rngArgsRequest.Pack(
		r.owner,
		new(big.Int).SetUint64(r.revealBlock-1),
		new(big.Int).SetUint64(r.revealBlock),
		new(big.Int).SetUint64(st),
	)
}
