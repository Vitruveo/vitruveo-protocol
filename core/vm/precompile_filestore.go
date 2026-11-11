package vm

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// File storage precompile. See contracts/filestore/IFileStore.sol.
//
// File bytes are never written to state. Each chunk is the calldata of a
// direct transaction to this precompile, so it lives in the block body, which
// every full node keeps permanently (chaindata, then the freezer). State keeps
// only the owner, size, content type, SHA-256 and the (block, tx index) of
// every chunk, which is enough to rebuild the file from the chain.
//
// Upload: begin(hash, size, contentType), then upload(hash, index, chunk) in
// order from index 0, then finalize(hash). A running SHA-256 state is kept
// between chunks; finalize checks it against the declared hash. Files are
// addressed by their SHA-256 and are immutable once finalized.
//
// Transactions sent directly to this address pay FileStoreDataGas per byte of
// calldata instead of the normal 16/4 (see core.IntrinsicGasFor).

const (
	FileStoreDataGas       = 2     // intrinsic gas per calldata byte for txs to this precompile
	FileStoreBaseGas       = 500   // every call
	FileStoreBeginGas      = 20000 // per upload session started
	FileStoreUploadGas     = 20000 // per chunk recorded
	FileStoreFinalizeGas   = 20000 // per file finalized
	FileStoreReadGas       = 2600  // per view call
	FileStoreMaxFileSize   = 10 << 20
	FileStoreMaxChunk      = 512 << 10
	FileStoreMaxChunks     = 64
	FileStoreMaxType       = 127
	FileStoreMaxExclusions = 8

	fsStatusUploading = 1
	fsStatusFinalized = 2
	fsMidstateSize    = 108 // crypto/sha256 marshaled state
)

var (
	fsSelBegin     = pbSelector("begin(bytes32,uint256,string)")
	fsSelBeginCred = pbSelector("beginWithCredential(bytes32,uint256,string,uint256[],uint256[])")
	fsSelCredInfo  = pbSelector("credentialInfo(bytes32)")
	fsSelUpload    = pbSelector("upload(bytes32,uint256,bytes)")
	fsSelFinalize  = pbSelector("finalize(bytes32)")
	fsSelExists    = pbSelector("exists(bytes32)")
	fsSelInfo      = pbSelector("info(bytes32)")
	fsSelSession   = pbSelector("session(address,bytes32)")
	fsSelChunk     = pbSelector("chunkLocation(bytes32,uint256)")

	fsArgsBegin     = abi.Arguments{{Type: pbTypeBytes32}, {Type: pbTypeUint256}, {Type: msTypeString}}
	fsArgsBeginCred = abi.Arguments{{Type: pbTypeBytes32}, {Type: pbTypeUint256}, {Type: msTypeString}, {Type: pbTypeUint256Array}, {Type: pbTypeUint256Array}}
	fsArgsCredInfo  = abi.Arguments{{Type: pbTypeBytes32}, {Type: pbTypeUint256Array}, {Type: pbTypeUint256Array}}
	fsArgsUpload    = abi.Arguments{{Type: pbTypeBytes32}, {Type: pbTypeUint256}, {Type: pbTypeBytes}}
	fsArgsHash      = abi.Arguments{{Type: pbTypeBytes32}}
	fsArgsSession   = abi.Arguments{{Type: pbTypeAddress}, {Type: pbTypeBytes32}}
	fsArgsChunk     = abi.Arguments{{Type: pbTypeBytes32}, {Type: pbTypeUint256}}
	fsArgsInfo      = abi.Arguments{{Type: pbTypeAddress}, {Type: pbTypeUint256}, {Type: msTypeString}, {Type: pbTypeUint256}, {Type: pbTypeUint256}}
	fsArgsStatus    = abi.Arguments{{Type: pbTypeUint256}, {Type: pbTypeUint256}, {Type: pbTypeUint256}, {Type: pbTypeUint256}}

	fsEvStored = crypto.Keccak256Hash([]byte("FileStored(bytes32,address,uint256,string)"))
)

// FileStoreChunk is where one chunk of a stored file lives on chain.
type FileStoreChunk struct {
	Block   uint64
	TxIndex uint64
}

// FileStoreInfo describes a finalized file.
type FileStoreInfo struct {
	Hash        common.Hash
	Owner       common.Address
	Size        uint64
	ContentType string
	Block       uint64
	Chunks      []FileStoreChunk

	// Set for files uploaded with beginWithCredential: SHA-256 of the file
	// without the excluded ranges (the embedded C2PA manifest store).
	ContentHash common.Hash
	Exclusions  []FileStoreExclusion
}

// FileStoreExclusion is a byte range left out of ContentHash.
type FileStoreExclusion struct {
	Start  uint64
	Length uint64
}

// StateReader is the read-only state access needed to look up stored files.
type StateReader interface {
	GetState(common.Address, common.Hash) common.Hash
}

type fsCtx struct {
	evm    *EVM
	caller common.Address
	static bool
	m      *pbMeter
}

func RunFileStore(evm *EVM, caller common.Address, input []byte, gas uint64, static bool) (ret []byte, gasLeft uint64, err error) {
	m := &pbMeter{left: gas}
	if m.use(FileStoreBaseGas) != nil {
		return nil, 0, ErrOutOfGas
	}
	snapshot := evm.StateDB.Snapshot()

	defer func() {
		if r := recover(); r != nil {
			evm.StateDB.RevertToSnapshot(snapshot)
			ret, gasLeft, err = nil, m.left, ErrExecutionReverted
		}
	}()

	if len(input) < 4 {
		return nil, m.left, ErrExecutionReverted
	}
	c := &fsCtx{evm: evm, caller: caller, static: static, m: m}
	sel, data := input[:4], input[4:]

	var out []byte
	switch {
	case bytes.Equal(sel, fsSelBegin):
		out, err = c.begin(data)
	case bytes.Equal(sel, fsSelBeginCred):
		out, err = c.beginWithCredential(data)
	case bytes.Equal(sel, fsSelCredInfo):
		out, err = c.credentialInfo(data)
	case bytes.Equal(sel, fsSelUpload):
		out, err = c.upload(data)
	case bytes.Equal(sel, fsSelFinalize):
		out, err = c.finalize(data)
	case bytes.Equal(sel, fsSelExists):
		out, err = c.exists(data)
	case bytes.Equal(sel, fsSelInfo):
		out, err = c.info(data)
	case bytes.Equal(sel, fsSelSession):
		out, err = c.session(data)
	case bytes.Equal(sel, fsSelChunk):
		out, err = c.chunkLocation(data)
	default:
		err = msFail("unknown function")
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

// ---------------------------------------------------------------------------
// Storage layout (in the precompile account's storage)
// ---------------------------------------------------------------------------

func fsSlot(label string, parts ...[]byte) common.Hash {
	data := append([][]byte{[]byte("vtru.filestore." + label)}, parts...)
	return crypto.Keccak256Hash(data...)
}

func fsSessionKey(owner common.Address, hash common.Hash) []byte {
	return crypto.Keccak256(owner.Bytes(), hash.Bytes())
}

func fsGetU(db StateReader, slot common.Hash) uint64 {
	return new(big.Int).SetBytes(db.GetState(FileStorePrecompileAddress, slot).Bytes()).Uint64()
}

func (c *fsCtx) setU(slot common.Hash, v uint64) {
	c.evm.StateDB.SetState(FileStorePrecompileAddress, slot, msWord(v))
}

func fsGetBytes(db StateReader, sk []byte, label string, n int) []byte {
	out := make([]byte, 0, n+31)
	for i := 0; len(out) < n; i++ {
		w := db.GetState(FileStorePrecompileAddress, fsSlot(label, sk, msWord(uint64(i)).Bytes()))
		out = append(out, w.Bytes()...)
	}
	return out[:n]
}

func (c *fsCtx) setBytes(sk []byte, label string, b []byte) {
	for i := 0; i*32 < len(b); i++ {
		var w common.Hash
		copy(w[:], b[i*32:])
		c.evm.StateDB.SetState(FileStorePrecompileAddress, fsSlot(label, sk, msWord(uint64(i)).Bytes()), w)
	}
}

func fsContentType(db StateReader, sk []byte) string {
	n := fsGetU(db, fsSlot("typelen", sk))
	if n == 0 || n > FileStoreMaxType {
		return ""
	}
	return string(fsGetBytes(db, sk, "type", int(n)))
}

func fsValidType(t string) bool {
	if len(t) > FileStoreMaxType {
		return false
	}
	for i := 0; i < len(t); i++ {
		if t[i] < 0x20 || t[i] > 0x7e {
			return false
		}
	}
	return true
}

func (c *fsCtx) writable() error {
	if c.static || c.evm.interpreter.readOnly {
		return errMSWrite
	}
	return nil
}

// ReadFileStoreInfo looks up a finalized file by its SHA-256.
func ReadFileStoreInfo(db StateReader, hash common.Hash) (*FileStoreInfo, bool) {
	owner := common.BytesToAddress(db.GetState(FileStorePrecompileAddress, fsSlot("owner", hash.Bytes())).Bytes())
	if owner == (common.Address{}) {
		return nil, false
	}
	sk := fsSessionKey(owner, hash)
	info := &FileStoreInfo{
		Hash:        hash,
		Owner:       owner,
		Size:        fsGetU(db, fsSlot("size", sk)),
		ContentType: fsContentType(db, sk),
		Block:       fsGetU(db, fsSlot("block", hash.Bytes())),
	}
	if info.Exclusions = fsExclusions(db, sk); len(info.Exclusions) > 0 {
		info.ContentHash = db.GetState(FileStorePrecompileAddress, fsSlot("chash", sk))
	}
	count := fsGetU(db, fsSlot("count", sk))
	if count > FileStoreMaxChunks {
		return nil, false
	}
	for i := uint64(0); i < count; i++ {
		v := fsGetU(db, fsSlot("loc", sk, msWord(i).Bytes()))
		info.Chunks = append(info.Chunks, FileStoreChunk{Block: v >> 32, TxIndex: v & 0xffffffff})
	}
	return info, true
}

// FileStoreChunkData extracts the chunk bytes from the calldata of an upload
// transaction, checking that it belongs to the given file and index.
func FileStoreChunkData(txData []byte, hash common.Hash, index uint64) ([]byte, error) {
	if len(txData) < 4 || !bytes.Equal(txData[:4], fsSelUpload) {
		return nil, errors.New("not an upload transaction")
	}
	args, err := fsArgsUpload.Unpack(txData[4:])
	if err != nil {
		return nil, err
	}
	if common.Hash(args[0].([32]byte)) != hash || args[1].(*big.Int).Cmp(new(big.Int).SetUint64(index)) != 0 {
		return nil, fmt.Errorf("upload transaction is for another file or chunk")
	}
	return args[2].([]byte), nil
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

func (c *fsCtx) begin(data []byte) ([]byte, error) {
	args, err := fsArgsBegin.Unpack(data)
	if err != nil {
		return nil, err
	}
	return c.start(common.Hash(args[0].([32]byte)), args[1].(*big.Int), args[2].(string), nil)
}

// beginWithCredential starts an upload of a file with embedded Content
// Credentials. The excluded ranges (the embedded manifest store) are left out
// of a second running hash, which is what a c2pa.hash.data assertion signs.
func (c *fsCtx) beginWithCredential(data []byte) ([]byte, error) {
	args, err := fsArgsBeginCred.Unpack(data)
	if err != nil {
		return nil, err
	}
	starts, lengths := args[3].([]*big.Int), args[4].([]*big.Int)
	if len(starts) == 0 || len(starts) != len(lengths) || len(starts) > FileStoreMaxExclusions {
		return nil, msFail("invalid exclusions")
	}
	excl := make([]FileStoreExclusion, len(starts))
	end := uint64(0)
	for i := range starts {
		if !starts[i].IsUint64() || !lengths[i].IsUint64() || lengths[i].Uint64() == 0 ||
			starts[i].Uint64() < end || starts[i].Uint64() > FileStoreMaxFileSize || lengths[i].Uint64() > FileStoreMaxFileSize {
			return nil, msFail("invalid exclusions")
		}
		excl[i] = FileStoreExclusion{Start: starts[i].Uint64(), Length: lengths[i].Uint64()}
		end = excl[i].Start + excl[i].Length
	}
	size := args[1].(*big.Int)
	if size.IsUint64() && end > size.Uint64() {
		return nil, msFail("invalid exclusions")
	}
	return c.start(common.Hash(args[0].([32]byte)), size, args[2].(string), excl)
}

func (c *fsCtx) start(hash common.Hash, size *big.Int, ctype string, excl []FileStoreExclusion) ([]byte, error) {
	if err := c.writable(); err != nil {
		return nil, err
	}
	if !size.IsUint64() || size.Uint64() == 0 || size.Uint64() > FileStoreMaxFileSize {
		return nil, msFail("invalid size")
	}
	if !fsValidType(ctype) {
		return nil, msFail("invalid content type")
	}
	if err := c.m.use(FileStoreBeginGas); err != nil {
		return nil, err
	}
	db := c.evm.StateDB
	if _, ok := ReadFileStoreInfo(db, hash); ok {
		return nil, msFail("file exists")
	}
	if db.GetNonce(FileStorePrecompileAddress) == 0 {
		db.SetNonce(FileStorePrecompileAddress, 1) // keeps the account from being pruned as empty
	}
	mid, _ := sha256.New().(encoding.BinaryMarshaler).MarshalBinary()

	sk := fsSessionKey(c.caller, hash)
	c.setU(fsSlot("status", sk), fsStatusUploading)
	c.setU(fsSlot("size", sk), size.Uint64())
	c.setU(fsSlot("recv", sk), 0)
	c.setU(fsSlot("count", sk), 0)
	c.setU(fsSlot("typelen", sk), uint64(len(ctype)))
	c.setBytes(sk, "type", []byte(ctype))
	c.setBytes(sk, "mid", mid)
	c.setU(fsSlot("exn", sk), uint64(len(excl)))
	for i, e := range excl {
		c.setU(fsSlot("exs", sk, msWord(uint64(i)).Bytes()), e.Start)
		c.setU(fsSlot("exl", sk, msWord(uint64(i)).Bytes()), e.Length)
	}
	if len(excl) > 0 {
		c.setBytes(sk, "cmid", mid)
	}
	return msArgsBool.Pack(true)
}

func fsExclusions(db StateReader, sk []byte) []FileStoreExclusion {
	n := fsGetU(db, fsSlot("exn", sk))
	if n > FileStoreMaxExclusions {
		return nil
	}
	out := make([]FileStoreExclusion, n)
	for i := range out {
		out[i].Start = fsGetU(db, fsSlot("exs", sk, msWord(uint64(i)).Bytes()))
		out[i].Length = fsGetU(db, fsSlot("exl", sk, msWord(uint64(i)).Bytes()))
	}
	return out
}

func fsLoadHash(db StateReader, sk []byte, label string) (hash.Hash, error) {
	h := sha256.New()
	if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(fsGetBytes(db, sk, label, fsMidstateSize)); err != nil {
		return nil, msFail("corrupt upload state")
	}
	return h, nil
}

func (c *fsCtx) upload(data []byte) ([]byte, error) {
	if err := c.writable(); err != nil {
		return nil, err
	}
	// The chunk must be the transaction's own calldata so it can be read back
	// from the block body.
	if c.evm.depth != 0 || c.caller != c.evm.Origin {
		return nil, msFail("upload must be a direct transaction")
	}
	idx, ok := c.evm.StateDB.(interface{ TxIndex() int })
	if !ok {
		return nil, msFail("tx index unavailable")
	}
	args, err := fsArgsUpload.Unpack(data)
	if err != nil {
		return nil, err
	}
	hash := common.Hash(args[0].([32]byte))
	index, chunk := args[1].(*big.Int), args[2].([]byte)

	if err := c.m.use(FileStoreUploadGas); err != nil {
		return nil, err
	}
	db := c.evm.StateDB
	sk := fsSessionKey(c.caller, hash)
	if fsGetU(db, fsSlot("status", sk)) != fsStatusUploading {
		return nil, msFail("no upload in progress")
	}
	count, recv, size := fsGetU(db, fsSlot("count", sk)), fsGetU(db, fsSlot("recv", sk)), fsGetU(db, fsSlot("size", sk))
	if !index.IsUint64() || index.Uint64() != count {
		return nil, msFail("wrong chunk index")
	}
	if len(chunk) == 0 || len(chunk) > FileStoreMaxChunk || count >= FileStoreMaxChunks {
		return nil, msFail("invalid chunk")
	}
	if recv+uint64(len(chunk)) > size {
		return nil, msFail("chunk exceeds file size")
	}
	h, err := fsLoadHash(db, sk, "mid")
	if err != nil {
		return nil, err
	}
	h.Write(chunk)
	mid, _ := h.(encoding.BinaryMarshaler).MarshalBinary()
	c.setBytes(sk, "mid", mid)

	if excl := fsExclusions(db, sk); len(excl) > 0 {
		ch, err := fsLoadHash(db, sk, "cmid")
		if err != nil {
			return nil, err
		}
		fsWriteExcluding(ch, chunk, recv, excl)
		cmid, _ := ch.(encoding.BinaryMarshaler).MarshalBinary()
		c.setBytes(sk, "cmid", cmid)
	}

	loc := c.evm.Context.BlockNumber.Uint64()<<32 | uint64(idx.TxIndex())&0xffffffff
	c.setU(fsSlot("loc", sk, msWord(count).Bytes()), loc)
	c.setU(fsSlot("count", sk), count+1)
	c.setU(fsSlot("recv", sk), recv+uint64(len(chunk)))
	return msArgsBool.Pack(true)
}

// fsWriteExcluding hashes the parts of chunk (which starts at file offset off)
// that fall outside the sorted, non-overlapping exclusions.
func fsWriteExcluding(h hash.Hash, chunk []byte, off uint64, excl []FileStoreExclusion) {
	pos, end := off, off+uint64(len(chunk))
	for _, e := range excl {
		eEnd := e.Start + e.Length
		if eEnd <= pos {
			continue
		}
		if e.Start >= end {
			break
		}
		if e.Start > pos {
			h.Write(chunk[pos-off : e.Start-off])
		}
		pos = eEnd
		if pos >= end {
			return
		}
	}
	if pos < end {
		h.Write(chunk[pos-off:])
	}
}

func (c *fsCtx) finalize(data []byte) ([]byte, error) {
	if err := c.writable(); err != nil {
		return nil, err
	}
	args, err := fsArgsHash.Unpack(data)
	if err != nil {
		return nil, err
	}
	hash := common.Hash(args[0].([32]byte))
	if err := c.m.use(FileStoreFinalizeGas); err != nil {
		return nil, err
	}
	db := c.evm.StateDB
	sk := fsSessionKey(c.caller, hash)
	if fsGetU(db, fsSlot("status", sk)) != fsStatusUploading {
		return nil, msFail("no upload in progress")
	}
	if _, ok := ReadFileStoreInfo(db, hash); ok {
		return nil, msFail("file exists")
	}
	size := fsGetU(db, fsSlot("size", sk))
	if fsGetU(db, fsSlot("recv", sk)) != size {
		return nil, msFail("upload incomplete")
	}
	h, err := fsLoadHash(db, sk, "mid")
	if err != nil {
		return nil, err
	}
	if common.BytesToHash(h.Sum(nil)) != hash {
		return nil, msFail("hash mismatch")
	}
	if len(fsExclusions(db, sk)) > 0 {
		ch, err := fsLoadHash(db, sk, "cmid")
		if err != nil {
			return nil, err
		}
		db.SetState(FileStorePrecompileAddress, fsSlot("chash", sk), common.BytesToHash(ch.Sum(nil)))
	}
	c.setU(fsSlot("status", sk), fsStatusFinalized)
	db.SetState(FileStorePrecompileAddress, fsSlot("owner", hash.Bytes()), common.BytesToHash(c.caller.Bytes()))
	c.setU(fsSlot("block", hash.Bytes()), c.evm.Context.BlockNumber.Uint64())

	ctype := fsContentType(db, sk)
	evData, _ := abi.Arguments{{Type: pbTypeUint256}, {Type: msTypeString}}.Pack(new(big.Int).SetUint64(size), ctype)
	db.AddLog(&types.Log{
		Address:     FileStorePrecompileAddress,
		Topics:      []common.Hash{fsEvStored, hash, common.BytesToHash(c.caller.Bytes())},
		Data:        evData,
		BlockNumber: c.evm.Context.BlockNumber.Uint64(),
	})
	return msArgsBool.Pack(true)
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

func (c *fsCtx) exists(data []byte) ([]byte, error) {
	args, err := fsArgsHash.Unpack(data)
	if err != nil {
		return nil, err
	}
	if err := c.m.use(FileStoreReadGas); err != nil {
		return nil, err
	}
	_, ok := ReadFileStoreInfo(c.evm.StateDB, common.Hash(args[0].([32]byte)))
	return msArgsBool.Pack(ok)
}

func (c *fsCtx) info(data []byte) ([]byte, error) {
	args, err := fsArgsHash.Unpack(data)
	if err != nil {
		return nil, err
	}
	if err := c.m.use(FileStoreReadGas); err != nil {
		return nil, err
	}
	f, ok := ReadFileStoreInfo(c.evm.StateDB, common.Hash(args[0].([32]byte)))
	if !ok {
		return nil, msFail("file not found")
	}
	return fsArgsInfo.Pack(f.Owner, new(big.Int).SetUint64(f.Size), f.ContentType,
		new(big.Int).SetUint64(uint64(len(f.Chunks))), new(big.Int).SetUint64(f.Block))
}

func (c *fsCtx) session(data []byte) ([]byte, error) {
	args, err := fsArgsSession.Unpack(data)
	if err != nil {
		return nil, err
	}
	if err := c.m.use(FileStoreReadGas); err != nil {
		return nil, err
	}
	db := c.evm.StateDB
	sk := fsSessionKey(args[0].(common.Address), common.Hash(args[1].([32]byte)))
	u := func(label string) *big.Int { return new(big.Int).SetUint64(fsGetU(db, fsSlot(label, sk))) }
	return fsArgsStatus.Pack(u("status"), u("size"), u("recv"), u("count"))
}

func (c *fsCtx) credentialInfo(data []byte) ([]byte, error) {
	args, err := fsArgsHash.Unpack(data)
	if err != nil {
		return nil, err
	}
	if err := c.m.use(FileStoreReadGas); err != nil {
		return nil, err
	}
	f, ok := ReadFileStoreInfo(c.evm.StateDB, common.Hash(args[0].([32]byte)))
	if !ok {
		return nil, msFail("file not found")
	}
	starts, lengths := make([]*big.Int, len(f.Exclusions)), make([]*big.Int, len(f.Exclusions))
	for i, e := range f.Exclusions {
		starts[i], lengths[i] = new(big.Int).SetUint64(e.Start), new(big.Int).SetUint64(e.Length)
	}
	return fsArgsCredInfo.Pack([32]byte(f.ContentHash), starts, lengths)
}

func (c *fsCtx) chunkLocation(data []byte) ([]byte, error) {
	args, err := fsArgsChunk.Unpack(data)
	if err != nil {
		return nil, err
	}
	if err := c.m.use(FileStoreReadGas); err != nil {
		return nil, err
	}
	f, ok := ReadFileStoreInfo(c.evm.StateDB, common.Hash(args[0].([32]byte)))
	if !ok {
		return nil, msFail("file not found")
	}
	i := args[1].(*big.Int)
	if !i.IsUint64() || i.Uint64() >= uint64(len(f.Chunks)) {
		return nil, msFail("invalid chunk index")
	}
	loc := f.Chunks[i.Uint64()]
	return msArgsUint2.Pack(new(big.Int).SetUint64(loc.Block), new(big.Int).SetUint64(loc.TxIndex))
}
