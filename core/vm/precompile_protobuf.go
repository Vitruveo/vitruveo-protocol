package vm

import (
	"bytes"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/protobuf/encoding/protowire"
)

// Protobuf precompile: schema-less wire-format codec plus cheap on-chain
// message storage with field-level access. See contracts/protobuf/ for the
// Solidity interface and typed helper library.
//
// Paths are arrays of field numbers. Each element except the last must be a
// length-delimited (embedded message) field; the last occurrence of a field
// is the one read or replaced ("last one wins", as in protobuf for singular
// fields).
//
// Values: varint/fixed64/fixed32 are 32-byte big-endian words (must fit the
// wire type); length-delimited values are raw bytes. Wire types: 0 varint,
// 1 fixed64, 2 length-delimited, 5 fixed32. Groups are rejected.
//
// Storage: messages are namespaced by the calling contract (msg.sender) and a
// bytes32 key, and kept as code of a derived account (prefixed with STOP so it
// can never execute). Writes are rejected inside STATICCALL.

const (
	ProtobufBaseGas      = 200     // every call
	ProtobufPerByteGas   = 1       // per byte of call input, and per byte scanned
	ProtobufPerItemGas   = 10      // per field scanned or produced
	ProtobufLoadGas      = 2600    // per stored message read
	ProtobufStoreGas     = 5000    // per stored message write or removal
	ProtobufStoreByteGas = 1       // per byte written to storage
	ProtobufMaxDepth     = 64      // max path length
	ProtobufMaxSize      = 1 << 20 // max stored message size (1 MiB)
)

var (
	pbSelDecode       = pbSelector("decode(bytes)")
	pbSelEncode       = pbSelector("encode(uint256[],uint256[],bytes[])")
	pbSelDecodePacked = pbSelector("decodePacked(bytes,uint256)")
	pbSelEncodePacked = pbSelector("encodePacked(uint256[],uint256)")

	pbSelRead    = pbSelector("read(bytes,uint256[])")
	pbSelReadAll = pbSelector("readAll(bytes,uint256[])")
	pbSelWrite   = pbSelector("write(bytes,uint256[],uint256,bytes)")
	pbSelAppend  = pbSelector("append(bytes,uint256[],uint256,bytes)")
	pbSelClear   = pbSelector("clear(bytes,uint256[])")

	pbSelStore       = pbSelector("store(bytes32,bytes)")
	pbSelLoad        = pbSelector("load(address,bytes32)")
	pbSelRemove      = pbSelector("remove(bytes32)")
	pbSelLoadField   = pbSelector("loadField(address,bytes32,uint256[])")
	pbSelLoadAll     = pbSelector("loadAll(address,bytes32,uint256[])")
	pbSelStoreField  = pbSelector("storeField(bytes32,uint256[],uint256,bytes)")
	pbSelAppendField = pbSelector("appendField(bytes32,uint256[],uint256,bytes)")
	pbSelClearField  = pbSelector("clearField(bytes32,uint256[])")

	pbTypeUint256      = mustABIType("uint256")
	pbTypeUint256Array = mustABIType("uint256[]")
	pbTypeBytes        = mustABIType("bytes")
	pbTypeBytesArray   = mustABIType("bytes[]")
	pbTypeBytes32      = mustABIType("bytes32")
	pbTypeAddress      = mustABIType("address")
	pbTypeBool         = mustABIType("bool")

	pbArgsBytes       = abi.Arguments{{Type: pbTypeBytes}}
	pbArgsUintArray   = abi.Arguments{{Type: pbTypeUint256Array}}
	pbArgsDecoded     = abi.Arguments{{Type: pbTypeUint256Array}, {Type: pbTypeUint256Array}, {Type: pbTypeBytesArray}}
	pbArgsBytesUint   = abi.Arguments{{Type: pbTypeBytes}, {Type: pbTypeUint256}}
	pbArgsUintArrUint = abi.Arguments{{Type: pbTypeUint256Array}, {Type: pbTypeUint256}}
	pbArgsBytesPath   = abi.Arguments{{Type: pbTypeBytes}, {Type: pbTypeUint256Array}}
	pbArgsBytesPathTV = abi.Arguments{{Type: pbTypeBytes}, {Type: pbTypeUint256Array}, {Type: pbTypeUint256}, {Type: pbTypeBytes}}
	pbArgsFound       = abi.Arguments{{Type: pbTypeBool}, {Type: pbTypeUint256}, {Type: pbTypeBytes}}
	pbArgsAll         = abi.Arguments{{Type: pbTypeUint256Array}, {Type: pbTypeBytesArray}}
	pbArgsKeyBytes    = abi.Arguments{{Type: pbTypeBytes32}, {Type: pbTypeBytes}}
	pbArgsOwnerKey    = abi.Arguments{{Type: pbTypeAddress}, {Type: pbTypeBytes32}}
	pbArgsKey         = abi.Arguments{{Type: pbTypeBytes32}}
	pbArgsOwnerKeyP   = abi.Arguments{{Type: pbTypeAddress}, {Type: pbTypeBytes32}, {Type: pbTypeUint256Array}}
	pbArgsKeyPathTV   = abi.Arguments{{Type: pbTypeBytes32}, {Type: pbTypeUint256Array}, {Type: pbTypeUint256}, {Type: pbTypeBytes}}
	pbArgsKeyPath     = abi.Arguments{{Type: pbTypeBytes32}, {Type: pbTypeUint256Array}}

	errPBMalformed = errors.New("protobuf: malformed input")
	errPBOutOfGas  = errors.New("protobuf: out of gas")
	errPBWrite     = errors.New("protobuf: write in static context")

	pbStorePrefix = []byte("vtru.protobuf.store")
)

func pbSelector(sig string) []byte { return crypto.Keccak256([]byte(sig))[:4] }

func mustABIType(t string) abi.Type {
	typ, err := abi.NewType(t, "", nil)
	if err != nil {
		panic(err)
	}
	return typ
}

// pbMeter tracks gas as work is discovered.
type pbMeter struct{ left uint64 }

func (m *pbMeter) use(n uint64) error {
	if m.left < n {
		m.left = 0
		return errPBOutOfGas
	}
	m.left -= n
	return nil
}

func (m *pbMeter) mul(n, per uint64) error {
	if n != 0 && per > ^uint64(0)/n {
		return m.use(^uint64(0))
	}
	return m.use(n * per)
}

// pbCtx carries the call context for storage operations.
type pbCtx struct {
	evm    *EVM
	caller common.Address
	static bool
	m      *pbMeter
}

func RunProtobuf(evm *EVM, caller common.Address, input []byte, gas uint64, static bool) (ret []byte, gasLeft uint64, err error) {
	m := &pbMeter{left: gas}
	if m.use(ProtobufBaseGas) != nil || m.mul(uint64(len(input)), ProtobufPerByteGas) != nil {
		return nil, 0, ErrOutOfGas
	}

	// Never let malformed ABI input take the node down.
	defer func() {
		if r := recover(); r != nil {
			ret, gasLeft, err = nil, m.left, ErrExecutionReverted
		}
	}()

	if len(input) < 4 {
		return nil, m.left, ErrExecutionReverted
	}
	ctx := &pbCtx{evm: evm, caller: caller, static: static, m: m}
	sel, data := input[:4], input[4:]

	var out []byte
	switch {
	case bytes.Equal(sel, pbSelDecode):
		out, err = pbDecode(m, data)
	case bytes.Equal(sel, pbSelEncode):
		out, err = pbEncode(m, data)
	case bytes.Equal(sel, pbSelDecodePacked):
		out, err = pbDecodePacked(m, data)
	case bytes.Equal(sel, pbSelEncodePacked):
		out, err = pbEncodePacked(m, data)

	case bytes.Equal(sel, pbSelRead):
		out, err = pbRead(m, data)
	case bytes.Equal(sel, pbSelReadAll):
		out, err = pbReadAll(m, data)
	case bytes.Equal(sel, pbSelWrite):
		out, err = pbWriteMem(m, data, pbModeSet)
	case bytes.Equal(sel, pbSelAppend):
		out, err = pbWriteMem(m, data, pbModeAppend)
	case bytes.Equal(sel, pbSelClear):
		out, err = pbClearMem(m, data)

	case bytes.Equal(sel, pbSelStore):
		out, err = ctx.store(data)
	case bytes.Equal(sel, pbSelLoad):
		out, err = ctx.load(data)
	case bytes.Equal(sel, pbSelRemove):
		out, err = ctx.remove(data)
	case bytes.Equal(sel, pbSelLoadField):
		out, err = ctx.loadField(data, false)
	case bytes.Equal(sel, pbSelLoadAll):
		out, err = ctx.loadField(data, true)
	case bytes.Equal(sel, pbSelStoreField):
		out, err = ctx.modifyField(data, pbModeSet)
	case bytes.Equal(sel, pbSelAppendField):
		out, err = ctx.modifyField(data, pbModeAppend)
	case bytes.Equal(sel, pbSelClearField):
		out, err = ctx.modifyField(data, pbModeClear)
	default:
		err = errPBMalformed
	}

	switch {
	case err == nil:
		return out, m.left, nil
	case err == errPBOutOfGas:
		return nil, 0, ErrOutOfGas
	case err == errPBWrite:
		return nil, 0, ErrWriteProtection
	default:
		return nil, m.left, ErrExecutionReverted
	}
}

// ---------------------------------------------------------------------------
// Wire scanning
// ---------------------------------------------------------------------------

type pbField struct {
	num        protowire.Number
	typ        protowire.Type
	start, end int    // whole field (tag + value) within the message
	raw        []byte // varint/fixed: decoded into word on demand; bytes: payload
	scalar     uint64
}

func (f pbField) value() []byte {
	if f.typ == protowire.BytesType {
		return f.raw
	}
	return pbWord(f.scalar)
}

// pbScan parses one message level, charging per byte and per field.
func pbScan(m *pbMeter, msg []byte) ([]pbField, error) {
	if err := m.mul(uint64(len(msg)), ProtobufPerByteGas); err != nil {
		return nil, err
	}
	var fields []pbField
	pos := 0
	for pos < len(msg) {
		if err := m.use(ProtobufPerItemGas); err != nil {
			return nil, err
		}
		start := pos
		num, typ, n := protowire.ConsumeTag(msg[pos:])
		if n < 0 {
			return nil, errPBMalformed
		}
		pos += n
		f := pbField{num: num, typ: typ, start: start}
		switch typ {
		case protowire.VarintType:
			f.scalar, n = protowire.ConsumeVarint(msg[pos:])
		case protowire.Fixed64Type:
			f.scalar, n = protowire.ConsumeFixed64(msg[pos:])
		case protowire.Fixed32Type:
			var v uint32
			v, n = protowire.ConsumeFixed32(msg[pos:])
			f.scalar = uint64(v)
		case protowire.BytesType:
			f.raw, n = protowire.ConsumeBytes(msg[pos:])
		default:
			return nil, errPBMalformed
		}
		if n < 0 {
			return nil, errPBMalformed
		}
		pos += n
		f.end = pos
		fields = append(fields, f)
	}
	return fields, nil
}

func pbLast(fields []pbField, num protowire.Number) int {
	for i := len(fields) - 1; i >= 0; i-- {
		if fields[i].num == num {
			return i
		}
	}
	return -1
}

func pbPath(raw []*big.Int) ([]protowire.Number, error) {
	if len(raw) == 0 || len(raw) > ProtobufMaxDepth {
		return nil, errPBMalformed
	}
	path := make([]protowire.Number, len(raw))
	for i, b := range raw {
		if !b.IsUint64() || b.Uint64() < uint64(protowire.MinValidNumber) || b.Uint64() > uint64(protowire.MaxValidNumber) {
			return nil, errPBMalformed
		}
		path[i] = protowire.Number(b.Uint64())
	}
	return path, nil
}

func pbWireType(b *big.Int) (protowire.Type, error) {
	if !b.IsUint64() {
		return 0, errPBMalformed
	}
	switch t := protowire.Type(b.Uint64()); t {
	case protowire.VarintType, protowire.Fixed64Type, protowire.Fixed32Type, protowire.BytesType:
		if b.Uint64() == uint64(t) {
			return t, nil
		}
	}
	return 0, errPBMalformed
}

// pbAppendField appends tag+value; numeric values are up to 32 big-endian bytes.
func pbAppendField(msg []byte, num protowire.Number, typ protowire.Type, val []byte) ([]byte, error) {
	msg = protowire.AppendTag(msg, num, typ)
	if typ == protowire.BytesType {
		return protowire.AppendBytes(msg, val), nil
	}
	v, ok := pbScalar(val)
	if !ok {
		return nil, errPBMalformed
	}
	if msg, ok = pbAppendScalar(msg, typ, v); !ok {
		return nil, errPBMalformed
	}
	return msg, nil
}

// pbNavigate follows path[:len-1] through embedded messages (last occurrence)
// and returns the fields of the final level. ok is false if any level is missing.
func pbNavigate(m *pbMeter, msg []byte, path []protowire.Number) ([]pbField, bool, error) {
	cur := msg
	for i := 0; ; i++ {
		fields, err := pbScan(m, cur)
		if err != nil {
			return nil, false, err
		}
		if i == len(path)-1 {
			return fields, true, nil
		}
		idx := pbLast(fields, path[i])
		if idx < 0 {
			return nil, false, nil
		}
		if fields[idx].typ != protowire.BytesType {
			return nil, false, errPBMalformed
		}
		cur = fields[idx].raw
	}
}

const (
	pbModeSet = iota
	pbModeAppend
	pbModeClear
)

// pbModify rewrites msg with the field at path set, appended, or cleared.
// Missing intermediate messages are created for set/append.
func pbModify(m *pbMeter, msg []byte, path []protowire.Number, mode int, typ protowire.Type, val []byte) ([]byte, error) {
	fields, err := pbScan(m, msg)
	if err != nil {
		return nil, err
	}
	num := path[0]

	if len(path) == 1 {
		var enc []byte
		if mode != pbModeClear {
			if enc, err = pbAppendField(nil, num, typ, val); err != nil {
				return nil, err
			}
		}
		out := make([]byte, 0, len(msg)+len(enc))
		switch mode {
		case pbModeAppend:
			out = append(append(out, msg...), enc...)
		default: // set or clear: drop every occurrence; set reinserts at the last one
			last := pbLast(fields, num)
			prev := 0
			for i, f := range fields {
				if f.num != num {
					continue
				}
				out = append(out, msg[prev:f.start]...)
				if i == last && mode == pbModeSet {
					out = append(out, enc...)
				}
				prev = f.end
			}
			out = append(out, msg[prev:]...)
			if last < 0 && mode == pbModeSet {
				out = append(out, enc...)
			}
		}
		return out, nil
	}

	idx := pbLast(fields, num)
	var child []byte
	if idx >= 0 {
		if fields[idx].typ != protowire.BytesType {
			return nil, errPBMalformed
		}
		child = fields[idx].raw
	} else if mode == pbModeClear {
		return msg, nil
	}
	newChild, err := pbModify(m, child, path[1:], mode, typ, val)
	if err != nil {
		return nil, err
	}
	enc := protowire.AppendBytes(protowire.AppendTag(nil, num, protowire.BytesType), newChild)

	out := make([]byte, 0, len(msg)+len(enc))
	if idx < 0 {
		return append(append(out, msg...), enc...), nil
	}
	out = append(out, msg[:fields[idx].start]...)
	out = append(out, enc...)
	return append(out, msg[fields[idx].end:]...), nil
}

// ---------------------------------------------------------------------------
// Codec (memory only)
// ---------------------------------------------------------------------------

func pbDecode(m *pbMeter, data []byte) ([]byte, error) {
	args, err := pbArgsBytes.Unpack(data)
	if err != nil {
		return nil, err
	}
	fields, err := pbScan(m, args[0].([]byte))
	if err != nil {
		return nil, err
	}
	nums := make([]*big.Int, len(fields))
	types := make([]*big.Int, len(fields))
	values := make([][]byte, len(fields))
	for i, f := range fields {
		nums[i] = new(big.Int).SetUint64(uint64(f.num))
		types[i] = new(big.Int).SetUint64(uint64(f.typ))
		values[i] = f.value()
	}
	return pbArgsDecoded.Pack(nums, types, values)
}

func pbEncode(m *pbMeter, data []byte) ([]byte, error) {
	args, err := pbArgsDecoded.Unpack(data)
	if err != nil {
		return nil, err
	}
	nums, types, values := args[0].([]*big.Int), args[1].([]*big.Int), args[2].([][]byte)
	if len(nums) != len(types) || len(nums) != len(values) {
		return nil, errPBMalformed
	}
	msg := []byte{}
	for i := range nums {
		if err := m.use(ProtobufPerItemGas); err != nil {
			return nil, err
		}
		path, err := pbPath(nums[i : i+1])
		if err != nil {
			return nil, err
		}
		typ, err := pbWireType(types[i])
		if err != nil {
			return nil, err
		}
		if msg, err = pbAppendField(msg, path[0], typ, values[i]); err != nil {
			return nil, err
		}
	}
	return pbArgsBytes.Pack(msg)
}

func pbDecodePacked(m *pbMeter, data []byte) ([]byte, error) {
	args, err := pbArgsBytesUint.Unpack(data)
	if err != nil {
		return nil, err
	}
	msg := args[0].([]byte)
	typ, err := pbPackedType(args[1].(*big.Int))
	if err != nil {
		return nil, err
	}
	values := []*big.Int{}
	for len(msg) > 0 {
		if err := m.use(ProtobufPerItemGas); err != nil {
			return nil, err
		}
		var (
			v uint64
			n int
		)
		switch typ {
		case protowire.VarintType:
			v, n = protowire.ConsumeVarint(msg)
		case protowire.Fixed64Type:
			v, n = protowire.ConsumeFixed64(msg)
		case protowire.Fixed32Type:
			var v32 uint32
			v32, n = protowire.ConsumeFixed32(msg)
			v = uint64(v32)
		}
		if n < 0 {
			return nil, errPBMalformed
		}
		msg = msg[n:]
		values = append(values, new(big.Int).SetUint64(v))
	}
	return pbArgsUintArray.Pack(values)
}

func pbEncodePacked(m *pbMeter, data []byte) ([]byte, error) {
	args, err := pbArgsUintArrUint.Unpack(data)
	if err != nil {
		return nil, err
	}
	values := args[0].([]*big.Int)
	typ, err := pbPackedType(args[1].(*big.Int))
	if err != nil {
		return nil, err
	}
	msg := []byte{}
	for _, b := range values {
		if err := m.use(ProtobufPerItemGas); err != nil {
			return nil, err
		}
		if !b.IsUint64() {
			return nil, errPBMalformed
		}
		var ok bool
		if msg, ok = pbAppendScalar(msg, typ, b.Uint64()); !ok {
			return nil, errPBMalformed
		}
	}
	return pbArgsBytes.Pack(msg)
}

func pbPackedType(b *big.Int) (protowire.Type, error) {
	t, err := pbWireType(b)
	if err != nil || t == protowire.BytesType {
		return 0, errPBMalformed
	}
	return t, nil
}

// ---------------------------------------------------------------------------
// Field access (memory)
// ---------------------------------------------------------------------------

func pbReadFields(m *pbMeter, msg []byte, rawPath []*big.Int, all bool) ([]byte, error) {
	path, err := pbPath(rawPath)
	if err != nil {
		return nil, err
	}
	fields, ok, err := pbNavigate(m, msg, path)
	if err != nil {
		return nil, err
	}
	num := path[len(path)-1]
	if all {
		types, values := []*big.Int{}, [][]byte{}
		if ok {
			for _, f := range fields {
				if f.num == num {
					types = append(types, new(big.Int).SetUint64(uint64(f.typ)))
					values = append(values, f.value())
				}
			}
		}
		return pbArgsAll.Pack(types, values)
	}
	if ok {
		if idx := pbLast(fields, num); idx >= 0 {
			f := fields[idx]
			return pbArgsFound.Pack(true, new(big.Int).SetUint64(uint64(f.typ)), f.value())
		}
	}
	return pbArgsFound.Pack(false, new(big.Int), []byte{})
}

func pbRead(m *pbMeter, data []byte) ([]byte, error) {
	args, err := pbArgsBytesPath.Unpack(data)
	if err != nil {
		return nil, err
	}
	return pbReadFields(m, args[0].([]byte), args[1].([]*big.Int), false)
}

func pbReadAll(m *pbMeter, data []byte) ([]byte, error) {
	args, err := pbArgsBytesPath.Unpack(data)
	if err != nil {
		return nil, err
	}
	return pbReadFields(m, args[0].([]byte), args[1].([]*big.Int), true)
}

func pbWriteMem(m *pbMeter, data []byte, mode int) ([]byte, error) {
	args, err := pbArgsBytesPathTV.Unpack(data)
	if err != nil {
		return nil, err
	}
	path, err := pbPath(args[1].([]*big.Int))
	if err != nil {
		return nil, err
	}
	typ, err := pbWireType(args[2].(*big.Int))
	if err != nil {
		return nil, err
	}
	out, err := pbModify(m, args[0].([]byte), path, mode, typ, args[3].([]byte))
	if err != nil {
		return nil, err
	}
	return pbArgsBytes.Pack(out)
}

func pbClearMem(m *pbMeter, data []byte) ([]byte, error) {
	args, err := pbArgsBytesPath.Unpack(data)
	if err != nil {
		return nil, err
	}
	path, err := pbPath(args[1].([]*big.Int))
	if err != nil {
		return nil, err
	}
	out, err := pbModify(m, args[0].([]byte), path, pbModeClear, 0, nil)
	if err != nil {
		return nil, err
	}
	return pbArgsBytes.Pack(out)
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

// ProtobufStoreAddress is the account holding owner's message under key.
func ProtobufStoreAddress(owner common.Address, key common.Hash) common.Address {
	return common.BytesToAddress(crypto.Keccak256(pbStorePrefix, owner.Bytes(), key.Bytes())[12:])
}

func (c *pbCtx) writable() error {
	if c.static || c.evm.interpreter.readOnly {
		return errPBWrite
	}
	return nil
}

func (c *pbCtx) get(owner common.Address, key common.Hash) ([]byte, error) {
	if err := c.m.use(ProtobufLoadGas); err != nil {
		return nil, err
	}
	code := c.evm.StateDB.GetCode(ProtobufStoreAddress(owner, key))
	if len(code) == 0 {
		return []byte{}, nil
	}
	if err := c.m.mul(uint64(len(code)), ProtobufPerByteGas); err != nil {
		return nil, err
	}
	return code[1:], nil // strip STOP prefix
}

func (c *pbCtx) put(key common.Hash, msg []byte) error {
	if len(msg) > ProtobufMaxSize {
		return errPBMalformed
	}
	if err := c.m.use(ProtobufStoreGas); err != nil {
		return err
	}
	if err := c.m.mul(uint64(len(msg)), ProtobufStoreByteGas); err != nil {
		return err
	}
	addr := ProtobufStoreAddress(c.caller, key)
	if len(msg) == 0 {
		c.evm.StateDB.SetCode(addr, nil) // empty account, pruned at end of tx
		return nil
	}
	code := make([]byte, 1+len(msg))
	copy(code[1:], msg) // code[0] = 0x00 (STOP)
	c.evm.StateDB.SetCode(addr, code)
	return nil
}

func (c *pbCtx) store(data []byte) ([]byte, error) {
	if err := c.writable(); err != nil {
		return nil, err
	}
	args, err := pbArgsKeyBytes.Unpack(data)
	if err != nil {
		return nil, err
	}
	msg := args[1].([]byte)
	if _, err := pbScan(c.m, msg); err != nil { // must be a valid message
		return nil, err
	}
	return nil, c.put(common.Hash(args[0].([32]byte)), msg)
}

func (c *pbCtx) load(data []byte) ([]byte, error) {
	args, err := pbArgsOwnerKey.Unpack(data)
	if err != nil {
		return nil, err
	}
	msg, err := c.get(args[0].(common.Address), common.Hash(args[1].([32]byte)))
	if err != nil {
		return nil, err
	}
	return pbArgsBytes.Pack(msg)
}

func (c *pbCtx) remove(data []byte) ([]byte, error) {
	if err := c.writable(); err != nil {
		return nil, err
	}
	args, err := pbArgsKey.Unpack(data)
	if err != nil {
		return nil, err
	}
	return nil, c.put(common.Hash(args[0].([32]byte)), nil)
}

func (c *pbCtx) loadField(data []byte, all bool) ([]byte, error) {
	args, err := pbArgsOwnerKeyP.Unpack(data)
	if err != nil {
		return nil, err
	}
	msg, err := c.get(args[0].(common.Address), common.Hash(args[1].([32]byte)))
	if err != nil {
		return nil, err
	}
	return pbReadFields(c.m, msg, args[2].([]*big.Int), all)
}

func (c *pbCtx) modifyField(data []byte, mode int) ([]byte, error) {
	if err := c.writable(); err != nil {
		return nil, err
	}
	var (
		key  common.Hash
		path []protowire.Number
		typ  protowire.Type
		val  []byte
	)
	if mode == pbModeClear {
		args, err := pbArgsKeyPath.Unpack(data)
		if err != nil {
			return nil, err
		}
		key = common.Hash(args[0].([32]byte))
		if path, err = pbPath(args[1].([]*big.Int)); err != nil {
			return nil, err
		}
	} else {
		args, err := pbArgsKeyPathTV.Unpack(data)
		if err != nil {
			return nil, err
		}
		key = common.Hash(args[0].([32]byte))
		if path, err = pbPath(args[1].([]*big.Int)); err != nil {
			return nil, err
		}
		if typ, err = pbWireType(args[2].(*big.Int)); err != nil {
			return nil, err
		}
		val = args[3].([]byte)
	}
	msg, err := c.get(c.caller, key)
	if err != nil {
		return nil, err
	}
	out, err := pbModify(c.m, msg, path, mode, typ, val)
	if err != nil {
		return nil, err
	}
	return nil, c.put(key, out)
}

// ---------------------------------------------------------------------------
// Scalars
// ---------------------------------------------------------------------------

// pbAppendScalar appends v for a varint/fixed64/fixed32 wire type.
func pbAppendScalar(msg []byte, typ protowire.Type, v uint64) ([]byte, bool) {
	switch typ {
	case protowire.VarintType:
		return protowire.AppendVarint(msg, v), true
	case protowire.Fixed64Type:
		return protowire.AppendFixed64(msg, v), true
	case protowire.Fixed32Type:
		if v > 0xffffffff {
			return msg, false
		}
		return protowire.AppendFixed32(msg, uint32(v)), true
	}
	return msg, false
}

// pbScalar reads up to 32 big-endian bytes that must fit in uint64.
func pbScalar(b []byte) (uint64, bool) {
	if len(b) > 32 {
		return 0, false
	}
	v := new(big.Int).SetBytes(b)
	if !v.IsUint64() {
		return 0, false
	}
	return v.Uint64(), true
}

func pbWord(v uint64) []byte {
	out := make([]byte, 32)
	new(big.Int).SetUint64(v).FillBytes(out)
	return out
}
