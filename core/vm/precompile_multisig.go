package vm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

// Native multisig precompile. See contracts/multisig/IMultisig.sol.
//
// Wallets are keyless addresses derived from (creator, salt). Their owners,
// threshold and nonce live in the wallet account's own storage. Only this
// precompile can act as a wallet, and only after enough owners approve.
//
// Owners are addresses (EOAs or contracts) or P-256 passkeys. Approvals:
//   - EIP-712 signatures from EOA owners (eth_signTypedData_v4)
//   - WebAuthn assertions from passkey owners (challenge = operation hash)
//   - on-chain approve() from any address owner (works for contract owners)
//   - msg.sender of execute(), if it is an address owner
//
// execute() runs a batch of calls as the wallet, all-or-nothing. Owner and
// threshold changes are calls from the wallet to this precompile, so they
// require the same approvals.

const (
	MultisigBaseGas      = 500   // every call
	MultisigPerByteGas   = 1     // per byte of call input
	MultisigCreateGas    = 10000 // per wallet created
	MultisigPerOwnerGas  = 2000  // per owner written
	MultisigScanGas      = 100   // per owner read
	MultisigWriteGas     = 2000  // approve and admin updates
	MultisigExecuteGas   = 2000  // per execute, plus forwarded call gas
	MultisigECDSAGas     = 3000  // per EOA signature
	MultisigPasskeyGas   = 3500  // per passkey signature
	MultisigMaxOwners    = 32
	MultisigMaxCalls     = 64
	multisigOwnerAddress = 1
	multisigOwnerPasskey = 2
)

var (
	msSelWalletAddress = pbSelector("walletAddress(address,bytes32)")
	msSelCreate        = pbSelector("create(address[],uint256[],uint256[],uint256,bytes32)")
	msSelOpHash        = pbSelector("operationHash(address,address[],uint256[],bytes[],uint256)")
	msSelExecute       = pbSelector("execute(address,address[],uint256[],bytes[],bytes[])")
	msSelApprove       = pbSelector("approve(address,bytes32)")
	msSelInfo          = pbSelector("info(address)")
	msSelApprovedBy    = pbSelector("approvedBy(address,bytes32)")
	msSelAddOwner      = pbSelector("addOwner(address)")
	msSelAddPasskey    = pbSelector("addPasskey(uint256,uint256)")
	msSelRemoveOwner   = pbSelector("removeOwner(bytes32)")
	msSelSetThreshold  = pbSelector("setThreshold(uint256)")

	msTypeAddressArray = mustABIType("address[]")
	msTypeBytes32Array = mustABIType("bytes32[]")
	msTypeString       = mustABIType("string")

	msArgsAddrKey    = abi.Arguments{{Type: pbTypeAddress}, {Type: pbTypeBytes32}}
	msArgsCreate     = abi.Arguments{{Type: msTypeAddressArray}, {Type: pbTypeUint256Array}, {Type: pbTypeUint256Array}, {Type: pbTypeUint256}, {Type: pbTypeBytes32}}
	msArgsOpHash     = abi.Arguments{{Type: pbTypeAddress}, {Type: msTypeAddressArray}, {Type: pbTypeUint256Array}, {Type: pbTypeBytesArray}, {Type: pbTypeUint256}}
	msArgsExecute    = abi.Arguments{{Type: pbTypeAddress}, {Type: msTypeAddressArray}, {Type: pbTypeUint256Array}, {Type: pbTypeBytesArray}, {Type: pbTypeBytesArray}}
	msArgsAddress    = abi.Arguments{{Type: pbTypeAddress}}
	msArgsBytes32    = abi.Arguments{{Type: pbTypeBytes32}}
	msArgsUint       = abi.Arguments{{Type: pbTypeUint256}}
	msArgsUint2      = abi.Arguments{{Type: pbTypeUint256}, {Type: pbTypeUint256}}
	msArgsBool       = abi.Arguments{{Type: pbTypeBool}}
	msArgsBytesArray = abi.Arguments{{Type: pbTypeBytesArray}}
	msArgsBytes32Arr = abi.Arguments{{Type: msTypeBytes32Array}}
	msArgsInfo       = abi.Arguments{{Type: msTypeAddressArray}, {Type: pbTypeUint256Array}, {Type: pbTypeUint256Array}, {Type: pbTypeUint256}, {Type: pbTypeUint256}}
	msArgsString     = abi.Arguments{{Type: msTypeString}}
	msArgsPasskeySig = abi.Arguments{{Type: pbTypeUint256}, {Type: pbTypeUint256}, {Type: pbTypeBytes}, {Type: msTypeString}, {Type: pbTypeUint256}, {Type: pbTypeUint256}}

	// EIP-712
	msDomainTypeHash  = crypto.Keccak256Hash([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))
	msNameHash        = crypto.Keccak256Hash([]byte("Vitruveo Multisig"))
	msVersionHash     = crypto.Keccak256Hash([]byte("1"))
	msCallTypeHash    = crypto.Keccak256Hash([]byte("Call(address to,uint256 value,bytes data)"))
	msExecuteTypeHash = crypto.Keccak256Hash([]byte("Execute(Call[] calls,uint256 nonce)Call(address to,uint256 value,bytes data)"))

	// Events (emitted from the precompile address)
	msEvWalletCreated    = crypto.Keccak256Hash([]byte("WalletCreated(address,address)"))
	msEvApproved         = crypto.Keccak256Hash([]byte("Approved(address,bytes32,bytes32)"))
	msEvExecuted         = crypto.Keccak256Hash([]byte("Executed(address,bytes32,uint256)"))
	msEvOwnerAdded       = crypto.Keccak256Hash([]byte("OwnerAdded(address,bytes32)"))
	msEvOwnerRemoved     = crypto.Keccak256Hash([]byte("OwnerRemoved(address,bytes32)"))
	msEvThresholdChanged = crypto.Keccak256Hash([]byte("ThresholdChanged(address,uint256)"))

	msErrorSelector = pbSelector("Error(string)")
	errMSWrite      = errors.New("multisig: write in static context")
)

// msRevert is a revert carrying an Error(string) reason for the caller.
type msRevert struct {
	reason string
	data   []byte // raw revert data from a failed inner call, if any
}

func (e *msRevert) Error() string { return "multisig: " + e.reason }

func msFail(reason string) error { return &msRevert{reason: reason} }

func (e *msRevert) revertData() []byte {
	if e.data != nil {
		return e.data
	}
	enc, _ := msArgsString.Pack(e.reason)
	return append(append([]byte{}, msErrorSelector...), enc...)
}

type msCtx struct {
	evm    *EVM
	caller common.Address
	static bool
	m      *pbMeter
}

func RunMultisig(evm *EVM, caller common.Address, input []byte, gas uint64, static bool) (ret []byte, gasLeft uint64, err error) {
	m := &pbMeter{left: gas}
	if m.use(MultisigBaseGas) != nil || m.mul(uint64(len(input)), MultisigPerByteGas) != nil {
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
	c := &msCtx{evm: evm, caller: caller, static: static, m: m}
	sel, data := input[:4], input[4:]

	var out []byte
	switch {
	case bytes.Equal(sel, msSelWalletAddress):
		out, err = c.walletAddress(data)
	case bytes.Equal(sel, msSelCreate):
		out, err = c.create(data)
	case bytes.Equal(sel, msSelOpHash):
		out, err = c.operationHash(data)
	case bytes.Equal(sel, msSelExecute):
		out, err = c.execute(data)
	case bytes.Equal(sel, msSelApprove):
		out, err = c.approve(data)
	case bytes.Equal(sel, msSelInfo):
		out, err = c.info(data)
	case bytes.Equal(sel, msSelApprovedBy):
		out, err = c.approvedBy(data)
	case bytes.Equal(sel, msSelAddOwner):
		out, err = c.addOwner(data)
	case bytes.Equal(sel, msSelAddPasskey):
		out, err = c.addPasskey(data)
	case bytes.Equal(sel, msSelRemoveOwner):
		out, err = c.removeOwner(data)
	case bytes.Equal(sel, msSelSetThreshold):
		out, err = c.setThreshold(data)
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
// Storage layout (in the wallet account's storage)
// ---------------------------------------------------------------------------

func msSlot(label string, parts ...[]byte) common.Hash {
	data := append([][]byte{[]byte("vtru.multisig." + label)}, parts...)
	return crypto.Keccak256Hash(data...)
}

var (
	msSlotThreshold = msSlot("threshold")
	msSlotNonce     = msSlot("nonce")
	msSlotCount     = msSlot("count")
)

func msWord(v uint64) common.Hash { return common.BigToHash(new(big.Int).SetUint64(v)) }

func (c *msCtx) getU(wallet common.Address, slot common.Hash) uint64 {
	return new(big.Int).SetBytes(c.evm.StateDB.GetState(wallet, slot).Bytes()).Uint64()
}

func (c *msCtx) setU(wallet common.Address, slot common.Hash, v uint64) {
	c.evm.StateDB.SetState(wallet, slot, msWord(v))
}

func msOwnerSlot(i uint64) common.Hash       { return msSlot("owner", msWord(i).Bytes()) }
func msIndexSlot(id common.Hash) common.Hash { return msSlot("index", id.Bytes()) }
func msPkxSlot(id common.Hash) common.Hash   { return msSlot("pkx", id.Bytes()) }
func msPkySlot(id common.Hash) common.Hash   { return msSlot("pky", id.Bytes()) }
func msApprovalSlot(op, id common.Hash) common.Hash {
	return msSlot("approval", op.Bytes(), id.Bytes())
}

// Owner ids: an address owner is its left-padded address; a passkey owner is
// keccak256(x || y), which never has 12 leading zero bytes in practice.
func msAddressID(a common.Address) common.Hash { return common.BytesToHash(a.Bytes()) }

func msPasskeyID(x, y *big.Int) common.Hash {
	return crypto.Keccak256Hash(common.BigToHash(x).Bytes(), common.BigToHash(y).Bytes())
}

// MultisigWalletAddress is the wallet created by creator with salt.
func MultisigWalletAddress(creator common.Address, salt common.Hash) common.Address {
	return common.BytesToAddress(crypto.Keccak256([]byte("vtru.multisig.wallet"), creator.Bytes(), salt.Bytes())[12:])
}

func (c *msCtx) writable() error {
	if c.static || c.evm.interpreter.readOnly {
		return errMSWrite
	}
	return nil
}

func (c *msCtx) initialized(wallet common.Address) bool {
	return c.getU(wallet, msSlotThreshold) != 0
}

func (c *msCtx) isOwner(wallet common.Address, id common.Hash) bool {
	return c.getU(wallet, msIndexSlot(id)) != 0
}

func (c *msCtx) owners(wallet common.Address) ([]common.Hash, error) {
	n := c.getU(wallet, msSlotCount)
	if err := c.m.mul(n, MultisigScanGas); err != nil {
		return nil, err
	}
	ids := make([]common.Hash, n)
	for i := uint64(0); i < n; i++ {
		ids[i] = c.evm.StateDB.GetState(wallet, msOwnerSlot(i))
	}
	return ids, nil
}

func (c *msCtx) addOwnerID(wallet common.Address, id common.Hash, x, y *big.Int) error {
	if c.isOwner(wallet, id) {
		return msFail("duplicate owner")
	}
	n := c.getU(wallet, msSlotCount)
	if n >= MultisigMaxOwners {
		return msFail("too many owners")
	}
	if err := c.m.use(MultisigPerOwnerGas); err != nil {
		return err
	}
	c.evm.StateDB.SetState(wallet, msOwnerSlot(n), id)
	c.setU(wallet, msIndexSlot(id), n+1)
	if x != nil {
		c.evm.StateDB.SetState(wallet, msPkxSlot(id), common.BigToHash(x))
		c.evm.StateDB.SetState(wallet, msPkySlot(id), common.BigToHash(y))
	}
	c.setU(wallet, msSlotCount, n+1)
	c.log(msEvOwnerAdded, wallet, id)
	return nil
}

func msValidPasskey(x, y *big.Int) bool {
	p := elliptic.P256().Params()
	if x.Sign() < 0 || y.Sign() < 0 || x.Cmp(p.P) >= 0 || y.Cmp(p.P) >= 0 {
		return false
	}
	return elliptic.P256().IsOnCurve(x, y)
}

func (c *msCtx) log(event common.Hash, wallet common.Address, topic common.Hash, data ...[]byte) {
	c.evm.StateDB.AddLog(&types.Log{
		Address:     MultisigPrecompileAddress,
		Topics:      []common.Hash{event, common.BytesToHash(wallet.Bytes()), topic},
		Data:        bytes.Join(data, nil),
		BlockNumber: c.evm.Context.BlockNumber.Uint64(),
	})
}

// ---------------------------------------------------------------------------
// Operation hash (EIP-712)
// ---------------------------------------------------------------------------

func msOpHash(chainID *big.Int, wallet common.Address, to []common.Address, value []*big.Int, data [][]byte, nonce *big.Int) common.Hash {
	domain := crypto.Keccak256Hash(
		msDomainTypeHash.Bytes(), msNameHash.Bytes(), msVersionHash.Bytes(),
		common.BigToHash(chainID).Bytes(), common.BytesToHash(wallet.Bytes()).Bytes(),
	)
	callHashes := make([]byte, 0, 32*len(to))
	for i := range to {
		h := crypto.Keccak256(
			msCallTypeHash.Bytes(), common.BytesToHash(to[i].Bytes()).Bytes(),
			common.BigToHash(value[i]).Bytes(), crypto.Keccak256(data[i]),
		)
		callHashes = append(callHashes, h...)
	}
	structHash := crypto.Keccak256(msExecuteTypeHash.Bytes(), crypto.Keccak256(callHashes), common.BigToHash(nonce).Bytes())
	return crypto.Keccak256Hash([]byte{0x19, 0x01}, domain.Bytes(), structHash)
}

func msCheckCalls(to []common.Address, value []*big.Int, data [][]byte) error {
	if len(to) == 0 || len(to) > MultisigMaxCalls || len(value) != len(to) || len(data) != len(to) {
		return msFail("invalid calls")
	}
	for _, v := range value {
		if v.Sign() < 0 || v.BitLen() > 256 {
			return msFail("invalid value")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

// msVerify returns the owner id that produced sig over op.
// Format: 0x01 | r | s | v            (EOA, 66 bytes)
//
//	0x02 | abi.encode(x, y, authenticatorData, clientDataJSON, r, s)  (passkey)
func (c *msCtx) msVerify(op common.Hash, sig []byte) (common.Hash, error) {
	if len(sig) == 0 {
		return common.Hash{}, msFail("empty signature")
	}
	switch sig[0] {
	case 0x01:
		if err := c.m.use(MultisigECDSAGas); err != nil {
			return common.Hash{}, err
		}
		if len(sig) != 66 {
			return common.Hash{}, msFail("bad signature")
		}
		r, s, v := new(big.Int).SetBytes(sig[1:33]), new(big.Int).SetBytes(sig[33:65]), sig[65]
		if v >= 27 {
			v -= 27
		}
		if v > 1 || !crypto.ValidateSignatureValues(v, r, s, true) {
			return common.Hash{}, msFail("bad signature")
		}
		rsv := append(append(append([]byte{}, sig[1:33]...), sig[33:65]...), v)
		pub, err := crypto.SigToPub(op.Bytes(), rsv)
		if err != nil {
			return common.Hash{}, msFail("bad signature")
		}
		return msAddressID(crypto.PubkeyToAddress(*pub)), nil

	case 0x02:
		if err := c.m.use(MultisigPasskeyGas); err != nil {
			return common.Hash{}, err
		}
		args, err := msArgsPasskeySig.Unpack(sig[1:])
		if err != nil {
			return common.Hash{}, msFail("bad passkey signature")
		}
		x, y := args[0].(*big.Int), args[1].(*big.Int)
		authData, clientJSON := args[2].([]byte), args[3].(string)
		r, s := args[4].(*big.Int), args[5].(*big.Int)
		if !msVerifyWebAuthn(op, x, y, authData, clientJSON, r, s) {
			return common.Hash{}, msFail("bad passkey signature")
		}
		return msPasskeyID(x, y), nil
	}
	return common.Hash{}, msFail("unknown signature type")
}

// msVerifyWebAuthn checks a WebAuthn assertion whose challenge is op.
func msVerifyWebAuthn(op common.Hash, x, y *big.Int, authData []byte, clientJSON string, r, s *big.Int) bool {
	if !msValidPasskey(x, y) || len(authData) < 37 || authData[32]&0x01 == 0 { // user present
		return false
	}
	var client struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
	}
	if json.Unmarshal([]byte(clientJSON), &client) != nil {
		return false
	}
	if client.Type != "webauthn.get" || client.Challenge != base64.RawURLEncoding.EncodeToString(op.Bytes()) {
		return false
	}
	n := elliptic.P256().Params().N
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return false
	}
	// Enforce low-S (s <= N/2) to prevent malleability, matching RunPasskey.
	if s.Cmp(p256HalfN) > 0 {
		return false
	}
	clientHash := sha256.Sum256([]byte(clientJSON))
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	return ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:], r, s)
}

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

func (c *msCtx) walletAddress(data []byte) ([]byte, error) {
	args, err := msArgsAddrKey.Unpack(data)
	if err != nil {
		return nil, err
	}
	return msArgsAddress.Pack(MultisigWalletAddress(args[0].(common.Address), common.Hash(args[1].([32]byte))))
}

func (c *msCtx) create(data []byte) ([]byte, error) {
	if err := c.writable(); err != nil {
		return nil, err
	}
	args, err := msArgsCreate.Unpack(data)
	if err != nil {
		return nil, err
	}
	addrs := args[0].([]common.Address)
	pkx, pky := args[1].([]*big.Int), args[2].([]*big.Int)
	threshold := args[3].(*big.Int)
	salt := common.Hash(args[4].([32]byte))

	total := len(addrs) + len(pkx)
	if len(pkx) != len(pky) || total == 0 || total > MultisigMaxOwners {
		return nil, msFail("invalid owners")
	}
	if !threshold.IsUint64() || threshold.Uint64() == 0 || threshold.Uint64() > uint64(total) {
		return nil, msFail("invalid threshold")
	}
	wallet, err := c.createWallet(addrs, pkx, pky, threshold.Uint64(), salt)
	if err != nil {
		return nil, err
	}
	return msArgsAddress.Pack(wallet)
}

// createWallet creates the wallet for (c.caller, salt). Owners and threshold
// must already be validated for count and range.
func (c *msCtx) createWallet(addrs []common.Address, pkx, pky []*big.Int, threshold uint64, salt common.Hash) (common.Address, error) {
	if err := c.m.use(MultisigCreateGas); err != nil {
		return common.Address{}, err
	}
	wallet := MultisigWalletAddress(c.caller, salt)
	db := c.evm.StateDB
	if c.initialized(wallet) || db.GetNonce(wallet) != 0 || db.GetCodeSize(wallet) != 0 {
		return common.Address{}, msFail("wallet exists")
	}
	db.SetNonce(wallet, 1) // keeps the account from being pruned as empty

	for _, a := range addrs {
		if a == (common.Address{}) {
			return common.Address{}, msFail("invalid owners")
		}
		if err := c.addOwnerID(wallet, msAddressID(a), nil, nil); err != nil {
			return common.Address{}, err
		}
	}
	for i := range pkx {
		if !msValidPasskey(pkx[i], pky[i]) {
			return common.Address{}, msFail("invalid passkey")
		}
		if err := c.addOwnerID(wallet, msPasskeyID(pkx[i], pky[i]), pkx[i], pky[i]); err != nil {
			return common.Address{}, err
		}
	}
	c.setU(wallet, msSlotThreshold, threshold)
	c.log(msEvWalletCreated, wallet, common.BytesToHash(c.caller.Bytes()))
	return wallet, nil
}

// multisigEnsureWallet creates a wallet with fixed address owners on behalf of
// creator (another precompile) if it does not exist yet, and returns its address.
func multisigEnsureWallet(evm *EVM, m *pbMeter, creator common.Address, salt common.Hash, owners []common.Address, threshold uint64) (common.Address, error) {
	c := &msCtx{evm: evm, caller: creator, m: m}
	wallet := MultisigWalletAddress(creator, salt)
	if c.initialized(wallet) {
		return wallet, nil
	}
	return c.createWallet(owners, nil, nil, threshold, salt)
}

func (c *msCtx) operationHash(data []byte) ([]byte, error) {
	args, err := msArgsOpHash.Unpack(data)
	if err != nil {
		return nil, err
	}
	to, value, calls := args[1].([]common.Address), args[2].([]*big.Int), args[3].([][]byte)
	if err := msCheckCalls(to, value, calls); err != nil {
		return nil, err
	}
	op := msOpHash(c.evm.chainConfig.ChainID, args[0].(common.Address), to, value, calls, args[4].(*big.Int))
	return msArgsBytes32.Pack([32]byte(op))
}

func (c *msCtx) execute(data []byte) ([]byte, error) {
	if err := c.writable(); err != nil {
		return nil, err
	}
	if err := c.m.use(MultisigExecuteGas); err != nil {
		return nil, err
	}
	args, err := msArgsExecute.Unpack(data)
	if err != nil {
		return nil, err
	}
	wallet := args[0].(common.Address)
	to, value, calls, sigs := args[1].([]common.Address), args[2].([]*big.Int), args[3].([][]byte), args[4].([][]byte)
	if !c.initialized(wallet) {
		return nil, msFail("no such wallet")
	}
	if err := msCheckCalls(to, value, calls); err != nil {
		return nil, err
	}
	nonce := c.getU(wallet, msSlotNonce)
	op := msOpHash(c.evm.chainConfig.ChainID, wallet, to, value, calls, new(big.Int).SetUint64(nonce))

	// Collect distinct approving owners.
	ids, err := c.owners(wallet)
	if err != nil {
		return nil, err
	}
	approvers := make(map[common.Hash]bool)
	if id := msAddressID(c.caller); c.isOwner(wallet, id) {
		approvers[id] = true
	}
	for _, id := range ids {
		if c.evm.StateDB.GetState(wallet, msApprovalSlot(op, id)) != (common.Hash{}) {
			approvers[id] = true
		}
	}
	for _, sig := range sigs {
		id, err := c.msVerify(op, sig)
		if err != nil {
			return nil, err
		}
		if !c.isOwner(wallet, id) {
			return nil, msFail("signer is not an owner")
		}
		approvers[id] = true
	}
	if uint64(len(approvers)) < c.getU(wallet, msSlotThreshold) {
		return nil, msFail("not enough approvals")
	}

	// Consume the nonce and stored approvals before any external call.
	c.setU(wallet, msSlotNonce, nonce+1)
	for _, id := range ids {
		c.evm.StateDB.SetState(wallet, msApprovalSlot(op, id), common.Hash{})
	}

	results := make([][]byte, len(to))
	for i := range to {
		v, overflow := uint256.FromBig(value[i])
		if overflow {
			return nil, msFail("invalid value")
		}
		ret, left, err := c.evm.Call(AccountRef(wallet), to[i], calls[i], c.m.left, v)
		c.m.left = left
		if err != nil {
			if err == ErrExecutionReverted && len(ret) > 0 {
				return nil, &msRevert{reason: "call failed", data: ret}
			}
			return nil, msFail("call " + big.NewInt(int64(i)).String() + " failed: " + err.Error())
		}
		results[i] = ret
	}
	c.log(msEvExecuted, wallet, op, msWord(nonce).Bytes())
	return msArgsBytesArray.Pack(results)
}

func (c *msCtx) approve(data []byte) ([]byte, error) {
	if err := c.writable(); err != nil {
		return nil, err
	}
	if err := c.m.use(MultisigWriteGas); err != nil {
		return nil, err
	}
	args, err := msArgsAddrKey.Unpack(data)
	if err != nil {
		return nil, err
	}
	wallet, op := args[0].(common.Address), common.Hash(args[1].([32]byte))
	id := msAddressID(c.caller)
	if !c.initialized(wallet) || !c.isOwner(wallet, id) {
		return nil, msFail("caller is not an owner")
	}
	c.evm.StateDB.SetState(wallet, msApprovalSlot(op, id), msWord(1))
	c.log(msEvApproved, wallet, op, id.Bytes())
	return msArgsBool.Pack(true)
}

func (c *msCtx) info(data []byte) ([]byte, error) {
	args, err := msArgsAddress.Unpack(data)
	if err != nil {
		return nil, err
	}
	wallet := args[0].(common.Address)
	ids, err := c.owners(wallet)
	if err != nil {
		return nil, err
	}
	addrs, pkx, pky := []common.Address{}, []*big.Int{}, []*big.Int{}
	for _, id := range ids {
		x := c.evm.StateDB.GetState(wallet, msPkxSlot(id))
		y := c.evm.StateDB.GetState(wallet, msPkySlot(id))
		if x == (common.Hash{}) && y == (common.Hash{}) {
			addrs = append(addrs, common.BytesToAddress(id.Bytes()))
		} else {
			pkx = append(pkx, x.Big())
			pky = append(pky, y.Big())
		}
	}
	return msArgsInfo.Pack(addrs, pkx, pky,
		new(big.Int).SetUint64(c.getU(wallet, msSlotThreshold)),
		new(big.Int).SetUint64(c.getU(wallet, msSlotNonce)))
}

func (c *msCtx) approvedBy(data []byte) ([]byte, error) {
	args, err := msArgsAddrKey.Unpack(data)
	if err != nil {
		return nil, err
	}
	wallet, op := args[0].(common.Address), common.Hash(args[1].([32]byte))
	ids, err := c.owners(wallet)
	if err != nil {
		return nil, err
	}
	out := [][32]byte{}
	for _, id := range ids {
		if c.evm.StateDB.GetState(wallet, msApprovalSlot(op, id)) != (common.Hash{}) {
			out = append(out, [32]byte(id))
		}
	}
	return msArgsBytes32Arr.Pack(out)
}

// Admin functions: callable only by a wallet itself (via execute).

func (c *msCtx) self() (common.Address, error) {
	if err := c.writable(); err != nil {
		return common.Address{}, err
	}
	if !c.initialized(c.caller) {
		return common.Address{}, msFail("caller is not a wallet")
	}
	return c.caller, c.m.use(MultisigWriteGas)
}

func (c *msCtx) addOwner(data []byte) ([]byte, error) {
	wallet, err := c.self()
	if err != nil {
		return nil, err
	}
	args, err := msArgsAddress.Unpack(data)
	if err != nil {
		return nil, err
	}
	a := args[0].(common.Address)
	if a == (common.Address{}) {
		return nil, msFail("invalid owner")
	}
	if err := c.addOwnerID(wallet, msAddressID(a), nil, nil); err != nil {
		return nil, err
	}
	return msArgsBool.Pack(true)
}

func (c *msCtx) addPasskey(data []byte) ([]byte, error) {
	wallet, err := c.self()
	if err != nil {
		return nil, err
	}
	args, err := msArgsUint2.Unpack(data)
	if err != nil {
		return nil, err
	}
	x, y := args[0].(*big.Int), args[1].(*big.Int)
	if !msValidPasskey(x, y) {
		return nil, msFail("invalid passkey")
	}
	if err := c.addOwnerID(wallet, msPasskeyID(x, y), x, y); err != nil {
		return nil, err
	}
	return msArgsBool.Pack(true)
}

func (c *msCtx) removeOwner(data []byte) ([]byte, error) {
	wallet, err := c.self()
	if err != nil {
		return nil, err
	}
	args, err := msArgsBytes32.Unpack(data)
	if err != nil {
		return nil, err
	}
	id := common.Hash(args[0].([32]byte))
	idx := c.getU(wallet, msIndexSlot(id))
	if idx == 0 {
		return nil, msFail("not an owner")
	}
	n := c.getU(wallet, msSlotCount)
	if n-1 < c.getU(wallet, msSlotThreshold) {
		return nil, msFail("would fall below threshold")
	}
	db := c.evm.StateDB
	// swap with last, then pop
	last := db.GetState(wallet, msOwnerSlot(n-1))
	db.SetState(wallet, msOwnerSlot(idx-1), last)
	c.setU(wallet, msIndexSlot(last), idx)
	db.SetState(wallet, msOwnerSlot(n-1), common.Hash{})
	db.SetState(wallet, msIndexSlot(id), common.Hash{})
	db.SetState(wallet, msPkxSlot(id), common.Hash{})
	db.SetState(wallet, msPkySlot(id), common.Hash{})
	c.setU(wallet, msSlotCount, n-1)
	c.log(msEvOwnerRemoved, wallet, id)
	return msArgsBool.Pack(true)
}

func (c *msCtx) setThreshold(data []byte) ([]byte, error) {
	wallet, err := c.self()
	if err != nil {
		return nil, err
	}
	args, err := msArgsUint.Unpack(data)
	if err != nil {
		return nil, err
	}
	t := args[0].(*big.Int)
	if !t.IsUint64() || t.Uint64() == 0 || t.Uint64() > c.getU(wallet, msSlotCount) {
		return nil, msFail("invalid threshold")
	}
	c.setU(wallet, msSlotThreshold, t.Uint64())
	c.log(msEvThresholdChanged, wallet, common.BigToHash(t))
	return msArgsBool.Pack(true)
}
