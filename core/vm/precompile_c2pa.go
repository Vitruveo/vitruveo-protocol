package vm

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm/c2pa"
	"github.com/ethereum/go-ethereum/crypto"
)

// Content authenticity (C2PA / Content Credentials) precompile.
// See contracts/c2pa/IContentCredentials.sol.
//
// verify() checks a C2PA manifest store against a file in the file storage
// precompile: every claim signature, assertion hash and ingredient link; the
// active signer's certificate chain against the on-chain trust list at the
// block time; and that the manifest's c2pa.hash.data hash equals the file's
// content hash (computed on chain during upload). The result is recorded so
// any contract can read it with provenance().
//
// The trust list (anchor certificates and revocations) is changed only by the
// admin, initially a native multisig wallet created by this precompile with
// fixed owners (C2PAAdminOwners, C2PAAdminThreshold). The admin can hand
// control to another address with setAdmin().

const (
	C2PABaseGas      = 2000
	C2PAPerByteGas   = 1    // per byte of input
	C2PAHashGas      = 1    // per 32 bytes hashed beyond the input
	C2PASignatureGas = 5000 // per signature checked (claims and certificates)
	C2PAWriteGas     = 5000 // per storage slot written
	C2PAReadGas      = 2600 // per view
	C2PAMaxAnchorDER = 4096
	C2PAMaxSubject   = 16 // anchors indexed per subject
	C2PAMaxLineage   = c2pa.MaxManifests
	c2paMaxString    = 128
)

var (
	// Initial trust list admin: a 2-of-2 multisig of these owners.
	C2PAAdminOwners = []common.Address{
		common.HexToAddress("0xAC51c04Cb72A5D0F56D71Baf3E2F2B28e6426922"),
		common.HexToAddress("0xe635275ef4B9B27422A0ebE4A32C2bB5F50befd7"),
	}
	C2PAAdminThreshold = uint64(2)
	C2PAAdminSalt      = crypto.Keccak256Hash([]byte("vtru.c2pa.admin"))

	// C2PAAdminWallet is the multisig wallet address of the initial admin.
	C2PAAdminWallet = MultisigWalletAddress(C2PAPrecompileAddress, C2PAAdminSalt)
)

var (
	c2Sel = func(sig string) []byte { return pbSelector(sig) }

	c2SelSetupAdmin   = c2Sel("setupAdmin()")
	c2SelAdmin        = c2Sel("admin()")
	c2SelSetAdmin     = c2Sel("setAdmin(address)")
	c2SelAddAnchor    = c2Sel("addAnchor(bytes)")
	c2SelRemoveAnchor = c2Sel("removeAnchor(bytes32)")
	c2SelRevoke       = c2Sel("revoke(bytes32,uint256)")
	c2SelUnrevoke     = c2Sel("unrevoke(bytes32)")
	c2SelIsAnchor     = c2Sel("isAnchor(bytes32)")
	c2SelRevokedAt    = c2Sel("revokedAt(bytes32)")
	c2SelVerify       = c2Sel("verify(bytes32,bytes)")
	c2SelCheck        = c2Sel("check(bytes)")
	c2SelProvenance   = c2Sel("provenance(bytes32)")
	c2SelLineage      = c2Sel("lineage(bytes32)")

	c2ArgsBytes      = abi.Arguments{{Type: pbTypeBytes}}
	c2ArgsFP         = abi.Arguments{{Type: pbTypeBytes32}}
	c2ArgsRevoke     = abi.Arguments{{Type: pbTypeBytes32}, {Type: pbTypeUint256}}
	c2ArgsRevokedOut = abi.Arguments{{Type: pbTypeBool}, {Type: pbTypeUint256}}
	c2ArgsVerify     = abi.Arguments{{Type: pbTypeBytes32}, {Type: pbTypeBytes}}
	c2ArgsVerifyOut  = abi.Arguments{{Type: pbTypeBytes32}, {Type: pbTypeBytes32}, {Type: msTypeString}, {Type: msTypeString}, {Type: pbTypeUint256}}
	c2ArgsCheckOut   = abi.Arguments{{Type: pbTypeBytes32}, {Type: pbTypeBytes32}, {Type: msTypeString}, {Type: msTypeString}, {Type: pbTypeUint256}, {Type: pbTypeBytes32}, {Type: pbTypeUint256Array}, {Type: pbTypeUint256Array}}
	c2ArgsProvOut    = abi.Arguments{{Type: pbTypeBool}, {Type: pbTypeBytes32}, {Type: pbTypeBytes32}, {Type: msTypeString}, {Type: msTypeString}, {Type: pbTypeUint256}, {Type: pbTypeUint256}, {Type: pbTypeAddress}}

	c2EvAdminChanged = crypto.Keccak256Hash([]byte("AdminChanged(address)"))
	c2EvAnchorAdded  = crypto.Keccak256Hash([]byte("AnchorAdded(bytes32)"))
	c2EvAnchorRemove = crypto.Keccak256Hash([]byte("AnchorRemoved(bytes32)"))
	c2EvRevoked      = crypto.Keccak256Hash([]byte("Revoked(bytes32,uint256)"))
	c2EvUnrevoked    = crypto.Keccak256Hash([]byte("Unrevoked(bytes32)"))
	c2EvVerified     = crypto.Keccak256Hash([]byte("ProvenanceVerified(bytes32,bytes32,bytes32)"))
)

type c2Ctx struct {
	evm    *EVM
	caller common.Address
	static bool
	m      *pbMeter
}

func RunC2PA(evm *EVM, caller common.Address, input []byte, gas uint64, static bool) (ret []byte, gasLeft uint64, err error) {
	m := &pbMeter{left: gas}
	if m.use(C2PABaseGas) != nil || m.mul(uint64(len(input)), C2PAPerByteGas) != nil {
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
	c := &c2Ctx{evm: evm, caller: caller, static: static, m: m}
	sel, data := input[:4], input[4:]

	var out []byte
	switch {
	case bytes.Equal(sel, c2SelSetupAdmin):
		out, err = c.setupAdmin()
	case bytes.Equal(sel, c2SelAdmin):
		out, err = c.adminView()
	case bytes.Equal(sel, c2SelSetAdmin):
		out, err = c.setAdmin(data)
	case bytes.Equal(sel, c2SelAddAnchor):
		out, err = c.addAnchor(data)
	case bytes.Equal(sel, c2SelRemoveAnchor):
		out, err = c.removeAnchor(data)
	case bytes.Equal(sel, c2SelRevoke):
		out, err = c.revoke(data)
	case bytes.Equal(sel, c2SelUnrevoke):
		out, err = c.unrevoke(data)
	case bytes.Equal(sel, c2SelIsAnchor):
		out, err = c.isAnchorView(data)
	case bytes.Equal(sel, c2SelRevokedAt):
		out, err = c.revokedAtView(data)
	case bytes.Equal(sel, c2SelVerify):
		out, err = c.verify(data)
	case bytes.Equal(sel, c2SelCheck):
		out, err = c.check(data)
	case bytes.Equal(sel, c2SelProvenance):
		out, err = c.provenance(data)
	case bytes.Equal(sel, c2SelLineage):
		out, err = c.lineage(data)
	default:
		err = msFail("unknown function")
	}
	if err == nil {
		return out, m.left, nil
	}

	evm.StateDB.RevertToSnapshot(snapshot)
	var rev *msRevert
	switch {
	case errors.Is(err, errPBOutOfGas):
		return nil, 0, ErrOutOfGas
	case errors.Is(err, errMSWrite):
		return nil, 0, ErrWriteProtection
	case errors.As(err, &rev):
		return rev.revertData(), m.left, ErrExecutionReverted
	default:
		// Verification failures carry their reason.
		return msFail(err.Error()).(*msRevert).revertData(), m.left, ErrExecutionReverted
	}
}

// ---------------------------------------------------------------------------
// Storage (in the precompile account)
// ---------------------------------------------------------------------------

func c2Slot(label string, parts ...[]byte) common.Hash {
	data := append([][]byte{[]byte("vtru.c2pa." + label)}, parts...)
	return crypto.Keccak256Hash(data...)
}

func (c *c2Ctx) get(slot common.Hash) common.Hash {
	return c.evm.StateDB.GetState(C2PAPrecompileAddress, slot)
}

func (c *c2Ctx) getU(slot common.Hash) uint64 {
	return new(big.Int).SetBytes(c.get(slot).Bytes()).Uint64()
}

func (c *c2Ctx) set(slot, v common.Hash) error {
	if err := c.m.use(C2PAWriteGas); err != nil {
		return err
	}
	db := c.evm.StateDB
	if db.GetNonce(C2PAPrecompileAddress) == 0 {
		db.SetNonce(C2PAPrecompileAddress, 1) // keeps the account from being pruned as empty
	}
	db.SetState(C2PAPrecompileAddress, slot, v)
	return nil
}

func (c *c2Ctx) setU(slot common.Hash, v uint64) error { return c.set(slot, msWord(v)) }

func (c *c2Ctx) getBytes(label string, key []byte) []byte {
	n := c.getU(c2Slot(label+".len", key))
	if n > C2PAMaxAnchorDER {
		return nil
	}
	out := make([]byte, 0, n+31)
	for i := uint64(0); uint64(len(out)) < n; i++ {
		out = append(out, c.get(c2Slot(label, key, msWord(i).Bytes())).Bytes()...)
	}
	return out[:n]
}

func (c *c2Ctx) setBytes(label string, key, b []byte) error {
	if err := c.setU(c2Slot(label+".len", key), uint64(len(b))); err != nil {
		return err
	}
	for i := 0; i*32 < len(b); i++ {
		var w common.Hash
		copy(w[:], b[i*32:])
		if err := c.set(c2Slot(label, key, msWord(uint64(i)).Bytes()), w); err != nil {
			return err
		}
	}
	return nil
}

func c2Truncate(s string) string {
	if len(s) > c2paMaxString {
		return s[:c2paMaxString]
	}
	return s
}

func (c *c2Ctx) writable() error {
	if c.static || c.evm.interpreter.readOnly {
		return errMSWrite
	}
	return nil
}

func (c *c2Ctx) log(topics []common.Hash, data []byte) {
	c.evm.StateDB.AddLog(&types.Log{
		Address:     C2PAPrecompileAddress,
		Topics:      topics,
		Data:        data,
		BlockNumber: c.evm.Context.BlockNumber.Uint64(),
	})
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

func (c *c2Ctx) admin() common.Address {
	if a := common.BytesToAddress(c.get(c2Slot("admin")).Bytes()); a != (common.Address{}) {
		return a
	}
	return C2PAAdminWallet
}

func (c *c2Ctx) onlyAdmin() error {
	if err := c.writable(); err != nil {
		return err
	}
	if c.caller != c.admin() {
		return msFail("caller is not the trust list admin")
	}
	return nil
}

// setupAdmin creates the initial admin multisig wallet. Anyone may call it;
// owners and threshold are fixed in code.
func (c *c2Ctx) setupAdmin() ([]byte, error) {
	if err := c.writable(); err != nil {
		return nil, err
	}
	wallet, err := multisigEnsureWallet(c.evm, c.m, C2PAPrecompileAddress, C2PAAdminSalt, C2PAAdminOwners, C2PAAdminThreshold)
	if err != nil {
		return nil, err
	}
	return msArgsAddress.Pack(wallet)
}

func (c *c2Ctx) adminView() ([]byte, error) {
	if err := c.m.use(C2PAReadGas); err != nil {
		return nil, err
	}
	return msArgsAddress.Pack(c.admin())
}

func (c *c2Ctx) setAdmin(data []byte) ([]byte, error) {
	if err := c.onlyAdmin(); err != nil {
		return nil, err
	}
	args, err := msArgsAddress.Unpack(data)
	if err != nil {
		return nil, err
	}
	a := args[0].(common.Address)
	if a == (common.Address{}) {
		return nil, msFail("invalid admin")
	}
	if err := c.set(c2Slot("admin"), common.BytesToHash(a.Bytes())); err != nil {
		return nil, err
	}
	c.log([]common.Hash{c2EvAdminChanged, common.BytesToHash(a.Bytes())}, nil)
	return msArgsBool.Pack(true)
}

func (c *c2Ctx) addAnchor(data []byte) ([]byte, error) {
	if err := c.onlyAdmin(); err != nil {
		return nil, err
	}
	args, err := c2ArgsBytes.Unpack(data)
	if err != nil {
		return nil, err
	}
	der := args[0].([]byte)
	if len(der) == 0 || len(der) > C2PAMaxAnchorDER {
		return nil, msFail("invalid certificate")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil || !cert.IsCA {
		return nil, msFail("invalid CA certificate")
	}
	fp := sha256.Sum256(der)
	if c.getU(c2Slot("anchor", fp[:])) == 1 {
		return nil, msFail("anchor exists")
	}
	if c.getU(c2Slot("der.len", fp[:])) == 0 { // first time: store DER and index by subject
		if err := c.setBytes("der", fp[:], der); err != nil {
			return nil, err
		}
		subj := crypto.Keccak256(cert.RawSubject)
		n := c.getU(c2Slot("subj.n", subj))
		if n >= C2PAMaxSubject {
			return nil, msFail("too many anchors with this subject")
		}
		if err := c.set(c2Slot("subj", subj, msWord(n).Bytes()), common.Hash(fp)); err != nil {
			return nil, err
		}
		if err := c.setU(c2Slot("subj.n", subj), n+1); err != nil {
			return nil, err
		}
	}
	if err := c.setU(c2Slot("anchor", fp[:]), 1); err != nil {
		return nil, err
	}
	c.log([]common.Hash{c2EvAnchorAdded, fp}, nil)
	return c2ArgsFP.Pack(fp)
}

func (c *c2Ctx) removeAnchor(data []byte) ([]byte, error) {
	if err := c.onlyAdmin(); err != nil {
		return nil, err
	}
	args, err := c2ArgsFP.Unpack(data)
	if err != nil {
		return nil, err
	}
	fp := args[0].([32]byte)
	if c.getU(c2Slot("anchor", fp[:])) != 1 {
		return nil, msFail("not an anchor")
	}
	if err := c.setU(c2Slot("anchor", fp[:]), 0); err != nil {
		return nil, err
	}
	c.log([]common.Hash{c2EvAnchorRemove, fp}, nil)
	return msArgsBool.Pack(true)
}

// revoke marks any certificate (anchor, intermediate or signer) revoked from
// effectiveTime (unix seconds). Records verified at or after that time are
// reported invalid by provenance().
func (c *c2Ctx) revoke(data []byte) ([]byte, error) {
	if err := c.onlyAdmin(); err != nil {
		return nil, err
	}
	args, err := c2ArgsRevoke.Unpack(data)
	if err != nil {
		return nil, err
	}
	fp, eff := args[0].([32]byte), args[1].(*big.Int)
	if !eff.IsUint64() || eff.Uint64() >= 1<<63 {
		return nil, msFail("invalid time")
	}
	if err := c.setU(c2Slot("revoked", fp[:]), eff.Uint64()+1); err != nil {
		return nil, err
	}
	c.log([]common.Hash{c2EvRevoked, fp}, msWord(eff.Uint64()).Bytes())
	return msArgsBool.Pack(true)
}

func (c *c2Ctx) unrevoke(data []byte) ([]byte, error) {
	if err := c.onlyAdmin(); err != nil {
		return nil, err
	}
	args, err := c2ArgsFP.Unpack(data)
	if err != nil {
		return nil, err
	}
	fp := args[0].([32]byte)
	if err := c.setU(c2Slot("revoked", fp[:]), 0); err != nil {
		return nil, err
	}
	c.log([]common.Hash{c2EvUnrevoked, fp}, nil)
	return msArgsBool.Pack(true)
}

// ---------------------------------------------------------------------------
// Trust store (c2pa.TrustStore over state) and meter
// ---------------------------------------------------------------------------

type c2Trust struct{ c *c2Ctx }

func (t c2Trust) IsAnchor(fp [32]byte) bool { return t.c.getU(c2Slot("anchor", fp[:])) == 1 }

func (t c2Trust) AnchorsBySubject(raw []byte) []*x509.Certificate {
	subj := crypto.Keccak256(raw)
	n := t.c.getU(c2Slot("subj.n", subj))
	var out []*x509.Certificate
	for i := uint64(0); i < n && i < C2PAMaxSubject; i++ {
		fp := t.c.get(c2Slot("subj", subj, msWord(i).Bytes()))
		if !t.IsAnchor(fp) {
			continue
		}
		if cert, err := x509.ParseCertificate(t.c.getBytes("der", fp[:])); err == nil {
			out = append(out, cert)
		}
	}
	return out
}

func (t c2Trust) RevokedAt(fp [32]byte) (uint64, bool) {
	v := t.c.getU(c2Slot("revoked", fp[:]))
	if v == 0 {
		return 0, false
	}
	return v - 1, true
}

type c2Meter struct{ m *pbMeter }

func (m c2Meter) Signature() error    { return m.m.use(C2PASignatureGas) }
func (m c2Meter) Hash(n uint64) error { return m.m.mul((n+31)/32, C2PAHashGas) }

func (c *c2Ctx) now() time.Time { return time.Unix(int64(c.evm.Context.Time), 0) }

func (c *c2Ctx) run(store []byte) (*c2pa.Result, error) {
	return c2pa.Verify(store, c.now(), c2Trust{c}, c2Meter{c.m})
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

func (c *c2Ctx) verify(data []byte) ([]byte, error) {
	if err := c.writable(); err != nil {
		return nil, err
	}
	args, err := c2ArgsVerify.Unpack(data)
	if err != nil {
		return nil, err
	}
	fileHash := common.Hash(args[0].([32]byte))
	store := args[1].([]byte)

	file, ok := ReadFileStoreInfo(c.evm.StateDB, fileHash)
	if !ok {
		return nil, msFail("file not found")
	}
	if len(file.Exclusions) == 0 {
		return nil, msFail("file was not uploaded with beginWithCredential")
	}
	res, err := c.run(store)
	if err != nil {
		return nil, err
	}
	if res.Hash == nil {
		return nil, msFail("manifest has no data hash")
	}
	if res.HashAlg != "sha256" {
		return nil, msFail("unsupported data hash algorithm")
	}
	if !bytes.Equal(res.Hash, file.ContentHash[:]) {
		return nil, msFail("manifest does not match file")
	}
	if len(res.Exclusions) != len(file.Exclusions) {
		return nil, msFail("exclusions do not match file")
	}
	for i, e := range res.Exclusions {
		if e.Start != file.Exclusions[i].Start || e.Length != file.Exclusions[i].Length {
			return nil, msFail("exclusions do not match file")
		}
	}

	// Record
	a := res.Active
	k := fileHash.Bytes()
	chain := make([][32]byte, 0, len(a.Chain)+1)
	for _, cert := range a.Chain {
		chain = append(chain, sha256.Sum256(cert.Raw))
	}
	if chain[len(chain)-1] != res.Anchor {
		chain = append(chain, res.Anchor)
	}
	writes := []struct {
		slot common.Hash
		v    common.Hash
	}{
		{c2Slot("p.signer", k), common.Hash(a.Signer)},
		{c2Slot("p.anchor", k), common.Hash(res.Anchor)},
		{c2Slot("p.n", k), msWord(uint64(len(res.Manifests)))},
		{c2Slot("p.block", k), msWord(c.evm.Context.BlockNumber.Uint64())},
		{c2Slot("p.time", k), msWord(c.evm.Context.Time)},
		{c2Slot("p.by", k), common.BytesToHash(c.caller.Bytes())},
		{c2Slot("p.chain.n", k), msWord(uint64(len(chain)))},
	}
	for _, w := range writes {
		if err := c.set(w.slot, w.v); err != nil {
			return nil, err
		}
	}
	for i, fp := range chain {
		if err := c.set(c2Slot("p.chain", k, msWord(uint64(i)).Bytes()), common.Hash(fp)); err != nil {
			return nil, err
		}
	}
	for i, man := range res.Manifests {
		if err := c.set(c2Slot("p.lineage", k, msWord(uint64(i)).Bytes()), common.Hash(man.Signer)); err != nil {
			return nil, err
		}
	}
	if err := c.setBytes("p.name", k, []byte(c2Truncate(a.SignerName))); err != nil {
		return nil, err
	}
	if err := c.setBytes("p.gen", k, []byte(c2Truncate(a.ClaimGenerator))); err != nil {
		return nil, err
	}
	c.log([]common.Hash{c2EvVerified, fileHash, a.Signer}, res.Anchor[:])
	return c2ArgsVerifyOut.Pack(a.Signer, res.Anchor, c2Truncate(a.SignerName), c2Truncate(a.ClaimGenerator), big.NewInt(int64(len(res.Manifests))))
}

// check verifies a manifest store without a stored file and without writing.
func (c *c2Ctx) check(data []byte) ([]byte, error) {
	args, err := c2ArgsBytes.Unpack(data)
	if err != nil {
		return nil, err
	}
	res, err := c.run(args[0].([]byte))
	if err != nil {
		return nil, err
	}
	var h [32]byte
	if res.HashAlg == "sha256" {
		copy(h[:], res.Hash)
	}
	starts, lengths := make([]*big.Int, len(res.Exclusions)), make([]*big.Int, len(res.Exclusions))
	for i, e := range res.Exclusions {
		starts[i], lengths[i] = new(big.Int).SetUint64(e.Start), new(big.Int).SetUint64(e.Length)
	}
	a := res.Active
	return c2ArgsCheckOut.Pack(a.Signer, res.Anchor, c2Truncate(a.SignerName), c2Truncate(a.ClaimGenerator),
		big.NewInt(int64(len(res.Manifests))), h, starts, lengths)
}

// provenance returns the recorded verification for a file. valid is false if
// any certificate on the recorded path has since been revoked effective at or
// before the verification time, or the anchor was removed.
func (c *c2Ctx) provenance(data []byte) ([]byte, error) {
	args, err := c2ArgsFP.Unpack(data)
	if err != nil {
		return nil, err
	}
	if err := c.m.use(C2PAReadGas); err != nil {
		return nil, err
	}
	k := args[0].([32]byte)
	signer := c.get(c2Slot("p.signer", k[:]))
	if signer == (common.Hash{}) {
		return nil, msFail("no provenance record")
	}
	anchor := c.get(c2Slot("p.anchor", k[:]))
	at := c.getU(c2Slot("p.time", k[:]))
	trust := c2Trust{c}
	valid := trust.IsAnchor(anchor)
	n := c.getU(c2Slot("p.chain.n", k[:]))
	for i := uint64(0); i < n && i <= c2pa.MaxChain+1; i++ {
		fp := c.get(c2Slot("p.chain", k[:], msWord(i).Bytes()))
		if eff, revoked := trust.RevokedAt(fp); revoked && eff <= at {
			valid = false
		}
	}
	return c2ArgsProvOut.Pack(valid, [32]byte(signer), [32]byte(anchor),
		string(c.getBytes("p.name", k[:])), string(c.getBytes("p.gen", k[:])),
		new(big.Int).SetUint64(c.getU(c2Slot("p.n", k[:]))),
		new(big.Int).SetUint64(c.getU(c2Slot("p.block", k[:]))),
		common.BytesToAddress(c.get(c2Slot("p.by", k[:])).Bytes()))
}

// lineage returns the signer of every manifest in the verified store, oldest
// first; the last entry is the active signer.
func (c *c2Ctx) lineage(data []byte) ([]byte, error) {
	args, err := c2ArgsFP.Unpack(data)
	if err != nil {
		return nil, err
	}
	if err := c.m.use(C2PAReadGas); err != nil {
		return nil, err
	}
	k := args[0].([32]byte)
	n := c.getU(c2Slot("p.n", k[:]))
	if n > C2PAMaxLineage {
		n = C2PAMaxLineage
	}
	out := make([][32]byte, n)
	for i := range out {
		out[i] = c.get(c2Slot("p.lineage", k[:], msWord(uint64(i)).Bytes()))
	}
	return msArgsBytes32Arr.Pack(out)
}

func (c *c2Ctx) isAnchorView(data []byte) ([]byte, error) {
	args, err := c2ArgsFP.Unpack(data)
	if err != nil {
		return nil, err
	}
	if err := c.m.use(C2PAReadGas); err != nil {
		return nil, err
	}
	return msArgsBool.Pack(c2Trust{c}.IsAnchor(args[0].([32]byte)))
}

func (c *c2Ctx) revokedAtView(data []byte) ([]byte, error) {
	args, err := c2ArgsFP.Unpack(data)
	if err != nil {
		return nil, err
	}
	if err := c.m.use(C2PAReadGas); err != nil {
		return nil, err
	}
	eff, revoked := c2Trust{c}.RevokedAt(args[0].([32]byte))
	return c2ArgsRevokedOut.Pack(revoked, new(big.Int).SetUint64(eff))
}
