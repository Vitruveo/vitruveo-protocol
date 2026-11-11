package c2pa

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"
)

// Limits keep verification cost bounded.
const (
	MaxManifests  = 16
	MaxAssertions = 128
	MaxChain      = 8
	maxRSABits    = 8192
)

// Exclusion is a byte range of the asset left out of the c2pa.hash.data hash
// (the embedded manifest store).
type Exclusion struct {
	Start  uint64
	Length uint64
}

// Manifest is one verified manifest of a store.
type Manifest struct {
	Label          string
	Title          string
	ClaimGenerator string
	Chain          []*x509.Certificate // x5chain, signer first
	Signer         [32]byte            // SHA-256 of the signer certificate (DER)
	SignerName     string
}

// Result is a verified manifest store.
type Result struct {
	Manifests  []*Manifest // store order; the active manifest is last
	Active     *Manifest
	Anchor     [32]byte // trust anchor the active signer chains to
	HashAlg    string   // c2pa.hash.data algorithm of the active manifest ("" if none)
	Hash       []byte   // c2pa.hash.data hash of the active manifest
	Exclusions []Exclusion
}

// TrustStore is the on-chain trust list.
type TrustStore interface {
	IsAnchor(fp [32]byte) bool
	AnchorsBySubject(rawSubject []byte) []*x509.Certificate
	RevokedAt(fp [32]byte) (effective uint64, revoked bool)
}

// Meter charges work as it is discovered; it returns an error to abort.
type Meter interface {
	Signature() error    // one public key signature verification
	Hash(n uint64) error // n bytes hashed beyond the input itself
}

var (
	ErrUntrusted    = errors.New("c2pa: signer not trusted")
	ErrRevoked      = errors.New("c2pa: certificate revoked")
	ErrExpired      = errors.New("c2pa: certificate not valid at this time")
	ErrSignature    = errors.New("c2pa: invalid claim signature")
	ErrHashMismatch = errors.New("c2pa: assertion hash mismatch")
)

func fail(format string, a ...any) error { return fmt.Errorf("c2pa: "+format, a...) }

// Verify parses a manifest store and verifies every manifest in it: claim
// signatures, assertion hashes and ingredient links. The active (last)
// manifest's signer must chain to a trust anchor, with every certificate in
// that path valid and unrevoked at now. Earlier manifests (edit history) are
// checked cryptographically but not for trust or expiry.
func Verify(store []byte, now time.Time, trust TrustStore, m Meter) (*Result, error) {
	boxes, err := parseBoxes(store, 0)
	if err != nil {
		return nil, err
	}
	if len(boxes) != 1 || boxes[0].Type != "jumb" || boxes[0].Label != "c2pa" {
		return nil, fail("not a manifest store")
	}
	root := boxes[0]
	var manifests []*box
	for _, c := range root.Children {
		if c.Type == "jumb" {
			manifests = append(manifests, c)
		}
	}
	if len(manifests) == 0 || len(manifests) > MaxManifests {
		return nil, fail("invalid manifest count")
	}
	res := &Result{}
	for i, mb := range manifests {
		active := i == len(manifests)-1
		man, hd, err := verifyManifest(root, mb, active, m)
		if err != nil {
			return nil, fmt.Errorf("manifest %q: %w", mb.Label, err)
		}
		res.Manifests = append(res.Manifests, man)
		if active {
			res.Active = man
			if hd != nil {
				res.HashAlg, res.Hash, res.Exclusions = hd.alg, hd.hash, hd.exclusions
			}
		}
	}
	anchor, err := checkTrust(res.Active.Chain, now, trust, m)
	if err != nil {
		return nil, err
	}
	res.Anchor = anchor
	return res, nil
}

type hashData struct {
	alg        string
	hash       []byte
	exclusions []Exclusion
}

func verifyManifest(root, mb *box, active bool, m Meter) (*Manifest, *hashData, error) {
	cb := mb.child("c2pa.claim.v2")
	if cb == nil {
		cb = mb.child("c2pa.claim")
	}
	if cb == nil || cb.content("cbor") == nil {
		return nil, nil, fail("missing claim")
	}
	claimBytes := cb.content("cbor").Payload
	cv, err := cborDecode(claimBytes)
	if err != nil {
		return nil, nil, err
	}
	claim, ok := cv.(cborMap)
	if !ok {
		return nil, nil, fail("claim is not a map")
	}
	alg := claim.str("alg")
	if alg == "" {
		alg = "sha256"
	}
	man := &Manifest{Label: mb.Label, Title: claim.str("dc:title"), ClaimGenerator: claim.str("claim_generator")}
	if man.ClaimGenerator == "" {
		if info, ok := claim.get("claim_generator_info"); ok {
			if im, ok := info.(cborMap); ok {
				man.ClaimGenerator = strings.TrimSpace(im.str("name") + " " + im.str("version"))
			}
		}
	}

	// Assertion references, each checked against the assertion's hash.
	var refs []any
	for _, key := range []string{"assertions", "created_assertions", "gathered_assertions"} {
		if v, ok := claim.get(key); ok {
			arr, ok := v.([]any)
			if !ok {
				return nil, nil, fail("bad assertion list")
			}
			refs = append(refs, arr...)
		}
	}
	if len(refs) > MaxAssertions {
		return nil, nil, fail("too many assertions")
	}
	var hd *hashData
	for _, r := range refs {
		ab, err := checkHashedURI(root, mb, r, alg, m)
		if err != nil {
			return nil, nil, err
		}
		label := ab.Label
		switch {
		case label == "c2pa.hash.data" || strings.HasPrefix(label, "c2pa.hash.data__"):
			if hd != nil {
				return nil, nil, fail("multiple data hash assertions")
			}
			if hd, err = parseHashData(ab, alg); err != nil {
				return nil, nil, err
			}
		case strings.HasPrefix(label, "c2pa.ingredient"):
			if err := checkIngredient(root, mb, ab, alg, m); err != nil {
				return nil, nil, err
			}
		}
	}

	// Claim signature (COSE_Sign1, detached payload = claim bytes).
	sigURL := claim.str("signature")
	sb, err := resolve(root, mb, sigURL)
	if err != nil || sb.content("cbor") == nil {
		return nil, nil, fail("missing signature")
	}
	chain, err := verifyCOSE(sb.content("cbor").Payload, claimBytes, m)
	if err != nil {
		return nil, nil, err
	}
	man.Chain = chain
	man.Signer = sha256.Sum256(chain[0].Raw)
	man.SignerName = chain[0].Subject.CommonName
	if man.SignerName == "" && len(chain[0].Subject.Organization) > 0 {
		man.SignerName = chain[0].Subject.Organization[0]
	}
	return man, hd, nil
}

// resolve finds the superbox a JUMBF URI points to, relative to manifest mb.
func resolve(root, mb *box, url string) (*box, error) {
	path, ok := strings.CutPrefix(url, "self#jumbf=")
	if !ok || path == "" {
		return nil, fail("bad JUMBF URI %q", url)
	}
	cur := mb
	if strings.HasPrefix(path, "/") {
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) == 0 || parts[0] != root.Label {
			return nil, fail("bad JUMBF URI %q", url)
		}
		cur, path = root, strings.Join(parts[1:], "/")
		if path == "" {
			return root, nil
		}
	}
	for _, p := range strings.Split(path, "/") {
		if cur = cur.child(p); cur == nil {
			return nil, fail("unresolved JUMBF URI %q", url)
		}
	}
	return cur, nil
}

func newHash(alg string) (hash.Hash, error) {
	switch alg {
	case "sha256":
		return sha256.New(), nil
	case "sha384":
		return sha512.New384(), nil
	case "sha512":
		return sha512.New(), nil
	}
	return nil, fail("unsupported hash algorithm %q", alg)
}

// checkHashedURI resolves a hashed URI map and checks the hash of the target
// superbox contents (description and content boxes, without its own header).
func checkHashedURI(root, mb *box, v any, defAlg string, m Meter) (*box, error) {
	ref, ok := v.(cborMap)
	if !ok {
		return nil, fail("bad hashed URI")
	}
	target, err := resolve(root, mb, ref.str("url"))
	if err != nil {
		return nil, err
	}
	alg := ref.str("alg")
	if alg == "" {
		alg = defAlg
	}
	h, err := newHash(alg)
	if err != nil {
		return nil, err
	}
	if err := m.Hash(uint64(len(target.Payload))); err != nil {
		return nil, err
	}
	h.Write(target.Payload)
	if !bytes.Equal(h.Sum(nil), ref.bytes("hash")) {
		return nil, ErrHashMismatch
	}
	return target, nil
}

func checkIngredient(root, mb, ab *box, alg string, m Meter) error {
	c := ab.content("cbor")
	if c == nil {
		return nil
	}
	v, err := cborDecode(c.Payload)
	if err != nil {
		return err
	}
	ing, ok := v.(cborMap)
	if !ok {
		return fail("bad ingredient")
	}
	for _, key := range []string{"c2pa_manifest", "activeManifest"} {
		if ref, ok := ing.get(key); ok {
			target, err := checkHashedURI(root, mb, ref, alg, m)
			if err != nil {
				return err
			}
			if target == root || !isManifest(root, target) {
				return fail("ingredient does not reference a manifest")
			}
		}
	}
	return nil
}

func isManifest(root, b *box) bool {
	for _, c := range root.Children {
		if c == b {
			return true
		}
	}
	return false
}

func parseHashData(ab *box, defAlg string) (*hashData, error) {
	c := ab.content("cbor")
	if c == nil {
		return nil, fail("bad data hash")
	}
	v, err := cborDecode(c.Payload)
	if err != nil {
		return nil, err
	}
	mp, ok := v.(cborMap)
	if !ok {
		return nil, fail("bad data hash")
	}
	hd := &hashData{alg: mp.str("alg"), hash: mp.bytes("hash")}
	if hd.alg == "" {
		hd.alg = defAlg
	}
	if len(hd.hash) == 0 {
		return nil, fail("bad data hash")
	}
	if ex, ok := mp.get("exclusions"); ok {
		arr, ok := ex.([]any)
		if !ok {
			return nil, fail("bad exclusions")
		}
		for _, e := range arr {
			em, ok := e.(cborMap)
			if !ok {
				return nil, fail("bad exclusions")
			}
			s, ok1 := em.get("start")
			l, ok2 := em.get("length")
			si, ok3 := cborInt(s)
			li, ok4 := cborInt(l)
			if !ok1 || !ok2 || !ok3 || !ok4 || si < 0 || li < 0 {
				return nil, fail("bad exclusions")
			}
			hd.exclusions = append(hd.exclusions, Exclusion{Start: uint64(si), Length: uint64(li)})
		}
	}
	return hd, nil
}

// verifyCOSE checks a COSE_Sign1 over payload and returns the signer chain.
func verifyCOSE(sig, payload []byte, m Meter) ([]*x509.Certificate, error) {
	v, err := cborDecode(sig)
	if err != nil {
		return nil, err
	}
	if t, ok := v.(cborTag); ok {
		if t.Num != 18 {
			return nil, fail("not COSE_Sign1")
		}
		v = t.Val
	}
	arr, ok := v.([]any)
	if !ok || len(arr) != 4 {
		return nil, fail("bad COSE_Sign1")
	}
	protRaw, ok1 := arr[0].([]byte)
	unprot, ok2 := arr[1].(cborMap)
	signature, ok3 := arr[3].([]byte)
	if !ok1 || !ok2 || !ok3 {
		return nil, fail("bad COSE_Sign1")
	}
	if p, ok := arr[2].([]byte); ok && !bytes.Equal(p, payload) {
		return nil, fail("COSE payload does not match claim")
	}
	var prot cborMap
	if len(protRaw) > 0 {
		pv, err := cborDecode(protRaw)
		if err != nil {
			return nil, err
		}
		if prot, ok = pv.(cborMap); !ok {
			return nil, fail("bad protected header")
		}
	}
	algV, _ := prot.get(1)
	alg, ok := cborInt(algV)
	if !ok {
		return nil, fail("missing COSE algorithm")
	}
	x5, ok := prot.get(33)
	if !ok {
		if x5, ok = unprot.get(33); !ok {
			x5, ok = unprot.get("x5chain")
		}
	}
	if !ok {
		return nil, fail("missing certificate chain")
	}
	var ders [][]byte
	switch x := x5.(type) {
	case []byte:
		ders = [][]byte{x}
	case []any:
		for _, e := range x {
			d, ok := e.([]byte)
			if !ok {
				return nil, fail("bad certificate chain")
			}
			ders = append(ders, d)
		}
	}
	if len(ders) == 0 || len(ders) > MaxChain {
		return nil, fail("bad certificate chain")
	}
	chain := make([]*x509.Certificate, len(ders))
	for i, d := range ders {
		if chain[i], err = x509.ParseCertificate(d); err != nil {
			return nil, fail("bad certificate: %v", err)
		}
	}
	// Sig_structure = ["Signature1", protected, external_aad, payload]
	tbs := []byte{0x84}
	tbs = cborAppendText(tbs, "Signature1")
	tbs = cborAppendBytes(tbs, protRaw)
	tbs = cborAppendBytes(tbs, nil)
	tbs = cborAppendBytes(tbs, payload)

	if err := m.Signature(); err != nil {
		return nil, err
	}
	if !verifySig(alg, chain[0].PublicKey, tbs, signature) {
		return nil, ErrSignature
	}
	return chain, nil
}

func verifySig(alg int64, pub any, msg, sig []byte) bool {
	digest := func(h crypto.Hash) []byte { w := h.New(); w.Write(msg); return w.Sum(nil) }
	switch alg {
	case -7, -35, -36: // ES256, ES384, ES512
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		want := map[int64]elliptic.Curve{-7: elliptic.P256(), -35: elliptic.P384(), -36: elliptic.P521()}[alg]
		hf := map[int64]crypto.Hash{-7: crypto.SHA256, -35: crypto.SHA384, -36: crypto.SHA512}[alg]
		n := (want.Params().BitSize + 7) / 8
		if k.Curve != want || len(sig) != 2*n {
			return false
		}
		r, s := new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])
		return ecdsa.Verify(k, digest(hf), r, s)
	case -37, -38, -39: // PS256, PS384, PS512
		k, ok := pub.(*rsa.PublicKey)
		if !ok || k.N.BitLen() > maxRSABits {
			return false
		}
		hf := map[int64]crypto.Hash{-37: crypto.SHA256, -38: crypto.SHA384, -39: crypto.SHA512}[alg]
		return rsa.VerifyPSS(k, hf, digest(hf), sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
	case -8: // EdDSA
		k, ok := pub.(ed25519.PublicKey)
		return ok && ed25519.Verify(k, msg, sig)
	}
	return false
}

func cborAppendHead(b []byte, major byte, n uint64) []byte {
	switch {
	case n < 24:
		return append(b, major<<5|byte(n))
	case n <= 0xff:
		return append(b, major<<5|24, byte(n))
	case n <= 0xffff:
		return append(b, major<<5|25, byte(n>>8), byte(n))
	case n <= 0xffffffff:
		return append(b, major<<5|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	b = append(b, major<<5|27)
	for i := 7; i >= 0; i-- {
		b = append(b, byte(n>>(8*i)))
	}
	return b
}

func cborAppendBytes(b, v []byte) []byte { return append(cborAppendHead(b, 2, uint64(len(v))), v...) }
func cborAppendText(b []byte, s string) []byte {
	return append(cborAppendHead(b, 3, uint64(len(s))), s...)
}

// checkTrust walks from the signer to a trust anchor. Every certificate on the
// path must be valid at now and not revoked as of now.
func checkTrust(chain []*x509.Certificate, now time.Time, trust TrustStore, m Meter) ([32]byte, error) {
	leaf := chain[0]
	if leaf.IsCA || (leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0) {
		return [32]byte{}, fail("signer certificate not usable for signing")
	}
	cur := leaf
	for depth := 0; depth <= MaxChain; depth++ {
		fp := sha256.Sum256(cur.Raw)
		if eff, revoked := trust.RevokedAt(fp); revoked && uint64(now.Unix()) >= eff {
			return [32]byte{}, ErrRevoked
		}
		if now.Before(cur.NotBefore) || now.After(cur.NotAfter) {
			return [32]byte{}, ErrExpired
		}
		if trust.IsAnchor(fp) {
			return fp, nil
		}
		var next *x509.Certificate
		cands := append([]*x509.Certificate{}, chain[1:]...)
		cands = append(cands, trust.AnchorsBySubject(cur.RawIssuer)...)
		for _, c := range cands {
			if c == cur || bytes.Equal(c.Raw, cur.Raw) || !bytes.Equal(c.RawSubject, cur.RawIssuer) {
				continue
			}
			if err := m.Signature(); err != nil {
				return [32]byte{}, err
			}
			if cur.CheckSignatureFrom(c) == nil {
				next = c
				break
			}
		}
		if next == nil {
			return [32]byte{}, ErrUntrusted
		}
		cur = next
	}
	return [32]byte{}, ErrUntrusted
}
