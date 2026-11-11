// Package c2pa parses and verifies C2PA manifest stores (Content Credentials)
// for the content authenticity precompile. It has no dependencies outside the
// Go standard library so every node evaluates manifests identically.
package c2pa

import (
	"encoding/binary"
	"errors"
	"math"
)

// Minimal CBOR (RFC 8949) decoder covering what C2PA claims, assertions and
// COSE_Sign1 structures use. Maps keep their entry order.

const cborMaxDepth = 32

var errCBOR = errors.New("c2pa: malformed CBOR")

type cborTag struct {
	Num uint64
	Val any
}

type cborPair struct {
	Key any
	Val any
}

type cborMap []cborPair

type cborSimple uint8

// Value types: uint64, int64 (negative), []byte, string, []any, cborMap,
// cborTag, bool, nil, cborSimple, float64.

func cborDecode(b []byte) (any, error) {
	v, n, err := cborItem(b, 0)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, errCBOR
	}
	return v, nil
}

func cborHead(b []byte) (major byte, arg uint64, info byte, n int, err error) {
	if len(b) < 1 {
		return 0, 0, 0, 0, errCBOR
	}
	major, info = b[0]>>5, b[0]&0x1f
	switch {
	case info < 24:
		return major, uint64(info), info, 1, nil
	case info == 24:
		if len(b) < 2 {
			return 0, 0, 0, 0, errCBOR
		}
		return major, uint64(b[1]), info, 2, nil
	case info == 25:
		if len(b) < 3 {
			return 0, 0, 0, 0, errCBOR
		}
		return major, uint64(binary.BigEndian.Uint16(b[1:])), info, 3, nil
	case info == 26:
		if len(b) < 5 {
			return 0, 0, 0, 0, errCBOR
		}
		return major, uint64(binary.BigEndian.Uint32(b[1:])), info, 5, nil
	case info == 27:
		if len(b) < 9 {
			return 0, 0, 0, 0, errCBOR
		}
		return major, binary.BigEndian.Uint64(b[1:]), info, 9, nil
	case info == 31:
		return major, 0, info, 1, nil // indefinite length
	}
	return 0, 0, 0, 0, errCBOR
}

func cborItem(b []byte, depth int) (any, int, error) {
	if depth > cborMaxDepth {
		return nil, 0, errCBOR
	}
	major, arg, info, n, err := cborHead(b)
	if err != nil {
		return nil, 0, err
	}
	indef := info == 31
	switch major {
	case 0:
		if indef {
			return nil, 0, errCBOR
		}
		return arg, n, nil
	case 1:
		if indef || arg > math.MaxInt64 {
			return nil, 0, errCBOR
		}
		return -1 - int64(arg), n, nil
	case 2, 3:
		var out []byte
		if indef {
			for {
				if n >= len(b) {
					return nil, 0, errCBOR
				}
				if b[n] == 0xff {
					n++
					break
				}
				m, a, inf, hn, err := cborHead(b[n:])
				if err != nil || m != major || inf == 31 || a > uint64(len(b)-n-hn) {
					return nil, 0, errCBOR
				}
				out = append(out, b[n+hn:n+hn+int(a)]...)
				n += hn + int(a)
			}
		} else {
			if arg > uint64(len(b)-n) {
				return nil, 0, errCBOR
			}
			out = b[n : n+int(arg)]
			n += int(arg)
		}
		if major == 3 {
			return string(out), n, nil
		}
		if out == nil {
			out = []byte{}
		}
		return out, n, nil
	case 4:
		var arr []any
		for i := uint64(0); indef || i < arg; i++ {
			if indef {
				if n >= len(b) {
					return nil, 0, errCBOR
				}
				if b[n] == 0xff {
					n++
					break
				}
			}
			if n >= len(b) {
				return nil, 0, errCBOR
			}
			v, m, err := cborItem(b[n:], depth+1)
			if err != nil {
				return nil, 0, err
			}
			arr = append(arr, v)
			n += m
		}
		return arr, n, nil
	case 5:
		var mp cborMap
		for i := uint64(0); indef || i < arg; i++ {
			if indef {
				if n >= len(b) {
					return nil, 0, errCBOR
				}
				if b[n] == 0xff {
					n++
					break
				}
			}
			if n >= len(b) {
				return nil, 0, errCBOR
			}
			k, m, err := cborItem(b[n:], depth+1)
			if err != nil {
				return nil, 0, err
			}
			n += m
			if n >= len(b) {
				return nil, 0, errCBOR
			}
			v, m2, err := cborItem(b[n:], depth+1)
			if err != nil {
				return nil, 0, err
			}
			n += m2
			mp = append(mp, cborPair{Key: k, Val: v})
		}
		return mp, n, nil
	case 6:
		if indef || n >= len(b) {
			return nil, 0, errCBOR
		}
		v, m, err := cborItem(b[n:], depth+1)
		if err != nil {
			return nil, 0, err
		}
		return cborTag{Num: arg, Val: v}, n + m, nil
	case 7:
		switch info {
		case 20:
			return false, n, nil
		case 21:
			return true, n, nil
		case 22, 23:
			return nil, n, nil
		case 25:
			return float64(halfToFloat(uint16(arg))), n, nil
		case 26:
			return float64(math.Float32frombits(uint32(arg))), n, nil
		case 27:
			return math.Float64frombits(arg), n, nil
		case 31:
			return nil, 0, errCBOR // stray break
		}
		return cborSimple(arg), n, nil
	}
	return nil, 0, errCBOR
}

func halfToFloat(h uint16) float32 {
	sign := uint32(h>>15) << 31
	exp := uint32(h>>10) & 0x1f
	frac := uint32(h) & 0x3ff
	switch exp {
	case 0:
		f := float32(frac) / 1024 / 16384
		if sign != 0 {
			return -f
		}
		return f
	case 31:
		return math.Float32frombits(sign | 0x7f800000 | frac<<13)
	}
	return math.Float32frombits(sign | (exp+112)<<23 | frac<<13)
}

// get returns the value for a text or integer key.
func (m cborMap) get(key any) (any, bool) {
	for _, p := range m {
		switch k := key.(type) {
		case string:
			if s, ok := p.Key.(string); ok && s == k {
				return p.Val, true
			}
		case int:
			switch pk := p.Key.(type) {
			case uint64:
				if k >= 0 && pk == uint64(k) {
					return p.Val, true
				}
			case int64:
				if pk == int64(k) {
					return p.Val, true
				}
			}
		}
	}
	return nil, false
}

func (m cborMap) str(key string) string {
	v, _ := m.get(key)
	s, _ := v.(string)
	return s
}

func (m cborMap) bytes(key any) []byte {
	v, _ := m.get(key)
	b, _ := v.([]byte)
	return b
}

func cborInt(v any) (int64, bool) {
	switch x := v.(type) {
	case uint64:
		if x > math.MaxInt64 {
			return 0, false
		}
		return int64(x), true
	case int64:
		return x, true
	}
	return 0, false
}
