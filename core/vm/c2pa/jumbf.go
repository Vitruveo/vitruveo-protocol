package c2pa

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// JUMBF (ISO/IEC 19566-5) box parsing.

var errJUMBF = errors.New("c2pa: malformed JUMBF")

const jumbfMaxDepth = 16

type box struct {
	Type    string
	Raw     []byte // entire box including header
	Payload []byte // box content after the header

	// superbox ('jumb') fields
	Label    string
	UUID     []byte
	Children []*box // content boxes after the description box
}

// parseBoxes splits b into consecutive boxes.
func parseBoxes(b []byte, depth int) ([]*box, error) {
	if depth > jumbfMaxDepth {
		return nil, errJUMBF
	}
	var out []*box
	for len(b) > 0 {
		if len(b) < 8 {
			return nil, errJUMBF
		}
		size := uint64(binary.BigEndian.Uint32(b))
		typ := string(b[4:8])
		hdr := uint64(8)
		switch size {
		case 0:
			size = uint64(len(b))
		case 1:
			if len(b) < 16 {
				return nil, errJUMBF
			}
			size, hdr = binary.BigEndian.Uint64(b[8:]), 16
		}
		if size < hdr || size > uint64(len(b)) {
			return nil, errJUMBF
		}
		bx := &box{Type: typ, Raw: b[:size], Payload: b[hdr:size]}
		if typ == "jumb" {
			if err := bx.parseSuper(depth); err != nil {
				return nil, err
			}
		}
		out = append(out, bx)
		b = b[size:]
	}
	return out, nil
}

func (bx *box) parseSuper(depth int) error {
	kids, err := parseBoxes(bx.Payload, depth+1)
	if err != nil {
		return err
	}
	if len(kids) == 0 || kids[0].Type != "jumd" {
		return errJUMBF
	}
	d := kids[0].Payload
	if len(d) < 17 {
		return errJUMBF
	}
	bx.UUID = d[:16]
	toggles := d[16]
	if toggles&0x02 != 0 {
		end := bytes.IndexByte(d[17:], 0)
		if end < 0 {
			return errJUMBF
		}
		bx.Label = string(d[17 : 17+end])
	}
	bx.Children = kids[1:]
	return nil
}

// child returns the first child superbox with the given label.
func (bx *box) child(label string) *box {
	for _, c := range bx.Children {
		if c.Type == "jumb" && c.Label == label {
			return c
		}
	}
	return nil
}

// content returns the first content box of the given type ('cbor', 'json', ...).
func (bx *box) content(typ string) *box {
	for _, c := range bx.Children {
		if c.Type == typ {
			return c
		}
	}
	return nil
}

// ExtractJPEG returns the C2PA manifest store embedded in a JPEG (APP11 JUMBF
// segments) and the byte range those segments occupy, which is the exclusion
// a c2pa.hash.data assertion uses.
func ExtractJPEG(file []byte) (store []byte, start, length uint64, err error) {
	if len(file) < 4 || file[0] != 0xff || file[1] != 0xd8 {
		return nil, 0, 0, errors.New("c2pa: not a JPEG")
	}
	pos, first, last := 2, -1, -1
	for pos+4 <= len(file) {
		if file[pos] != 0xff {
			return nil, 0, 0, errors.New("c2pa: bad JPEG marker")
		}
		marker := file[pos+1]
		if marker == 0xda || marker == 0xd9 { // start of scan / end of image
			break
		}
		if marker == 0x01 || (marker >= 0xd0 && marker <= 0xd7) || marker == 0xff {
			pos += 2
			continue
		}
		segLen := int(binary.BigEndian.Uint16(file[pos+2:]))
		if segLen < 2 || pos+2+segLen > len(file) {
			return nil, 0, 0, errors.New("c2pa: bad JPEG segment")
		}
		seg := file[pos+4 : pos+2+segLen]
		// APP11: "JP" CI, En(2), Z(4), then box header (LBox, TBox) and payload
		if marker == 0xeb && len(seg) >= 16 && seg[0] == 'J' && seg[1] == 'P' && string(seg[12:16]) == "jumb" {
			if first < 0 {
				store = append(store, seg[8:]...)
				first = pos
			} else {
				store = append(store, seg[16:]...)
			}
			last = pos + 2 + segLen
		}
		pos += 2 + segLen
	}
	if first < 0 {
		return nil, 0, 0, errors.New("c2pa: no manifest store")
	}
	return store, uint64(first), uint64(last - first), nil
}

// ExtractPNG returns the C2PA manifest store embedded in a PNG ('caBX' chunk)
// and the byte range of that chunk.
func ExtractPNG(file []byte) (store []byte, start, length uint64, err error) {
	sig := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}
	if !bytes.HasPrefix(file, sig) {
		return nil, 0, 0, errors.New("c2pa: not a PNG")
	}
	pos := len(sig)
	for pos+12 <= len(file) {
		n := int(binary.BigEndian.Uint32(file[pos:]))
		if n < 0 || pos+12+n > len(file) {
			return nil, 0, 0, errors.New("c2pa: bad PNG chunk")
		}
		if string(file[pos+4:pos+8]) == "caBX" {
			return file[pos+8 : pos+8+n], uint64(pos), uint64(12 + n), nil
		}
		pos += 12 + n
	}
	return nil, 0, 0, errors.New("c2pa: no manifest store")
}
