package ipintel

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
)

// Binary blob format (little-endian throughout), version 1:
//
//	Header (16 bytes):
//	  magic    [4]byte = "V42I"
//	  version  uint8   = 1
//	  reserved [3]byte = 0
//	  v4count  uint32
//	  v6count  uint32
//	Then v4count v4 records (11 bytes each), sorted by start ascending:
//	  start uint32   inclusive
//	  end   uint32   inclusive
//	  cc    [2]byte  ISO alpha-2 uppercase, or {0,0} for none
//	  flags uint8    bit0 hosting, bit1 tor
//	Then v6count v6 records (35 bytes each), sorted by (startHi,startLo):
//	  startHi uint64
//	  startLo uint64
//	  endHi   uint64
//	  endLo   uint64
//	  cc      [2]byte
//	  flags   uint8
//
// The generator guarantees the records are sorted and non-overlapping; decode
// re-sorts defensively so a hand-built or slightly out-of-order blob still
// yields correct binary-search results.
const (
	blobVersion = 1
	headerLen   = 16
	v4RecLen    = 11
	v6RecLen    = 35

	flagHosting uint8 = 1 << 0
	flagTor     uint8 = 1 << 1
)

var blobMagic = [4]byte{'V', '4', '2', 'I'}

// Errors returned by Load/decode for a structurally corrupt blob.
var (
	ErrBadMagic   = errors.New("ipintel: bad magic")
	ErrBadVersion = errors.New("ipintel: unsupported version")
	ErrTruncated  = errors.New("ipintel: truncated blob")
)

type v4Range struct {
	start uint32
	end   uint32
	cc    [2]byte
	flags uint8
}

type v6Range struct {
	startHi, startLo uint64
	endHi, endLo     uint64
	cc               [2]byte
	flags            uint8
}

// Range is a source interval used to build a blob in Go (tests, and any future
// in-process generator). Lo and Hi are inclusive and must be the same family.
type Range struct {
	Lo, Hi  netip.Addr
	CC      string // ISO alpha-2; anything not exactly two ASCII letters stores as none
	Hosting bool
	Tor     bool
}

func encodeCC(cc string) [2]byte {
	var out [2]byte
	if len(cc) != 2 {
		return out
	}
	a, b := cc[0], cc[1]
	// Normalize to uppercase; reject non-letters (leaves {0,0} = none).
	up := func(c byte) (byte, bool) {
		switch {
		case c >= 'A' && c <= 'Z':
			return c, true
		case c >= 'a' && c <= 'z':
			return c - 32, true
		default:
			return 0, false
		}
	}
	ua, oka := up(a)
	ub, okb := up(b)
	if !oka || !okb {
		return out
	}
	out[0], out[1] = ua, ub
	return out
}

func flagsFor(hosting, tor bool) uint8 {
	var f uint8
	if hosting {
		f |= flagHosting
	}
	if tor {
		f |= flagTor
	}
	return f
}

// Marshal serializes ranges into the binary blob format. It is the Go
// reference encoder used by tests; the shipped blob is produced by the Python
// generator, which writes the identical wire format. Ranges of the wrong shape
// (invalid, mismatched family, or Hi < Lo) are skipped.
func Marshal(ranges []Range) []byte {
	var v4 []v4Range
	var v6 []v6Range
	for _, r := range ranges {
		if !r.Lo.IsValid() || !r.Hi.IsValid() {
			continue
		}
		lo := r.Lo.Unmap()
		hi := r.Hi.Unmap()
		if lo.Is4() != hi.Is4() {
			continue
		}
		cc := encodeCC(r.CC)
		fl := flagsFor(r.Hosting, r.Tor)
		if lo.Is4() {
			s := beU32(lo.As4())
			e := beU32(hi.As4())
			if e < s {
				continue
			}
			v4 = append(v4, v4Range{start: s, end: e, cc: cc, flags: fl})
		} else {
			sh, sl := as128(lo)
			eh, el := as128(hi)
			if less128(eh, el, sh, sl) {
				continue
			}
			v6 = append(v6, v6Range{startHi: sh, startLo: sl, endHi: eh, endLo: el, cc: cc, flags: fl})
		}
	}
	slices.SortFunc(v4, cmpV4)
	slices.SortFunc(v6, cmpV6)

	out := make([]byte, headerLen+len(v4)*v4RecLen+len(v6)*v6RecLen)
	copy(out[0:4], blobMagic[:])
	out[4] = blobVersion
	binary.LittleEndian.PutUint32(out[8:12], uint32(len(v4)))  // #nosec G115 -- range count is bounded by the RIR/prefix data, far below uint32 max
	binary.LittleEndian.PutUint32(out[12:16], uint32(len(v6))) // #nosec G115 -- range count is bounded by the RIR/prefix data, far below uint32 max
	off := headerLen
	for _, r := range v4 {
		binary.LittleEndian.PutUint32(out[off:off+4], r.start)
		binary.LittleEndian.PutUint32(out[off+4:off+8], r.end)
		out[off+8] = r.cc[0]
		out[off+9] = r.cc[1]
		out[off+10] = r.flags
		off += v4RecLen
	}
	for _, r := range v6 {
		binary.LittleEndian.PutUint64(out[off:off+8], r.startHi)
		binary.LittleEndian.PutUint64(out[off+8:off+16], r.startLo)
		binary.LittleEndian.PutUint64(out[off+16:off+24], r.endHi)
		binary.LittleEndian.PutUint64(out[off+24:off+32], r.endLo)
		out[off+32] = r.cc[0]
		out[off+33] = r.cc[1]
		out[off+34] = r.flags
		off += v6RecLen
	}
	return out
}

// decode parses a blob into a snapshot, returning an error only for structural
// corruption. An empty (headers, zero counts) blob decodes to an empty snapshot.
func decode(blob []byte) (*snapshot, error) {
	if len(blob) < headerLen {
		return nil, ErrTruncated
	}
	if [4]byte(blob[0:4]) != blobMagic {
		return nil, ErrBadMagic
	}
	if blob[4] != blobVersion {
		return nil, ErrBadVersion
	}
	v4n := int(binary.LittleEndian.Uint32(blob[8:12]))
	v6n := int(binary.LittleEndian.Uint32(blob[12:16]))
	want := headerLen + v4n*v4RecLen + v6n*v6RecLen
	if len(blob) < want {
		return nil, ErrTruncated
	}

	s := &snapshot{
		v4: make([]v4Range, v4n),
		v6: make([]v6Range, v6n),
	}
	off := headerLen
	for i := 0; i < v4n; i++ {
		s.v4[i] = v4Range{
			start: binary.LittleEndian.Uint32(blob[off : off+4]),
			end:   binary.LittleEndian.Uint32(blob[off+4 : off+8]),
			cc:    [2]byte{blob[off+8], blob[off+9]},
			flags: blob[off+10],
		}
		off += v4RecLen
	}
	for i := 0; i < v6n; i++ {
		s.v6[i] = v6Range{
			startHi: binary.LittleEndian.Uint64(blob[off : off+8]),
			startLo: binary.LittleEndian.Uint64(blob[off+8 : off+16]),
			endHi:   binary.LittleEndian.Uint64(blob[off+16 : off+24]),
			endLo:   binary.LittleEndian.Uint64(blob[off+24 : off+32]),
			cc:      [2]byte{blob[off+32], blob[off+33]},
			flags:   blob[off+34],
		}
		off += v6RecLen
	}
	// Defensive: binary search requires sorted-by-start order.
	if !slices.IsSortedFunc(s.v4, cmpV4) {
		slices.SortFunc(s.v4, cmpV4)
	}
	if !slices.IsSortedFunc(s.v6, cmpV6) {
		slices.SortFunc(s.v6, cmpV6)
	}
	return s, nil
}

func cmpV4(a, b v4Range) int {
	switch {
	case a.start < b.start:
		return -1
	case a.start > b.start:
		return 1
	default:
		return 0
	}
}

func cmpV6(a, b v6Range) int {
	if a.startHi != b.startHi {
		if a.startHi < b.startHi {
			return -1
		}
		return 1
	}
	switch {
	case a.startLo < b.startLo:
		return -1
	case a.startLo > b.startLo:
		return 1
	default:
		return 0
	}
}

// beU32 reads a 4-byte IPv4 address as a big-endian (network-order) uint32.
func beU32(b [4]byte) uint32 { return binary.BigEndian.Uint32(b[:]) }

// as128 splits a 16-byte address into big-endian high and low uint64 halves.
func as128(ip netip.Addr) (hi, lo uint64) {
	b := ip.As16()
	return binary.BigEndian.Uint64(b[0:8]), binary.BigEndian.Uint64(b[8:16])
}

// less128 reports whether (aHi,aLo) < (bHi,bLo) as an unsigned 128-bit value.
func less128(aHi, aLo, bHi, bLo uint64) bool {
	if aHi != bHi {
		return aHi < bHi
	}
	return aLo < bLo
}
