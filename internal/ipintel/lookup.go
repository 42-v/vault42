package ipintel

import (
	"net/netip"
	"sort"
	"strings"
)

// Lookup resolves an address to its Info. It never returns an error and never
// blocks. Invalid, private, loopback, link-local, multicast, or unallocated
// addresses fail open to the zero Info. O(log n) binary search over the sorted,
// non-overlapping range table.
func (d *DB) Lookup(ip netip.Addr) Info {
	if !ip.IsValid() {
		return Info{}
	}
	ip = ip.Unmap()
	// Fail-open on any non-global address: these never appear in the table and
	// must not be reported as a country or as infrastructure.
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return Info{}
	}
	s := d.snap.Load()
	if s == nil {
		return Info{}
	}
	if ip.Is4() {
		return s.lookupV4(beU32(ip.As4()))
	}
	hi, lo := as128(ip)
	return s.lookupV6(hi, lo)
}

// LookupString parses s and looks it up. An unparseable string fails open to
// the zero Info.
func (d *DB) LookupString(s string) Info {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return Info{}
	}
	return d.Lookup(ip)
}

func (s *snapshot) lookupV4(ip uint32) Info {
	r := s.v4
	// Rightmost range whose start <= ip.
	i := sort.Search(len(r), func(i int) bool { return r[i].start > ip })
	if i == 0 {
		return Info{}
	}
	e := r[i-1]
	if ip <= e.end {
		return infoFrom(e.cc, e.flags)
	}
	return Info{}
}

func (s *snapshot) lookupV6(hi, lo uint64) Info {
	r := s.v6
	i := sort.Search(len(r), func(i int) bool {
		return less128(hi, lo, r[i].startHi, r[i].startLo)
	})
	if i == 0 {
		return Info{}
	}
	e := r[i-1]
	// ip <= end  ==  !(end < ip)
	if !less128(e.endHi, e.endLo, hi, lo) {
		return infoFrom(e.cc, e.flags)
	}
	return Info{}
}

func infoFrom(cc [2]byte, flags uint8) Info {
	var info Info
	if cc[0] != 0 && cc[1] != 0 {
		info.CountryCode = string(cc[:])
	}
	info.IsHosting = flags&flagHosting != 0
	info.IsTor = flags&flagTor != 0
	info.IsVPN = false // deferred: precise VPN detection needs a paid data feed
	info.IsAnonymous = info.IsTor || info.IsHosting || info.IsVPN
	return info
}
