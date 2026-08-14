package ipintel

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// These tests close the coverage gaps in the encode/decode/lookup helpers that
// the fixture-driven tests in ipintel_test.go do not reach: the country-code
// normaliser's reject paths, the Marshal skip branches for malformed ranges, the
// unsupported-version and re-sort branches in decode, the raw comparators, and
// the file-override arm of Default. They exercise the real wire format the
// generator writes and the same code paths production takes.

// ---------------------------------------------------------------------------
// encodeCC: normalisation and the reject paths
// ---------------------------------------------------------------------------

func TestEncodeCC(t *testing.T) {
	cases := []struct {
		in   string
		want [2]byte
	}{
		{"ZZ", [2]byte{'Z', 'Z'}}, // already uppercase
		{"us", [2]byte{'U', 'S'}}, // lowercase -> uppercased
		{"De", [2]byte{'D', 'E'}}, // mixed case
		{"", [2]byte{}},           // length 0 -> none
		{"U", [2]byte{}},          // length 1 -> none
		{"USA", [2]byte{}},        // length 3 -> none
		{"U1", [2]byte{}},         // second char not a letter -> none
		{"1Z", [2]byte{}},         // first char not a letter -> none
		{"--", [2]byte{}},         // neither a letter -> none
	}
	for _, c := range cases {
		if got := encodeCC(c.in); got != c.want {
			t.Errorf("encodeCC(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Marshal: every malformed range is skipped, not encoded
// ---------------------------------------------------------------------------

func TestMarshalSkipsMalformedRanges(t *testing.T) {
	mustAddr := func(s string) netip.Addr {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("parse %s: %v", s, err)
		}
		return a
	}
	bad := []Range{
		{},                                                             // invalid (zero) Lo/Hi
		{Lo: mustAddr("1.1.1.0"), Hi: mustAddr("2001:db8::")},          // mismatched family (v4 lo, v6 hi)
		{Lo: mustAddr("1.1.1.255"), Hi: mustAddr("1.1.1.0"), CC: "AA"}, // v4 Hi < Lo
		{Lo: mustAddr("2001:db8::ffff"), Hi: mustAddr("2001:db8::")},   // v6 Hi < Lo
	}
	blob := Marshal(bad)

	// Header is present; both counts are zero because every range was skipped.
	if len(blob) != headerLen {
		t.Fatalf("Marshal encoded %d bytes for all-malformed input, want a bare %d-byte header", len(blob), headerLen)
	}
	if v4n := binary.LittleEndian.Uint32(blob[8:12]); v4n != 0 {
		t.Errorf("v4 count = %d, want 0", v4n)
	}
	if v6n := binary.LittleEndian.Uint32(blob[12:16]); v6n != 0 {
		t.Errorf("v6 count = %d, want 0", v6n)
	}

	db, err := Load(blob)
	if err != nil {
		t.Fatalf("Load(all-skipped blob): %v", err)
	}
	for _, s := range []string{"1.1.1.0", "2001:db8::1"} {
		if got := db.LookupString(s); (got != Info{}) {
			t.Errorf("LookupString(%q) = %+v, want zero Info (nothing was encoded)", s, got)
		}
	}
}

// ---------------------------------------------------------------------------
// decode: unsupported version and the defensive re-sort
// ---------------------------------------------------------------------------

func TestLoadRejectsUnsupportedVersion(t *testing.T) {
	blob := Marshal([]Range{
		{Lo: netip.MustParseAddr("1.1.1.0"), Hi: netip.MustParseAddr("1.1.1.255"), CC: "AA"},
	})
	blob[4] = blobVersion + 1 // bump the version byte past what decode accepts
	if _, err := Load(blob); err != ErrBadVersion {
		t.Fatalf("Load(bad version) error = %v, want ErrBadVersion", err)
	}
}

// buildRawBlob writes records in exactly the given order WITHOUT sorting, so a
// deliberately out-of-order table can be handed to decode. Marshal always sorts,
// so this is the only way to drive decode's re-sort branch.
func buildRawBlob(v4 []v4Range, v6 []v6Range) []byte {
	out := make([]byte, headerLen+len(v4)*v4RecLen+len(v6)*v6RecLen)
	copy(out[0:4], blobMagic[:])
	out[4] = blobVersion
	binary.LittleEndian.PutUint32(out[8:12], uint32(len(v4)))
	binary.LittleEndian.PutUint32(out[12:16], uint32(len(v6)))
	off := headerLen
	for _, r := range v4 {
		binary.LittleEndian.PutUint32(out[off:off+4], r.start)
		binary.LittleEndian.PutUint32(out[off+4:off+8], r.end)
		out[off+8], out[off+9], out[off+10] = r.cc[0], r.cc[1], r.flags
		off += v4RecLen
	}
	for _, r := range v6 {
		binary.LittleEndian.PutUint64(out[off:off+8], r.startHi)
		binary.LittleEndian.PutUint64(out[off+8:off+16], r.startLo)
		binary.LittleEndian.PutUint64(out[off+16:off+24], r.endHi)
		binary.LittleEndian.PutUint64(out[off+24:off+32], r.endLo)
		out[off+32], out[off+33], out[off+34] = r.cc[0], r.cc[1], r.flags
		off += v6RecLen
	}
	return out
}

func TestDecodeReSortsOutOfOrderRecords(t *testing.T) {
	a4 := netip.MustParseAddr("1.1.1.0").As4()
	a4end := netip.MustParseAddr("1.1.1.255").As4()
	b4 := netip.MustParseAddr("8.8.8.0").As4()
	b4end := netip.MustParseAddr("8.8.8.255").As4()
	// v4 records supplied high-start-first, i.e. NOT sorted by start.
	v4 := []v4Range{
		{start: beU32(b4), end: beU32(b4end), cc: [2]byte{'B', 'B'}},
		{start: beU32(a4), end: beU32(a4end), cc: [2]byte{'A', 'A'}},
	}

	cHi, cLo := as128(netip.MustParseAddr("2001:db8:1::"))
	cEHi, cELo := as128(netip.MustParseAddr("2001:db8:1:ffff:ffff:ffff:ffff:ffff"))
	dHi, dLo := as128(netip.MustParseAddr("2001:db8:2::"))
	dEHi, dELo := as128(netip.MustParseAddr("2001:db8:2:ffff:ffff:ffff:ffff:ffff"))
	// v6 records supplied high-start-first, i.e. NOT sorted.
	v6 := []v6Range{
		{startHi: dHi, startLo: dLo, endHi: dEHi, endLo: dELo, cc: [2]byte{'D', 'D'}},
		{startHi: cHi, startLo: cLo, endHi: cEHi, endLo: cELo, cc: [2]byte{'C', 'C'}},
	}

	db, err := Load(buildRawBlob(v4, v6))
	if err != nil {
		t.Fatalf("Load(unsorted blob): %v", err)
	}

	// Binary search is only correct if decode re-sorted; a wrong lookup here means
	// the re-sort branch did not run.
	for _, c := range []struct{ ip, cc string }{
		{"1.1.1.9", "AA"},
		{"8.8.8.9", "BB"},
		{"2001:db8:1::5", "CC"},
		{"2001:db8:2::5", "DD"},
	} {
		if got := db.LookupString(c.ip); got.CountryCode != c.cc {
			t.Errorf("LookupString(%q) CountryCode = %q, want %q (decode did not re-sort)", c.ip, got.CountryCode, c.cc)
		}
	}
}

// ---------------------------------------------------------------------------
// Raw comparators and the 128-bit less-than, exercised directly so every arm is
// covered independently of whatever order a sort happens to compare in.
// ---------------------------------------------------------------------------

func TestComparators(t *testing.T) {
	if got := cmpV4(v4Range{start: 1}, v4Range{start: 2}); got != -1 {
		t.Errorf("cmpV4 less = %d, want -1", got)
	}
	if got := cmpV4(v4Range{start: 2}, v4Range{start: 1}); got != 1 {
		t.Errorf("cmpV4 greater = %d, want 1", got)
	}
	if got := cmpV4(v4Range{start: 5}, v4Range{start: 5}); got != 0 {
		t.Errorf("cmpV4 equal = %d, want 0", got)
	}

	if got := cmpV6(v6Range{startHi: 1}, v6Range{startHi: 2}); got != -1 {
		t.Errorf("cmpV6 hi less = %d, want -1", got)
	}
	if got := cmpV6(v6Range{startHi: 2}, v6Range{startHi: 1}); got != 1 {
		t.Errorf("cmpV6 hi greater = %d, want 1", got)
	}
	if got := cmpV6(v6Range{startHi: 1, startLo: 1}, v6Range{startHi: 1, startLo: 2}); got != -1 {
		t.Errorf("cmpV6 lo less = %d, want -1", got)
	}
	if got := cmpV6(v6Range{startHi: 1, startLo: 2}, v6Range{startHi: 1, startLo: 1}); got != 1 {
		t.Errorf("cmpV6 lo greater = %d, want 1", got)
	}
	if got := cmpV6(v6Range{startHi: 1, startLo: 1}, v6Range{startHi: 1, startLo: 1}); got != 0 {
		t.Errorf("cmpV6 equal = %d, want 0", got)
	}

	if !less128(1, 2, 1, 3) { // equal high, low 2 < 3
		t.Error("less128(1,2,1,3) = false, want true")
	}
	if less128(1, 3, 1, 2) { // equal high, low 3 !< 2
		t.Error("less128(1,3,1,2) = true, want false")
	}
	if !less128(1, 9, 2, 0) { // high 1 < 2 regardless of low
		t.Error("less128(1,9,2,0) = false, want true")
	}
}

// ---------------------------------------------------------------------------
// Lookup: invalid address and a nil snapshot both fail open
// ---------------------------------------------------------------------------

func TestLookupInvalidAddressAndNilSnapshot(t *testing.T) {
	db := loadFixture(t)
	if got := db.Lookup(netip.Addr{}); (got != Info{}) { // invalid addr -> fail open
		t.Errorf("Lookup(invalid) = %+v, want zero Info", got)
	}

	// A DB whose snapshot pointer was never set (the zero value) must fail open
	// rather than panic: the global-address guards pass, then snap.Load() is nil.
	var empty DB
	if got := empty.Lookup(netip.MustParseAddr("8.8.8.8")); (got != Info{}) {
		t.Errorf("Lookup on a nil-snapshot DB = %+v, want zero Info", got)
	}
}

// ---------------------------------------------------------------------------
// Default: a valid VAULT_IPINTEL_DATA override replaces the embedded blob
// ---------------------------------------------------------------------------

func TestDefaultPrefersValidOverride(t *testing.T) {
	blob := Marshal([]Range{
		{Lo: netip.MustParseAddr("9.9.9.0"), Hi: netip.MustParseAddr("9.9.9.255"), CC: "XX", Hosting: true},
	})
	path := filepath.Join(t.TempDir(), "override.bin")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("write override: %v", err)
	}
	t.Setenv(EnvDataPath, path)

	db, err := Default()
	if err != nil {
		t.Fatalf("Default with override: %v", err)
	}
	got := db.LookupString("9.9.9.9")
	if got.CountryCode != "XX" || !got.IsHosting {
		t.Fatalf("override table not loaded: %+v", got)
	}
	// A code that is only in the override and not in the embedded blob proves the
	// override, not the embedded default, answered.
	if got := db.LookupString("8.8.8.8"); got.CountryCode == "US" {
		t.Errorf("Default served the embedded blob despite a valid override: %+v", got)
	}
}

// TestDefaultFallsBackFromUnusableOverride covers the fall-through arms: an
// override path that cannot be read, and one that reads but does not decode,
// both degrade to the embedded blob rather than failing.
func TestDefaultFallsBackFromUnusableOverride(t *testing.T) {
	t.Run("unreadable path", func(t *testing.T) {
		t.Setenv(EnvDataPath, filepath.Join(t.TempDir(), "does-not-exist.bin"))
		if _, err := Default(); err != nil {
			t.Fatalf("Default with a missing override should fall back, got %v", err)
		}
	})
	t.Run("undecodable file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "garbage.bin")
		if err := os.WriteFile(path, []byte("not a blob"), 0o600); err != nil {
			t.Fatalf("write garbage: %v", err)
		}
		t.Setenv(EnvDataPath, path)
		if _, err := Default(); err != nil {
			t.Fatalf("Default with a corrupt override should fall back, got %v", err)
		}
	})
}
