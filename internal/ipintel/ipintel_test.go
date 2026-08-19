package ipintel

import (
	"net/netip"
	"testing"
)

// fixtureBlob builds a tiny, hand-specified table in the real wire format so
// the core lookup tests are fully deterministic and independent of the fetched
// data blob. It exercises the same Marshal -> Load -> Lookup path production
// uses.
//
// Layout:
//   - 203.0.113.0/24  (TEST-NET-3) -> country ZZ, hosting  (fake "AWS" block)
//   - 198.51.100.0/24 (TEST-NET-2) -> country ZZ, tor exit
//   - 8.8.8.0/24                    -> country US (plain country, no flags)
//   - 2001:db8::/48                 -> country DE, hosting  (v6 hosting)
func fixtureBlob(t *testing.T) []byte {
	t.Helper()
	ranges := []Range{
		{Lo: netip.MustParseAddr("203.0.113.0"), Hi: netip.MustParseAddr("203.0.113.255"), CC: "ZZ", Hosting: true},
		{Lo: netip.MustParseAddr("198.51.100.0"), Hi: netip.MustParseAddr("198.51.100.255"), CC: "ZZ", Tor: true},
		{Lo: netip.MustParseAddr("8.8.8.0"), Hi: netip.MustParseAddr("8.8.8.255"), CC: "US"},
		{Lo: netip.MustParseAddr("2001:db8::"), Hi: netip.MustParseAddr("2001:db8:0:ffff:ffff:ffff:ffff:ffff"), CC: "DE", Hosting: true},
	}
	return Marshal(ranges)
}

func loadFixture(t *testing.T) *DB {
	t.Helper()
	db, err := Load(fixtureBlob(t))
	if err != nil {
		t.Fatalf("Load(fixture): %v", err)
	}
	return db
}

func TestLookupHosting(t *testing.T) {
	db := loadFixture(t)
	got := db.LookupString("203.0.113.42")
	if !got.IsHosting {
		t.Errorf("IsHosting = false, want true (%+v)", got)
	}
	if !got.IsAnonymous {
		t.Errorf("IsAnonymous = false, want true for a hosting IP (%+v)", got)
	}
	if got.IsTor {
		t.Errorf("IsTor = true, want false (%+v)", got)
	}
	if got.IsVPN {
		t.Errorf("IsVPN = true, want false (VPN deferred) (%+v)", got)
	}
	if got.CountryCode != "ZZ" {
		t.Errorf("CountryCode = %q, want %q", got.CountryCode, "ZZ")
	}
}

func TestLookupTor(t *testing.T) {
	db := loadFixture(t)
	got := db.LookupString("198.51.100.7")
	if !got.IsTor {
		t.Errorf("IsTor = false, want true (%+v)", got)
	}
	if !got.IsAnonymous {
		t.Errorf("IsAnonymous = false, want true for a tor exit (%+v)", got)
	}
	if got.IsHosting {
		t.Errorf("IsHosting = true, want false (%+v)", got)
	}
}

func TestLookupCountryOnly(t *testing.T) {
	db := loadFixture(t)
	got := db.LookupString("8.8.8.8")
	if got.CountryCode != "US" {
		t.Errorf("CountryCode = %q, want %q", got.CountryCode, "US")
	}
	if got.IsHosting || got.IsTor || got.IsVPN || got.IsAnonymous {
		t.Errorf("plain country IP should have no flags set: %+v", got)
	}
}

func TestLookupV6Hosting(t *testing.T) {
	db := loadFixture(t)
	got := db.LookupString("2001:db8:0:1::1")
	if got.CountryCode != "DE" {
		t.Errorf("CountryCode = %q, want %q", got.CountryCode, "DE")
	}
	if !got.IsHosting || !got.IsAnonymous {
		t.Errorf("v6 hosting IP: %+v", got)
	}
}

func TestFailOpenUnknownAndPrivate(t *testing.T) {
	db := loadFixture(t)
	cases := []string{
		"10.0.0.1",        // private
		"192.168.1.1",     // private
		"172.16.5.4",      // private
		"127.0.0.1",       // loopback
		"::1",             // v6 loopback
		"fe80::1",         // link-local
		"1.2.3.4",         // valid public but absent from fixture
		"2606:4700::1",    // valid public v6 but absent
		"not-an-ip",       // unparseable
		"",                // empty
		"999.999.999.999", // invalid
	}
	for _, s := range cases {
		got := db.LookupString(s)
		if (got != Info{}) {
			t.Errorf("LookupString(%q) = %+v, want zero Info", s, got)
		}
	}
}

func TestLookupBoundaries(t *testing.T) {
	db := loadFixture(t)
	// First and last address of the hosting block are inside; neighbors are out.
	if !db.LookupString("203.0.113.0").IsHosting {
		t.Error("first address of block should be hosting")
	}
	if !db.LookupString("203.0.113.255").IsHosting {
		t.Error("last address of block should be hosting")
	}
	if (db.LookupString("203.0.112.255") != Info{}) {
		t.Error("address just below block should be zero Info")
	}
	if (db.LookupString("203.0.114.0") != Info{}) {
		t.Error("address just above block should be zero Info")
	}
}

func TestEmptyDB(t *testing.T) {
	db := NewEmpty()
	for _, s := range []string{"8.8.8.8", "203.0.113.42", "2001:db8::1"} {
		if got := db.LookupString(s); (got != Info{}) {
			t.Errorf("empty DB LookupString(%q) = %+v, want zero Info", s, got)
		}
	}
}

func TestLoadCorrupt(t *testing.T) {
	cases := map[string][]byte{
		"too short": {1, 2, 3},
		"bad magic": append([]byte("XXXX"), make([]byte, 12)...),
		"truncated body": func() []byte {
			b := fixtureBlob(t)
			return b[:len(b)-5] // chop the middle of the last record
		}(),
	}
	for name, blob := range cases {
		if _, err := Load(blob); err == nil {
			t.Errorf("Load(%s): expected error, got nil", name)
		}
	}
}

func TestLoadEmptyBlobOK(t *testing.T) {
	// A well-formed header with zero counts is valid and yields an empty DB.
	blob := Marshal(nil)
	db, err := Load(blob)
	if err != nil {
		t.Fatalf("Load(empty): %v", err)
	}
	if got := db.LookupString("8.8.8.8"); (got != Info{}) {
		t.Errorf("empty-blob lookup = %+v, want zero Info", got)
	}
}

func TestReloadHotSwap(t *testing.T) {
	db := NewEmpty()
	if got := db.LookupString("203.0.113.42"); (got != Info{}) {
		t.Fatalf("pre-reload = %+v, want zero", got)
	}
	if err := db.Reload(fixtureBlob(t)); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := db.LookupString("203.0.113.42"); !got.IsHosting {
		t.Errorf("post-reload = %+v, want hosting", got)
	}
	// A bad reload must leave the good table in place.
	if err := db.Reload([]byte("garbage")); err == nil {
		t.Error("Reload(garbage): expected error")
	}
	if got := db.LookupString("203.0.113.42"); !got.IsHosting {
		t.Errorf("after failed reload = %+v, want hosting still", got)
	}
}

// TestEmbeddedBlobSmoke ties the tests to the real fetched data when it is
// present. It skips against the empty placeholder blob so the package builds
// and tests before the generator has ever run.
func TestEmbeddedBlobSmoke(t *testing.T) {
	db, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	s := db.snap.Load()
	if s == nil || (len(s.v4) == 0 && len(s.v6) == 0) {
		t.Skip("embedded blob is empty (generator not yet run); skipping real-data smoke test")
	}

	// Stable, long-lived allocations with a known registration country. Any
	// single RIR mirror can be slow and get skipped by the generator, so every
	// address that resolves must resolve correctly and at least one must resolve.
	wellKnown := []struct {
		ip, cc, who string
	}{
		{"8.8.8.8", "US", "Google DNS (ARIN)"},
		{"133.11.1.1", "JP", "University of Tokyo (APNIC)"},
		{"193.0.6.139", "NL", "RIPE NCC (RIPE)"},
	}
	resolved := 0
	for _, w := range wellKnown {
		got := db.LookupString(w.ip)
		if got.CountryCode == "" {
			continue // that RIR may have been skipped this run
		}
		resolved++
		if got.CountryCode != w.cc {
			t.Errorf("%s (%s): CountryCode = %q, want %q", w.ip, w.who, got.CountryCode, w.cc)
		}
		if got.IsTor {
			t.Errorf("%s flagged as Tor exit; implausible: %+v", w.ip, got)
		}
	}
	if resolved == 0 {
		t.Error("no well-known IP resolved to a country; the country table looks empty")
	}

	// A private address must still fail open even against the full table.
	if p := db.LookupString("10.1.2.3"); (p != Info{}) {
		t.Errorf("private IP against real blob = %+v, want zero Info", p)
	}
}
