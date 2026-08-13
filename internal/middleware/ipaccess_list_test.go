package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// blockedThrough reports whether the IPAccess middleware refuses a request from
// this address. Exercising the real middleware rather than an internal helper is
// the point: the blocklist is only worth anything if a request actually stops.
func blockedThrough(t *testing.T, ip string) bool {
	t.Helper()
	reached := false
	h := IPAccess()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	req.RemoteAddr = ip + ":51000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return !reached && rec.Code == http.StatusForbidden
}

// The blocklist is a live security control: an operator adds an address to it
// while an attack is in progress. These are the edges where a silent no-op leaves
// the caller believing an address is blocked when it is not.
func TestIPBlocklist_AddAndRemove(t *testing.T) {
	// This test asserts that one address is blocked and its neighbour is not, so
	// it needs the geo lists clear: a geo allowlist left set by an earlier test
	// denies every request, and "blocked" then reads true for both.
	resetIPAccess()

	t.Cleanup(func() {
		RemoveFromIPBlocklist("198.51.100.7/32", "2001:db8::1/128", "203.0.113.0/24")
	})

	t.Run("a bare address is normalised to a host route and blocks", func(t *testing.T) {
		// An operator blocks "198.51.100.7", not "198.51.100.7/32". If the bare form
		// were dropped, the address would stay reachable with no error reported.
		if n := AddToIPBlocklist("198.51.100.7"); n != 1 {
			t.Fatalf("added = %d, want 1", n)
		}
		if !blockedThrough(t, "198.51.100.7") {
			t.Error("a bare IPv4 address was not blocked")
		}
		if blockedThrough(t, "198.51.100.8") {
			t.Error("blocking one host also blocked its neighbour")
		}
	})

	t.Run("bare IPv6 too", func(t *testing.T) {
		if n := AddToIPBlocklist("2001:db8::1"); n != 1 {
			t.Fatalf("added = %d, want 1", n)
		}
		if !blockedThrough(t, "2001:db8::1") {
			t.Error("a bare IPv6 address was not blocked")
		}
	})

	t.Run("a CIDR range blocks the whole range, and removal releases it", func(t *testing.T) {
		if n := AddToIPBlocklist("203.0.113.0/24"); n != 1 {
			t.Fatalf("added = %d, want 1", n)
		}
		if !blockedThrough(t, "203.0.113.42") {
			t.Error("an address inside a blocked range was let through")
		}

		if n := RemoveFromIPBlocklist("203.0.113.0/24"); n != 1 {
			t.Fatalf("removed = %d, want 1", n)
		}
		if blockedThrough(t, "203.0.113.42") {
			t.Error("address is still blocked after its range was removed")
		}
	})

	t.Run("empty and malformed input is rejected, not silently accepted", func(t *testing.T) {
		if n := AddToIPBlocklist(); n != 0 {
			t.Errorf("adding nothing reported %d entries", n)
		}
		if n := AddToIPBlocklist("", "   "); n != 0 {
			t.Errorf("adding blanks reported %d entries", n)
		}
		// The dangerous case: an operator fat-fingers an address during an incident
		// and is told it was blocked.
		if n := AddToIPBlocklist("not-an-ip", "999.999.999.999/32"); n != 0 {
			t.Errorf("malformed entries reported as blocked (%d) — the operator would believe the address was stopped", n)
		}
		if n := RemoveFromIPBlocklist("192.0.2.1/32"); n != 0 {
			t.Errorf("removing an absent entry reported %d removals", n)
		}
	})
}

// Removing nothing, or removing garbage, must report zero removals rather than
// claiming a removal that never happened.
func TestIPBlocklist_RemoveRejectsEmptyAndMalformed(t *testing.T) {
	if n := RemoveFromIPBlocklist(); n != 0 {
		t.Errorf("removing nothing reported %d removals", n)
	}
	if n := RemoveFromIPBlocklist("", "   ", "not-an-ip"); n != 0 {
		t.Errorf("removing malformed entries reported %d removals", n)
	}
}
