package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The four access lists live in package globals with no initializer, so every
// one of them is a nil pointer until SetIPAccessLists runs. resetIPAccess does
// not reproduce that state: it calls SetIPAccessLists, which always stores a
// non-nil empty list. This puts the package back to genuinely unconfigured.
func clearIPAccessState(t *testing.T) {
	t.Helper()

	ipAllowCIDRs.Store(nil)
	ipBlockCIDRs.Store(nil)
	geoAllowSet.Store(nil)
	geoBlockSet.Store(nil)
	geoIPHeader.Store("")

	// ClientIP believes proxy headers only from a trusted peer, so clearing the
	// proxy list pins the client address to RemoteAddr.
	SetTrustedProxies(nil)
	t.Cleanup(resetIPAccess)
}

// TestIPAccessServesRequestsBeforeAnyListIsConfigured pins the nil-safety of the
// four list accessors, which is the entire reason they are functions rather than
// direct pointer loads.
//
// IPAccess reads all four lists on every request it does not bypass, and it is
// mounted globally, ahead of authentication, on every route. A process that
// mounts it without calling SetIPAccessLists therefore dereferences four nil
// pointers on its first request, and the result is not one failed handler but a
// panic on the front door. That is not hypothetical wiring: AddToIPBlocklist is
// reachable from the runtime ban path and reads the same globals, so ordering
// between an incident response and startup wiring is enough to get here.
func TestIPAccessServesRequestsBeforeAnyListIsConfigured(t *testing.T) {
	clearIPAccessState(t)

	h := IPAccess()(ok200)
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: no list has been configured, so the middleware has "+
			"nothing to enforce and must stand out of the way rather than fail the request",
			rec.Code)
	}
}

// TestAddToIPBlocklistBansBeforeAnyListIsConfigured covers the other reader of
// the never-initialized blocklist pointer.
//
// The runtime ban is what an operator reaches for during an attack, and it takes
// a copy of the current list before publishing the new one. Reading that list
// must not depend on startup wiring having stored an empty one first, or the
// first ban of a process is the one that fails.
func TestAddToIPBlocklistBansBeforeAnyListIsConfigured(t *testing.T) {
	clearIPAccessState(t)

	if added := AddToIPBlocklist("192.0.2.5"); added != 1 {
		t.Fatalf("AddToIPBlocklist added %d entries, want 1", added)
	}

	h := IPAccess()(ok200)

	banned := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	banned.RemoteAddr = "192.0.2.5:4444"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, banned)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403: the address was banned at runtime and is still being "+
			"served", rec.Code)
	}

	// Without this the same failure would also pass a middleware that had
	// regressed into refusing everything.
	other := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	other.RemoteAddr = "203.0.113.9:5555"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, other)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: banning one address must not close the service to "+
			"everyone else", rec.Code)
	}
}
