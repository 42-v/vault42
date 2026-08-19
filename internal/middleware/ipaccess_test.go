package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ok200 is a simple handler that writes 200 OK.
var ok200 = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// resetIPAccess clears all IP access lists to a clean state between tests.
func resetIPAccess() {
	SetIPAccessLists(nil, nil, nil, nil, "")
}

func TestIPAccessNoListsPassthrough(t *testing.T) {
	resetIPAccess()
	h := IPAccess()(ok200)

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("no lists: got %d, want 200", rec.Code)
	}
}

func TestIPAccessAllowlistMatchAllows(t *testing.T) {
	resetIPAccess()
	SetIPAccessLists([]string{"10.0.0.0/8"}, nil, nil, nil, "")
	h := IPAccess()(ok200)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("allowlist match: got %d, want 200", rec.Code)
	}
}

func TestIPAccessAllowlistNonMatchBlocks(t *testing.T) {
	resetIPAccess()
	SetIPAccessLists([]string{"10.0.0.0/8"}, nil, nil, nil, "")
	h := IPAccess()(ok200)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "192.168.1.1:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("allowlist non-match: got %d, want 403", rec.Code)
	}
	assertAccessDeniedBody(t, rec)
}

func TestIPAccessBlocklistMatchBlocks(t *testing.T) {
	resetIPAccess()
	SetIPAccessLists(nil, []string{"192.0.2.0/24"}, nil, nil, "")
	h := IPAccess()(ok200)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "192.0.2.50:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("blocklist match: got %d, want 403", rec.Code)
	}
}

func TestIPAccessBlocklistNonMatchAllows(t *testing.T) {
	resetIPAccess()
	SetIPAccessLists(nil, []string{"192.0.2.0/24"}, nil, nil, "")
	h := IPAccess()(ok200)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "10.0.0.1:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("blocklist non-match: got %d, want 200", rec.Code)
	}
}

func TestIPAccessAllowlistBeforeBlocklist(t *testing.T) {
	// IP is in blocklist but NOT in allowlist → 403 (allowlist checked first)
	resetIPAccess()
	SetIPAccessLists([]string{"10.0.0.0/8"}, []string{"192.168.1.0/24"}, nil, nil, "")
	h := IPAccess()(ok200)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "192.168.1.5:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("allowlist+blocklist: got %d, want 403 (not in allowlist)", rec.Code)
	}
}

func TestIPAccessGeoAllowlistMatchAllows(t *testing.T) {
	resetIPAccess()
	// A trusted peer, because these cases are about the list logic and the
	// country is only believed from a hop the operator trusts.
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)
	SetIPAccessLists(nil, nil, []string{"SK", "CZ"}, nil, "CF-IPCountry")
	h := IPAccess()(ok200)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "10.0.0.7:5555"
	req.Header.Set("CF-IPCountry", "SK")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("geo allowlist match: got %d, want 200", rec.Code)
	}
}

func TestIPAccessGeoAllowlistNonMatchBlocks(t *testing.T) {
	resetIPAccess()
	// A trusted peer, because these cases are about the list logic and the
	// country is only believed from a hop the operator trusts.
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)
	SetIPAccessLists(nil, nil, []string{"SK", "CZ"}, nil, "CF-IPCountry")
	h := IPAccess()(ok200)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "10.0.0.7:5555"
	req.Header.Set("CF-IPCountry", "US")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("geo allowlist non-match: got %d, want 403", rec.Code)
	}
}

func TestIPAccessGeoBlocklistMatchBlocks(t *testing.T) {
	resetIPAccess()
	// A trusted peer, because these cases are about the list logic and the
	// country is only believed from a hop the operator trusts.
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)
	SetIPAccessLists(nil, nil, nil, []string{"CN", "RU"}, "CF-IPCountry")
	h := IPAccess()(ok200)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "10.0.0.7:5555"
	req.Header.Set("CF-IPCountry", "RU")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("geo blocklist match: got %d, want 403", rec.Code)
	}
}

func TestIPAccessGeoBlocklistNonMatchAllows(t *testing.T) {
	resetIPAccess()
	// A trusted peer, because these cases are about the list logic and the
	// country is only believed from a hop the operator trusts.
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)
	SetIPAccessLists(nil, nil, nil, []string{"CN", "RU"}, "CF-IPCountry")
	h := IPAccess()(ok200)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "10.0.0.7:5555"
	req.Header.Set("CF-IPCountry", "SK")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("geo blocklist non-match: got %d, want 200", rec.Code)
	}
}

func TestIPAccessGeoNoHeaderIsDeniedUnderAnAllowlist(t *testing.T) {
	resetIPAccess()
	SetIPAccessLists(nil, nil, []string{"SK"}, nil, "CF-IPCountry")
	h := IPAccess()(ok200)

	// This test used to assert 200 and was named ...SkipsCheck. It pinned the
	// defect: an allowlist says only these countries may reach this service, and
	// omitting the header was a bypass that did not even require knowing which
	// countries were on the list.
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("no geo header under an allowlist: got %d, want 403", rec.Code)
	}
}

func TestIPAccessGeoNoGeoHeaderConfigSkipsCheck(t *testing.T) {
	// GeoAllowlist set but GeoIPHeader is empty → geo checks never run
	resetIPAccess()
	// A trusted peer, because this case is about the list logic and the
	// country is only believed from a hop the operator trusts.
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)
	SetIPAccessLists(nil, nil, []string{"SK"}, nil, "")
	h := IPAccess()(ok200)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "10.0.0.7:5555"
	req.Header.Set("CF-IPCountry", "CN") // should be ignored
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("no geo header config: got %d, want 200 (geo disabled)", rec.Code)
	}
}

func TestIPAccessHealthzBypass(t *testing.T) {
	resetIPAccess()
	// Block everything — health probes should still pass
	SetIPAccessLists([]string{"255.255.255.255/32"}, nil, nil, nil, "")
	h := IPAccess()(ok200)

	for _, path := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "1.2.3.4:5555"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("%s bypass: got %d, want 200", path, rec.Code)
		}
	}
}

func TestIPAccessBareIP(t *testing.T) {
	resetIPAccess()
	// Bare IP (no CIDR suffix) should be normalized to /32
	SetIPAccessLists([]string{"10.0.0.1"}, nil, nil, nil, "")
	h := IPAccess()(ok200)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "10.0.0.1:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("bare IP: got %d, want 200", rec.Code)
	}
}

func TestIPAccessIPv6CIDR(t *testing.T) {
	resetIPAccess()
	SetIPAccessLists([]string{"2001:db8::/32"}, nil, nil, nil, "")
	h := IPAccess()(ok200)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "[2001:db8::1]:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("IPv6 CIDR match: got %d, want 200", rec.Code)
	}

	// Non-matching IPv6
	req2 := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req2.RemoteAddr = "[2001:db9::1]:5555"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusForbidden {
		t.Errorf("IPv6 CIDR non-match: got %d, want 403", rec2.Code)
	}
}

func TestIPAccessInvalidCIDRSkipped(t *testing.T) {
	resetIPAccess()
	// Invalid entry should be skipped, valid entry should work
	SetIPAccessLists([]string{"not-a-cidr", "10.0.0.0/8"}, nil, nil, nil, "")
	h := IPAccess()(ok200)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("invalid CIDR skipped: got %d, want 200", rec.Code)
	}
}

func TestIPAccessTorExitNode(t *testing.T) {
	// Cloudflare uses "T1" for Tor exit nodes
	resetIPAccess()
	// A trusted peer, because this case is about the list logic and the
	// country is only believed from a hop the operator trusts.
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)
	SetIPAccessLists(nil, nil, nil, []string{"T1"}, "CF-IPCountry")
	h := IPAccess()(ok200)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "10.0.0.7:5555"
	req.Header.Set("CF-IPCountry", "T1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Tor exit: got %d, want 403", rec.Code)
	}
}

func TestIPAccessGeoCaseInsensitive(t *testing.T) {
	resetIPAccess()
	// A trusted peer, because this case is about the list logic and the
	// country is only believed from a hop the operator trusts.
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)
	SetIPAccessLists(nil, nil, []string{"sk"}, nil, "CF-IPCountry")
	h := IPAccess()(ok200)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "10.0.0.7:5555"
	req.Header.Set("CF-IPCountry", "sk")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("geo case insensitive: got %d, want 200", rec.Code)
	}
}

func TestClientIPRealIPHeader(t *testing.T) {
	// Setup: trusted proxy + real IP header
	SetTrustedProxies([]string{"172.16.0.0/12"})
	SetRealIPHeader("CF-Connecting-IP")
	defer func() {
		SetTrustedProxies(nil)
		SetRealIPHeader("")
	}()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "172.16.0.1:8080"
	req.Header.Set("CF-Connecting-IP", "203.0.113.50")
	req.Header.Set("X-Forwarded-For", "198.51.100.1, 172.16.0.1")

	got := ClientIP(req)
	if got != "203.0.113.50" {
		t.Errorf("ClientIP with CF-Connecting-IP: got %q, want %q", got, "203.0.113.50")
	}
}

func TestClientIPRealIPHeaderNotTrusted(t *testing.T) {
	// When remote is NOT a trusted proxy, real IP header should be ignored
	SetTrustedProxies([]string{"172.16.0.0/12"})
	SetRealIPHeader("CF-Connecting-IP")
	defer func() {
		SetTrustedProxies(nil)
		SetRealIPHeader("")
	}()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:8080" // NOT in trusted proxies
	req.Header.Set("CF-Connecting-IP", "203.0.113.50")

	got := ClientIP(req)
	if got != "1.2.3.4" {
		t.Errorf("ClientIP untrusted proxy: got %q, want %q", got, "1.2.3.4")
	}
}

func TestClientIPRealIPHeaderEmpty(t *testing.T) {
	// When header is configured but not present, falls through to XFF
	SetTrustedProxies([]string{"172.16.0.0/12"})
	SetRealIPHeader("CF-Connecting-IP")
	defer func() {
		SetTrustedProxies(nil)
		SetRealIPHeader("")
	}()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "172.16.0.1:8080"
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	// No CF-Connecting-IP header

	got := ClientIP(req)
	if got != "198.51.100.1" {
		t.Errorf("ClientIP no real IP header: got %q, want %q", got, "198.51.100.1")
	}
}

func TestClientIPRealIPHeaderDisabled(t *testing.T) {
	// When RealIPHeader is empty, CF-Connecting-IP should be ignored even if present
	SetTrustedProxies([]string{"172.16.0.0/12"})
	SetRealIPHeader("")
	defer func() {
		SetTrustedProxies(nil)
	}()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "172.16.0.1:8080"
	req.Header.Set("CF-Connecting-IP", "203.0.113.50")
	req.Header.Set("X-Forwarded-For", "198.51.100.1")

	got := ClientIP(req)
	if got != "198.51.100.1" {
		t.Errorf("ClientIP disabled real IP header: got %q, want %q", got, "198.51.100.1")
	}
}

func TestIPAccessCustomGeoHeader(t *testing.T) {
	// Verify that a custom geo header name (e.g. X-Geo-Country) works
	resetIPAccess()
	// A trusted peer: the country is only believed from a hop the operator
	// trusts, so a geo case has to declare one to be testing the list logic.
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)
	SetIPAccessLists(nil, nil, nil, []string{"CN"}, "X-Geo-Country")
	h := IPAccess()(ok200)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "10.0.0.7:5555"
	req.Header.Set("X-Geo-Country", "CN")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("custom geo header: got %d, want 403", rec.Code)
	}
}

func TestAddToIPBlocklistDynamic(t *testing.T) {
	resetIPAccess()
	h := IPAccess()(ok200)

	// Initially no blocklist — request passes
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "192.0.2.1:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("before ban: got %d, want 200", rec.Code)
	}

	// Dynamically add the IP to the blocklist
	added := AddToIPBlocklist("192.0.2.1")
	if added != 1 {
		t.Errorf("AddToIPBlocklist: added %d, want 1", added)
	}

	// Now the same IP should be blocked
	req2 := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req2.RemoteAddr = "192.0.2.1:5555"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Errorf("after ban: got %d, want 403", rec2.Code)
	}
}

func TestAddToIPBlocklistDuplicate(t *testing.T) {
	resetIPAccess()
	AddToIPBlocklist("192.0.2.1")
	added := AddToIPBlocklist("192.0.2.1")
	if added != 0 {
		t.Errorf("duplicate add: added %d, want 0", added)
	}
}

func TestRemoveFromIPBlocklist(t *testing.T) {
	resetIPAccess()
	AddToIPBlocklist("192.0.2.1")
	h := IPAccess()(ok200)

	// Blocked
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "192.0.2.1:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("before unban: got %d, want 403", rec.Code)
	}

	// Remove from blocklist
	removed := RemoveFromIPBlocklist("192.0.2.1")
	if removed != 1 {
		t.Errorf("RemoveFromIPBlocklist: removed %d, want 1", removed)
	}

	// Now passes
	req2 := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req2.RemoteAddr = "192.0.2.1:5555"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Errorf("after unban: got %d, want 200", rec2.Code)
	}
}

func TestRemoveFromIPBlocklistNotPresent(t *testing.T) {
	resetIPAccess()
	removed := RemoveFromIPBlocklist("192.0.2.99")
	if removed != 0 {
		t.Errorf("remove non-existent: removed %d, want 0", removed)
	}
}

// assertAccessDeniedBody checks the response body contains "access_denied".
func assertAccessDeniedBody(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body["error"] != "access_denied" {
		t.Errorf("body error = %q, want %q", body["error"], "access_denied")
	}
}
