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

// TestIPAccess is the whole decision table for the middleware: address lists,
// country lists, the order the two are consulted in, and the health-probe
// bypass. Each row is one configuration and one request, because the failure
// this guards against is a configuration that silently admits somebody rather
// than a single check misbehaving.
//
// Every geo row declares a trusted proxy. The country header is believed only
// from a hop the operator trusts, so a geo case with an untrusted peer would be
// testing the trust gate rather than the list logic -- except the two rows that
// say so in their names.
func TestIPAccess(t *testing.T) {
	tests := []struct {
		name string
		// Arguments to SetIPAccessLists, in order.
		allow, block, geoAllow, geoBlock []string
		geoHeader                        string

		trusted    []string
		remoteAddr string
		path       string
		// header is the country header sent by the client, if any.
		header [2]string
		want   int
	}{
		{
			name:       "no lists at all lets everything through",
			remoteAddr: "1.2.3.4:1234", path: "/auth/login", want: http.StatusOK,
		},
		{
			name:       "an address on the allowlist is admitted",
			allow:      []string{"10.0.0.0/8"},
			remoteAddr: "10.1.2.3:5555", want: http.StatusOK,
		},
		{
			name:       "an address off the allowlist is refused",
			allow:      []string{"10.0.0.0/8"},
			remoteAddr: "192.168.1.1:5555", want: http.StatusForbidden,
		},
		{
			name:       "an address on the blocklist is refused",
			block:      []string{"192.0.2.0/24"},
			remoteAddr: "192.0.2.50:5555", want: http.StatusForbidden,
		},
		{
			name:       "an address off the blocklist is admitted",
			block:      []string{"192.0.2.0/24"},
			remoteAddr: "10.0.0.1:5555", want: http.StatusOK,
		},
		{
			// The allowlist is consulted first, so being absent from it refuses the
			// request whatever the blocklist says.
			name:  "on the blocklist and off the allowlist is refused by the allowlist",
			allow: []string{"10.0.0.0/8"}, block: []string{"192.168.1.0/24"},
			remoteAddr: "192.168.1.5:5555", want: http.StatusForbidden,
		},
		{
			name:       "a bare address in a list is read as a single host",
			allow:      []string{"10.0.0.1"},
			remoteAddr: "10.0.0.1:5555", want: http.StatusOK,
		},
		{
			name:       "an IPv6 address inside an allowlisted prefix",
			allow:      []string{"2001:db8::/32"},
			remoteAddr: "[2001:db8::1]:5555", want: http.StatusOK,
		},
		{
			name:       "an IPv6 address outside an allowlisted prefix",
			allow:      []string{"2001:db8::/32"},
			remoteAddr: "[2001:db9::1]:5555", want: http.StatusForbidden,
		},
		{
			// An unparseable entry must be dropped rather than widened into a match,
			// so the valid neighbor keeps working ...
			name:       "an unparseable list entry does not break its valid neighbor",
			allow:      []string{"not-a-cidr", "10.0.0.0/8"},
			remoteAddr: "10.1.2.3:5555", want: http.StatusOK,
		},
		{
			// ... and nothing outside that neighbor is admitted by it.
			name:       "an unparseable list entry does not admit anyone",
			allow:      []string{"not-a-cidr", "10.0.0.0/8"},
			remoteAddr: "203.0.113.9:5555", want: http.StatusForbidden,
		},
		{
			name:     "a country on the geo allowlist is admitted",
			geoAllow: []string{"SK", "CZ"}, geoHeader: "CF-IPCountry",
			trusted: []string{"10.0.0.0/8"}, remoteAddr: "10.0.0.7:5555",
			header: [2]string{"CF-IPCountry", "SK"}, want: http.StatusOK,
		},
		{
			name:     "a country off the geo allowlist is refused",
			geoAllow: []string{"SK", "CZ"}, geoHeader: "CF-IPCountry",
			trusted: []string{"10.0.0.0/8"}, remoteAddr: "10.0.0.7:5555",
			header: [2]string{"CF-IPCountry", "US"}, want: http.StatusForbidden,
		},
		{
			name:     "a country on the geo blocklist is refused",
			geoBlock: []string{"CN", "RU"}, geoHeader: "CF-IPCountry",
			trusted: []string{"10.0.0.0/8"}, remoteAddr: "10.0.0.7:5555",
			header: [2]string{"CF-IPCountry", "RU"}, want: http.StatusForbidden,
		},
		{
			name:     "a country off the geo blocklist is admitted",
			geoBlock: []string{"CN", "RU"}, geoHeader: "CF-IPCountry",
			trusted: []string{"10.0.0.0/8"}, remoteAddr: "10.0.0.7:5555",
			header: [2]string{"CF-IPCountry", "SK"}, want: http.StatusOK,
		},
		{
			// Cloudflare reports Tor exits as the pseudo-country T1, so the list has
			// to work on a value that is not an ISO country code.
			name:     "the Tor pseudo-country blocks like any other",
			geoBlock: []string{"T1"}, geoHeader: "CF-IPCountry",
			trusted: []string{"10.0.0.0/8"}, remoteAddr: "10.0.0.7:5555",
			header: [2]string{"CF-IPCountry", "T1"}, want: http.StatusForbidden,
		},
		{
			name:     "the geo header name is configurable",
			geoBlock: []string{"CN"}, geoHeader: "X-Geo-Country",
			trusted: []string{"10.0.0.0/8"}, remoteAddr: "10.0.0.7:5555",
			header: [2]string{"X-Geo-Country", "CN"}, want: http.StatusForbidden,
		},
		{
			name:     "country comparison ignores case",
			geoAllow: []string{"sk"}, geoHeader: "CF-IPCountry",
			trusted: []string{"10.0.0.0/8"}, remoteAddr: "10.0.0.7:5555",
			header: [2]string{"CF-IPCountry", "sk"}, want: http.StatusOK,
		},
		{
			// An allowlist says only these countries may reach the service, so
			// omitting the header must not be a bypass that does not even require
			// knowing which countries are on the list. This row used to assert 200.
			name:     "a missing country header under a geo allowlist is refused",
			geoAllow: []string{"SK"}, geoHeader: "CF-IPCountry",
			remoteAddr: "1.2.3.4:5555", want: http.StatusForbidden,
		},
		{
			name:     "a geo list with no header name configured is inert",
			geoAllow: []string{"SK"}, geoHeader: "",
			trusted: []string{"10.0.0.0/8"}, remoteAddr: "10.0.0.7:5555",
			header: [2]string{"CF-IPCountry", "CN"}, want: http.StatusOK,
		},
		{
			// Blocking every address must not take the probes down with it, or a
			// tightened list rolls the pods.
			name:       "healthz is exempt from an allowlist that blocks everything",
			allow:      []string{"255.255.255.255/32"},
			remoteAddr: "1.2.3.4:5555", path: "/healthz", want: http.StatusOK,
		},
		{
			name:       "readyz is exempt from an allowlist that blocks everything",
			allow:      []string{"255.255.255.255/32"},
			remoteAddr: "1.2.3.4:5555", path: "/readyz", want: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetIPAccess()
			SetIPAccessLists(tt.allow, tt.block, tt.geoAllow, tt.geoBlock, tt.geoHeader)
			SetTrustedProxies(tt.trusted)
			t.Cleanup(func() {
				resetIPAccess()
				SetTrustedProxies(nil)
			})

			path := tt.path
			if path == "" {
				path = "/api/test"
			}
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.header[0] != "" {
				req.Header.Set(tt.header[0], tt.header[1])
			}

			rec := httptest.NewRecorder()
			IPAccess()(ok200).ServeHTTP(rec, req)

			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
			if tt.want == http.StatusForbidden {
				assertAccessDeniedBody(t, rec)
			}
		})
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
