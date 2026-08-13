package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// geoProbe drives one request through IPAccess with the given peer and country
// header, and reports the status.
func geoProbe(t *testing.T, remoteAddr, header, country string) int {
	t.Helper()

	h := IPAccess()(ok200)
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	req.RemoteAddr = remoteAddr
	if country != "" {
		req.Header.Set(header, country)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// TestGeoAllowlistIgnoresAnUntrustedPeersCountryHeader closes a fence anyone
// could walk through.
//
// The geo check read its country straight off the request. Every other
// caller-supplied signal in this package is gated on isTrustedProxy first:
// ClientIP will not believe X-Forwarded-For from an untrusted peer, and neither
// will the app header. The country header was not, so a caller who reached the
// origin directly, through a leaked ClusterIP, a NodePort, a mis-published
// Service, or any hop that forwards client headers, simply sent the country the
// allowlist wanted.
//
// IPAccess is mounted globally and ahead of authentication, so the fence covers
// login, register, password reset, the client-credentials grant and every
// authenticated route behind them. An operator who configured GEO_ALLOWLIST
// believed all of that was closed to everywhere else.
func TestGeoAllowlistIgnoresAnUntrustedPeersCountryHeader(t *testing.T) {
	resetIPAccess()
	SetIPAccessLists(nil, nil, []string{"US", "DE"}, nil, "CF-IPCountry")

	if code := geoProbe(t, "203.0.113.9:5555", "CF-IPCountry", "US"); code != http.StatusForbidden {
		t.Errorf("status = %d, want 403. An untrusted peer sent CF-IPCountry: US and the "+
			"allowlist believed it, so the country fence is whatever the caller says it is.",
			code)
	}
}

// TestGeoAllowlistDeniesAPeerWithNoCountry is the fail-open half.
//
// A missing header skipped the entire geo ladder, and a test pinned that as
// intended. Under an allowlist it is backwards: the operator has said only
// these countries may reach this service, and a caller whose country cannot be
// established is not one of them. Omitting the header was the simplest possible
// bypass, needing no knowledge of which country the list contains.
func TestGeoAllowlistDeniesAPeerWithNoCountry(t *testing.T) {
	resetIPAccess()
	SetIPAccessLists(nil, nil, []string{"US", "DE"}, nil, "CF-IPCountry")

	if code := geoProbe(t, "203.0.113.9:5555", "CF-IPCountry", ""); code != http.StatusForbidden {
		t.Errorf("status = %d, want 403. With an allowlist configured, a request whose country "+
			"cannot be established must not pass: sending no header at all was a bypass that "+
			"did not even require knowing which countries are allowed.", code)
	}
}

// TestGeoBlocklistStillPassesAnUnknownCountry keeps the two list kinds distinct.
//
// A blocklist is an exception list rather than a fence: it says these countries
// may not, not only these may. There is nothing to compare an unknown country
// against, and failing closed there would turn a blocklist into an allowlist of
// one, denying every caller the proxy did not annotate.
func TestGeoBlocklistStillPassesAnUnknownCountry(t *testing.T) {
	resetIPAccess()
	SetIPAccessLists(nil, nil, nil, []string{"CN", "RU"}, "CF-IPCountry")

	if code := geoProbe(t, "203.0.113.9:5555", "CF-IPCountry", ""); code != http.StatusOK {
		t.Errorf("status = %d, want 200. A blocklist names what is refused, so a caller whose "+
			"country is unknown matches nothing on it and a denial would silently turn the "+
			"blocklist into an allowlist.", code)
	}
}

// TestGeoTrustsACountryFromATrustedProxy is the negative control, and the case
// the feature exists for.
//
// The header is real when the hop that set it is one the operator trusts. If
// this fails, the fence rejects the deployment it was designed for.
func TestGeoTrustsACountryFromATrustedProxy(t *testing.T) {
	resetIPAccess()
	SetTrustedProxies([]string{"10.0.0.0/8"})
	defer SetTrustedProxies(nil)
	SetIPAccessLists(nil, nil, []string{"US", "DE"}, nil, "CF-IPCountry")

	if code := geoProbe(t, "10.0.0.7:5555", "CF-IPCountry", "US"); code != http.StatusOK {
		t.Errorf("status = %d, want 200: a country from a trusted proxy is the signal this "+
			"feature reads, and refusing it breaks the deployment the fence is for.", code)
	}
	if code := geoProbe(t, "10.0.0.7:5555", "CF-IPCountry", "CN"); code != http.StatusForbidden {
		t.Errorf("status = %d, want 403: a country outside the allowlist must still be refused "+
			"when the proxy is trusted.", code)
	}
}
