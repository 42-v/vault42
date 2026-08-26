package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The SDK's own requests have to survive a cross-origin preflight, and its own
// responses have to be readable.
//
// Neither was true. Access-Control-Allow-Headers listed Content-Type,
// Authorization and DPoP; the Vue SDK sends X-Requested-With on every request
// and X-Blob-Checksum and X-Blob-Label on blob writes. None of those three is
// CORS-safelisted, so the browser refuses the request at preflight and it never
// reaches vault42 at all. And with no Access-Control-Expose-Headers at all, the
// blob helpers -- which return the checksum and the label to their caller --
// read null cross-origin while working perfectly same-origin.
//
// That is the failure shape worth naming: the documented cross-origin mode did
// not degrade, it did not error usefully, it simply did not work, and every test
// in the suite is same-origin so nothing saw it.
//
// These lists are duplicated deliberately. The middleware states what is
// allowed; this test states what the SDK needs. If either moves without the
// other, one of them is wrong and this fails rather than a deployment doing it.

// sdkRequestHeaders are the non-safelisted headers the SDK sets on a request.
// X-Vault-App is not here: it is proxy-set, so no browser asks for it.
var sdkRequestHeaders = []string{"X-Requested-With", "X-Blob-Checksum", "X-Blob-Label"}

// sdkResponseHeaders are the headers a browser client has to be able to read.
var sdkResponseHeaders = []string{"X-Blob-Checksum", "X-Blob-Label", "Retry-After"}

func corsPreflight(t *testing.T, origin string) http.Header {
	t.Helper()
	h := CORS(origin, nil, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodOptions, "/user/blobs", nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result().Header
}

func TestCORSAllowsEveryHeaderTheSDKSends(t *testing.T) {
	got := corsPreflight(t, "https://app.example.com")
	allowed := got.Get("Access-Control-Allow-Headers")
	if allowed == "" {
		t.Fatal("no Access-Control-Allow-Headers on a preflight response")
	}

	lower := strings.ToLower(allowed)
	for _, want := range sdkRequestHeaders {
		if !strings.Contains(lower, strings.ToLower(want)) {
			t.Errorf("Access-Control-Allow-Headers omits %s, which the SDK sets on its "+
				"requests. The browser refuses the request at preflight, so it never "+
				"reaches vault42 and no server-side test can see it.\ngot: %s", want, allowed)
		}
	}
}

func TestCORSExposesEveryHeaderTheSDKReads(t *testing.T) {
	got := corsPreflight(t, "https://app.example.com")
	exposed := got.Get("Access-Control-Expose-Headers")
	if exposed == "" {
		t.Fatal("no Access-Control-Expose-Headers. Only the CORS-safelisted response " +
			"headers reach a cross-origin caller, and none of the ones vault42 sets " +
			"is on that list, so they all read null.")
	}

	lower := strings.ToLower(exposed)
	for _, want := range sdkResponseHeaders {
		if !strings.Contains(lower, strings.ToLower(want)) {
			t.Errorf("Access-Control-Expose-Headers omits %s, so a cross-origin caller "+
				"reads it as null while the same call works same-origin\ngot: %s", want, exposed)
		}
	}
}

// Widening the allow-list must not have widened the origin check with it: the
// headers are advertised, the origin is still the one configured.
func TestCORSStillRefusesAnUnconfiguredOrigin(t *testing.T) {
	h := CORS("https://app.example.com", nil, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodOptions, "/user/blobs", nil)
	req.Header.Set("Origin", "https://evil.test")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Result().Header.Get("Access-Control-Allow-Origin"); got == "https://evil.test" {
		t.Fatalf("an unconfigured origin was allowed: %q", got)
	}
}
