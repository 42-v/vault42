package attack

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/config"
	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/server"
)

// The body cap this file certifies is the one internal/server installs, not one
// the test picks. The suite used to build middleware.MaxBody(100) of its own and
// assert that it capped at 100 — an assertion about the test's argument. There
// were three body limits in the tree and MaxBody shipped in none of them: the
// API installs MaxBodyWithExemptions(8*1024, ...) and the admin plane installs
// adminapi.MaxBody(64*1024). Widening the deployed exemption list to every path
// left this file green.
//
// So every test below drives server.Chain — the single assembly Start serves —
// over a probe handler that reports what it was allowed to read. The limit and
// the exempt prefixes are read out of the deployment, never supplied here.

// deployedLimitBytes is the cap internal/server installs. It is not passed to
// anything: it is the number the assertions compare against, and a change to
// the deployed value must be reflected here for the suite to keep passing.
const deployedLimitBytes = 8 * 1024

// bodyProbe reports what the innermost handler was allowed to read off the
// request body after the deployed chain has wrapped it.
type bodyProbe struct {
	read int
	err  error
}

// chainOverProbe wraps a probe handler in the real deployed middleware chain.
func chainOverProbe(t *testing.T) (http.Handler, *bodyProbe) {
	t.Helper()
	memCache := cache.NewMemoryCache()
	t.Cleanup(func() { _ = memCache.Close() })

	srv := server.New(&server.Deps{
		Config: &config.Config{
			Origin:            "https://vault.localhost",
			AppName:           "Vault Attack Suite",
			PasswordMinLength: 15,
		},
		Cache:     memCache,
		ReadyDeps: &handler.ReadyzDeps{},
	})

	probe := &bodyProbe{}
	return srv.Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		probe.read = len(data)
		probe.err = err
		w.WriteHeader(http.StatusOK)
	})), probe
}

// serveThroughChain drives one request through the chain and returns the
// probe's reading.
func serveThroughChain(t *testing.T, method, path string, bodyBytes int) *bodyProbe {
	t.Helper()
	h, probe := chainOverProbe(t)
	var body io.Reader
	if bodyBytes > 0 {
		body = strings.NewReader(strings.Repeat("A", bodyBytes))
	}
	req := httptest.NewRequest(method, path, body)
	h.ServeHTTP(httptest.NewRecorder(), req)
	return probe
}

// TestMaxBodySkipsGETRequests verifies that the deployed body cap does not apply
// to GET, which is what lets the embedded frontend serve assets larger than the
// cap.
func TestMaxBodySkipsGETRequests(t *testing.T) {
	probe := serveThroughChain(t, http.MethodGet, "/some-asset.js", 0)
	if probe.err != nil {
		t.Fatalf("GET body read through the deployed chain: %v", probe.err)
	}
}

// TestMaxBodySkipsHEADRequests verifies HEAD bypasses the deployed cap.
func TestMaxBodySkipsHEADRequests(t *testing.T) {
	probe := serveThroughChain(t, http.MethodHead, "/healthz", 0)
	if probe.err != nil {
		t.Fatalf("HEAD body read through the deployed chain: %v", probe.err)
	}
}

// TestMaxBodyEnforcesOnPOST is the assertion the suite exists for: a POST to a
// non-exempt route can never hand the handler more than the deployed cap, so a
// 1 GB JSON payload is refused at the reader rather than buffered.
//
// It fails on a deployment that widens the exemption list, raises the cap, or
// stops installing the middleware — none of which the isolated version noticed.
func TestMaxBodyEnforcesOnPOST(t *testing.T) {
	probe := serveThroughChain(t, http.MethodPost, "/auth/login", 4*deployedLimitBytes)

	if probe.err == nil {
		t.Errorf("POST /auth/login: no MaxBytesReader error draining a %d-byte body; "+
			"the handler was handed %d bytes, so the deployed cap is not on this path",
			4*deployedLimitBytes, probe.read)
	}
	if probe.read > deployedLimitBytes {
		t.Errorf("POST /auth/login: handler read %d bytes, want <= %d (the cap internal/server installs)",
			probe.read, deployedLimitBytes)
	}
}

// TestMaxBodyZeroPOSTBody verifies an empty POST body is not an error under the
// deployed cap.
func TestMaxBodyZeroPOSTBody(t *testing.T) {
	probe := serveThroughChain(t, http.MethodPost, "/auth/logout", 0)
	if probe.err != nil {
		t.Fatalf("empty POST body through the deployed chain: %v", probe.err)
	}
	if probe.read != 0 {
		t.Fatalf("empty POST body read %d bytes", probe.read)
	}
}

// TestMaxBodyExemptRoutesEnforceTheirOwn pins the exemption list itself. The two
// prefixes the deployment exempts carry their own MaxBytesReader inside the
// handler, and that is the whole justification for exempting them. The assertion
// is that the global cap is genuinely off for these paths — so widening the list
// to "/" (the mutation the old suite could not see) fails the POST test above,
// and dropping a real prefix fails this one.
func TestMaxBodyExemptRoutesEnforceTheirOwn(t *testing.T) {
	for _, path := range []string{"/user/blobs", "/service/documents"} {
		t.Run(path, func(t *testing.T) {
			probe := serveThroughChain(t, http.MethodPost, path, 4*deployedLimitBytes)
			if probe.err != nil {
				t.Fatalf("POST %s: exempt route hit the global cap: %v", path, probe.err)
			}
			if probe.read != 4*deployedLimitBytes {
				t.Fatalf("POST %s: exempt route delivered %d of %d bytes", path, probe.read, 4*deployedLimitBytes)
			}
		})
	}
}
