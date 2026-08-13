package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// upstreamProbe is a stand-in vault that answers /healthz however the test asks
// it to, and records the paths it was probed on.
type upstreamProbe struct {
	srv *httptest.Server

	mu    sync.Mutex
	paths []string
}

func newUpstreamProbe(t *testing.T, status int) *upstreamProbe {
	t.Helper()

	p := &upstreamProbe{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.paths = append(p.paths, r.URL.Path)
		p.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *upstreamProbe) probedPaths() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.paths...)
}

// decodeReadyz reads the readiness document, which is the only machine-readable
// output the probe has.
func decodeReadyz(t *testing.T, body []byte) map[string]string {
	t.Helper()
	var doc map[string]string
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("readyz body %q is not a JSON object of strings: %v", body, err)
	}
	return doc
}

// TestHealthzIsIndependentOfUpstreams keeps liveness and readiness apart. The
// liveness probe decides whether Kubernetes restarts the pod, so it must answer
// on the bridge's own health alone. If it consulted the upstreams, a vault
// outage would roll the bridge, and a rolling bridge cannot serve the decoy
// pages or hold the flag set that a vault outage is the worst time to lose.
func TestHealthzIsIndependentOfUpstreams(t *testing.T) {
	hh := NewHealthHandler("http://127.0.0.1:1", "http://127.0.0.1:1")

	req := httptest.NewRequest(http.MethodGet, "/bridge/healthz", nil)
	w := httptest.NewRecorder()
	hh.Healthz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var doc map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("body %q is not JSON: %v", w.Body.Bytes(), err)
	}
	if doc["status"] != "ok" {
		t.Errorf("status field = %q, want %q", doc["status"], "ok")
	}
}

// TestHealthzIgnoresMethod records that liveness answers any verb. Kubernetes
// only ever sends GET, so this is not a feature to rely on, but it does mean the
// probe cannot be turned into a method-confusion surface.
func TestHealthzIgnoresMethod(t *testing.T) {
	hh := NewHealthHandler("http://example.invalid", "http://example.invalid")

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodDelete} {
		w := httptest.NewRecorder()
		hh.Healthz(w, httptest.NewRequest(method, "/bridge/healthz", nil))
		if w.Code != http.StatusOK {
			t.Errorf("%s status = %d, want %d", method, w.Code, http.StatusOK)
		}
	}
}

// TestReadyzReportsEachUpstreamSeparately is the operator-facing half. Readiness
// gates traffic, and the per-upstream fields are what tells an operator which of
// the two vaults is the problem. A readiness probe that collapsed both into a
// single boolean would say "not ready" for an outage of the honeypot, which
// carries no production traffic, without ever saying which one broke.
func TestReadyzReportsEachUpstreamSeparately(t *testing.T) {
	tests := []struct {
		name         string
		realStatus   int
		honeyStatus  int
		wantCode     int
		wantStatus   string
		wantReal     string
		wantHoneypot string
	}{
		{"both up", http.StatusOK, http.StatusOK, http.StatusOK, "ready", "up", "up"},
		{"real down", http.StatusInternalServerError, http.StatusOK, http.StatusServiceUnavailable, "not_ready", "down", "up"},
		{"honeypot down", http.StatusOK, http.StatusBadGateway, http.StatusServiceUnavailable, "not_ready", "up", "down"},
		{"both down", http.StatusNotFound, http.StatusNotFound, http.StatusServiceUnavailable, "not_ready", "down", "down"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			real := newUpstreamProbe(t, tt.realStatus)
			honeypot := newUpstreamProbe(t, tt.honeyStatus)

			hh := NewHealthHandler(real.srv.URL, honeypot.srv.URL)

			w := httptest.NewRecorder()
			hh.Readyz(w, httptest.NewRequest(http.MethodGet, "/bridge/readyz", nil))

			if w.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", w.Code, tt.wantCode)
			}
			if ct := w.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}

			doc := decodeReadyz(t, w.Body.Bytes())
			if doc["status"] != tt.wantStatus {
				t.Errorf("status field = %q, want %q", doc["status"], tt.wantStatus)
			}
			if doc["real"] != tt.wantReal {
				t.Errorf("real field = %q, want %q", doc["real"], tt.wantReal)
			}
			if doc["honeypot"] != tt.wantHoneypot {
				t.Errorf("honeypot field = %q, want %q", doc["honeypot"], tt.wantHoneypot)
			}

			// Both upstreams are probed on every call, and on /healthz rather
			// than on the base URL, so an upstream root that happens to return
			// 200 cannot mask a dead service.
			for name, p := range map[string]*upstreamProbe{"real": real, "honeypot": honeypot} {
				paths := p.probedPaths()
				if len(paths) != 1 {
					t.Fatalf("%s upstream saw %d probes, want 1", name, len(paths))
				}
				if paths[0] != "/healthz" {
					t.Errorf("%s upstream probed at %q, want /healthz", name, paths[0])
				}
			}
		})
	}
}

// TestReadyzTreatsUnreachableUpstreamAsDown covers the transport error rather
// than the status code. A refused connection is the shape of a vault that has
// not finished starting, which is the exact case readiness exists to catch.
func TestReadyzTreatsUnreachableUpstreamAsDown(t *testing.T) {
	honeypot := newUpstreamProbe(t, http.StatusOK)
	hh := NewHealthHandler("http://"+deadAddr(t), honeypot.srv.URL)

	w := httptest.NewRecorder()
	hh.Readyz(w, httptest.NewRequest(http.MethodGet, "/bridge/readyz", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	doc := decodeReadyz(t, w.Body.Bytes())
	if doc["real"] != "down" {
		t.Errorf("real field = %q, want down", doc["real"])
	}
	if doc["honeypot"] != "up" {
		t.Errorf("honeypot field = %q, want up", doc["honeypot"])
	}
}

// TestReadyzTreatsUnparseableUpstreamAsDown covers the case where the configured
// URL cannot even be turned into a request. Config does not validate the
// upstream URLs beyond url.Parse, so a value like a bare hostname reaches the
// health client intact and must report down rather than panic.
func TestReadyzTreatsUnparseableUpstreamAsDown(t *testing.T) {
	hh := NewHealthHandler("://not-a-url", "http:// spaces in host")

	w := httptest.NewRecorder()
	hh.Readyz(w, httptest.NewRequest(http.MethodGet, "/bridge/readyz", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	doc := decodeReadyz(t, w.Body.Bytes())
	if doc["real"] != "down" || doc["honeypot"] != "down" {
		t.Errorf("readyz = %v, want both down", doc)
	}
}

// TestReadyzBoundsHowLongAHangingUpstreamCanStallIt is the timeout that keeps a
// readiness probe from becoming a liveness problem. The health client is capped
// at three seconds, so an upstream that accepts the connection and then never
// answers still produces a verdict rather than holding the probe open until
// kubelet's own timeout fires and reports a probe failure with no detail.
func TestReadyzBoundsHowLongAHangingUpstreamCanStallIt(t *testing.T) {
	release := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer hang.Close()
	defer close(release)

	honeypot := newUpstreamProbe(t, http.StatusOK)
	hh := NewHealthHandler(hang.URL, honeypot.srv.URL)

	start := time.Now()
	w := httptest.NewRecorder()
	hh.Readyz(w, httptest.NewRequest(http.MethodGet, "/bridge/readyz", nil))
	elapsed := time.Since(start)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	if doc := decodeReadyz(t, w.Body.Bytes()); doc["real"] != "down" {
		t.Errorf("real field = %q, want down", doc["real"])
	}
	if elapsed > 10*time.Second {
		t.Errorf("Readyz took %v against a hanging upstream, want it bounded by the client timeout", elapsed)
	}
	if elapsed < time.Second {
		t.Errorf("Readyz returned in %v, so it did not actually wait on the hanging upstream", elapsed)
	}
}

// TestCheckUpstreamAcceptsOnly200 pins the readiness bar. A vault that answers
// 204, or that redirects /healthz to a login page, is not a vault that can serve
// traffic, and treating any non-error response as healthy would let the bridge
// declare itself ready in front of a broken upstream.
func TestCheckUpstreamAcceptsOnly200(t *testing.T) {
	tests := []struct {
		status int
		want   bool
	}{
		{http.StatusOK, true},
		{http.StatusNoContent, false},
		{http.StatusPartialContent, false},
		{http.StatusUnauthorized, false},
		{http.StatusInternalServerError, false},
		{http.StatusServiceUnavailable, false},
	}

	for _, tt := range tests {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			probe := newUpstreamProbe(t, tt.status)
			hh := NewHealthHandler(probe.srv.URL, probe.srv.URL)

			if got := hh.checkUpstream(probe.srv.URL); got != tt.want {
				t.Errorf("checkUpstream on %d = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

// TestBoolToStatus keeps the two words the readiness document is built from from
// drifting, since dashboards and alert rules match on them.
func TestBoolToStatus(t *testing.T) {
	if got := boolToStatus(true); got != "up" {
		t.Errorf("boolToStatus(true) = %q, want %q", got, "up")
	}
	if got := boolToStatus(false); got != "down" {
		t.Errorf("boolToStatus(false) = %q, want %q", got, "down")
	}
}
