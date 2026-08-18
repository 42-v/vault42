package server

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/config"
	"github.com/42-v/vault42/internal/metrics"
)

func testCollector() *metrics.Collector {
	return metrics.NewCollector(
		func() int64 { return 0 },
		func() int64 { return 0 },
		func() int { return 0 },
	)
}

// freeAddr returns a loopback address nothing is listening on.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// waitForListener blocks until addr accepts a connection, or the test gives up.
func waitForListener(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("nothing ever listened on %s", addr)
}

// TestMetricsIsNotOnThePublicListener is the regression for a mitigation that
// could not work as written.
//
// GET /metrics was mounted on the public mux with no auth, gated only by
// VAULT_METRICS_ENABLED, under a comment saying to protect it with a
// NetworkPolicy in production. A NetworkPolicy selects on namespace, pod and
// PORT; it has no path awareness at all, so it cannot admit /auth/login and
// refuse /metrics on the same listener. The stated mitigation was therefore not
// implementable, and the counters — process-global document read and write
// rates — were a coarse cross-client volume oracle to any in-cluster caller,
// through the same port the Service and Ingress expose.
//
// Moving the collector to its own listener is what makes the NetworkPolicy
// mitigation real: a port is exactly what a NetworkPolicy can select on.
func TestMetricsIsNotOnThePublicListener(t *testing.T) {
	cfg := &config.Config{Origin: "https://vault.localhost", AppName: "Vault Test", PasswordMinLength: 15}
	deps, mc := newTestDeps(cfg)
	defer mc.Close()
	deps.Metrics = testCollector()

	mux := New(deps).setupRoutes()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /metrics on the public mux = %d, want 404. The scrape endpoint shares the "+
			"listener the Ingress exposes, so the NetworkPolicy the comment relies on cannot "+
			"separate them.", rec.Code)
	}
}

// TestMetricsListenerServesOnItsOwnPort is the other half: the collector still
// has to be reachable, on a port an operator can fence off.
func TestMetricsListenerServesOnItsOwnPort(t *testing.T) {
	scrapeAddr := freeAddr(t)
	t.Setenv(metricsAddrEnv, scrapeAddr)

	publicAddr := freeAddr(t)
	deps := startTestDeps(t, publicAddr)
	deps.Metrics = testCollector()

	s := New(deps)
	errCh := make(chan error, 1)
	go func() { errCh <- s.Start() }()

	waitForListener(t, publicAddr)
	waitForListener(t, scrapeAddr)

	resp, err := http.Get("http://" + scrapeAddr + "/metrics")
	if err != nil {
		t.Fatalf("scrape the metrics listener: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /metrics on the metrics listener = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "vault_argon2_active") {
		t.Errorf("the metrics listener served %q, which is not the collector's output", body)
	}

	// And the public listener still refuses it.
	pub, err := http.Get("http://" + publicAddr + "/metrics")
	if err != nil {
		t.Fatalf("request the public listener: %v", err)
	}
	pub.Body.Close()
	if pub.StatusCode != http.StatusNotFound {
		t.Errorf("GET /metrics on the public listener = %d, want 404", pub.StatusCode)
	}

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("signal: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("shutdown returned an error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not shut down on SIGTERM")
	}

	if resp, err := http.Get("http://" + scrapeAddr + "/metrics"); err == nil {
		resp.Body.Close()
		t.Error("the metrics listener kept serving after shutdown; it outlives the process's drain")
	}
}

// TestMetricsBindFailureLeavesTheVaultServing keeps an observability problem
// from becoming an outage.
//
// The metrics port is now separate, so it can be taken by something else. That
// must cost the deployment its scrape, not its authentication service.
func TestMetricsBindFailureLeavesTheVaultServing(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer taken.Close()
	t.Setenv(metricsAddrEnv, taken.Addr().String())

	publicAddr := freeAddr(t)
	deps := startTestDeps(t, publicAddr)
	deps.Metrics = testCollector()

	s := New(deps)
	errCh := make(chan error, 1)
	go func() { errCh <- s.Start() }()

	waitForListener(t, publicAddr)
	resp, err := http.Get("http://" + publicAddr + "/healthz")
	if err != nil {
		t.Fatalf("the vault stopped serving because the metrics port was busy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", resp.StatusCode)
	}

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("signal: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("shutdown returned an error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not shut down on SIGTERM")
	}
}

// TestMetricsAddrDefaultsToLoopback pins the safe-by-default half.
//
// Nothing in the chart sets this variable, so the default is what a deployment
// that is not changed gets. Loopback means the scrape port is unreachable from
// the cluster until an operator deliberately opens it, which is the opposite of
// the situation this finding described: an endpoint exposed through the port
// the Ingress already published, with a mitigation that could not be written.
func TestMetricsAddrDefaultsToLoopback(t *testing.T) {
	t.Setenv(metricsAddrEnv, "")
	if got := metricsAddr(); got != defaultMetricsAddr {
		t.Errorf("metricsAddr() = %q, want %q", got, defaultMetricsAddr)
	}
	if !strings.HasPrefix(defaultMetricsAddr, "127.0.0.1:") {
		t.Errorf("the default metrics address %q is not loopback, so an unchanged deployment "+
			"publishes the scrape port to the cluster", defaultMetricsAddr)
	}

	t.Setenv(metricsAddrEnv, ":9090")
	if got := metricsAddr(); got != ":9090" {
		t.Errorf("metricsAddr() = %q, want the configured address", got)
	}
}
