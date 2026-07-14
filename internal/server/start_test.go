package server

import (
	"net"
	"net/http"
	"syscall"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/config"
	"github.com/42-v/vault42/internal/handler"
)

func startTestDeps(t *testing.T, addr string) *Deps {
	t.Helper()
	memCache := cache.NewMemoryCache()
	t.Cleanup(func() { _ = memCache.Close() })

	return &Deps{
		Config: &config.Config{
			Origin:            "https://vault.localhost",
			AppName:           "Vault Test",
			PasswordMinLength: 15,
			ListenAddr:        addr,
			Profile:           config.ProfileDev,
			ShutdownTimeout:   2 * time.Second,
		},
		Cache:     memCache,
		ReadyDeps: &handler.ReadyzDeps{},
	}
}

// Start wires the entire middleware chain and the graceful-shutdown path — the
// code every single request passes through, and the code that decides whether a
// rolling deploy drops connections. It was completely untested: setupRoutes was
// exercised directly, so nothing ever built the chain around it or proved the
// server comes up, serves, and stops cleanly on SIGTERM.
func TestStart_ServesThenShutsDownCleanly(t *testing.T) {
	// Port 0: let the kernel choose, so the test cannot collide with anything.
	deps := startTestDeps(t, "127.0.0.1:0")

	// Bind first to learn the port, then hand the address to the server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	deps.Config.ListenAddr = addr

	s := New(deps)

	errCh := make(chan error, 1)
	go func() { errCh <- s.Start() }()

	// Wait for the listener to come up.
	var conn net.Conn
	for i := 0; i < 100; i++ {
		conn, err = net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if conn == nil {
		t.Fatalf("server never started listening on %s: %v", addr, err)
	}
	_ = conn.Close()

	// A request must actually traverse the chain Start built.
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("request through the middleware chain failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", resp.StatusCode)
	}
	// The security headers middleware is in the chain; if the chain were not
	// assembled, the response would come back bare.
	if resp.Header.Get("X-Content-Type-Options") == "" {
		t.Error("security headers missing — the middleware chain was not applied")
	}

	// SIGTERM is how Kubernetes stops a pod. Start must return nil, not an error:
	// a non-nil return here would make the process exit non-zero on every normal
	// rollout.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("signal: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("graceful shutdown returned an error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not shut down on SIGTERM")
	}
}

// A port that cannot be bound must surface as an error rather than a silent
// no-op — otherwise a misconfigured pod would report healthy while serving
// nothing.
func TestStart_BindFailureIsReported(t *testing.T) {
	// Hold the port so the server cannot have it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	deps := startTestDeps(t, ln.Addr().String())
	s := New(deps)

	if err := s.Start(); err == nil {
		t.Error("Start returned nil when the address was already in use")
	}
}
