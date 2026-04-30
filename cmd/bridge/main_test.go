package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBridgeRouting(t *testing.T) {
	// Set up mock upstreams
	realServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "real")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"upstream":"real"}`))
	}))
	defer realServer.Close()

	honeypotServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "honeypot")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"upstream":"honeypot"}`))
	}))
	defer honeypotServer.Close()

	cfg := &Config{
		ListenAddr:         ":0",
		RealUpstream:       realServer.URL,
		HoneypotUpstream:   honeypotServer.URL,
		RateThreshold:      100,
		RateWindow:         time.Minute,
		LoginFailThreshold: 5,
		LoginFailWindow:    15 * time.Minute,
		FlagTTL:            time.Hour,
		FlagThreshold:      100,
		LogLevel:           "info",
	}

	bridge, err := NewBridge(cfg)
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}
	defer bridge.Close()

	ts := httptest.NewServer(bridge)
	defer ts.Close()

	t.Run("clean traffic goes to real", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/auth/login")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "real") {
			t.Errorf("expected real upstream, got %s", body)
		}
	})

	t.Run("flagged IP goes to honeypot", func(t *testing.T) {
		bridge.flags.Flag("127.0.0.1", "test", 100)

		resp, err := http.Get(ts.URL + "/auth/login")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "honeypot") {
			t.Errorf("expected honeypot upstream, got %s", body)
		}

		bridge.flags.Unflag("127.0.0.1")
	})

	t.Run("decoy path flags and serves HTML", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/wp-admin")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "WordPress") {
			t.Errorf("expected WordPress decoy page")
		}

		// Clean up — decoy flagged 127.0.0.1
		bridge.flags.Unflag("127.0.0.1")
	})

	t.Run("bridge health endpoint", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/bridge/healthz")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})

	t.Run("automation UA gets scored", func(t *testing.T) {
		// Reset score state from previous subtests (Go's default http client
		// has "Go-http-client" UA which also scores, accumulating across subtests)
		bridge.scores.mu.Lock()
		delete(bridge.scores.scores, "127.0.0.1")
		bridge.scores.mu.Unlock()

		// This single request scores 30 (below threshold of 100)
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth/login", nil)
		req.Header.Set("User-Agent", "sqlmap/1.5")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()

		// Score 30 < threshold 100, so still goes to real
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "real") {
			t.Errorf("expected real upstream for first automation request, got %s", body)
		}
	})
}
