package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

// TestMainStartsServesAndShutsDown drives the real entry point rather than the
// handler, because everything main does between LoadConfig and Shutdown exists
// only there: the server timeouts, the reaper goroutine, the signal handling and
// the ordering between them. A bridge that parsed its configuration correctly
// but never wired the handler onto the listener, or that ignored SIGTERM and got
// killed mid-request on every rolling update, would pass every other test in
// this package.
//
// The test calls main in a goroutine and then signals the test process itself.
// That is safe because main registers its signal handler before it starts
// listening, so the listener answering is proof the handler is installed and the
// signal will be delivered to main's channel rather than terminating the run.
func TestMainStartsServesAndShutsDown(t *testing.T) {
	realVault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("X-Upstream", "real")
		io.WriteString(w, `{"upstream":"real"}`) // #nosec G104 -- test upstream response
	}))
	defer realVault.Close()

	honeypotVault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("X-Upstream", "honeypot")
		io.WriteString(w, `{"upstream":"honeypot"}`) // #nosec G104 -- test upstream response
	}))
	defer honeypotVault.Close()

	// deadAddr binds a port and releases it, which is the usual way to get one
	// that is free right now.
	listenAddr := deadAddr(t)

	tokenFile := filepath.Join(t.TempDir(), "admin-token")
	const adminToken = "main-test-admin-token"
	if err := os.WriteFile(tokenFile, []byte(adminToken+"\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	// A flag written by this process has to reach Redis, which is what lets the
	// next pod in a rolling update inherit it. Wiring the fake in here is the
	// only place that whole path runs from configuration rather than from a
	// hand-built FlagStore.
	redis := newFakeRedis(t)
	// A flag left over from a previous bridge run, which startup must restore.
	redis.preload("bridge:flag:203.0.113.99", "auto:score|140|"+time.Now().Format(time.RFC3339))

	clearBridgeEnv(t)
	t.Setenv("BRIDGE_LISTEN_ADDR", listenAddr)
	t.Setenv("BRIDGE_REAL_UPSTREAM", realVault.URL)
	t.Setenv("BRIDGE_HONEYPOT_UPSTREAM", honeypotVault.URL)
	t.Setenv("BRIDGE_ADMIN_TOKEN_FILE", tokenFile)
	t.Setenv("BRIDGE_REDIS_ADDR", redis.addr())
	t.Setenv("BRIDGE_FLAG_THRESHOLD", "30")
	t.Setenv("BRIDGE_LOG_LEVEL", "debug")

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		main()
	}()

	// Wait for the listener. Its readiness is also the happens-before edge that
	// makes the signal below safe to send.
	base := "http://" + listenAddr
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(20 * time.Second)
	var up bool
	for time.Now().Before(deadline) {
		resp, err := client.Get(base + "/bridge/healthz")
		if err == nil {
			resp.Body.Close()
			up = resp.StatusCode == http.StatusOK
			if up {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !up {
		t.Fatalf("the bridge never started listening on %s", listenAddr)
	}

	t.Run("readiness reports both upstreams", func(t *testing.T) {
		resp, err := client.Get(base + "/bridge/readyz")
		if err != nil {
			t.Fatalf("GET readyz: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		var doc map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if doc["status"] != "ready" || doc["real"] != "up" || doc["honeypot"] != "up" {
			t.Errorf("readyz = %v, want ready with both upstreams up", doc)
		}
	})

	t.Run("clean traffic reaches the real vault", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, base+"/auth/login", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("User-Agent", benignUA)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if servedBy(t, string(body)) != "real" {
			t.Errorf("served by %q, want real", servedBy(t, string(body)))
		}
	})

	t.Run("the admin token was read from its file and Redis was restored", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, base+"/bridge/flags", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+adminToken)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET flags: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d; the token file was not loaded", resp.StatusCode, http.StatusOK)
		}

		var doc struct {
			Flags []FlagEntry `json:"flags"`
			Count int         `json:"count"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if doc.Count != 1 || len(doc.Flags) != 1 {
			t.Fatalf("flag list = %+v, want the one flag preloaded into Redis", doc)
		}
		if doc.Flags[0].IP != "203.0.113.99" || doc.Flags[0].Score != 140 {
			t.Errorf("restored flag = %+v, want 203.0.113.99 with score 140", doc.Flags[0])
		}
	})

	t.Run("a decoy hit routes the caller to the honeypot", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, base+"/wp-admin", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("User-Agent", benignUA)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET wp-admin: %v", err)
		}
		io.Copy(io.Discard, resp.Body) // #nosec G104 -- draining for connection reuse
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("decoy status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		follow, err := http.NewRequest(http.MethodGet, base+"/auth/login", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		follow.Header.Set("User-Agent", benignUA)
		resp, err = client.Do(follow)
		if err != nil {
			t.Fatalf("GET after decoy: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if servedBy(t, string(body)) != "honeypot" {
			t.Errorf("served by %q after a decoy hit, want honeypot", servedBy(t, string(body)))
		}

		// The flag has to be written through to Redis, otherwise it dies with
		// this process and the attacker is handed back to the real vault by the
		// next pod.
		stored, ok := redis.snapshot()["bridge:flag:127.0.0.1"]
		if !ok {
			t.Fatalf("Redis holds %v, want a flag for 127.0.0.1", redis.snapshot())
		}
		if !strings.HasPrefix(stored, "decoy:/wp-admin|100|") {
			t.Errorf("stored flag = %q, want it to record the decoy path and score", stored)
		}
	})

	// SIGTERM is what Kubernetes sends first on every rolling update, so a
	// bridge that did not shut down on it would be killed after the grace period
	// with connections still open.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("signal self: %v", err)
	}

	select {
	case <-returned:
	case <-time.After(30 * time.Second):
		t.Fatal("main did not return after SIGTERM")
	}

	// The listener must be released, not merely stopped accepting, or the next
	// pod in a rolling update could not bind it.
	conn, err := net.DialTimeout("tcp", listenAddr, 2*time.Second)
	if err == nil {
		conn.Close() // #nosec G104 -- test client cleanup
		t.Errorf("%s still accepts connections after shutdown", listenAddr)
	}
}
