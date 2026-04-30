//go:build honeypot_e2e

// Package honeypot_test provides end-to-end tests for the bridge + honeypot
// deployment. These tests spin up real containers (2x Postgres, 2x Vault, bridge)
// and exercise the full detection → flagging → routing flow.
//
// Run manually: go test -tags honeypot_e2e -count=1 -v -timeout 5m ./tests/honeypot/...
package honeypot_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// testEnv holds references to all containers for a bridge E2E test.
type testEnv struct {
	realPG      *postgres.PostgresContainer
	honeypotPG  *postgres.PostgresContainer
	realVault   testcontainers.Container
	honeypotVault testcontainers.Container
	bridge      testcontainers.Container
	bridgeURL   string
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()

	// Start two PostgreSQL containers
	realPG, err := postgres.Run(ctx, "postgres:17-alpine",
		postgres.WithDatabase("vault"),
		postgres.WithUsername("vault_mig"),
		postgres.WithPassword("test-mig-password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start real postgres: %v", err)
	}
	t.Cleanup(func() { realPG.Terminate(ctx) })

	honeypotPG, err := postgres.Run(ctx, "postgres:17-alpine",
		postgres.WithDatabase("vault_honeypot"),
		postgres.WithUsername("vault_mig"),
		postgres.WithPassword("test-mig-password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start honeypot postgres: %v", err)
	}
	t.Cleanup(func() { honeypotPG.Terminate(ctx) })

	realPGHost, _ := realPG.Host(ctx)
	realPGPort, _ := realPG.MappedPort(ctx, "5432/tcp")
	hpPGHost, _ := honeypotPG.Host(ctx)
	hpPGPort, _ := honeypotPG.MappedPort(ctx, "5432/tcp")

	// Common Vault env
	commonEnv := map[string]string{
		"VAULT_AUTO_MIGRATE":       "true",
		"VAULT_TLS_ENABLED":        "false",
		"VAULT_ORIGIN":             "http://localhost",
		"VAULT_APP_NAME":           "Test Vault",
		"VAULT_PASSWORD_MIN_LENGTH": "15",
		"DB_PORT":                  "5432",
		"DB_SSLMODE":              "disable",
		"DB_MAX_CONNS":            "5",
		"DB_MIG_USER":             "vault_mig",
		"DB_MIG_PASSWORD":         "test-mig-password",
		"DB_APP_USER":             "vault_mig",
		"DB_APP_PASSWORD":         "test-mig-password",
		"CACHE_BACKEND":           "memory",
		"LISTEN_ADDR":             ":8080",
		"VAULT_RATE_LIMIT_ENABLED": "false",
	}

	// Real Vault
	realEnv := copyMap(commonEnv)
	realEnv["VAULT_PROFILE"] = "dev"
	realEnv["DB_HOST"] = realPGHost
	realEnv["DB_PORT"] = realPGPort.Port()
	realEnv["DB_NAME"] = "vault"
	// Mark responses so we can distinguish which upstream handled the request
	realEnv["VAULT_APP_NAME"] = "Real Vault"

	realVault, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "vault:dev",
			ExposedPorts: []string{"8080/tcp"},
			Env:          realEnv,
			WaitingFor:   wait.ForHTTP("/healthz").WithPort("8080/tcp").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start real vault: %v", err)
	}
	t.Cleanup(func() { realVault.Terminate(ctx) })

	// Honeypot Vault
	hpEnv := copyMap(commonEnv)
	hpEnv["VAULT_PROFILE"] = "honeypot"
	hpEnv["DB_HOST"] = hpPGHost
	hpEnv["DB_PORT"] = hpPGPort.Port()
	hpEnv["DB_NAME"] = "vault_honeypot"
	hpEnv["VAULT_SERVE_FRONTEND"] = "true"
	hpEnv["VAULT_APP_NAME"] = "Honeypot Vault"

	honeypotVault, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "vault:dev",
			ExposedPorts: []string{"8080/tcp"},
			Env:          hpEnv,
			WaitingFor:   wait.ForHTTP("/healthz").WithPort("8080/tcp").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start honeypot vault: %v", err)
	}
	t.Cleanup(func() { honeypotVault.Terminate(ctx) })

	realVaultHost, _ := realVault.Host(ctx)
	realVaultPort, _ := realVault.MappedPort(ctx, "8080/tcp")
	hpVaultHost, _ := honeypotVault.Host(ctx)
	hpVaultPort, _ := honeypotVault.MappedPort(ctx, "8080/tcp")

	// Bridge
	bridgeEnv := map[string]string{
		"BRIDGE_LISTEN_ADDR":          ":8080",
		"BRIDGE_REAL_UPSTREAM":        fmt.Sprintf("http://%s:%s", realVaultHost, realVaultPort.Port()),
		"BRIDGE_HONEYPOT_UPSTREAM":    fmt.Sprintf("http://%s:%s", hpVaultHost, hpVaultPort.Port()),
		"BRIDGE_RATE_THRESHOLD":       "10",
		"BRIDGE_RATE_WINDOW":          "1m",
		"BRIDGE_LOGIN_FAIL_THRESHOLD": "3",
		"BRIDGE_LOGIN_FAIL_WINDOW":    "5m",
		"BRIDGE_FLAG_TTL":             "1h",
		"BRIDGE_FLAG_THRESHOLD":       "100",
		"BRIDGE_ADMIN_TOKEN":          "e2e-test-token",
		"BRIDGE_LOG_LEVEL":            "debug",
	}

	bridge, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "vault-bridge:dev",
			ExposedPorts: []string{"8080/tcp"},
			Env:          bridgeEnv,
			WaitingFor:   wait.ForHTTP("/bridge/healthz").WithPort("8080/tcp").WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start bridge: %v", err)
	}
	t.Cleanup(func() { bridge.Terminate(ctx) })

	bridgeHost, _ := bridge.Host(ctx)
	bridgePort, _ := bridge.MappedPort(ctx, "8080/tcp")

	return &testEnv{
		realPG:        realPG,
		honeypotPG:    honeypotPG,
		realVault:     realVault,
		honeypotVault: honeypotVault,
		bridge:        bridge,
		bridgeURL:     fmt.Sprintf("http://%s:%s", bridgeHost, bridgePort.Port()),
	}
}

func TestBridgeCleanTraffic(t *testing.T) {
	env := setupTestEnv(t)

	resp, err := http.Get(env.bridgeURL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz status = %d, want 200", resp.StatusCode)
	}
}

func TestBridgeDecoyPathFlags(t *testing.T) {
	env := setupTestEnv(t)

	resp, err := http.Get(env.bridgeURL + "/wp-admin")
	if err != nil {
		t.Fatalf("GET /wp-admin: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("decoy status = %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "WordPress") {
		t.Error("expected WordPress decoy page")
	}
}

func TestBridgeAdminFlagUnflag(t *testing.T) {
	env := setupTestEnv(t)
	client := &http.Client{Timeout: 10 * time.Second}

	// Flag an IP
	flagBody := `{"ip":"192.168.1.100","reason":"e2e test"}`
	req, _ := http.NewRequest(http.MethodPost, env.bridgeURL+"/bridge/flag", strings.NewReader(flagBody))
	req.Header.Set("Authorization", "Bearer e2e-test-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /bridge/flag: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("flag status = %d, want 201", resp.StatusCode)
	}

	// List flags
	req, _ = http.NewRequest(http.MethodGet, env.bridgeURL+"/bridge/flags", nil)
	req.Header.Set("Authorization", "Bearer e2e-test-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /bridge/flags: %v", err)
	}
	defer resp.Body.Close()

	var listResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&listResp)
	if count, ok := listResp["count"].(float64); !ok || count < 1 {
		t.Errorf("expected at least 1 flag, got %v", listResp["count"])
	}

	// Unflag
	unflagBody := `{"ip":"192.168.1.100"}`
	req, _ = http.NewRequest(http.MethodDelete, env.bridgeURL+"/bridge/flag", strings.NewReader(unflagBody))
	req.Header.Set("Authorization", "Bearer e2e-test-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("DELETE /bridge/flag: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("unflag status = %d, want 200", resp.StatusCode)
	}
}

func TestBridgeHealthEndpoints(t *testing.T) {
	env := setupTestEnv(t)

	for _, path := range []string{"/bridge/healthz", "/bridge/readyz"} {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(env.bridgeURL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("%s status = %d, want 200", path, resp.StatusCode)
			}

			var body map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&body)
			if body["status"] == nil {
				t.Errorf("%s response missing 'status' field", path)
			}
		})
	}
}

func TestBridgeAutomationUAScoring(t *testing.T) {
	env := setupTestEnv(t)
	client := &http.Client{Timeout: 10 * time.Second}

	// Send request with automation UA — should be scored but not immediately flagged
	// (score 30 < threshold 100)
	req, _ := http.NewRequest(http.MethodGet, env.bridgeURL+"/healthz", nil)
	req.Header.Set("User-Agent", "sqlmap/1.5#stable")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET with sqlmap UA: %v", err)
	}
	resp.Body.Close()

	// Should still get a response (routed to real vault on first hit)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func copyMap(m map[string]string) map[string]string {
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}
