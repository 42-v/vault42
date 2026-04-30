//go:build stress

package stress

import (
	"crypto/rand"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

// --- Tier 1: Core Auth ---

func TestStress_Healthz(t *testing.T) {
	skipIfUnreachable(t)
	client := stressClient()

	result := runWorkers(t, concurrency, duration, func() (int, time.Duration) {
		resp, lat, err := getJSON(client, baseURL+"/healthz", nil)
		if err != nil {
			return 0, lat
		}
		resp.Body.Close()
		return resp.StatusCode, lat
	})

	result.Report(t, "TestStress_Healthz")
	if result.ServerErr > 0 {
		t.Errorf("server errors: %d", result.ServerErr)
	}
	if result.Total == 0 {
		t.Fatal("no requests completed")
	}
	totalPerSec := float64(result.Total) / duration.Seconds()
	if totalPerSec < 10 {
		t.Errorf("throughput too low: %.1f req/s (want >10)", totalPerSec)
	}
}

func TestStress_Login(t *testing.T) {
	skipIfUnreachable(t)
	client := stressClient()

	t.Log("provisioning 10 users...")
	users := provisionUsers(t, 10)
	t.Logf("provisioned %d users", len(users))

	result := runWorkers(t, concurrency, duration, func() (int, time.Duration) {
		idx := randInt(len(users))
		u := users[idx]
		resp, lat, err := postJSON(client, baseURL+"/auth/login", map[string]string{
			"email":    u.Email,
			"password": testPass,
		}, spoofHeaders(nil))
		if err != nil {
			return 0, lat
		}
		resp.Body.Close()
		return resp.StatusCode, lat
	})

	result.Report(t, "TestStress_Login")
	if result.ServerErr > 0 {
		t.Errorf("server errors: %d", result.ServerErr)
	}
}

func TestStress_Register(t *testing.T) {
	skipIfUnreachable(t)
	client := stressClient()

	result := runWorkers(t, concurrency, duration, func() (int, time.Duration) {
		email := uniqueEmail("reg")
		resp, lat, err := postJSON(client, baseURL+"/auth/register", map[string]string{
			"email":    email,
			"password": testPass,
		}, spoofHeaders(nil))
		if err != nil {
			return 0, lat
		}
		resp.Body.Close()
		return resp.StatusCode, lat
	})

	result.Report(t, "TestStress_Register")
	if result.ServerErr > 0 {
		t.Errorf("server errors: %d", result.ServerErr)
	}
}

func TestStress_Refresh(t *testing.T) {
	skipIfUnreachable(t)
	client := stressClient()

	t.Log("provisioning 1 user for refresh race...")
	user := provisionUser(t, client)
	if user.RefreshToken == "" {
		t.Fatal("no refresh token from login")
	}

	// Each round: all workers race to refresh the same token.
	// First one wins (200), rest get 401 (replay detection).
	result := runWorkers(t, concurrency, duration, func() (int, time.Duration) {
		req, _ := http.NewRequest("POST", baseURL+"/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "__Host-refresh_token", Value: user.RefreshToken})
		start := time.Now()
		resp, err := client.Do(req) // #nosec G107 -- test code
		lat := time.Since(start)
		if err != nil {
			return 0, lat
		}
		resp.Body.Close()
		return resp.StatusCode, lat
	})

	result.Report(t, "TestStress_Refresh")
	if result.ServerErr > 0 {
		t.Errorf("server errors: %d", result.ServerErr)
	}
	// Most should be 401 (replay) except the first one per round
	t.Logf("  (expected: mostly 401 replay detection, some 200)")
}

func TestStress_Logout(t *testing.T) {
	skipIfUnreachable(t)
	client := stressClient()

	t.Log("provisioning 10 users for logout test...")
	users := provisionUsers(t, 10)

	result := runWorkers(t, concurrency, duration, func() (int, time.Duration) {
		idx := randInt(len(users))
		u := users[idx]
		resp, lat, err := postJSON(client, baseURL+"/auth/logout", nil, map[string]string{
			"Authorization": "Bearer " + u.AccessToken,
		})
		if err != nil {
			return 0, lat
		}
		resp.Body.Close()
		return resp.StatusCode, lat
	})

	result.Report(t, "TestStress_Logout")
	if result.ServerErr > 0 {
		t.Errorf("server errors: %d", result.ServerErr)
	}
}

// --- Tier 2: Data Endpoints ---

func TestStress_Profile(t *testing.T) {
	skipIfUnreachable(t)
	client := stressClient()

	t.Log("provisioning 10 users for profile test...")
	users := provisionUsers(t, 10)

	result := runWorkers(t, concurrency, duration, func() (int, time.Duration) {
		idx := randInt(len(users))
		u := users[idx]
		resp, lat, err := getJSON(client, baseURL+"/user/profile", map[string]string{
			"Authorization": "Bearer " + u.AccessToken,
		})
		if err != nil {
			return 0, lat
		}
		resp.Body.Close()
		return resp.StatusCode, lat
	})

	result.Report(t, "TestStress_Profile")
	if result.ServerErr > 0 {
		t.Errorf("server errors: %d", result.ServerErr)
	}
}

func TestStress_Sessions(t *testing.T) {
	skipIfUnreachable(t)
	client := stressClient()

	t.Log("provisioning 10 users for sessions test...")
	users := provisionUsers(t, 10)

	result := runWorkers(t, concurrency, duration, func() (int, time.Duration) {
		idx := randInt(len(users))
		u := users[idx]
		resp, lat, err := getJSON(client, baseURL+"/user/sessions", map[string]string{
			"Authorization": "Bearer " + u.AccessToken,
		})
		if err != nil {
			return 0, lat
		}
		resp.Body.Close()
		return resp.StatusCode, lat
	})

	result.Report(t, "TestStress_Sessions")
	if result.ServerErr > 0 {
		t.Errorf("server errors: %d", result.ServerErr)
	}
}

func TestStress_JWKS(t *testing.T) {
	skipIfUnreachable(t)
	client := stressClient()

	result := runWorkers(t, concurrency, duration, func() (int, time.Duration) {
		resp, lat, err := getJSON(client, baseURL+"/.well-known/jwks.json", nil)
		if err != nil {
			return 0, lat
		}
		resp.Body.Close()
		return resp.StatusCode, lat
	})

	result.Report(t, "TestStress_JWKS")
	if result.ServerErr > 0 {
		t.Errorf("server errors: %d", result.ServerErr)
	}
}

// --- Tier 3: Edge Cases ---

func TestStress_OversizePayload(t *testing.T) {
	skipIfUnreachable(t)
	client := stressClient()

	// 16KB payload — large enough to trigger body size rejection
	bigBody := strings.Repeat("A", 16*1024)
	// Fewer workers to avoid overwhelming server with large payloads
	workers := concurrency / 5
	if workers < 1 {
		workers = 1
	}

	result := runWorkers(t, workers, duration, func() (int, time.Duration) {
		req, _ := http.NewRequest("POST", baseURL+"/auth/login", strings.NewReader(bigBody))
		req.Header.Set("Content-Type", "application/json")
		start := time.Now()
		resp, err := client.Do(req) // #nosec G107 -- test code
		lat := time.Since(start)
		if err != nil {
			return 0, lat
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
		return resp.StatusCode, lat
	})

	result.Report(t, "TestStress_OversizePayload")
	if result.ServerErr > 0 {
		t.Errorf("server errors: %d (want 0 — should be 4xx rejections)", result.ServerErr)
	}
}

func TestStress_ConnectionExhaustion(t *testing.T) {
	skipIfUnreachable(t)

	const hardcodedWorkers = 200
	result := runWorkers(t, hardcodedWorkers, duration, func() (int, time.Duration) {
		// Fresh connection each time — no keep-alive
		client := freshConnClient()
		resp, lat, err := getJSON(client, baseURL+"/healthz", nil)
		if err != nil {
			return 0, lat
		}
		resp.Body.Close()
		return resp.StatusCode, lat
	})

	result.Report(t, "TestStress_ConnectionExhaustion")
	if result.ServerErr > 0 {
		t.Errorf("server errors: %d", result.ServerErr)
	}
}

func TestStress_Frontend(t *testing.T) {
	skipIfUnreachable(t)
	client := stressClient()

	// Quick check if frontend is enabled
	resp, _, err := getJSON(client, baseURL+"/", nil)
	if err != nil {
		t.Fatalf("frontend check: %v", err)
	}
	ct := resp.Header.Get("Content-Type")
	resp.Body.Close()
	if resp.StatusCode == 404 || !strings.Contains(ct, "text/html") {
		t.Skip("frontend not enabled (VAULT_SERVE_FRONTEND=false)")
	}

	result := runWorkers(t, concurrency, duration, func() (int, time.Duration) {
		resp, lat, err := getJSON(client, baseURL+"/", nil)
		if err != nil {
			return 0, lat
		}
		ct := resp.Header.Get("Content-Type")
		resp.Body.Close()
		if resp.StatusCode == 200 && !strings.Contains(ct, "text/html") {
			// Count wrong content-type as client error for reporting
			return 400, lat
		}
		return resp.StatusCode, lat
	})

	result.Report(t, "TestStress_Frontend")
	if result.ServerErr > 0 {
		t.Errorf("server errors: %d", result.ServerErr)
	}
}

func TestStress_Spike(t *testing.T) {
	skipIfUnreachable(t)
	client := stressClient()

	phases := []struct {
		name    string
		workers int
		dur     time.Duration
	}{
		{"warm-up", 5, 10 * time.Second},
		{"spike", 50, 10 * time.Second},
		{"cool-down", 5, 10 * time.Second},
	}

	for _, phase := range phases {
		t.Logf("phase: %s (%d workers, %s)", phase.name, phase.workers, phase.dur)
		result := runWorkers(t, phase.workers, phase.dur, func() (int, time.Duration) {
			resp, lat, err := getJSON(client, baseURL+"/healthz", nil)
			if err != nil {
				return 0, lat
			}
			resp.Body.Close()
			return resp.StatusCode, lat
		})
		result.Report(t, "TestStress_Spike/"+phase.name)
		if result.ServerErr > 0 {
			t.Errorf("phase %s: server errors: %d", phase.name, result.ServerErr)
		}
	}
}

// randInt returns a random int in [0, n) using crypto/rand.
func randInt(n int) int {
	if n <= 1 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}
