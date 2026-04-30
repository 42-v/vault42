package main

import (
	"encoding/json"
	"net/http"
	"time"
)

// HealthHandler provides liveness and readiness probes.
type HealthHandler struct {
	realUpstream     string
	honeypotUpstream string
	client           *http.Client
}

// NewHealthHandler creates health check handlers.
func NewHealthHandler(realUpstream, honeypotUpstream string) *HealthHandler {
	return &HealthHandler{
		realUpstream:     realUpstream,
		honeypotUpstream: honeypotUpstream,
		client: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

// Healthz is a simple liveness probe — always returns 200 if the bridge is running.
func (hh *HealthHandler) Healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"}) // #nosec G104 -- health response best-effort
}

// Readyz checks both upstreams are reachable.
func (hh *HealthHandler) Readyz(w http.ResponseWriter, _ *http.Request) {
	realOK := hh.checkUpstream(hh.realUpstream)
	honeypotOK := hh.checkUpstream(hh.honeypotUpstream)

	status := "ready"
	code := http.StatusOK
	if !realOK || !honeypotOK {
		status = "not_ready"
		code = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]interface{}{ // #nosec G104 -- health response best-effort
		"status":   status,
		"real":     boolToStatus(realOK),
		"honeypot": boolToStatus(honeypotOK),
	})
}

func (hh *HealthHandler) checkUpstream(baseURL string) bool {
	resp, err := hh.client.Get(baseURL + "/healthz") // #nosec G107 -- upstream URLs are operator-configured
	if err != nil {
		return false
	}
	resp.Body.Close() // #nosec G104 -- health check best-effort cleanup
	return resp.StatusCode == http.StatusOK
}

func boolToStatus(ok bool) string {
	if ok {
		return "up"
	}
	return "down"
}
