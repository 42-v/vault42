package main

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// HealthHandler provides liveness and readiness probes.
type HealthHandler struct {
	realUpstream     string
	honeypotUpstream string
	client           *http.Client

	// Cached probe result, so an unauthenticated caller cannot drive one
	// upstream request per probe into each upstream.
	mu         sync.Mutex
	checkedAt  time.Time
	realOK     bool
	honeypotOK bool
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

// readyCacheTTL bounds how often a probe reaches the upstreams.
//
// /bridge/readyz is on the public listener, ahead of every scoring path, and
// each call used to fan out to both upstreams: 200 unauthenticated requests
// produced 200 real plus 200 honeypot hits with nothing counting them. One
// second of cache keeps the kubelet's view fresh and turns the amplifier into
// a constant.
const readyCacheTTL = time.Second

// Readyz checks both upstreams are reachable.
//
// detailed is true only for a caller that presented the admin token. An
// anonymous caller gets the status code and an empty body: the per-upstream
// breakdown named the honeypot, which is exactly what the deception design
// promises a client cannot learn.
func (hh *HealthHandler) Readyz(w http.ResponseWriter, _ *http.Request, detailed bool) {
	realOK, honeypotOK := hh.probe()

	status := "ready"
	code := http.StatusOK
	if !realOK || !honeypotOK {
		status = "not_ready"
		code = http.StatusServiceUnavailable
	}

	if !detailed {
		w.WriteHeader(code)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]interface{}{ // #nosec G104 -- health response best-effort
		"status":   status,
		"real":     boolToStatus(realOK),
		"honeypot": boolToStatus(honeypotOK),
	})
}

// probe returns the cached upstream state, refreshing it at most once per
// readyCacheTTL.
func (hh *HealthHandler) probe() (realOK, honeypotOK bool) {
	hh.mu.Lock()
	defer hh.mu.Unlock()
	if time.Since(hh.checkedAt) < readyCacheTTL {
		return hh.realOK, hh.honeypotOK
	}
	hh.realOK = hh.checkUpstream(hh.realUpstream)
	hh.honeypotOK = hh.checkUpstream(hh.honeypotUpstream)
	hh.checkedAt = time.Now()
	return hh.realOK, hh.honeypotOK
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
