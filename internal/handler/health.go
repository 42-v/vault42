package handler

import "net/http"

// Healthz handles GET /healthz (liveness check).
// Version is intentionally omitted to avoid information disclosure.
func Healthz(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, StatusResponse{Status: "ok"})
}

// ReadyzDeps holds dependencies for the readiness probe handler.
type ReadyzDeps struct {
	// PingDB, when non-nil, is called on every GET /readyz. A non-nil
	// error makes the probe return 503 with status=not_ready and
	// database=down. Nil skips the database check entirely.
	PingDB func() error
	// PingCache, when non-nil, is called on every GET /readyz. A non-nil
	// error is reported as cache=degraded but does not fail the probe,
	// because a cache outage must not take the process out of rotation.
	// Nil skips the cache check.
	PingCache func() error
}

// Readyz handles GET /readyz (readiness check).
func Readyz(deps *ReadyzDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := map[string]string{"status": "ready"}

		if deps.PingDB != nil {
			if err := deps.PingDB(); err != nil {
				status["status"] = "not_ready"
				status["database"] = "down"
				WriteJSON(w, http.StatusServiceUnavailable, status)
				return
			}
			status["database"] = "up"
		}

		if deps.PingCache != nil {
			if err := deps.PingCache(); err != nil {
				status["cache"] = "degraded"
			} else {
				status["cache"] = "up"
			}
		}

		WriteJSON(w, http.StatusOK, status)
	}
}
