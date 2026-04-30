package handler

import "net/http"

// Healthz handles GET /healthz (liveness check).
// Version is intentionally omitted to avoid information disclosure.
func Healthz(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, StatusResponse{Status: "ok"})
}

// ReadyzDeps holds dependencies for the readiness probe handler.
type ReadyzDeps struct {
	PingDB    func() error
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
