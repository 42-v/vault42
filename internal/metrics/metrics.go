// Package metrics provides Prometheus-compatible metrics exposition for The Vault.
// Metrics are served in Prometheus text exposition format (text/plain; version=0.0.4)
// at GET /metrics when VAULT_METRICS_ENABLED=true. No external dependencies.
package metrics

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

// Collector aggregates operational metrics from various subsystems and exposes
// them in Prometheus text exposition format via its HTTP handler.
type Collector struct {
	// Argon2 accessors (set from crypto package)
	argon2Active        func() int64
	argon2Rejected      func() int64
	argon2MaxConcurrent func() int

	// Auth counters
	loginAttempts   atomic.Int64
	loginSuccess    atomic.Int64
	loginFailed     atomic.Int64
	tokensIssued    atomic.Int64
	tokensRefreshed atomic.Int64
}

// NewCollector creates a new metrics collector. The argon2 accessor functions
// are passed in to avoid a circular import between crypto and metrics.
func NewCollector(argon2Active, argon2Rejected func() int64, argon2MaxConcurrent func() int) *Collector {
	return &Collector{
		argon2Active:        argon2Active,
		argon2Rejected:      argon2Rejected,
		argon2MaxConcurrent: argon2MaxConcurrent,
	}
}

// RecordLoginAttempt increments the login attempts counter.
func (c *Collector) RecordLoginAttempt() { c.loginAttempts.Add(1) }

// RecordLoginSuccess increments the login success counter.
func (c *Collector) RecordLoginSuccess() { c.loginSuccess.Add(1) }

// RecordLoginFailed increments the login failure counter.
func (c *Collector) RecordLoginFailed() { c.loginFailed.Add(1) }

// RecordTokenIssued increments the token issuance counter.
func (c *Collector) RecordTokenIssued() { c.tokensIssued.Add(1) }

// RecordTokenRefreshed increments the token refresh counter.
func (c *Collector) RecordTokenRefreshed() { c.tokensRefreshed.Add(1) }

// Handler returns an http.HandlerFunc that serves Prometheus text exposition format.
func (c *Collector) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		// Argon2 metrics
		fmt.Fprintf(w, "# HELP vault_argon2_active Current number of in-flight argon2id operations.\n")
		fmt.Fprintf(w, "# TYPE vault_argon2_active gauge\n")
		fmt.Fprintf(w, "vault_argon2_active %d\n", c.argon2Active())

		fmt.Fprintf(w, "# HELP vault_argon2_max Maximum concurrent argon2id operations (semaphore capacity).\n")
		fmt.Fprintf(w, "# TYPE vault_argon2_max gauge\n")
		fmt.Fprintf(w, "vault_argon2_max %d\n", c.argon2MaxConcurrent())

		fmt.Fprintf(w, "# HELP vault_argon2_rejected_total Total argon2id requests rejected due to semaphore saturation.\n")
		fmt.Fprintf(w, "# TYPE vault_argon2_rejected_total counter\n")
		fmt.Fprintf(w, "vault_argon2_rejected_total %d\n", c.argon2Rejected())

		// Auth metrics
		fmt.Fprintf(w, "# HELP vault_login_attempts_total Total login attempts.\n")
		fmt.Fprintf(w, "# TYPE vault_login_attempts_total counter\n")
		fmt.Fprintf(w, "vault_login_attempts_total %d\n", c.loginAttempts.Load())

		fmt.Fprintf(w, "# HELP vault_login_success_total Total successful logins.\n")
		fmt.Fprintf(w, "# TYPE vault_login_success_total counter\n")
		fmt.Fprintf(w, "vault_login_success_total %d\n", c.loginSuccess.Load())

		fmt.Fprintf(w, "# HELP vault_login_failed_total Total failed logins.\n")
		fmt.Fprintf(w, "# TYPE vault_login_failed_total counter\n")
		fmt.Fprintf(w, "vault_login_failed_total %d\n", c.loginFailed.Load())

		fmt.Fprintf(w, "# HELP vault_tokens_issued_total Total access tokens issued.\n")
		fmt.Fprintf(w, "# TYPE vault_tokens_issued_total counter\n")
		fmt.Fprintf(w, "vault_tokens_issued_total %d\n", c.tokensIssued.Load())

		fmt.Fprintf(w, "# HELP vault_tokens_refreshed_total Total token refresh operations.\n")
		fmt.Fprintf(w, "# TYPE vault_tokens_refreshed_total counter\n")
		fmt.Fprintf(w, "vault_tokens_refreshed_total %d\n", c.tokensRefreshed.Load())
	}
}
