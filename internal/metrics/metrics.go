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

	// Queue depth and cumulative wait, set separately by SetArgon2Queue.
	//
	// They are the early-warning half of the argon2 signal: active and rejected
	// only move once the semaphore is full and work is being refused, whereas
	// these rise as soon as callers start queueing, which is when logins start
	// getting slower. The commit that added the counters in internal/crypto
	// wrote that the mean wait "is the number an alert should be written
	// against", and then no collector read either of them.
	argon2Waiting   func() int64
	argon2WaitNanos func() int64

	// Auth counters
	loginAttempts   atomic.Int64
	loginSuccess    atomic.Int64
	loginFailed     atomic.Int64
	tokensIssued    atomic.Int64
	tokensRefreshed atomic.Int64

	// Mint counters are kept apart from the token counters above on purpose: a
	// minted token asserts a subject vault42 never authenticated, so folding it
	// into vault_tokens_issued_total would hide the one number an operator most
	// wants to alert on.
	mintIssued   atomic.Int64
	mintRejected atomic.Int64

	svcDocWrites  atomic.Int64
	svcDocReads   atomic.Int64
	svcDocRejects atomic.Int64
}

// The audit drop tallies are package level, unlike every counter above, because
// of where the audit logger sits in startup. It is built before the collector
// exists and is handed to the auth service, the honeypot alerter and the admin
// API, none of which hold a collector, so giving it one would mean threading a
// collector through every one of those call sites for a figure that is
// process-wide anyway. The argon2 counters in crypto are package level for the
// same reason and are read here through accessor functions instead.
//
// They are kept here rather than read out of internal/audit so this package
// keeps importing nothing from the rest of vault42. That is what lets any
// subsystem report into it without risking the import cycle the argon2
// accessors exist to avoid.
//
// Two series rather than one. Both mean audit records were lost, but they are
// lost at different stages, by different causes, and are fixed by different
// people. A full buffer means the process is producing events faster than the
// flush interval drains them: the store is healthy and the answer is a larger
// VAULT_AUDIT_BUFFER_SIZE, a shorter flush interval or load shedding. A drop at
// flush means the store rejected a batch and the retry had nowhere to put it:
// the answer is to fix the database, and every lost entry had already been
// reported to its caller as written. Summing them produces a number that pages
// the wrong team half the time.
var (
	auditBufferFull    atomic.Int64
	auditEventsDropped atomic.Int64
)

// RecordAuditBufferFull counts an audit event that arrived to a full in-memory
// buffer. Critical event types are written straight to the store instead of
// being discarded, so this is an upper bound on what was lost at enqueue rather
// than the loss itself.
func RecordAuditBufferFull() { auditBufferFull.Add(1) }

// RecordAuditEventsDropped counts buffered audit entries discarded either
// because a rejected batch would not fit back into the buffer, or because the
// store refused them individually while it was accepting others and retrying
// them would wedge the flush loop. Every one is a hole in the audit trail,
// which has no second copy.
func RecordAuditEventsDropped(n int64) {
	if n > 0 {
		auditEventsDropped.Add(n)
	}
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

// SetArgon2Queue wires the queue-depth accessors.
//
// Separate from NewCollector so that adding a signal does not rewrite every
// caller that never had one, and nil-tolerant so a collector built without it
// reports zero rather than panicking on the scrape.
func (c *Collector) SetArgon2Queue(waiting, waitNanos func() int64) {
	c.argon2Waiting = waiting
	c.argon2WaitNanos = waitNanos
}

// gaugeOrZero reads an optional accessor.
func gaugeOrZero(f func() int64) int64 {
	if f == nil {
		return 0
	}
	return f()
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

// RecordMintIssued counts a token signed for a caller-asserted subject.
func (c *Collector) RecordMintIssued() { c.mintIssued.Add(1) }

// RecordMintRejected counts a mint refused by policy. A sustained rise here is
// a misconfigured caller or someone probing the allow-lists.
func (c *Collector) RecordMintRejected() { c.mintRejected.Add(1) }

// RecordSvcDocWrite counts a stored service document.
func (c *Collector) RecordSvcDocWrite() { c.svcDocWrites.Add(1) }

// RecordSvcDocRead counts a served service document.
func (c *Collector) RecordSvcDocRead() { c.svcDocReads.Add(1) }

// RecordSvcDocRejected counts a document refused on validation, quota or scope.
func (c *Collector) RecordSvcDocRejected() { c.svcDocRejects.Add(1) }

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

		fmt.Fprintf(w, "# HELP vault_argon2_waiting Callers currently queued for an argon2id semaphore slot.\n")
		fmt.Fprintf(w, "# TYPE vault_argon2_waiting gauge\n")
		fmt.Fprintf(w, "vault_argon2_waiting %d\n", gaugeOrZero(c.argon2Waiting))

		fmt.Fprintf(w, "# HELP vault_argon2_wait_nanoseconds_total Cumulative time callers have spent queued for an argon2id semaphore slot.\n")
		fmt.Fprintf(w, "# TYPE vault_argon2_wait_nanoseconds_total counter\n")
		fmt.Fprintf(w, "vault_argon2_wait_nanoseconds_total %d\n", gaugeOrZero(c.argon2WaitNanos))

		// Auth metrics
		fmt.Fprintf(w, "# HELP vault_login_attempts_total Total login attempts.\n")
		fmt.Fprintf(w, "# TYPE vault_login_attempts_total counter\n")
		fmt.Fprintf(w, "vault_login_attempts_total %d\n", c.loginAttempts.Load())

		fmt.Fprintf(w, "# HELP vault_login_success_total Total successful logins.\n")
		fmt.Fprintf(w, "# TYPE vault_login_success_total counter\n")
		fmt.Fprintf(w, "vault_login_success_total %d\n", c.loginSuccess.Load())

		fmt.Fprintf(w, "# HELP vault_mint_issued_total Tokens signed for a caller-asserted subject via POST /mint.\n")
		fmt.Fprintf(w, "# TYPE vault_mint_issued_total counter\n")
		fmt.Fprintf(w, "vault_mint_issued_total %d\n", c.mintIssued.Load())

		fmt.Fprintf(w, "# HELP vault_mint_rejected_total Mint requests refused by policy.\n")
		fmt.Fprintf(w, "# TYPE vault_mint_rejected_total counter\n")
		fmt.Fprintf(w, "vault_mint_rejected_total %d\n", c.mintRejected.Load())

		fmt.Fprintf(w, "# HELP vault_svcdoc_writes_total Service documents stored.\n")
		fmt.Fprintf(w, "# TYPE vault_svcdoc_writes_total counter\n")
		fmt.Fprintf(w, "vault_svcdoc_writes_total %d\n", c.svcDocWrites.Load())

		fmt.Fprintf(w, "# HELP vault_svcdoc_reads_total Service documents served.\n")
		fmt.Fprintf(w, "# TYPE vault_svcdoc_reads_total counter\n")
		fmt.Fprintf(w, "vault_svcdoc_reads_total %d\n", c.svcDocReads.Load())

		fmt.Fprintf(w, "# HELP vault_svcdoc_rejected_total Service document requests refused on validation, quota or scope.\n")
		fmt.Fprintf(w, "# TYPE vault_svcdoc_rejected_total counter\n")
		fmt.Fprintf(w, "vault_svcdoc_rejected_total %d\n", c.svcDocRejects.Load())

		fmt.Fprintf(w, "# HELP vault_audit_buffer_full_total Audit events that arrived to a full in-memory buffer. Non-critical events were discarded here; critical ones were written straight to the store.\n")
		fmt.Fprintf(w, "# TYPE vault_audit_buffer_full_total counter\n")
		fmt.Fprintf(w, "vault_audit_buffer_full_total %d\n", auditBufferFull.Load())

		fmt.Fprintf(w, "# HELP vault_audit_events_dropped_total Buffered audit entries discarded because a rejected batch would not fit back into the buffer. Each one is a missing audit record.\n")
		fmt.Fprintf(w, "# TYPE vault_audit_events_dropped_total counter\n")
		fmt.Fprintf(w, "vault_audit_events_dropped_total %d\n", auditEventsDropped.Load())

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
