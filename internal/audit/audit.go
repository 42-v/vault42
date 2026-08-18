// Package audit provides append-only audit logging for security-relevant events.
// The audit log is append-only at the database level (the vault_app role has
// INSERT and SELECT only on the audit schema, no UPDATE or DELETE). Sensitive
// metadata keys (passwords, tokens, secrets) are automatically scrubbed before
// storage. Batching is supported for high-throughput deployments.
package audit

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/42-v/vault42/internal/alert"
	"github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/metrics"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// Event type constants for audit logging. Each constant represents a
// security-relevant action that is recorded in the append-only audit log.
const (
	// LoginSuccess records a successful user authentication.
	LoginSuccess = "login_success"
	// LoginFailure records a failed login attempt (wrong password, locked account, etc.).
	LoginFailure = "login_failure"
	// LoginNewCountry records a successful login from a country this user has not
	// been seen logging in from before (and only when they already had at least
	// one recorded country — a first-ever login seeds silently). Metadata carries
	// the ISO alpha-2 country code only, never the IP: the notice is derived from
	// coarse IP-registration data locally and reduced to country granularity
	// before anything is stored (docs/PRIVACY.md P4, data minimisation).
	LoginNewCountry = "login_new_country"
	// Registration records a new user account creation.
	Registration = "registration"
	// TokenRefresh records a refresh token exchange for a new access token.
	TokenRefresh = "token_refresh"
	// TokenRevoke records an explicit refresh token revocation (logout).
	TokenRevoke = "token_revoke"
	// TokenMinted records a token signed for a caller-asserted subject via
	// POST /mint. vault42 never authenticated that subject. The signature is
	// indistinguishable from any other issued token, so this event is the only
	// attribution of who asked. It is critical: under a non-zero flush interval
	// the buffer can drop it, which is worse than dropping a password_change.
	TokenMinted = "token_minted"
	// PasswordChange records a user-initiated password change.
	PasswordChange = "password_change"
	// PasswordReset records a password reset via email token.
	PasswordReset = "password_reset"
	// AccountErased records a GDPR account erasure (self-service or admin). The
	// real email is masked in the audit metadata; it survives only in the
	// encrypted account-recovery escrow log.
	AccountErased = "account_erased"
	// ConsentGranted records an opt-in to a consent-based processing purpose.
	// Art. 7(1) puts the burden of demonstrating consent on the controller, so
	// the grant is logged with its source; the record itself lives on the
	// encrypted identity profile.
	ConsentGranted = "consent_granted"
	// ConsentWithdrawn records a withdrawal of consent (Art. 7(3)). Withdrawal
	// must be as easy as granting, so this is also emitted by the unauthenticated
	// one-click unsubscribe path.
	ConsentWithdrawn = "consent_withdrawn"
	// TwoFASetup records TOTP or WebAuthn credential enrollment.
	TwoFASetup = "2fa_setup"
	// TwoFAVerify records a two-factor authentication verification attempt.
	TwoFAVerify = "2fa_verify"
	// DeviceTrust records a new device being trusted after login.
	DeviceTrust = "device_trust"
	// SessionRevoke records an explicit session revocation by user or admin.
	SessionRevoke = "session_revoke"
	// ClientAuth records a client credentials grant authentication.
	ClientAuth = "client_auth"
	// KMSUnwrap records a KEK envelope-unwrap request via POST /kms/unwrap.
	// Metadata carries the KEK kid and outcome only — never key material.
	KMSUnwrap = "kms_unwrap"
	// RateLimit records a rate limit trigger event.
	RateLimit = "rate_limit"
	// FingerprintAnomaly records a fingerprint mismatch on token refresh.
	FingerprintAnomaly = "fingerprint_anomaly"
	// DPoPBindingMismatch records a refused rotation of a DPoP-bound refresh
	// family: the caller presented the refresh cookie but did not prove
	// possession of the key the family was bound to (RFC 9449 §5). Metadata
	// carries the family's expected thumbprint and whether any proof arrived,
	// never the thumbprint the caller chose. It is the signal that a refresh
	// cookie is in use by something other than the browser it was issued to,
	// and it is deliberately NOT in isCriticalEvent: the caller decides how
	// many of these to generate, and a synchronous write per attempt would be
	// a lever on the audit path. FingerprintAnomaly, the control it sits
	// beside, is buffered for the same reason.
	DPoPBindingMismatch = "dpop_binding_mismatch"
	// OAuth2Authorize records an OAuth2 authorization redirect initiation.
	OAuth2Authorize = "oauth2_authorize"
	// OAuth2Callback records an OAuth2 callback processing result.
	OAuth2Callback = "oauth2_callback"
	// AdminAction records an administrative CLI action.
	AdminAction = "admin_action"
	// DataExport records a user exporting their personal data (GDPR Articles 15/20).
	DataExport = "data_export"
	// HoneypotTrigger records a trap credential being used in honeypot mode.
	HoneypotTrigger = "honeypot_trigger"
	// HoneypotAlert records a webhook dispatch in honeypot mode.
	HoneypotAlert = "honeypot_alert"

	// AdminLogin records a successful admin gateway login.
	AdminLogin = "admin_login"
	// AdminLoginFailure records a failed admin gateway login attempt.
	AdminLoginFailure = "admin_login_failure"
	// AdminLogout records an admin gateway session logout.
	AdminLogout = "admin_logout"
	// AdminSessionRevoke records an admin revoking sessions.
	AdminSessionRevoke = "admin_session_revoke"
	// AdminUserLock records an admin locking a user account.
	AdminUserLock = "admin_user_lock"
	// AdminUserUnlock records an admin unlocking a user account.
	AdminUserUnlock = "admin_user_unlock"
	// AdminUserDelete records an admin deleting a user account.
	AdminUserDelete = "admin_user_delete"
	// AdminUserResetRequired records an admin imposing a forced password reset
	// on a user account: the stored password stops signing that account in and
	// the account holder is mailed a reset link on the next attempt.
	AdminUserResetRequired = "admin_user_reset_required"
	// AdminUserResetCleared records an admin lifting a forced password reset,
	// returning the account to the ordinary password gate. It shares the
	// admin_user_reset_ prefix with the event above so one filter reads the
	// whole lifecycle of the flag.
	AdminUserResetCleared = "admin_user_reset_cleared"
	// AdminKeyRotate records an admin rotating a signing key.
	AdminKeyRotate = "admin_key_rotate"
	// AdminKeyRevoke records an admin revoking a signing key.
	AdminKeyRevoke = "admin_key_revoke"
	// AdminClientCreate records an admin creating a service client.
	AdminClientCreate = "admin_client_create"
	// AdminClientRevoke records an admin revoking a service client.
	AdminClientRevoke = "admin_client_revoke"
	// AdminClientRotate records an admin rotating a client secret.
	AdminClientRotate = "admin_client_rotate"
	// AdminConfigChange records an admin changing a config value.
	AdminConfigChange = "admin_config_change"
	// AdminAccountCreate records an admin creating a new admin account.
	AdminAccountCreate = "admin_account_create"
	// AdminAccountRevoke records an admin revoking another admin account.
	AdminAccountRevoke = "admin_account_revoke"
	// AdminLockout records an admin account being locked due to too many failed logins.
	AdminLockout = "admin_lockout"
	// AdminAuthzDenied records an admin-plane RBAC permission denial: an
	// authenticated admin was refused a route because their role lacks the
	// required permission. The decision is enforced regardless of this record;
	// the record is the trail a privilege-boundary probe leaves behind.
	AdminAuthzDenied = "admin_authz_denied"
	// AdminSessionRejected records an admin-plane session-token rejection: a
	// request was refused before authentication because its bearer token or
	// session failed a validity check (missing or malformed Authorization
	// header, an unknown, revoked or expired session, or a session whose admin
	// no longer exists). The reason is carried in the metadata. The decision is
	// enforced regardless of this record; the record is the trail a session
	// replay or bogus-token probe leaves behind.
	AdminSessionRejected = "admin_session_rejected"

	// SvcDocPut records a service document being created or replaced.
	SvcDocPut = "svcdoc_put"
	// SvcDocGet records a service document being read.
	SvcDocGet = "svcdoc_get"
	// SvcDocDelete records a service document being deleted.
	SvcDocDelete = "svcdoc_delete"
)

// sensitiveKeys are metadata keys that must NEVER be stored.
var sensitiveKeys = map[string]bool{
	"password": true, "secret": true, "token": true,
	"access_token": true, "refresh_token": true, "code": true,
	"totp_secret": true, "backup_code": true, "master_key": true,
	"client_secret": true, "api_key": true,
}

// blobSensitiveKeys are metadata keys that must NEVER be stored on a blob
// event. The plaintext reference name of a named blob and a blob label are
// exactly what the objects store keeps out of the database (docs/PRIVACY.md
// 3.1: only the HMAC of the name and the AES-GCM ciphertext of the label are
// persisted), and audit rows survive account erasure under Art. 17(3)(b)/(e).
// "name" is scrubbed per event class rather than globally because admin role
// and client events legitimately record a non-personal object name.
var blobSensitiveKeys = map[string]bool{
	"name": true, "blob_name": true, "ref_name": true, "label": true,
}

// blobEventPrefix identifies the event types the blob key set applies to.
const blobEventPrefix = "blob_"

// svcDocSensitiveKeys are the keys a service-document event must never carry.
//
// Service documents are opaque, service-authored JSON about a user, so their
// contents are personal data under Art. 4(1) whatever the writing service put
// there. The event metadata is deliberately limited to the document key, its
// size, its visibility and the outcome; none of these names belong in it, and a
// caller reaching for one is reaching for the body.
//
// doc_key is deliberately absent from this set. It is an identifier the store
// requires to be a bounded charset, it is what makes an audit trail useful, and
// dropping it would leave events that say a document changed without saying
// which.
var svcDocSensitiveKeys = map[string]bool{
	"value": true, "body": true, "content": true, "document": true,
	"doc": true, "data": true, "plaintext": true, "payload": true,
}

// svcDocEventPrefix identifies the event types the service-document key set
// applies to.
const svcDocEventPrefix = "svcdoc_"

// Logger handles audit event logging with optional batching. When flushEvery
// is greater than zero, entries are buffered in memory and flushed periodically.
// Sensitive metadata keys are automatically scrubbed before storage.
type Logger struct {
	repo       repository.AuditRepository
	flushEvery time.Duration
	bufferSize int

	mu           sync.Mutex
	buffer       []*model.AuditEntry
	done         chan struct{}
	closeOnce    sync.Once
	droppedTotal atomic.Int64

	// afterCloseTotal counts entries Log handled after Close, which take the
	// synchronous path because the buffer they would otherwise join is dead.
	// Separate from droppedTotal: these are written, not dropped, and mixing
	// them would make both figures unreadable.
	afterCloseTotal atomic.Int64

	quarantinedTotal atomic.Int64

	// detector raises operator-facing alerts from the events this logger
	// records. Held atomically because Log reads it from every request
	// goroutine while startup writes it once; nil is inert. See alerting.go.
	detector atomic.Pointer[alert.Detector]
}

// QuarantinedTotal returns the number of entries the store refused individually
// while it was demonstrably reachable, and which were therefore discarded
// instead of retried.
func (l *Logger) QuarantinedTotal() int64 {
	return l.quarantinedTotal.Load()
}

// isCriticalEvent returns true for security-critical event types that must
// not be silently dropped when the buffer is full. KMSUnwrap is a key-release
// action (envelope-unwrap oracle) — every attempt needs a guaranteed audit
// trail, so it is written synchronously rather than buffered where a DoS-driven
// buffer overflow could drop it.
//
// TokenMinted is the same shape of oracle for subject assertions: POST /mint
// signs a subject vault42 never authenticated, and the JWT is indistinguishable
// from any other, so the event is the only attribution. Losing it under the
// embedded profile's default flush interval is worse than losing a
// password_change, which was already in this set.
//
// Every svcdoc_ event is a record of who accessed whose personal data. The
// match is by prefix so a future svcdoc_ type cannot silently fall back to the
// droppable buffer the way token_minted did when it was added without updating
// this function.
//
// HoneypotTrigger is the only durable record that a trap credential was used.
// The webhook beside it is rate limited and best-effort, and the honeypot's
// process log is not evidence. The attacker also chooses how much traffic the
// trap sees, so leaving the trigger droppable handed them the buffer pressure
// that erases their own visit.
//
// AdminAuthzDenied and AdminSessionRejected are the trail a privilege-boundary
// probe and a session-token replay leave behind (ASVS V16.3.2). The decision
// is enforced regardless; losing the row under buffer pressure is how a
// viewer floods the logger and then probes in silence.
func isCriticalEvent(eventType string) bool {
	if strings.HasPrefix(eventType, svcDocEventPrefix) {
		return true
	}
	switch eventType {
	case LoginFailure, PasswordChange, PasswordReset, TokenRevoke, AdminAction, KMSUnwrap, TokenMinted, HoneypotTrigger, AdminAuthzDenied, AdminSessionRejected:
		return true
	}
	return false
}

// DroppedTotal returns the number of times an event met a full buffer.
//
// It counts occurrences, not losses, and the difference matters to anyone
// reading it as an alert: a critical event that meets a full buffer increments
// this counter and is then written synchronously anyway, so the figure is an
// upper bound on what was actually lost rather than the loss itself. Reading it
// as "events missing from the audit trail" over-reports by the number of
// critical events that arrived under buffer pressure.
//
// It also sums two conditions that need different responses, which is why the
// scrape does not use it: /metrics reports vault_audit_buffer_full_total and
// vault_audit_events_dropped_total separately. This total stays a per-Logger
// figure for callers holding one.
func (l *Logger) DroppedTotal() int64 {
	return l.droppedTotal.Load()
}

// AfterCloseTotal returns how many entries were logged after Close and
// therefore written synchronously rather than buffered.
//
// Non-zero means something outlived the logger: a background job still running
// when shutdown reached it. That is a shutdown-ordering fact worth having a
// number for, because the alternative — the behavior this replaced — was a
// silent append to a buffer nothing would flush.
func (l *Logger) AfterCloseTotal() int64 {
	return l.afterCloseTotal.Load()
}

// NewLogger creates an audit logger backed by the given repository. If
// flushEvery is greater than zero, batch mode is enabled and a background
// goroutine periodically flushes buffered entries.
func NewLogger(repo repository.AuditRepository, flushEvery time.Duration) *Logger {
	return NewLoggerWithBufferSize(repo, flushEvery, 1000)
}

// NewLoggerWithBufferSize creates an audit logger with a configurable buffer cap.
// If bufferSize is <= 0, the default of 1000 is used.
func NewLoggerWithBufferSize(repo repository.AuditRepository, flushEvery time.Duration, bufferSize int) *Logger {
	if bufferSize <= 0 {
		bufferSize = 1000
	}
	l := &Logger{
		repo:       repo,
		flushEvery: flushEvery,
		bufferSize: bufferSize,
		done:       make(chan struct{}),
	}
	if flushEvery > 0 {
		go l.batchLoop()
	}
	return l
}

// Log writes an audit entry. In batch mode, the entry is buffered until the
// next flush interval. In immediate mode, it is written directly to the
// repository. Metadata is scrubbed of sensitive keys before storage.
//
// After Close the buffer is dead — the flush loop has exited and nothing will
// drain it again — so a closed logger writes straight through to the store and
// reports what happens, rather than appending to a slice no one will read. A
// caller can still be running at that point: notifyNewCountry writes from the
// deferwork pool, and however carefully shutdown is ordered the ordering is a
// property of one caller's defer stack, which is not the thing that should
// decide whether an audit row survives.
// The risk score is not a parameter. It was one, and every production call site
// passed an integer literal, so the parameter offered a choice nobody made and
// the same event class ended up carrying four different numbers. Deriving it
// from the class is what turns risk_score >= N into a predicate; severity.go
// argues why leaving an override in would have left it a curiosity.
func (l *Logger) Log(ctx context.Context, eventType string, userID, clientID, ip, ua, fpHash, deviceID string, metadata map[string]interface{}) error {
	id, err := crypto.RandomUUID()
	if err != nil {
		return fmt.Errorf("audit: generate ID: %w", err)
	}

	entry := &model.AuditEntry{
		ID:              id,
		Timestamp:       time.Now(),
		EventType:       eventType,
		UserID:          userID,
		ClientID:        clientID,
		IP:              ip,
		UserAgent:       ua,
		FingerprintHash: fpHash,
		DeviceID:        deviceID,
		Metadata:        scrubEventMetadata(eventType, metadata),
		RiskScore:       Severity(eventType),
	}

	// Detection runs on the way out of whichever branch below handles the entry,
	// never before one and never instead of one. See observe in alerting.go: an
	// alert that could fail the audit write would turn a notification problem
	// into an authentication problem.
	defer l.observe(ctx, entry)

	if l.flushEvery > 0 && !l.isClosed() {
		l.mu.Lock()
		// Cap buffer to prevent unbounded memory growth under DoS.
		if len(l.buffer) >= l.bufferSize {
			l.mu.Unlock()
			l.droppedTotal.Add(1)
			metrics.RecordAuditBufferFull()
			// Critical security events are written synchronously even when buffer is full.
			if isCriticalEvent(eventType) {
				if err := l.repo.Insert(ctx, entry); err != nil {
					log.Printf("WARNING: audit sync insert failed for critical event type=%s: %v", eventType, err)
				}
				return nil
			}
			log.Printf("WARNING: audit buffer full (%d entries), dropping event type=%s", l.bufferSize, eventType)
			return nil
		}
		l.buffer = append(l.buffer, entry)
		l.mu.Unlock()
		return nil
	}

	if l.flushEvery > 0 {
		// Batch mode, closed logger. Loud on the way through: an entry arriving
		// here is one whose writer outlived the logger, which is worth a line
		// whether or not the store takes it.
		l.afterCloseTotal.Add(1)
		log.Printf("WARNING: audit entry written after Close (type=%s); inserting synchronously", eventType)
		if err := l.repo.Insert(ctx, entry); err != nil {
			log.Printf("WARNING: audit entry lost after Close (type=%s): %v", eventType, err)
			return fmt.Errorf("audit: insert after close: %w", err)
		}
		return nil
	}

	return l.repo.Insert(ctx, entry)
}

// isClosed reports whether Close has run. The channel close is the
// happens-before edge, so no additional synchronization is needed.
func (l *Logger) isClosed() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

// Flush writes all buffered entries to the repository.
func (l *Logger) Flush(ctx context.Context) error {
	l.mu.Lock()
	entries := l.buffer
	l.buffer = nil
	l.mu.Unlock()

	if len(entries) == 0 {
		return nil
	}
	if err := l.repo.InsertBatch(ctx, entries); err != nil {
		l.isolate(ctx, entries)
		return err
	}
	return nil
}

// isolate decides what to do with a batch the store rejected as a whole.
//
// A batch is one transaction, so the first row the store refuses takes every
// other row down with it and nothing lands. Requeueing the lot then puts the
// offending row back at the FRONT, where it is retried first on the next tick,
// and the next, forever: the buffer fills behind it, everything logged after it
// is counted into droppedTotal and discarded, and the audit trail for that
// process never drains again. One crafted request is enough to reach that state
// — the audit actor id is a Go string written into a UUID column, so a service
// document or a mint filed under a non-UUID subject is refused with 22P02 for
// as long as the row exists — and a security control that dies silently is the
// worst failure mode this repository has.
//
// So the two causes have to be told apart, and the evidence is in the same
// flush. Each entry is offered to the store on its own. If the store took any
// of them it is reachable, which makes the ones it refused the problem rather
// than the store, and those are quarantined: dropped, counted and named in the
// process log with the store's own error. If it took none, the store is down —
// an outage, an exhausted pool, a partition — and every entry is requeued
// exactly as before, because retrying is the right answer to that.
//
// The pass costs one round trip per entry of a batch that already failed. That
// is the price of the distinction, it is bounded by the buffer size, and it is
// only paid on the failure path.
//
// A batch whose entries are ALL unwritable takes no successes and is therefore
// requeued. It unwedges itself on the first flush that also carries a writable
// entry, which ordinary traffic supplies, and until then there is nothing
// behind it to lose.
func (l *Logger) isolate(ctx context.Context, entries []*model.AuditEntry) {
	var (
		accepted int
		refused  []*model.AuditEntry
		reasons  []error
	)
	for _, e := range entries {
		if err := l.repo.Insert(ctx, e); err != nil {
			refused = append(refused, e)
			reasons = append(reasons, err)
			continue
		}
		accepted++
	}

	if accepted == 0 {
		l.requeue(refused)
		return
	}
	l.quarantine(refused, reasons)
}

// quarantine discards entries the store refused while it was demonstrably
// reachable, and makes the loss loud.
//
// This is still a lost audit record, so it is counted in the same
// events-dropped metric an operator already alerts on, and each row names its
// id, its event type and the store's verbatim error. That error carries the
// SQLSTATE and the value the store choked on, which is what turns "the audit
// log lost a row" into "this caller files events under a malformed actor id"
// without anyone having to reproduce it.
func (l *Logger) quarantine(entries []*model.AuditEntry, reasons []error) {
	l.quarantinedTotal.Add(int64(len(entries)))
	metrics.RecordAuditEventsDropped(int64(len(entries)))
	for i, e := range entries {
		log.Printf("ERROR: audit: quarantined an unwritable entry the store refused while it was "+
			"accepting others: id=%s type=%s actor=%q: %v", e.ID, e.EventType, e.UserID, reasons[i])
	}
}

// requeue puts a rejected batch back at the front of the buffer.
//
// Flush empties the buffer under the lock and inserts outside it, so before
// this existed a repository error left the entries already gone and nothing put
// them back: one transient database problem destroyed a whole batch of audit
// records. batchLoop discarded the error too, under a comment claiming errors
// were logged inside Flush, so the loss was silent at both levels and
// DroppedTotal did not move. The audit log is the only copy of those records,
// and the events most likely to be in flight during a database problem are the
// ones describing what was happening at the time.
//
// They go at the FRONT because they are older than anything logged while the
// insert was in flight, and an append-only trail should lose its newest records
// rather than its oldest when it has to lose some.
//
// The retry is bounded by the buffer, deliberately. A store that stays down
// would otherwise grow this slice without limit inside a process that is
// already unhealthy. What does not fit is counted in droppedTotal, so the
// figure an operator alerts on stays honest instead of the loss simply moving
// somewhere quieter.
func (l *Logger) requeue(entries []*model.AuditEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	room := l.bufferSize - len(l.buffer)
	if room <= 0 {
		l.droppedTotal.Add(int64(len(entries)))
		metrics.RecordAuditEventsDropped(int64(len(entries)))
		return
	}
	if len(entries) > room {
		l.droppedTotal.Add(int64(len(entries) - room))
		metrics.RecordAuditEventsDropped(int64(len(entries) - room))
		entries = entries[:room]
	}
	l.buffer = append(entries, l.buffer...)
}

// Close flushes remaining entries and stops the batch loop. Safe to call multiple times.
func (l *Logger) Close(ctx context.Context) error {
	var err error
	l.closeOnce.Do(func() {
		close(l.done)
		err = l.Flush(ctx)
	})
	return err
}

func (l *Logger) batchLoop() {
	ticker := time.NewTicker(l.flushEvery)
	defer ticker.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-ticker.C:
			// The error is logged rather than discarded. It used to be dropped
			// under a comment saying Flush logged it, which Flush did not do, so
			// a store that was rejecting every batch produced no signal at all.
			// Flush puts the entries back, so this is a report rather than a
			// loss, and it is the only place that report can come from.
			if err := l.Flush(context.Background()); err != nil {
				log.Printf("audit: flush failed, entries retained for the next attempt: %v", err)
			}
		}
	}
}

// scrubEventMetadata removes the globally sensitive keys plus any key set
// scoped to the event class.
func scrubEventMetadata(eventType string, m map[string]interface{}) map[string]interface{} {
	clean := scrubMetadata(m)
	// Per-class key sets rather than one global list: a name is personal data on a
	// blob event and a legitimate non-personal object name on an admin role or
	// client event, so dropping it everywhere would blind the admin audit trail.
	for _, class := range []struct {
		prefix string
		drop   map[string]bool
	}{
		{blobEventPrefix, blobSensitiveKeys},
		{svcDocEventPrefix, svcDocSensitiveKeys},
	} {
		if strings.HasPrefix(eventType, class.prefix) {
			return dropKeys(clean, class.drop)
		}
	}
	return clean
}

// dropKeys recursively deletes the given keys from an already-scrubbed map.
func dropKeys(m map[string]interface{}, drop map[string]bool) map[string]interface{} {
	if m == nil {
		return nil
	}
	for k, v := range m {
		if drop[strings.ToLower(k)] {
			delete(m, k)
			continue
		}
		if nested, ok := v.(map[string]interface{}); ok {
			dropKeys(nested, drop)
		}
	}
	return m
}

// scrubMetadata recursively removes sensitive keys from metadata.
func scrubMetadata(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	clean := make(map[string]interface{}, len(m))
	for k, v := range m {
		if sensitiveKeys[strings.ToLower(k)] {
			continue
		}
		// Recursively scrub nested maps
		if nested, ok := v.(map[string]interface{}); ok {
			clean[k] = scrubMetadata(nested)
		} else {
			clean[k] = v
		}
	}
	return clean
}
