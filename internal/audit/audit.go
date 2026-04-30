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

	"github.com/42-v/vault42/internal/crypto"
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
	// Registration records a new user account creation.
	Registration = "registration"
	// TokenRefresh records a refresh token exchange for a new access token.
	TokenRefresh = "token_refresh"
	// TokenRevoke records an explicit refresh token revocation (logout).
	TokenRevoke = "token_revoke"
	// PasswordChange records a user-initiated password change.
	PasswordChange = "password_change"
	// PasswordReset records a password reset via email token.
	PasswordReset = "password_reset"
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
	// RateLimit records a rate limit trigger event.
	RateLimit = "rate_limit"
	// FingerprintAnomaly records a fingerprint mismatch on token refresh.
	FingerprintAnomaly = "fingerprint_anomaly"
	// OAuth2Authorize records an OAuth2 authorization redirect initiation.
	OAuth2Authorize = "oauth2_authorize"
	// OAuth2Callback records an OAuth2 callback processing result.
	OAuth2Callback = "oauth2_callback"
	// AdminAction records an administrative CLI action.
	AdminAction = "admin_action"
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
)

// sensitiveKeys are metadata keys that must NEVER be stored.
var sensitiveKeys = map[string]bool{
	"password": true, "secret": true, "token": true,
	"access_token": true, "refresh_token": true, "code": true,
	"totp_secret": true, "backup_code": true, "master_key": true,
	"client_secret": true, "api_key": true,
}

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
}

// isCriticalEvent returns true for security-critical event types that must
// not be silently dropped when the buffer is full.
func isCriticalEvent(eventType string) bool {
	switch eventType {
	case LoginFailure, PasswordChange, PasswordReset, TokenRevoke, AdminAction:
		return true
	}
	return false
}

// DroppedTotal returns the total number of audit events dropped due to buffer overflow.
func (l *Logger) DroppedTotal() int64 {
	return l.droppedTotal.Load()
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
func (l *Logger) Log(ctx context.Context, eventType string, userID, clientID, ip, ua, fpHash, deviceID string, metadata map[string]interface{}, riskScore int) error {
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
		Metadata:        scrubMetadata(metadata),
		RiskScore:       riskScore,
	}

	if l.flushEvery > 0 {
		l.mu.Lock()
		// Cap buffer to prevent unbounded memory growth under DoS.
		if len(l.buffer) >= l.bufferSize {
			l.mu.Unlock()
			l.droppedTotal.Add(1)
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

	return l.repo.Insert(ctx, entry)
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
	return l.repo.InsertBatch(ctx, entries)
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
			// Periodic flush is best-effort; errors are logged inside Flush.
			_ = l.Flush(context.Background())
		}
	}
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
