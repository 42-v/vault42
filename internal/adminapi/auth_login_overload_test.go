package adminapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// Argon2id backpressure is not a wrong password.
//
// The admin plane used to fold the ErrArgon2Overloaded return from
// VerifyPassword into the same branch as a failed comparison. Two things went
// wrong when the semaphore was full. The server charged the rejection against
// the admin's lockout budget, so a busy process could lock the break-glass
// account out with credentials that were never actually checked, and the audit
// trail recorded "wrong_password" about a password the server never compared,
// which is the record an incident responder would read afterwards.
//
// Both halves are asserted below on an account deliberately parked one failure
// short of its limit, so a regression to the old behavior locks it.

// adminapiCollectedAudit records the audit entries a handler writes. The logger
// is built with a zero flush interval, which makes Log write through to the
// repository synchronously, so what this holds after Login returns is complete.
type adminapiCollectedAudit struct {
	mu      sync.Mutex
	entries []*model.AuditEntry
}

func (c *adminapiCollectedAudit) logger() *audit.Logger {
	return audit.NewLogger(&mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, e *model.AuditEntry) error {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.entries = append(c.entries, e)
			return nil
		},
	}, 0)
}

// snapshot copies the entries written so far. The audit logger hands critical
// events to a goroutine in some configurations, so every read goes through the
// same lock the writer takes.
func (c *adminapiCollectedAudit) snapshot() []*model.AuditEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*model.AuditEntry, len(c.entries))
	copy(out, c.entries)
	return out
}

func TestAdminLogin_Argon2OverloadDoesNotCountAsAWrongPassword(t *testing.T) {
	const password = "the-real-break-glass-password"

	// Hashed before the semaphore is saturated: afterwards no hash can be
	// produced at all, including this fixture's.
	hash, err := vaultcrypto.HashPassword(password, "")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	repo := newFakeAdminRepo()
	repo.users["adm-1"] = &model.AdminUser{
		ID: "adm-1", Username: "root", PasswordHash: hash,
		// One short of maxFailed: charging this request as a failure locks it.
		FailedLoginCount: 4,
	}

	collected := &adminapiCollectedAudit{}
	h := NewAuthHandler(repo, &stubAdminSessionRepo{}, collected.logger(),
		make([]byte, 32), "", time.Hour, 5, time.Hour)

	adminapiSaturateArgon2(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/auth/login",
		strings.NewReader(`{"username":"root","password":"`+password+`"}`))
	req.RemoteAddr = "203.0.113.7:44321"
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	body := rec.Body.String()
	// 503 rather than 401: the credentials were never compared, so telling the
	// caller they were wrong is a lie, and a client that retries on 503 recovers
	// once the queue drains while one that sees 401 gives up.
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body: %s)", rec.Code, body)
	}
	if code := adminapiErrorCode(t, body); code != "server_busy" {
		t.Errorf("error = %q, want server_busy", code)
	}

	if got := repo.failed["adm-1"]; got != 0 {
		t.Errorf("the failed-login counter advanced by %d; server-side backpressure is being charged to the admin's lockout budget", got)
	}
	if locked := repo.users["adm-1"].LockedUntil; locked != nil {
		t.Errorf("the account was locked until %v because the server was busy, not because anyone guessed wrong", *locked)
	}
	for _, e := range collected.snapshot() {
		if reason, _ := e.Metadata["reason"].(string); reason == "wrong_password" {
			t.Errorf("audit event %q blames a wrong password for a comparison that never ran", e.EventType)
		}
	}
}
