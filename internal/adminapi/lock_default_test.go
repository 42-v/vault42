package adminapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// Locking an account is what an operator does to a compromised user, often in a hurry
// and often from a script or a curl with no body at all. If an unparseable body left
// the duration at zero, LockUntil would be handed a timestamp of "now" — the account
// would be locked until this instant, which is to say not locked, and the endpoint
// would still answer 200 with a lock timestamp in the body.
//
// The guarantee is that a lock request with no usable duration still locks, and for
// the documented default rather than for nothing.
func TestLockUser_UnparseableBodyStillLocksForTheDefault(t *testing.T) {
	for _, body := range []string{"", "not json", `{"duration": ""}`, `{"duration": "-5h"}`} {
		t.Run(body, func(t *testing.T) {
			var lockedUntil time.Time
			var revokedFor string
			h := &Handler{
				users: &mocks.MockUserRepo{
					LockUntilFn: func(_ context.Context, _ string, until time.Time) error {
						lockedUntil = until
						return nil
					},
				},
				// Locking revokes the user's refresh tokens, so the repository is
				// no longer optional here. A lock that leaves live sessions
				// rotating is not containment.
				tokens: &mocks.MockRefreshTokenRepo{
					RevokeAllForUserFn: func(_ context.Context, userID string) error {
						revokedFor = userID
						return nil
					},
				},
				auditLog: audit.NewLogger(&mocks.MockAuditRepo{}, 0),
			}

			req := httptest.NewRequest(http.MethodPost, "/admin/users/u-1/lock", strings.NewReader(body))
			req.SetPathValue("id", "u-1")
			req = req.WithContext(context.WithValue(req.Context(), adminUserKey,
				&model.AdminUser{ID: "adm-1", Username: "root"}))

			rec := httptest.NewRecorder()
			h.LockUser(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if revokedFor != "u-1" {
				t.Errorf("revoked sessions for %q, want u-1: the lock must terminate the "+
					"sessions the compromised account already holds", revokedFor)
			}
			if !lockedUntil.After(time.Now().Add(23 * time.Hour)) {
				t.Errorf("locked until %v — an account the operator believes is locked would accept a login immediately", lockedUntil)
			}
		})
	}
}

// TestLockUser_NilTokenRepoLocksWithoutPanicking pins the guard that keeps a
// wiring mistake from becoming a crash on the containment route.
//
// cmd/admin-gateway passed nil for this repository, and LockUser dereferenced
// it after the lock had already committed. The recovery middleware turned the
// panic into a 500, so the operator responding to a takeover saw "lock failed"
// on an account that was in fact locked, no audit row was written, and an
// unlock to try again would have handed the account back.
//
// The wiring itself is asserted in tests/spec, because a unit test that
// supplies its own mock cannot see what main.go passes. This one covers what
// happens if it goes wrong again: the lock still commits, the request still
// succeeds, and the audit row says the sessions were not revoked, which is the
// honest answer rather than a crash.
func TestLockUser_NilTokenRepoLocksWithoutPanicking(t *testing.T) {
	var lockedUntil time.Time
	var auditedRevoked any

	h := &Handler{
		users: &mocks.MockUserRepo{
			LockUntilFn: func(_ context.Context, _ string, until time.Time) error {
				lockedUntil = until
				return nil
			},
		},
		tokens: nil,
		auditLog: audit.NewLogger(&mocks.MockAuditRepo{
			InsertFn: func(_ context.Context, e *model.AuditEntry) error {
				auditedRevoked = e.Metadata["sessions_revoked"]
				return nil
			},
		}, 0),
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/users/u-1/lock", strings.NewReader(`{"duration":"24h"}`))
	req.SetPathValue("id", "u-1")
	req = req.WithContext(context.WithValue(req.Context(), adminUserKey,
		&model.AdminUser{ID: "adm-1", Username: "root"}))

	rec := httptest.NewRecorder()
	h.LockUser(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: a missing token repository must not turn the lock into "+
			"a failure the operator reads as 'the account is not locked'", rec.Code)
	}
	if lockedUntil.IsZero() {
		t.Error("the lock was not written")
	}
	if auditedRevoked != false {
		t.Errorf("sessions_revoked = %v, want false: the audit row is where an operator learns "+
			"the sessions are still alive, so it must not claim they were revoked", auditedRevoked)
	}
}

// TestLockUser_RevokeFailureIsReportedNotSwallowed covers the other half of the
// revoke bookkeeping.
//
// The lock is written before the sessions are revoked, deliberately: failing the
// request after the lock has committed would tell an operator the account is not
// locked when it is. That makes the audit row the only place the revoke outcome
// is recorded, so a repository error has to reach it rather than being reported
// as a success.
func TestLockUser_RevokeFailureIsReportedNotSwallowed(t *testing.T) {
	var auditedRevoked any

	h := &Handler{
		users: &mocks.MockUserRepo{
			LockUntilFn: func(context.Context, string, time.Time) error { return nil },
		},
		tokens: &mocks.MockRefreshTokenRepo{
			RevokeAllForUserFn: func(context.Context, string) error {
				return errors.New("refresh store unavailable")
			},
		},
		auditLog: audit.NewLogger(&mocks.MockAuditRepo{
			InsertFn: func(_ context.Context, e *model.AuditEntry) error {
				auditedRevoked = e.Metadata["sessions_revoked"]
				return nil
			},
		}, 0),
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/users/u-1/lock", strings.NewReader(`{"duration":"24h"}`))
	req.SetPathValue("id", "u-1")
	req = req.WithContext(context.WithValue(req.Context(), adminUserKey,
		&model.AdminUser{ID: "adm-1", Username: "root"}))

	rec := httptest.NewRecorder()
	h.LockUser(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: the lock committed, so the request must not report failure", rec.Code)
	}
	if auditedRevoked != false {
		t.Errorf("sessions_revoked = %v, want false; the revoke failed and the audit row is the "+
			"only record an operator has of whether the sessions are still alive", auditedRevoked)
	}
}
