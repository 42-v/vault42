package adminapi

import (
	"context"
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
