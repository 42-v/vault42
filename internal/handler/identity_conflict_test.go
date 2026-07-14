package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// losingRepo always reports that its compare-and-set lost the race, which is what a
// concurrent write to the same profile looks like from inside the service.
type losingRepo struct {
	mocks.MockIdentityRepo
}

func (r *losingRepo) UpsertCAS(context.Context, *model.IdentityProfile, time.Time) (bool, error) {
	return false, nil // never wins
}

// The identity profile is written under a compare-and-set so a profile update cannot
// silently revert a marketing-consent withdrawal that landed a moment earlier. When the
// CAS keeps losing, the service gives up with ErrConcurrentUpdate.
//
// The HTTP mapping for that is the part nobody had tested. It must be 409 — a conflict the
// client retries — and emphatically not a 500 (which reads as "the server is broken", so
// nobody retries) and not a 200 (which reads as "your change was saved" when it was not).
// A 200 here is the same defect the CAS exists to prevent, just moved one layer up.
func TestIdentityHandlers_ConcurrentUpdateIs409(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x42}, 32)
	svc := service.NewIdentityService(&losingRepo{}, masterKey, []byte("hmac-secret"))
	h := NewIdentityHandler(svc, newTestAuditLogger())

	t.Run("PUT /user/identity", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/user/identity",
			strings.NewReader(`{"username":"alice","marketing_emails":true}`))
		req = setAuthContext(req, "user-1")
		rec := httptest.NewRecorder()

		h.Put(rec, req)

		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409 — a lost race must be retryable, not a 500 and not a fake success", rec.Code)
		}
		if body := rec.Body.String(); !strings.Contains(body, "concurrent_update") {
			t.Errorf("body = %s, want concurrent_update", body)
		}
	})

	t.Run("unsubscribe", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/user/identity/unsubscribe", nil)
		req = setAuthContext(req, "user-1")
		rec := httptest.NewRecorder()

		h.Unsubscribe(rec, req)

		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409 — an unsubscribe that lost the race must not report success", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "unsubscribed") {
			t.Error("the user was told they were unsubscribed when the write never landed")
		}
	})
}
