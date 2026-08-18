package adminapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/tests/mocks"
)

// countingSessionRepo records whether the admin-session nuke was reached.
type countingSessionRepo struct {
	*fakeSessionRepo
	revokeAllCalls int
}

func (c *countingSessionRepo) RevokeAll(ctx context.Context) error {
	c.revokeAllCalls++
	return c.fakeSessionRepo.RevokeAll(ctx)
}

// TestRevokeAllSessionsRevokesUserTokensNotAdminSessions is the regression for a
// break-glass control that did not exist.
//
// docs/security.md, docs/api.md, the SessionsRevoke permission's own definition
// in internal/rbac/rbac.go and the mitigation named in
// tests/attack/atk_authtok_lock_refresh_test.go all describe this endpoint as
// the global revocation of every USER's refresh tokens: the containment an
// operator reaches for when refresh tokens have been stolen in bulk. It ran
// UPDATE auth.admin_sessions instead, touching zero rows in auth.refresh_tokens,
// and answered 200 all_sessions_revoked while nothing was contained. Worse, the
// permission sits at operator tier, so pressing it logged every super_admin out
// mid-incident — a lower tier holding an availability lever over higher ones.
//
// The endpoint now does what its four documents say, and stops touching admin
// sessions at all. Which repository it calls was previously unobservable: the
// only test injected a session repository and asserted the status code, so the
// mis-wire was invisible to the suite that covered it.
func TestRevokeAllSessionsRevokesUserTokensNotAdminSessions(t *testing.T) {
	userTokensRevoked := 0
	tokens := &mocks.MockRefreshTokenRepo{
		RevokeAllFn: func(context.Context) error {
			userTokensRevoked++
			return nil
		},
	}
	sessions := &countingSessionRepo{fakeSessionRepo: newFakeSessionRepo()}

	h := newTestHandler(nil, nil, nil, nil)
	h.tokens = tokens
	h.sessions = sessions

	rec := httptest.NewRecorder()
	h.RevokeAllSessions(rec, withActor(httptest.NewRequest(http.MethodPost, "/admin/sessions/revoke-all", nil)))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body %s", rec.Code, rec.Body.String())
	}
	if userTokensRevoked != 1 {
		t.Errorf("RefreshTokenRepo.RevokeAll called %d times, want 1. The documented global "+
			"containment control revoked no user session at all, and the operator was told it "+
			"had.", userTokensRevoked)
	}
	if sessions.revokeAllCalls != 0 {
		t.Errorf("AdminSessionRepo.RevokeAll called %d times, want 0. An operator-tier admin "+
			"must not be able to log every super_admin out of the admin plane.",
			sessions.revokeAllCalls)
	}
}

// TestRevokeAllSessionsFailsLoudlyWithoutATokenRepository keeps the endpoint
// from lying in the other direction.
//
// The refresh-token repository arrives as a positional argument and has been
// passed as nil before, on this very handler. A break-glass control that
// answers 200 while holding no repository to revoke through is the same defect
// this finding is about, so an unwired one reports 503 instead.
func TestRevokeAllSessionsFailsLoudlyWithoutATokenRepository(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	h.tokens = nil

	rec := httptest.NewRecorder()
	h.RevokeAllSessions(rec, withActor(httptest.NewRequest(http.MethodPost, "/admin/sessions/revoke-all", nil)))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: an unwired revoke-all reported success", rec.Code)
	}
}

// TestRevokeAllSessionsReportsAStoreThatRefused pins the error path onto the
// repository that now backs the endpoint.
func TestRevokeAllSessionsReportsAStoreThatRefused(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	h.tokens = &mocks.MockRefreshTokenRepo{
		RevokeAllFn: func(context.Context) error { return errors.New("db down") },
	}

	rec := httptest.NewRecorder()
	h.RevokeAllSessions(rec, withActor(httptest.NewRequest(http.MethodPost, "/admin/sessions/revoke-all", nil)))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}
