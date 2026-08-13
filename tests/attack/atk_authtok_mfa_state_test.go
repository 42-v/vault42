package attack

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
)

// The 2FA challenge flow issues a short-lived (5 min) challenge token after the
// password step, then mints the real session inside AuthService.CompleteMFALogin
// once a second factor verifies. Every OTHER issuance path re-checks the account
// state at the moment it issues:
//
//   - Login gates banned / disabled / deleted / locked before the challenge
//     (auth.go ~539-589).
//   - Refresh re-reads the user and revokes the family for nil / Deleted / Banned
//     / Disabled on every rotation (auth.go ~806-820).
//   - The OAuth callback gates banned / disabled / deleted before issuing
//     (internal/handler/oauth.go ~389-401).
//
// CompleteMFALogin does not. It re-reads the user solely to recompute roles and
// falls through to issuance for any non-nil row, banned or not (auth.go ~906-919).
// So an account that transitions to banned / disabled / locked during the 5-minute
// window between the password step and the second factor still receives a full
// session when the second factor completes. The realistic trigger is an operator
// banning or locking an account in response to the very compromise in progress:
// the attacker, already holding the challenge token, completes 2FA and is let in.
//
// Each test encodes the secure expectation (MFA completion must refuse a
// banned / disabled / locked subject) and FAILS against the current code, which
// hands back a token pair.

// TestAtk_CompleteMFALoginIssuesForBannedUser proves a banned account still
// receives a session by completing 2FA.
func TestAtk_CompleteMFALoginIssuesForBannedUser(t *testing.T) {
	svc, d := atkAuthTokService(t)

	const userID = "banned-during-mfa"
	d.users.GetByIDFn = func(_ context.Context, id string) (*model.User, error) {
		return &model.User{ID: id, Roles: []string{"user"}, Banned: true}, nil
	}

	// jti empty => single-use cache check is skipped, isolating the account-state
	// question from the (correct, separately tested) challenge replay control.
	res, err := svc.CompleteMFALogin(context.Background(), userID, "fp", "9.9.9.9", "UA", "")
	if err == nil {
		t.Fatalf("SECURITY: CompleteMFALogin issued a session for a BANNED account "+
			"(access token len=%d); the second-factor issuance path skips the "+
			"account-state gate that Login, Refresh and the OAuth callback all enforce",
			len(res.AccessToken))
	}
}

// TestAtk_CompleteMFALoginIssuesForDisabledUser proves the same for a disabled
// account.
func TestAtk_CompleteMFALoginIssuesForDisabledUser(t *testing.T) {
	svc, d := atkAuthTokService(t)

	const userID = "disabled-during-mfa"
	d.users.GetByIDFn = func(_ context.Context, id string) (*model.User, error) {
		return &model.User{ID: id, Roles: []string{"user"}, Disabled: true}, nil
	}

	if _, err := svc.CompleteMFALogin(context.Background(), userID, "fp", "9.9.9.9", "UA", ""); err == nil {
		t.Fatalf("SECURITY: CompleteMFALogin issued a session for a DISABLED account")
	}
}

// TestAtk_CompleteMFALoginIssuesForLockedUser proves the same for an
// administratively locked account. This is the sharpest variant: locking is the
// documented first response to a suspected takeover, yet a challenge already in
// flight completes straight through it.
func TestAtk_CompleteMFALoginIssuesForLockedUser(t *testing.T) {
	svc, d := atkAuthTokService(t)

	const userID = "locked-during-mfa"
	lockedUntil := time.Now().Add(24 * time.Hour)
	d.users.GetByIDFn = func(_ context.Context, id string) (*model.User, error) {
		return &model.User{ID: id, Roles: []string{"user"}, LockedUntil: &lockedUntil}, nil
	}

	if _, err := svc.CompleteMFALogin(context.Background(), userID, "fp", "9.9.9.9", "UA", ""); err == nil {
		t.Fatalf("SECURITY: CompleteMFALogin issued a session for an admin-LOCKED account")
	}
}
