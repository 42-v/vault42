package handler

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// A sign-counter regression is the strongest evidence of compromise this
// service can produce: it says the credential private key answered from two
// places. Refusing the assertion is only half the response. The other half is
// revoking every refresh-token family the user holds, because the sessions the
// clone already opened are what the attacker actually wants, and they outlive a
// single refused assertion by the whole refresh-token lifetime.
//
// These tests assert that the containment leaves a record whichever way it
// goes. Both cases below produce an identical response to the caller, so the
// audit row is the only thing that can tell an operator which one happened.

// cloneFixture is a user whose stored sign count the next assertion will not
// advance, which is what makes go-webauthn raise CloneWarning.
type cloneFixture struct {
	handler  *WebAuthnHandler
	request  *http.Request
	recorder *httptest.ResponseRecorder
	trail    *auditCapture
}

// newCloneFixture wires a handler whose refresh-token store behaves as
// revokeErr says, then builds the assertion that trips clone detection.
func newCloneFixture(t *testing.T, credID string, revokeErr error, revokedFor *string) *cloneFixture {
	t.Helper()

	wan := newWanfidoWebAuthn(t)
	auth := newWanfidoAuthenticator(t, credID)
	sessions := newWanfidoSessionCache()

	const storedCount = 12
	existing := []*model.WebAuthnCredential{
		{ID: "cred-row-1", UserID: "user-1", CredentialID: auth.credID, PublicKey: auth.coseKey(), SignCount: storedCount},
	}
	challenge := wanfidoLoginSession(t, wan, sessions, "user-1", existing)

	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) {
			return existing, nil
		},
		UpdateSignCountFn: func(context.Context, string, int) error {
			t.Error("a cloned assertion was allowed to move the stored sign count")
			return nil
		},
	}

	tokens := &mocks.MockRefreshTokenRepo{
		RevokeAllForUserFn: func(_ context.Context, userID string) error {
			if revokedFor != nil {
				*revokedFor = userID
			}
			return revokeErr
		},
	}

	trail := &auditCapture{}
	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, newWanfidoAuthService(t, tokens, sessions), false)
	h.SetAuditLog(trail.logger())

	// The asserted count equals the stored one, so it does not move forward.
	req := auth.assertionRequest(t, challenge, storedCount, wanfidoFlagUP|wanfidoFlagUV, nil)

	return &cloneFixture{
		handler:  h,
		request:  setChallengeContext(req, "user-1", "jti-clone-containment"),
		recorder: httptest.NewRecorder(),
		trail:    trail,
	}
}

// wantCloneRefusal fails unless the caller was told the assertion was refused
// for the reason it was refused, and was given no session.
func wantCloneRefusal(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "cloned_authenticator_detected" {
		t.Errorf("error = %q, want cloned_authenticator_detected", result["error"])
	}
	if strings.Contains(rec.Body.String(), "access_token") {
		t.Error("a cloned authenticator was issued a session")
	}
}

// A clone signal whose containment succeeded must still say so in the trail.
// Without a row the only evidence a clone was ever detected is a process log
// line, which is not the append-only store the incident timeline is
// reconstructed from, and an investigator has no way to tell that every session
// was torn down at that moment rather than by the owner signing out.
func TestWebAuthnVerifyFinish_SuccessfulCloneContainmentIsRecordedInTheTrail(t *testing.T) {
	revokedFor := ""
	f := newCloneFixture(t, "cloned-credential", nil, &revokedFor)

	f.handler.VerifyFinish(f.recorder, f.request)

	wantCloneRefusal(t, f.recorder)
	if revokedFor != "user-1" {
		t.Errorf("RevokeAllTokensForUser called for %q, want user-1", revokedFor)
	}

	entry := f.trail.only(t, audit.TokenRevoke)
	wantMeta(t, entry, "reason", "cloned_authenticator")
	wantMeta(t, entry, "method", "webauthn")
	wantMeta(t, entry, "outcome", "revoked")
	if entry.UserID != "user-1" {
		t.Errorf("containment recorded against %q, want user-1", entry.UserID)
	}
	// A refused assertion is not a verification. Recording one would put a
	// successful second factor in the trail at the exact moment the service
	// decided the authenticator was cloned.
	f.trail.none(t, audit.TwoFAVerify)
}

// A containment that fails must be recorded as a failure, and must not change
// the refusal.
//
// The revoke hangs off a database write, so a transient outage makes it fail
// while the assertion is still correctly refused. Discarding that error leaves
// the attacker holding every session they had before the clone was detected,
// with a trail that reads exactly like the case where containment worked. The
// one signal that says "this key is in two places" then produces an incident
// response that never ran, and nobody finds out until the attacker uses one of
// the sessions that was supposed to be gone.
func TestWebAuthnVerifyFinish_FailedCloneContainmentIsRecordedAndStillRefuses(t *testing.T) {
	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(prev) })

	f := newCloneFixture(t, "uncontained-credential", errors.New("tokens db down"), nil)

	f.handler.VerifyFinish(f.recorder, f.request)

	// Fail-closed first: the refusal must not depend on the revoke landing.
	wantCloneRefusal(t, f.recorder)

	entry := f.trail.only(t, audit.TokenRevoke)
	wantMeta(t, entry, "reason", "cloned_authenticator")
	wantMeta(t, entry, "outcome", "revoke_failed")

	if !strings.Contains(logBuf.String(), "tokens db down") {
		t.Errorf("the revoke error never reached the log; captured: %s", logBuf.String())
	}
	if strings.Contains(f.recorder.Body.String(), "tokens db down") {
		t.Error("the storage error leaked to the client")
	}
}
