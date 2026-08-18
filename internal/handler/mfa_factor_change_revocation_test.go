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
	"time"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// Rotating a second factor is the containment step the product documents for a
// suspected compromise: delete the key that may have been cloned, disable and
// re-enrol the authenticator, print a fresh set of backup codes. Every one of
// those routes used to return 200 without touching the refresh-token store, so
// the family the attacker was rotating survived the response that told the
// victim they had fixed it, and kept rotating for the absolute session lifetime
// (VAULT_MAX_SESSION_LIFETIME, 720h by default).
//
// Nothing on the refresh path re-reads the enrolled factors — Refresh consults
// only the account-state flags — so a changed factor is invisible to a live
// session by construction. Revocation at the moment of the change is the only
// thing that makes the lever work.
//
// These tests pin one revoke per mutating factor route, and pin that a revoke
// which does not land is reported rather than swallowed: a containment step
// that silently fails is worse than one that never ran, because the victim
// stops looking.

// factorChangeProbe records what the handler asked the refresh-token store to
// do, and can make that request fail.
type factorChangeProbe struct {
	calls   int
	userID  string
	failErr error
}

func (p *factorChangeProbe) repo() *mocks.MockRefreshTokenRepo {
	return &mocks.MockRefreshTokenRepo{
		RevokeAllForUserFn: func(_ context.Context, userID string) error {
			p.calls++
			p.userID = userID
			return p.failErr
		},
	}
}

// authService wires a minimal AuthService over the probe. The MFA handlers hold
// an AuthService rather than the repository, and RevokeAllTokensForUser is the
// one-line wrapper over the same RevokeAllForUser the password-change path
// calls, so this is the production mechanism and not a test-only one.
func (p *factorChangeProbe) authService(t *testing.T) *service.AuthService {
	t.Helper()
	tokenSvc, _ := newTestTokenService(t)
	return service.NewAuthService(
		&mocks.MockUserRepo{}, p.repo(), &mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, newTestAuditLogger(), nil, cache.NewMemoryCache(), nil,
		"https://vault.test", "TestVault", "", 15, false, nil,
	)
}

// wantRevoked fails unless the subject's families were revoked exactly once.
func (p *factorChangeProbe) wantRevoked(t *testing.T, subject, what string) {
	t.Helper()
	if p.calls == 0 {
		t.Fatalf("%s revoked nothing: the caller's other sessions kept rotating for the "+
			"absolute session lifetime after the factor changed", what)
	}
	if p.calls != 1 {
		t.Errorf("%s revoked %d times, want 1", what, p.calls)
	}
	if p.userID != subject {
		t.Errorf("%s revoked for %q, want %q", what, p.userID, subject)
	}
}

// captureLog redirects the standard logger for the duration of a test and
// returns the buffer it wrote to.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

func newRevokingTOTPHandler(t *testing.T, p *factorChangeProbe, repo *mocks.MockTOTPRepo) *TOTPHandler {
	t.Helper()
	h := NewTOTPHandler(repo, make([]byte, 32), "TestVault", &mocks.MockCache{}, p.authService(t), false)
	h.SetAuditLog(newTestAuditLogger())
	return h
}

// Binding a new TOTP secret to the account is an enrolment, and an enrolment
// made from a stolen session is how an attacker turns a borrowed session into a
// factor of their own. The sessions that existed before it must not survive it.
func TestTOTPSetup_RevokesTheSubjectsSessions(t *testing.T) {
	p := &factorChangeProbe{}
	h := newRevokingTOTPHandler(t, p, &mocks.MockTOTPRepo{
		GetByUserIDFn: func(context.Context, string) (*model.TOTPSecret, error) { return nil, nil },
		CreateFn:      func(context.Context, *model.TOTPSecret) error { return nil },
	})

	rec := httptest.NewRecorder()
	h.Setup(rec, setAuthContext(httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/setup", nil), "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	p.wantRevoked(t, "user-1", "TOTP setup")
}

// Taking the factor off the account is the documented answer to "my
// authenticator was stolen". It has to reach the thief's session, which is the
// thing the victim is actually trying to remove.
func TestTOTPDisable_RevokesTheSubjectsSessions(t *testing.T) {
	p := &factorChangeProbe{}
	h := newRevokingTOTPHandler(t, p, &mocks.MockTOTPRepo{
		GetByUserIDFn: func(_ context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{ID: "totp-1", UserID: userID, Verified: true, CreatedAt: time.Now()}, nil
		},
		DeleteByUserIDFn: func(context.Context, string) error { return nil },
	})

	rec := httptest.NewRecorder()
	h.Disable(rec, setAuthContext(httptest.NewRequest(http.MethodDelete, "/auth/2fa/totp", nil), "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	p.wantRevoked(t, "user-1", "TOTP disable")
}

// A revoke that fails leaves the attacker holding every session they had before
// the factor changed, with a response that reads exactly like the case where
// containment worked. The caller has to be told, or they stop looking.
func TestTOTPDisable_AFailedRevokeIsReportedNotSwallowed(t *testing.T) {
	logs := captureLog(t)
	p := &factorChangeProbe{failErr: errors.New("tokens db down")}
	h := newRevokingTOTPHandler(t, p, &mocks.MockTOTPRepo{
		GetByUserIDFn: func(_ context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{ID: "totp-1", UserID: userID, Verified: true, CreatedAt: time.Now()}, nil
		},
		DeleteByUserIDFn: func(context.Context, string) error { return nil },
	})

	rec := httptest.NewRecorder()
	h.Disable(rec, setAuthContext(httptest.NewRequest(http.MethodDelete, "/auth/2fa/totp", nil), "user-1"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 — the sessions were not revoked and the caller was told "+
			"the factor change succeeded; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(logs.String(), "tokens db down") {
		t.Errorf("the revoke error never reached the log; captured: %s", logs.String())
	}
	if strings.Contains(rec.Body.String(), "tokens db down") {
		t.Error("the storage error leaked to the client")
	}
}

// An enrolment whose containment failed must not hand back the new secret as
// though the account were now clean. The secret is already stored, so a retry
// is the caller's next move and it costs them nothing.
func TestTOTPSetup_AFailedRevokeIsReportedNotSwallowed(t *testing.T) {
	logs := captureLog(t)
	p := &factorChangeProbe{failErr: errors.New("tokens db down")}
	h := newRevokingTOTPHandler(t, p, &mocks.MockTOTPRepo{
		GetByUserIDFn: func(context.Context, string) (*model.TOTPSecret, error) { return nil, nil },
		CreateFn:      func(context.Context, *model.TOTPSecret) error { return nil },
	})

	rec := httptest.NewRecorder()
	h.Setup(rec, setAuthContext(httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/setup", nil), "user-1"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "otpauth://") {
		t.Error("the enrolment secret was handed out after containment failed")
	}
	if !strings.Contains(logs.String(), "tokens db down") {
		t.Errorf("the revoke error never reached the log; captured: %s", logs.String())
	}
}

// ---------------------------------------------------------------------------
// Backup codes
// ---------------------------------------------------------------------------

// A fresh set of backup codes hands the caller ten standing bypasses of every
// other factor and invalidates whatever the owner had written down. It is both
// the quietest way to take an account and, in the other direction, a step the
// owner takes when they think the old list leaked.
func TestBackupCodesGenerate_RevokesTheSubjectsSessions(t *testing.T) {
	p := &factorChangeProbe{}
	h := NewBackupCodeHandler(&mocks.MockBackupCodeRepo{
		DeleteAllForUserFn: func(context.Context, string) error { return nil },
		CreateBatchFn:      func(context.Context, []*model.BackupCode) error { return nil },
	}, make([]byte, 32), p.authService(t), false)
	h.SetAuditLog(newTestAuditLogger())

	rec := httptest.NewRecorder()
	h.Generate(rec, setAuthContext(httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-codes", nil), "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	p.wantRevoked(t, "user-1", "backup-code regeneration")
}

func TestBackupCodesGenerate_AFailedRevokeIsReportedNotSwallowed(t *testing.T) {
	logs := captureLog(t)
	p := &factorChangeProbe{failErr: errors.New("tokens db down")}
	h := NewBackupCodeHandler(&mocks.MockBackupCodeRepo{
		DeleteAllForUserFn: func(context.Context, string) error { return nil },
		CreateBatchFn:      func(context.Context, []*model.BackupCode) error { return nil },
	}, make([]byte, 32), p.authService(t), false)
	h.SetAuditLog(newTestAuditLogger())

	rec := httptest.NewRecorder()
	h.Generate(rec, setAuthContext(httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-codes", nil), "user-1"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "code") && strings.Contains(rec.Body.String(), "warning") {
		t.Error("the new codes were handed out after containment failed")
	}
	if !strings.Contains(logs.String(), "tokens db down") {
		t.Errorf("the revoke error never reached the log; captured: %s", logs.String())
	}
}

// ---------------------------------------------------------------------------
// WebAuthn
// ---------------------------------------------------------------------------

// Enrolling a passkey puts a permanent credential on the account. Done from a
// stolen session it outlives the theft entirely, so the sessions that existed
// when it was bound must not.
func TestWebAuthnRegisterFinish_RevokesTheSubjectsSessions(t *testing.T) {
	p := &factorChangeProbe{}
	wan := newWanfidoWebAuthn(t)
	auth := newWanfidoAuthenticator(t, "enrolled-credential")
	sessions := newWanfidoSessionCache()
	challenge := wanfidoRegistrationSession(t, wan, sessions, "user-1")

	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn:        func(context.Context, string) ([]*model.WebAuthnCredential, error) { return nil, nil },
		GetByCredentialIDFn: func(context.Context, []byte) (*model.WebAuthnCredential, error) { return nil, nil },
		CreateFn:            func(context.Context, *model.WebAuthnCredential) error { return nil },
	}
	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, p.authService(t), false)
	h.SetAuditLog(newTestAuditLogger())

	rec := httptest.NewRecorder()
	h.RegisterFinish(rec, setAuthContext(auth.attestationRequest(t, challenge, 7), "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	p.wantRevoked(t, "user-1", "WebAuthn registration")
}

// The credential is written before the revoke, so a failure here is a torn
// state either way. Reporting it is what tells the caller the enrolment did not
// come with the clean slate it implies.
func TestWebAuthnRegisterFinish_AFailedRevokeIsReportedNotSwallowed(t *testing.T) {
	logs := captureLog(t)
	p := &factorChangeProbe{failErr: errors.New("tokens db down")}
	wan := newWanfidoWebAuthn(t)
	auth := newWanfidoAuthenticator(t, "uncontained-enrolment")
	sessions := newWanfidoSessionCache()
	challenge := wanfidoRegistrationSession(t, wan, sessions, "user-1")

	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn:        func(context.Context, string) ([]*model.WebAuthnCredential, error) { return nil, nil },
		GetByCredentialIDFn: func(context.Context, []byte) (*model.WebAuthnCredential, error) { return nil, nil },
		CreateFn:            func(context.Context, *model.WebAuthnCredential) error { return nil },
	}
	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, p.authService(t), false)
	h.SetAuditLog(newTestAuditLogger())

	rec := httptest.NewRecorder()
	h.RegisterFinish(rec, setAuthContext(auth.attestationRequest(t, challenge, 7), "user-1"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(logs.String(), "tokens db down") {
		t.Errorf("the revoke error never reached the log; captured: %s", logs.String())
	}
}

// Deleting a credential is the response to a key that may have been cloned or
// lost. The sessions that key opened are what the victim is removing.
func TestWebAuthnDeleteCredential_RevokesTheSubjectsSessions(t *testing.T) {
	p := &factorChangeProbe{}
	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(_ context.Context, userID string) ([]*model.WebAuthnCredential, error) {
			return []*model.WebAuthnCredential{{ID: "cred-1", UserID: userID}}, nil
		},
		DeleteFn: func(context.Context, string, string) error { return nil },
	}
	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), &mocks.MockCache{}, nil, p.authService(t), false)
	h.SetAuditLog(newTestAuditLogger())

	req := setAuthContext(httptest.NewRequest(http.MethodDelete, "/auth/2fa/webauthn/credentials/cred-1", nil), "user-1")
	req.SetPathValue("id", "cred-1")
	rec := httptest.NewRecorder()
	h.DeleteCredential(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	p.wantRevoked(t, "user-1", "WebAuthn credential delete")
}

func TestWebAuthnDeleteCredential_AFailedRevokeIsReportedNotSwallowed(t *testing.T) {
	logs := captureLog(t)
	p := &factorChangeProbe{failErr: errors.New("tokens db down")}
	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(_ context.Context, userID string) ([]*model.WebAuthnCredential, error) {
			return []*model.WebAuthnCredential{{ID: "cred-1", UserID: userID}}, nil
		},
		DeleteFn: func(context.Context, string, string) error { return nil },
	}
	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), &mocks.MockCache{}, nil, p.authService(t), false)
	h.SetAuditLog(newTestAuditLogger())

	req := setAuthContext(httptest.NewRequest(http.MethodDelete, "/auth/2fa/webauthn/credentials/cred-1", nil), "user-1")
	req.SetPathValue("id", "cred-1")
	rec := httptest.NewRecorder()
	h.DeleteCredential(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(logs.String(), "tokens db down") {
		t.Errorf("the revoke error never reached the log; captured: %s", logs.String())
	}
}
