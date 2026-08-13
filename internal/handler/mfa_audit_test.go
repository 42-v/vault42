package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// These tests describe one regression: for the whole of 0.x, changing or using
// a second factor left no trace, and neither did signing every other session
// out. Only failures were recorded, as login_failure with reason mfa_failed.
//
// The consequence is an investigation that cannot be run. An attacker holding a
// stolen session enrolls their own TOTP secret or passkey, revokes the owner's
// sessions, and the owner is locked out of an account whose audit trail runs
// from their last successful login straight into silence. Nothing distinguishes
// that from an account nobody touched, and nothing distinguishes a user signing
// their own devices out from an attacker doing it for them.
//
// Each test below asserts the row that answers one of those questions.

// auditCapture collects the entries a handler would have written.
type auditCapture struct {
	entries []*model.AuditEntry
}

// logger returns an immediate-mode audit logger feeding this capture. Batch mode
// is deliberately off: buffering would make the assertions depend on a flush.
func (c *auditCapture) logger() *audit.Logger {
	return audit.NewLogger(&mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, entry *model.AuditEntry) error {
			c.entries = append(c.entries, entry)
			return nil
		},
	}, 0)
}

// only returns the single entry of the given type, failing when the count is
// anything but one. An action that logs twice is as wrong as one that logs
// never: a duplicated row invites a reader to count two enrollments.
func (c *auditCapture) only(t *testing.T, eventType string) *model.AuditEntry {
	t.Helper()
	var found []*model.AuditEntry
	for _, e := range c.entries {
		if e.EventType == eventType {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("recorded %d %s entries, want exactly 1; captured %v", len(found), eventType, c.types())
	}
	return found[0]
}

// none fails when an entry of the given type was recorded.
func (c *auditCapture) none(t *testing.T, eventType string) {
	t.Helper()
	for _, e := range c.entries {
		if e.EventType == eventType {
			t.Fatalf("recorded a %s entry that no action justifies; captured %v", eventType, c.types())
		}
	}
}

// types lists what was captured, so a failure says what happened instead.
func (c *auditCapture) types() []string {
	out := make([]string, 0, len(c.entries))
	for _, e := range c.entries {
		out = append(out, e.EventType)
	}
	return out
}

// wantMeta fails when a metadata key is missing or holds another value.
func wantMeta(t *testing.T, entry *model.AuditEntry, key string, want interface{}) {
	t.Helper()
	got, ok := entry.Metadata[key]
	if !ok {
		t.Fatalf("%s entry has no %q in its metadata: %v", entry.EventType, key, entry.Metadata)
	}
	if got != want {
		t.Errorf("%s entry metadata[%q] = %v, want %v", entry.EventType, key, got, want)
	}
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

// totpFixture is a user with an encrypted TOTP secret the handler can decrypt.
type totpFixture struct {
	masterKey []byte
	secret    string
	repo      *mocks.MockTOTPRepo
	verified  bool
	deleted   bool
}

func newTOTPFixture(t *testing.T, userID string, alreadyVerified bool) *totpFixture {
	t.Helper()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = 0x42
	}
	secret, err := vaultcrypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("generate TOTP secret: %v", err)
	}
	encrypted, err := vaultcrypto.Encrypt([]byte(secret), masterKey, []byte(userID))
	if err != nil {
		t.Fatalf("encrypt TOTP secret: %v", err)
	}

	f := &totpFixture{masterKey: masterKey, secret: secret}
	f.repo = &mocks.MockTOTPRepo{
		GetByUserIDFn: func(_ context.Context, uid string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{
				ID:        "totp-1",
				UserID:    uid,
				SecretEnc: hex.EncodeToString(encrypted),
				Verified:  alreadyVerified,
			}, nil
		},
		MarkVerifiedFn: func(context.Context, string) error {
			f.verified = true
			return nil
		},
		DeleteByUserIDFn: func(context.Context, string) error {
			f.deleted = true
			return nil
		},
	}
	return f
}

func (f *totpFixture) handler(trail *auditCapture) *TOTPHandler {
	h := NewTOTPHandler(f.repo, f.masterKey, "VaultTest", &mocks.MockCache{}, nil, false)
	if trail != nil {
		h.SetAuditLog(trail.logger())
	}
	return h
}

func (f *totpFixture) verifyRequest(t *testing.T, userID string) *http.Request {
	t.Helper()
	code, err := vaultcrypto.GenerateTOTPCode(f.secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/verify", jsonBody(t, map[string]string{"code": code}))
	return setAuthContext(req, userID)
}

// The first accepted code is what turns a pending secret into a factor that
// gates logins, so it is the enrollment an investigator looks for after a
// takeover. Without this row, an attacker who binds their own authenticator to
// a stolen session leaves the account with a second factor it never had and the
// trail with nothing to show for it.
func TestTOTPVerifyRecordsEnrollmentAndVerification(t *testing.T) {
	f := newTOTPFixture(t, "user-1", false)
	trail := &auditCapture{}
	h := f.handler(trail)

	rec := httptest.NewRecorder()
	h.Verify(rec, f.verifyRequest(t, "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if !f.verified {
		t.Fatal("the secret was not marked verified, so this is not the enrollment path")
	}

	setup := trail.only(t, audit.TwoFASetup)
	if setup.UserID != "user-1" {
		t.Errorf("enrollment recorded against %q, want the token subject", setup.UserID)
	}
	wantMeta(t, setup, "method", "totp")
	wantMeta(t, setup, "action", "enrolled")

	verify := trail.only(t, audit.TwoFAVerify)
	wantMeta(t, verify, "method", "totp")
}

// Every later code is a verification and nothing more. Re-recording enrollment
// on each login would make the trail read as an authenticator being rebound
// daily, which buries the one enrollment that mattered.
func TestTOTPVerifyOnAnEnrolledSecretRecordsOnlyVerification(t *testing.T) {
	f := newTOTPFixture(t, "user-1", true)
	trail := &auditCapture{}
	h := f.handler(trail)

	rec := httptest.NewRecorder()
	h.Verify(rec, f.verifyRequest(t, "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	trail.none(t, audit.TwoFASetup)
	wantMeta(t, trail.only(t, audit.TwoFAVerify), "method", "totp")
}

// A rejected code must not look like a successful verification. 2fa_verify is
// what an operator counts to spot a factor being brute-forced from a new
// address; if failures landed in the same bucket the count would be noise.
func TestTOTPVerifyRecordsNothingOnAWrongCode(t *testing.T) {
	f := newTOTPFixture(t, "user-1", true)
	trail := &auditCapture{}
	h := f.handler(trail)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/verify", jsonBody(t, map[string]string{"code": "000000"}))
	rec := httptest.NewRecorder()
	h.Verify(rec, setAuthContext(req, "user-1"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", rec.Code, rec.Body.String())
	}
	trail.none(t, audit.TwoFAVerify)
	trail.none(t, audit.TwoFASetup)
}

// Taking the factor off the account is the step that makes a takeover
// permanent, and it is the one the owner will most want dated. The event type
// is shared with enrollment because the audit vocabulary has no removal
// constant, so the action key is what tells the two apart.
func TestTOTPDisableRecordsFactorRemoval(t *testing.T) {
	f := newTOTPFixture(t, "user-1", true)
	trail := &auditCapture{}
	h := f.handler(trail)

	req := httptest.NewRequest(http.MethodDelete, "/auth/2fa/totp", nil)
	rec := httptest.NewRecorder()
	h.Disable(rec, setAuthContext(req, "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if !f.deleted {
		t.Fatal("the secret was not deleted, so this is not the removal path")
	}

	removal := trail.only(t, audit.TwoFASetup)
	wantMeta(t, removal, "method", "totp")
	wantMeta(t, removal, "action", "removed")
}

// A factor the server refuses to delete has not been removed, so recording a
// removal would date an event that never happened and send an investigator
// looking for an attacker who was turned away.
func TestTOTPDisableRecordsNothingWhenTheDeleteFails(t *testing.T) {
	f := newTOTPFixture(t, "user-1", true)
	f.repo.DeleteByUserIDFn = func(context.Context, string) error { return errors.New("db down") }
	trail := &auditCapture{}
	h := f.handler(trail)

	req := httptest.NewRequest(http.MethodDelete, "/auth/2fa/totp", nil)
	rec := httptest.NewRecorder()
	h.Disable(rec, setAuthContext(req, "user-1"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
	trail.none(t, audit.TwoFASetup)
}

// An audit backend that is down must not cost the user their second factor.
// The trail is evidence, not a gate, and a handler that failed closed here
// would turn an audit outage into a lockout for everyone with 2FA enabled.
func TestTOTPVerifySurvivesAFailingAuditBackend(t *testing.T) {
	f := newTOTPFixture(t, "user-1", true)
	h := f.handler(nil)
	h.SetAuditLog(audit.NewLogger(&mocks.MockAuditRepo{
		InsertFn: func(context.Context, *model.AuditEntry) error { return errors.New("audit db down") },
	}, 0))

	rec := httptest.NewRecorder()
	h.Verify(rec, f.verifyRequest(t, "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; a failed audit write must not fail the verification; body: %s",
			rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// WebAuthn
// ---------------------------------------------------------------------------

// A passkey is a permanent credential on the account: whoever enrolls one can
// sign in long after the session they used to enroll it is gone. That makes
// enrollment the single most valuable row in a takeover investigation, and it
// was the one this handler never wrote.
func TestWebAuthnRegisterFinishRecordsEnrollment(t *testing.T) {
	wan := newWanfidoWebAuthn(t)
	auth := newWanfidoAuthenticator(t, "audited-credential")
	sessions := newWanfidoSessionCache()
	challenge := wanfidoRegistrationSession(t, wan, sessions, "user-1")

	var stored *model.WebAuthnCredential
	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) { return nil, nil },
		CreateFn: func(_ context.Context, cred *model.WebAuthnCredential) error {
			stored = cred
			return nil
		},
	}

	trail := &auditCapture{}
	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, nil, false)
	h.SetAuditLog(trail.logger())

	rec := httptest.NewRecorder()
	h.RegisterFinish(rec, setAuthContext(auth.attestationRequest(t, challenge, 1), "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	entry := trail.only(t, audit.TwoFASetup)
	if entry.UserID != "user-1" {
		t.Errorf("enrollment recorded against %q, want the token subject", entry.UserID)
	}
	wantMeta(t, entry, "method", "webauthn")
	wantMeta(t, entry, "action", "enrolled")
	// The row has to name which credential appeared, or an account with several
	// keys cannot be reconciled against its credential list.
	if stored == nil {
		t.Fatal("registration returned 200 without persisting a credential")
	}
	wantMeta(t, entry, "credential_id", stored.ID)
}

// A ceremony that fails verification enrolled nothing. Recording it would put
// an enrollment in the trail for an authenticator the server rejected.
func TestWebAuthnRegisterFinishRecordsNothingOnAFailedCeremony(t *testing.T) {
	wan := newWanfidoWebAuthn(t)
	auth := newWanfidoAuthenticator(t, "rejected-credential")
	sessions := newWanfidoSessionCache()
	wanfidoRegistrationSession(t, wan, sessions, "user-1")

	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) { return nil, nil },
	}

	trail := &auditCapture{}
	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, nil, false)
	h.SetAuditLog(trail.logger())

	// A challenge the relying party never issued.
	rec := httptest.NewRecorder()
	h.RegisterFinish(rec, setAuthContext(auth.attestationRequest(t, "not-the-issued-challenge", 1), "user-1"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	trail.none(t, audit.TwoFASetup)
}

// Each accepted assertion is a use of the key. Without these rows the trail can
// show that a passkey exists but never that it was used, so an owner reporting
// logins they did not make has nothing to point at.
func TestWebAuthnVerifyFinishRecordsVerification(t *testing.T) {
	wan := newWanfidoWebAuthn(t)
	auth := newWanfidoAuthenticator(t, "asserting-credential")
	sessions := newWanfidoSessionCache()

	existing := []*model.WebAuthnCredential{
		{ID: "cred-row-1", UserID: "user-1", CredentialID: auth.credID, PublicKey: auth.coseKey(), SignCount: 4},
	}
	challenge := wanfidoLoginSession(t, wan, sessions, "user-1", existing)

	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn:      func(context.Context, string) ([]*model.WebAuthnCredential, error) { return existing, nil },
		UpdateSignCountFn: func(context.Context, string, int) error { return nil },
		UpdateFlagsFn:     func(context.Context, string, int) error { return nil },
	}

	trail := &auditCapture{}
	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, nil, false)
	h.SetAuditLog(trail.logger())

	req := auth.assertionRequest(t, challenge, 9, wanfidoFlagUP|wanfidoFlagUV, nil)
	rec := httptest.NewRecorder()
	h.VerifyFinish(rec, setAuthContext(req, "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	wantMeta(t, trail.only(t, audit.TwoFAVerify), "method", "webauthn")
	trail.none(t, audit.TwoFASetup)
}

// Removing the owner's key is how a lockout is made to stick, and the row is
// what lets support tell that apart from a user retiring a lost security key.
func TestWebAuthnDeleteCredentialRecordsFactorRemoval(t *testing.T) {
	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) {
			return []*model.WebAuthnCredential{{ID: "cred-row-1", UserID: "user-1"}}, nil
		},
		DeleteFn: func(context.Context, string, string) error { return nil },
	}

	trail := &auditCapture{}
	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), newWanfidoSessionCache(), nil, nil, false)
	h.SetAuditLog(trail.logger())

	req := httptest.NewRequest(http.MethodDelete, "/auth/2fa/webauthn/credentials/cred-row-1", nil)
	req.SetPathValue("id", "cred-row-1")
	rec := httptest.NewRecorder()
	h.DeleteCredential(rec, setAuthContext(req, "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	entry := trail.only(t, audit.TwoFASetup)
	wantMeta(t, entry, "method", "webauthn")
	wantMeta(t, entry, "action", "removed")
	wantMeta(t, entry, "credential_id", "cred-row-1")
}

// ---------------------------------------------------------------------------
// Backup codes
// ---------------------------------------------------------------------------

// Generating codes hands the caller ten standing bypasses of every other factor
// and invalidates whatever the owner had written down. It is the quietest way
// to take an account, and it used to be entirely unrecorded.
func TestBackupCodeGenerateRecordsEnrollmentWithoutTheCodes(t *testing.T) {
	repo := &mocks.MockBackupCodeRepo{
		DeleteAllForUserFn: func(context.Context, string) error { return nil },
		CreateBatchFn:      func(context.Context, []*model.BackupCode) error { return nil },
	}

	trail := &auditCapture{}
	h := NewBackupCodeHandler(repo, []byte("test-hmac-key"), nil, false)
	h.SetAuditLog(trail.logger())

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-codes", nil)
	rec := httptest.NewRecorder()
	h.Generate(rec, setAuthContext(req, "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	entry := trail.only(t, audit.TwoFASetup)
	wantMeta(t, entry, "method", "backup_code")
	wantMeta(t, entry, "action", "enrolled")
	wantMeta(t, entry, "count", backupCodeCount)

	// Audit rows survive account erasure, and a backup code is the factor
	// itself. One leaking into the trail would leave a working credential in a
	// table nobody treats as a secret store.
	var issued BackupCodesResponse
	decodeResponse(t, rec, &issued)
	if len(issued.Codes) == 0 {
		t.Fatal("no codes issued, so this asserts nothing")
	}
	serialized, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal audit entry: %v", err)
	}
	for _, code := range issued.Codes {
		if strings.Contains(string(serialized), code) {
			t.Fatal("an issued backup code reached the audit entry")
		}
	}
}

// A spent code from an unfamiliar address is what separates "the owner lost
// their phone" from "someone else had the list". Only failures were recorded
// before, so the trail could show attempts and never a success.
func TestBackupCodeVerifyRecordsVerification(t *testing.T) {
	hmacKey := []byte("test-hmac-key")
	code := "0123456789abcdef"
	repo := &mocks.MockBackupCodeRepo{
		ListUnusedByUserFn: func(context.Context, string) ([]*model.BackupCode, error) {
			return []*model.BackupCode{{
				ID:       "backup-1",
				UserID:   "user-1",
				CodeHash: vaultcrypto.HMACSign([]byte(code), hmacKey),
			}}, nil
		},
		MarkUsedFn: func(context.Context, string) (bool, error) { return true, nil },
	}

	trail := &auditCapture{}
	h := NewBackupCodeHandler(repo, hmacKey, nil, false)
	h.SetAuditLog(trail.logger())

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-code/verify", jsonBody(t, map[string]string{"code": code}))
	rec := httptest.NewRecorder()
	h.Verify(rec, setAuthContext(req, "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	wantMeta(t, trail.only(t, audit.TwoFAVerify), "method", "backup_code")
}

// A code that matched nothing was not spent, and recording it as a verification
// would make a brute-force attempt indistinguishable from a redemption.
func TestBackupCodeVerifyRecordsNothingOnAMiss(t *testing.T) {
	repo := &mocks.MockBackupCodeRepo{
		ListUnusedByUserFn: func(context.Context, string) ([]*model.BackupCode, error) { return nil, nil },
	}

	trail := &auditCapture{}
	h := NewBackupCodeHandler(repo, []byte("test-hmac-key"), nil, false)
	h.SetAuditLog(trail.logger())

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-code/verify", jsonBody(t, map[string]string{"code": "deadbeefdeadbeef"}))
	rec := httptest.NewRecorder()
	h.Verify(rec, setAuthContext(req, "user-1"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", rec.Code, rec.Body.String())
	}
	trail.none(t, audit.TwoFAVerify)
}

// ---------------------------------------------------------------------------
// Session revocation
// ---------------------------------------------------------------------------

// Signing the owner out is how a takeover ends, and the devices row that would
// have shown the attacker's login is deleted in the same request. Without these
// rows the only record of the attacker's device is destroyed by the act that
// completes the attack, and a self-service sign-out looks identical to a
// hostile one.
func TestSessionRevocationRecordsTheDeviceItRemoved(t *testing.T) {
	cases := []struct {
		name     string
		invoke   func(h *UserHandler, rec *httptest.ResponseRecorder, r *http.Request)
		request  func(t *testing.T) *http.Request
		wantDev  string
		wantScop string
	}{
		{
			name:   "one session",
			invoke: func(h *UserHandler, rec *httptest.ResponseRecorder, r *http.Request) { h.RevokeSession(rec, r) },
			request: func(t *testing.T) *http.Request {
				t.Helper()
				r := httptest.NewRequest(http.MethodDelete, "/user/sessions/device-7", nil)
				r.SetPathValue("id", "device-7")
				return r
			},
			wantDev:  "device-7",
			wantScop: "session",
		},
		{
			name:   "one device",
			invoke: func(h *UserHandler, rec *httptest.ResponseRecorder, r *http.Request) { h.DeleteDevice(rec, r) },
			request: func(t *testing.T) *http.Request {
				t.Helper()
				r := httptest.NewRequest(http.MethodDelete, "/user/devices/device-7", nil)
				r.SetPathValue("id", "device-7")
				return r
			},
			wantDev:  "device-7",
			wantScop: "device",
		},
		{
			name:   "everywhere",
			invoke: func(h *UserHandler, rec *httptest.ResponseRecorder, r *http.Request) { h.RevokeAllSessions(rec, r) },
			request: func(t *testing.T) *http.Request {
				t.Helper()
				return httptest.NewRequest(http.MethodDelete, "/user/sessions", nil)
			},
			// A blanket revocation names no single device, and inventing one
			// would make the trail claim more than happened.
			wantDev:  "",
			wantScop: "all",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			devices := &mocks.MockDeviceRepo{
				GetByIDFn: func(_ context.Context, id string) (*model.Device, error) {
					return &model.Device{ID: id, UserID: "user-1"}, nil
				},
				DeleteFn:           func(context.Context, string, string) error { return nil },
				DeleteAllForUserFn: func(context.Context, string) error { return nil },
			}
			tokens := &mocks.MockRefreshTokenRepo{
				RevokeByDeviceIDFn: func(context.Context, string) error { return nil },
				RevokeAllForUserFn: func(context.Context, string) error { return nil },
			}

			trail := &auditCapture{}
			h := NewUserHandler(&mocks.MockUserRepo{}, devices, tokens, nil)
			h.SetAuditLog(trail.logger())

			rec := httptest.NewRecorder()
			tc.invoke(h, rec, setAuthContext(tc.request(t), "user-1"))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
			}

			entry := trail.only(t, audit.SessionRevoke)
			if entry.UserID != "user-1" {
				t.Errorf("revocation recorded against %q, want the token subject", entry.UserID)
			}
			if entry.DeviceID != tc.wantDev {
				t.Errorf("device column = %q, want %q; without it a revocation cannot be joined "+
					"against the login that created the device", entry.DeviceID, tc.wantDev)
			}
			wantMeta(t, entry, "scope", tc.wantScop)
		})
	}
}

// A revocation the server refused did not happen. Recording it would tell the
// owner their sessions are gone while the attacker's is still live.
func TestSessionRevocationRecordsNothingWhenTheDeleteFails(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.Device, error) {
			return &model.Device{ID: id, UserID: "user-1"}, nil
		},
		DeleteFn: func(context.Context, string, string) error { return errors.New("db down") },
	}
	tokens := &mocks.MockRefreshTokenRepo{
		RevokeByDeviceIDFn: func(context.Context, string) error { return nil },
	}

	trail := &auditCapture{}
	h := NewUserHandler(&mocks.MockUserRepo{}, devices, tokens, nil)
	h.SetAuditLog(trail.logger())

	req := httptest.NewRequest(http.MethodDelete, "/user/sessions/device-7", nil)
	req.SetPathValue("id", "device-7")
	rec := httptest.NewRecorder()
	h.RevokeSession(rec, setAuthContext(req, "user-1"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
	trail.none(t, audit.SessionRevoke)
}

// Handlers built without a logger still have to serve. Several test suites and
// the honeypot profile construct them that way, and a nil dereference here
// would take down the endpoints the audit trail exists to describe.
func TestFactorAndSessionHandlersServeWithoutALogger(t *testing.T) {
	devices := &mocks.MockDeviceRepo{
		DeleteAllForUserFn: func(context.Context, string) error { return nil },
	}
	tokens := &mocks.MockRefreshTokenRepo{
		RevokeAllForUserFn: func(context.Context, string) error { return nil },
	}
	user := NewUserHandler(&mocks.MockUserRepo{}, devices, tokens, nil)

	rec := httptest.NewRecorder()
	user.RevokeAllSessions(rec, setAuthContext(httptest.NewRequest(http.MethodDelete, "/user/sessions", nil), "user-1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("RevokeAllSessions status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	f := newTOTPFixture(t, "user-1", true)
	rec = httptest.NewRecorder()
	f.handler(nil).Verify(rec, f.verifyRequest(t, "user-1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("TOTP Verify status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
}

// SetAuditLog must ignore a nil logger rather than storing one. Wiring code
// passes whatever the dependency struct holds, and a stored nil would turn
// every later call into a nil dereference instead of a silent skip.
func TestSetAuditLogIgnoresANilLogger(t *testing.T) {
	trail := &auditCapture{}
	f := newTOTPFixture(t, "user-1", true)
	h := f.handler(trail)
	h.SetAuditLog(nil)

	rec := httptest.NewRecorder()
	h.Verify(rec, f.verifyRequest(t, "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	trail.only(t, audit.TwoFAVerify)
}
