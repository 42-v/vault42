package service

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"testing"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

func testErasureUser() *model.User {
	return &model.User{
		ID:          "user-1",
		Email:       "user@example.com",
		DisplayName: "Test User",
		Roles:       []string{"user"},
	}
}

// erasureMocks bundles the mock repos so a test can assert on what was called.
type erasureMocks struct {
	users       *mocks.MockUserRepo
	identity    *mocks.MockIdentityRepo
	blobs       *mocks.MockBlobRepo
	devices     *mocks.MockDeviceRepo
	social      *mocks.MockSocialAccountRepo
	pwHistory   *mocks.MockPasswordHistoryRepo
	tokens      *mocks.MockRefreshTokenRepo
	totp        *mocks.MockTOTPRepo
	webauthn    *mocks.MockWebAuthnRepo
	backupCodes *mocks.MockBackupCodeRepo
	recovery    *mocks.MockAccountRecoveryRepo
}

func newErasureService(t *testing.T, pub *rsa.PublicKey, m *erasureMocks) *ErasureService {
	t.Helper()
	if m.users.GetByIDFn == nil {
		m.users.GetByIDFn = func(context.Context, string) (*model.User, error) {
			return testErasureUser(), nil
		}
	}
	return NewErasureService(
		m.users, m.identity, m.blobs, m.devices, m.social, m.pwHistory,
		m.tokens, m.totp, m.webauthn, m.backupCodes,
		m.recovery, audit.NewLogger(&mocks.MockAuditRepo{}, 0),
		pub, testHMAC,
	)
}

func newErasureMocks() *erasureMocks {
	return &erasureMocks{
		users:       &mocks.MockUserRepo{},
		identity:    &mocks.MockIdentityRepo{},
		blobs:       &mocks.MockBlobRepo{},
		devices:     &mocks.MockDeviceRepo{},
		social:      &mocks.MockSocialAccountRepo{},
		pwHistory:   &mocks.MockPasswordHistoryRepo{},
		tokens:      &mocks.MockRefreshTokenRepo{},
		totp:        &mocks.MockTOTPRepo{},
		webauthn:    &mocks.MockWebAuthnRepo{},
		backupCodes: &mocks.MockBackupCodeRepo{},
		recovery:    &mocks.MockAccountRecoveryRepo{},
	}
}

// Art. 17 requires the MFA authenticators to go with the account. They hang off
// user_id with ON DELETE CASCADE, but erasure soft-deletes the user row with an
// UPDATE, so the cascade never fires — without an explicit delete the encrypted
// TOTP secret, the WebAuthn public keys and the backup-code hashes survive the
// erasure. docs/PRIVACY.md §5.3 promises they do not.
func TestDeleteAccount_ErasesMFAAuthenticators(t *testing.T) {
	m := newErasureMocks()

	var totpDeleted, webauthnDeleted, backupDeleted string
	m.totp.DeleteByUserIDFn = func(_ context.Context, userID string) error {
		totpDeleted = userID
		return nil
	}
	m.webauthn.DeleteAllForUserFn = func(_ context.Context, userID string) error {
		webauthnDeleted = userID
		return nil
	}
	m.backupCodes.DeleteAllForUserFn = func(_ context.Context, userID string) error {
		backupDeleted = userID
		return nil
	}

	svc := newErasureService(t, nil, m)
	if err := svc.DeleteAccount(context.Background(), "user-1", "self", "user request"); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	if totpDeleted != "user-1" {
		t.Errorf("TOTP secret not erased: got %q, want %q", totpDeleted, "user-1")
	}
	if webauthnDeleted != "user-1" {
		t.Errorf("WebAuthn credentials not erased: got %q, want %q", webauthnDeleted, "user-1")
	}
	if backupDeleted != "user-1" {
		t.Errorf("backup codes not erased: got %q, want %q", backupDeleted, "user-1")
	}
}

// A failure to remove an MFA authenticator must abort the erasure loudly. If it
// were swallowed, DeleteAccount would report success while the encrypted TOTP
// secret or the WebAuthn keys stayed behind — the caller would believe the data
// was gone, which is the worst possible outcome for an Art. 17 request.
func TestDeleteAccount_MFADeleteFailureAborts(t *testing.T) {
	boom := errors.New("db down")

	tests := []struct {
		name string
		wire func(m *erasureMocks)
	}{
		{"totp", func(m *erasureMocks) {
			m.totp.DeleteByUserIDFn = func(context.Context, string) error { return boom }
		}},
		{"webauthn", func(m *erasureMocks) {
			m.webauthn.DeleteAllForUserFn = func(context.Context, string) error { return boom }
		}},
		{"backup codes", func(m *erasureMocks) {
			m.backupCodes.DeleteAllForUserFn = func(context.Context, string) error { return boom }
		}},
		{"refresh tokens", func(m *erasureMocks) {
			m.tokens.DeleteAllForUserFn = func(context.Context, string) error { return boom }
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newErasureMocks()
			scrubbed := false
			m.users.SoftDeleteScrubFn = func(context.Context, string, string) error {
				scrubbed = true
				return nil
			}
			tc.wire(m)

			svc := newErasureService(t, nil, m)
			err := svc.DeleteAccount(context.Background(), "user-1", "self", "user request")
			if err == nil {
				t.Fatalf("expected erasure to fail when %s deletion fails", tc.name)
			}
			if !errors.Is(err, boom) {
				t.Errorf("error did not wrap the cause: %v", err)
			}
			if scrubbed {
				t.Error("user row must not be scrubbed once the cascade has failed")
			}
		})
	}
}

func TestDeleteAccount_EscrowsAndCascades(t *testing.T) {
	priv, _ := vaultcrypto.GenerateRSAKeyPair()
	m := newErasureMocks()

	var appended *model.AccountRecovery
	m.recovery.AppendFn = func(_ context.Context, rec *model.AccountRecovery) error {
		appended = rec
		return nil
	}
	var scrubbedEmail string
	m.users.SoftDeleteScrubFn = func(_ context.Context, _, tombstone string) error {
		scrubbedEmail = tombstone
		return nil
	}
	// Erasure hard-deletes the token rows rather than flipping revoked=TRUE: a
	// revoked row still carries the fingerprint hash and the device reference.
	tokensDeleted := false
	m.tokens.DeleteAllForUserFn = func(context.Context, string) error {
		tokensDeleted = true
		return nil
	}

	svc := newErasureService(t, &priv.PublicKey, m)
	if err := svc.DeleteAccount(context.Background(), "user-1", "self", "user_request"); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	if appended == nil {
		t.Fatal("expected a recovery record to be appended")
	}
	if !tokensDeleted {
		t.Error("expected refresh token rows to be deleted, not merely revoked")
	}
	if scrubbedEmail != "deleted-user-1@deleted.invalid" {
		t.Errorf("tombstone email = %q", scrubbedEmail)
	}

	// The escrow payload must decrypt to the original email with the offline key,
	// and must NOT contain the plaintext email on the wire.
	if string(appended.Payload) == "" {
		t.Fatal("empty recovery payload")
	}
	plain, err := vaultcrypto.DecryptRecovery(priv, appended.Payload)
	if err != nil {
		t.Fatalf("decrypt recovery: %v", err)
	}
	var p recoveryPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if p.Email != "user@example.com" {
		t.Errorf("recovered email = %q", p.Email)
	}
}

func TestDeleteAccount_EscrowFailureAborts(t *testing.T) {
	priv, _ := vaultcrypto.GenerateRSAKeyPair()
	m := newErasureMocks()
	m.recovery.AppendFn = func(context.Context, *model.AccountRecovery) error {
		return errors.New("db down")
	}
	scrubbed := false
	m.users.SoftDeleteScrubFn = func(context.Context, string, string) error {
		scrubbed = true
		return nil
	}

	svc := newErasureService(t, &priv.PublicKey, m)
	err := svc.DeleteAccount(context.Background(), "user-1", "self", "user_request")
	if err == nil {
		t.Fatal("expected DeleteAccount to fail when escrow fails (fail closed)")
	}
	if scrubbed {
		t.Error("user was scrubbed despite escrow failure — must fail closed")
	}
}

func TestDeleteAccount_NotFound(t *testing.T) {
	m := newErasureMocks()
	m.users.GetByIDFn = func(context.Context, string) (*model.User, error) {
		return nil, nil
	}
	svc := newErasureService(t, nil, m)
	err := svc.DeleteAccount(context.Background(), "missing", "self", "user_request")
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

func TestDeleteAccount_RecoveryDisabledStillDeletes(t *testing.T) {
	m := newErasureMocks()
	appendCalled := false
	m.recovery.AppendFn = func(context.Context, *model.AccountRecovery) error {
		appendCalled = true
		return nil
	}
	scrubbed := false
	m.users.SoftDeleteScrubFn = func(context.Context, string, string) error {
		scrubbed = true
		return nil
	}

	svc := newErasureService(t, nil, m) // nil recovery key = escrow disabled
	if err := svc.DeleteAccount(context.Background(), "user-1", "admin:a1", "admin_request"); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}
	if appendCalled {
		t.Error("recovery append should not be called when escrow is disabled")
	}
	if !scrubbed {
		t.Error("user should still be scrubbed when escrow is disabled")
	}
}
