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
	users     *mocks.MockUserRepo
	identity  *mocks.MockIdentityRepo
	blobs     *mocks.MockBlobRepo
	devices   *mocks.MockDeviceRepo
	social    *mocks.MockSocialAccountRepo
	pwHistory *mocks.MockPasswordHistoryRepo
	tokens    *mocks.MockRefreshTokenRepo
	recovery  *mocks.MockAccountRecoveryRepo
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
		m.tokens, m.recovery, audit.NewLogger(&mocks.MockAuditRepo{}, 0),
		pub, testHMAC,
	)
}

func newErasureMocks() *erasureMocks {
	return &erasureMocks{
		users:     &mocks.MockUserRepo{},
		identity:  &mocks.MockIdentityRepo{},
		blobs:     &mocks.MockBlobRepo{},
		devices:   &mocks.MockDeviceRepo{},
		social:    &mocks.MockSocialAccountRepo{},
		pwHistory: &mocks.MockPasswordHistoryRepo{},
		tokens:    &mocks.MockRefreshTokenRepo{},
		recovery:  &mocks.MockAccountRecoveryRepo{},
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
	tokensRevoked := false
	m.tokens.RevokeAllForUserFn = func(context.Context, string) error {
		tokensRevoked = true
		return nil
	}

	svc := newErasureService(t, &priv.PublicKey, m)
	if err := svc.DeleteAccount(context.Background(), "user-1", "self", "user_request"); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	if appended == nil {
		t.Fatal("expected a recovery record to be appended")
	}
	if !tokensRevoked {
		t.Error("expected refresh tokens to be revoked")
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
