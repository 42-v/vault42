package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

func registerSvc(t *testing.T, users *mocks.MockUserRepo, minLen int, hibp bool) *AuthService {
	t.Helper()
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	tokenSvc := NewTokenService(key, kid, "https://vault.test", "https://vault.test",
		15*time.Minute, 24*time.Hour, 30*24*time.Hour)

	return NewAuthService(
		users, &mocks.MockRefreshTokenRepo{},
		&mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, audit.NewLogger(&mocks.MockAuditRepo{}, 0), NewHIBPClient(),
		&mocks.MockCache{}, &mocks.MockEmailSender{}, "https://vault.test", "TestVault",
		"", minLen, hibp, nil,
	)
}

// Registration is the front door. Each of these guards refuses to create an
// account, and each refusal has to happen before any account exists — a guard
// that runs after the insert is not a guard.
func TestRegister_RejectsShortPasswords(t *testing.T) {
	created := false
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(context.Context, string) (*model.User, error) { return nil, nil },
		CreateFn: func(context.Context, *model.User) error {
			created = true
			return nil
		},
	}
	svc := registerSvc(t, users, 15, false)

	_, err := svc.Register(context.Background(), RegisterInput{
		Email:    "new@example.com",
		Password: "short",
	}, "203.0.113.1")
	if !errors.Is(err, ErrPasswordTooShort) {
		t.Errorf("err = %v, want ErrPasswordTooShort", err)
	}
	if created {
		t.Error("an account was created despite a rejected password")
	}
}

// The email-taken response must cost the same as the new-email one. Without the
// dummy Argon2id burn, "already registered" returns in ~0ms while a fresh
// address takes ~150ms — which is a user-enumeration oracle anyone can measure.
func TestRegister_EmailTakenDoesNotLeakByTiming(t *testing.T) {
	created := false
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, email string) (*model.User, error) {
			return &model.User{ID: "existing", Email: email}, nil
		},
		CreateFn: func(context.Context, *model.User) error {
			created = true
			return nil
		},
	}
	svc := registerSvc(t, users, 15, false)

	start := time.Now()
	_, err := svc.Register(context.Background(), RegisterInput{
		Email:    "taken@example.com",
		Password: "a-sufficiently-long-password",
	}, "203.0.113.1")
	elapsed := time.Since(start)

	if !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("err = %v, want ErrEmailTaken", err)
	}
	if created {
		t.Error("a duplicate account was created")
	}
	// The dummy hash is a real Argon2id run (46 MiB, ~150ms). If this returns
	// instantly the burn has been removed and the enumeration oracle is back.
	if elapsed < 10*time.Millisecond {
		t.Errorf("email-taken returned in %v — the constant-time dummy hash is not running", elapsed)
	}
}

// A failure looking the email up must abort, not fall through into creating an
// account whose uniqueness was never checked.
func TestRegister_LookupFailureAborts(t *testing.T) {
	created := false
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(context.Context, string) (*model.User, error) {
			return nil, errors.New("db down")
		},
		CreateFn: func(context.Context, *model.User) error {
			created = true
			return nil
		},
	}
	svc := registerSvc(t, users, 15, false)

	if _, err := svc.Register(context.Background(), RegisterInput{
		Email:    "new@example.com",
		Password: "a-sufficiently-long-password",
	}, "203.0.113.1"); err == nil {
		t.Error("registration proceeded despite a failed uniqueness check")
	}
	if created {
		t.Error("an account was created without a successful uniqueness check")
	}
}
