package service

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
)

// Every identifier, token and OTP the auth service hands out comes from
// crypto/rand, and each generator has an error return that no test reached. The
// danger is not the error itself but what a caller does with it: a zero-value
// UUID, an empty refresh token or an all-zero OTP accepted with a nil error
// would each be a credential an attacker can predict. These tests starve the
// entropy source at a chosen point in each flow and pin that the caller aborts
// and persists nothing.

var errServiceAuthEntropy = errors.New("service test: entropy exhausted")

// serviceAuthScriptedReader serves budget whole reads and then fails. Only code
// that reaches crypto/rand through io.ReadFull (RandomBytes and everything built
// on it) sees the error: crypto/rand.Read is process-fatal on a failing reader,
// so the budget must always cover the direct rand.Read calls a flow makes.
type serviceAuthScriptedReader struct {
	left atomic.Int64
}

func (r *serviceAuthScriptedReader) Read(p []byte) (int, error) {
	if r.left.Add(-1) < 0 {
		return 0, errServiceAuthEntropy
	}
	for i := range p {
		p[i] = 0x42
	}
	return len(p), nil
}

// serviceAuthStarveEntropy installs a reader that dies after budget reads and
// restores the previous one when the test ends.
func serviceAuthStarveEntropy(t *testing.T, budget int64) {
	t.Helper()
	r := &serviceAuthScriptedReader{}
	r.left.Store(budget)
	previous := rand.Reader
	rand.Reader = r
	t.Cleanup(func() { rand.Reader = previous })
}

var _ io.Reader = (*serviceAuthScriptedReader)(nil)

// The user ID is generated after the password hash. A registration that
// continued past the failure would insert a row keyed by an empty ID.
func TestRegisterUserIDEntropyFailureCreatesNoAccount(t *testing.T) {
	var created atomic.Bool
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.CreateFn = func(context.Context, *model.User) error {
			created.Store(true)
			return nil
		}
	})

	serviceAuthStarveEntropy(t, 1)

	res, err := svc.Register(context.Background(), RegisterInput{
		Email: "entropy@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4")

	if !errors.Is(err, errServiceAuthEntropy) {
		t.Fatalf("err = %v, want the entropy failure to surface", err)
	}
	if !strings.Contains(err.Error(), "generate user ID") {
		t.Errorf("err = %v, want it to name the user ID generation step", err)
	}
	if res != nil {
		t.Error("a registration result was returned without a user ID")
	}
	if created.Load() {
		t.Error("a user row was written after the user ID generation failed")
	}
}

// Password history is documented as best effort. A failure to mint its row ID
// must be swallowed: the account is already created and the caller must not see
// the registration fail after the fact.
func TestRegisterPasswordHistoryEntropyFailureStillRegisters(t *testing.T) {
	var historyWritten atomic.Bool
	svc, o := newMockAuthService(t, func(o *mockAuthOpts) {
		o.pwHistory.CreateFn = func(context.Context, *model.PasswordHistory) error {
			historyWritten.Store(true)
			return nil
		}
	})
	o.emailSender.SendFn = func(context.Context, string, string, string, string) error { return nil }

	serviceAuthStarveEntropy(t, 2)

	res, err := svc.Register(context.Background(), RegisterInput{
		Email: "history@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4")
	if err != nil {
		t.Fatalf("registration failed on a best-effort password history error: %v", err)
	}
	if res == nil || res.UserID == "" {
		t.Fatal("registration returned no user")
	}
	if historyWritten.Load() {
		t.Error("a password history row was written with no ID")
	}
}

// A verification link is a bearer credential. Without a token there is nothing
// to store and nothing to send.
func TestSendVerificationEmailEntropyFailureStoresNothing(t *testing.T) {
	svc, mockCache, mockEmail := newAuthServiceWithDeps(t)

	var stored, sent atomic.Bool
	mockCache.SetFn = func(context.Context, string, string, time.Duration) error {
		stored.Store(true)
		return nil
	}
	mockEmail.SendFn = func(context.Context, string, string, string, string) error {
		sent.Store(true)
		return nil
	}

	serviceAuthStarveEntropy(t, 0)

	svc.sendVerificationEmail("user@example.com", "user-123", "", "")

	if stored.Load() {
		t.Error("a verification token was cached despite the generator failing")
	}
	if sent.Load() {
		t.Error("a verification email went out without a token")
	}
}

// The import claim link is a password reset token in disguise. The same rule
// holds: no token, no cache entry, no email.
func TestSendImportClaimLinkEntropyFailureStoresNothing(t *testing.T) {
	started := make(chan struct{}, 1)
	stored := make(chan string, 1)
	sent := make(chan struct{}, 1)

	svc, o := newMockAuthService(t)
	o.cache.GetAndDeleteFn = func(context.Context, string) (string, error) {
		started <- struct{}{}
		return "", nil
	}
	o.cache.SetFn = func(_ context.Context, key, _ string, _ time.Duration) error {
		stored <- key
		return nil
	}
	o.emailSender.SendFn = func(context.Context, string, string, string, string) error {
		sent <- struct{}{}
		return nil
	}

	serviceAuthStarveEntropy(t, 0)

	svc.sendImportClaimLink("user-1", "imported@example.com", "")

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the claim link goroutine never ran")
	}

	select {
	case key := <-stored:
		t.Fatalf("cached %q despite the claim token generator failing", key)
	case <-sent:
		t.Fatal("emailed a claim link with no token behind it")
	case <-time.After(250 * time.Millisecond):
	}
}

// The old refresh token is already marked used by the time the new row ID is
// generated. Failing here must abort the rotation: handing back a refresh token
// that was never stored would leave the caller holding a credential the service
// cannot look up, expire or revoke.
func TestRefreshRowIDEntropyFailureStoresNoSuccessor(t *testing.T) {
	var successorStored atomic.Bool
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(context.Context, string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		}
		o.tokenRepo.CreateFn = func(context.Context, *model.RefreshToken) error {
			successorStored.Store(true)
			return nil
		}
	})

	serviceAuthStarveEntropy(t, 2)

	res, err := svc.Refresh(context.Background(), "raw-refresh-token", "1.2.3.4", "TestAgent",
		vaultcrypto.FingerprintInput{})

	if !errors.Is(err, errServiceAuthEntropy) {
		t.Fatalf("err = %v, want the entropy failure to surface", err)
	}
	if !strings.Contains(err.Error(), "generate refresh token ID") {
		t.Errorf("err = %v, want it to name the refresh token ID step", err)
	}
	if res != nil {
		t.Error("a refresh result was returned without a stored successor token")
	}
	if successorStored.Load() {
		t.Error("a successor refresh token row was written with no ID")
	}
}

// Login mints the access token before it stores the refresh token. A failure to
// generate the row ID has to fail the whole login: returning the pair anyway
// would hand out a refresh token with no database row to revoke.
func TestLoginRefreshRowIDEntropyFailureFailsClosed(t *testing.T) {
	hash := validPasswordHash(t)
	var stored atomic.Bool
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.userRepo.GetByEmailFn = func(context.Context, string) (*model.User, error) {
			return &model.User{
				ID: "user-1", Email: "store@example.com",
				PasswordHash: hash, EmailVerified: true,
			}, nil
		}
		o.deviceRepo.GetByFingerprintFn = func(context.Context, string, string) (*model.Device, error) {
			return &model.Device{ID: "dev-1"}, nil
		}
		o.tokenRepo.CreateFn = func(context.Context, *model.RefreshToken) error {
			stored.Store(true)
			return nil
		}
	})

	serviceAuthStarveEntropy(t, 3)

	res, err := svc.Login(context.Background(), LoginInput{
		Email: "store@example.com", Password: "correct-horse-battery-staple",
	}, "1.2.3.4", "TestAgent")

	if !errors.Is(err, errServiceAuthEntropy) {
		t.Fatalf("err = %v, want the entropy failure to surface", err)
	}
	if !strings.Contains(err.Error(), "generate refresh token ID") {
		t.Errorf("err = %v, want it to name the refresh token ID step", err)
	}
	if res != nil {
		t.Error("login returned tokens although the refresh token could not be stored")
	}
	if stored.Load() {
		t.Error("a refresh token row was written with no ID")
	}
}

// Device registration is explicitly non-critical: it may not abort the login.
// It also may not invent a device, so the failure returns an empty ID and
// writes nothing.
func TestFindOrCreateDeviceEntropyFailureCreatesNoDevice(t *testing.T) {
	var created atomic.Bool
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.deviceRepo.CreateFn = func(context.Context, *model.Device) error {
			created.Store(true)
			return nil
		}
	})

	serviceAuthStarveEntropy(t, 0)

	id := svc.findOrCreateDevice(context.Background(), "user-1", "fp-hash", "1.2.3.4", "TestAgent")

	if id != "" {
		t.Errorf("device ID = %q, want empty when the generator fails", id)
	}
	if created.Load() {
		t.Error("a device row was written with no ID")
	}
}

// An email OTP is six digits. Deriving it from a failed read would produce a
// fixed code, so nothing may be cached and nothing may be sent.
func TestSendEmailOTPEntropyFailureCachesNoCode(t *testing.T) {
	var cached, sent atomic.Bool
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.mfaSvc = mfaNoMethods(true)
		o.cache.SetFn = func(context.Context, string, string, time.Duration) error {
			cached.Store(true)
			return nil
		}
		o.emailSender.SendFn = func(context.Context, string, string, string, string) error {
			sent.Store(true)
			return nil
		}
	})

	serviceAuthStarveEntropy(t, 0)

	err := svc.SendEmailOTP(context.Background(), "user-1", "otp@example.com")

	if !errors.Is(err, errServiceAuthEntropy) {
		t.Fatalf("err = %v, want the entropy failure to surface", err)
	}
	if !strings.Contains(err.Error(), "generate OTP") {
		t.Errorf("err = %v, want it to name the OTP generation step", err)
	}
	if cached.Load() {
		t.Error("an OTP signature was cached although the code could not be generated")
	}
	if sent.Load() {
		t.Error("an OTP email went out with no code behind it")
	}
}
