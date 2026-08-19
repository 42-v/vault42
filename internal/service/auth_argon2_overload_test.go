package service

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/honeypot"
	"github.com/42-v/vault42/internal/model"
)

// The argon2id semaphore turns an overload into a 503 instead of an OOM kill.
// Every auth entry point that hashes or verifies a password has to hand that
// rejection back untouched. If any one of them swallowed it and fell through to
// its own verdict, the pair "503" / "409 email taken" (or "401 invalid
// credentials") would tell an attacker under load which accounts exist. These
// tests saturate the semaphore for real and pin that every entry point answers
// with the same ErrArgon2Overloaded and mutates nothing on the way out.

// serviceAuthBlockedReader parks every read until release is closed. Installed
// as crypto/rand.Reader it lets a HashPassword call take a semaphore slot and
// hold it for as long as the test needs, without burning CPU.
type serviceAuthBlockedReader struct {
	release chan struct{}
}

func (r serviceAuthBlockedReader) Read(p []byte) (int, error) {
	<-r.release
	for i := range p {
		p[i] = 0x42
	}
	return len(p), nil
}

// serviceAuthSaturateArgon2 fills every argon2 semaphore slot and keeps it full
// until the test ends. Callers must build anything that needs entropy before
// calling it.
func serviceAuthSaturateArgon2(t *testing.T) {
	t.Helper()

	release := make(chan struct{})
	serviceRandUse(t, serviceAuthBlockedReader{release: release})

	var wg sync.WaitGroup
	for i := 0; i < vaultcrypto.Argon2MaxConcurrent(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = vaultcrypto.HashPassword("hold-an-argon2-slot")
		}()
	}
	// Registered after serviceRandUse, so LIFO cleanup releases the blocked
	// readers and drains the goroutines before the entropy source is restored.
	t.Cleanup(func() {
		close(release)
		wg.Wait()
	})

	deadline := time.Now().Add(30 * time.Second)
	for vaultcrypto.Argon2ActiveCount() < int64(vaultcrypto.Argon2MaxConcurrent()) {
		if time.Now().After(deadline) {
			t.Fatal("argon2 semaphore never reached capacity")
		}
		time.Sleep(time.Millisecond)
	}
}

// serviceAuthOverloadSideEffects records the mutations that must not happen
// when a request is rejected for overload.
type serviceAuthOverloadSideEffects struct {
	userCreated    atomic.Bool
	failureCounted atomic.Bool
	tokenStored    atomic.Bool
	emailSent      atomic.Bool
	gotResult      atomic.Bool
}

func TestAuthArgon2OverloadPropagatesFromEveryEntryPoint(t *testing.T) {
	hash := validPasswordHash(t)
	ctx := context.Background()
	const password = "correct-horse-battery-staple"

	cases := []struct {
		name    string
		build   func(rec *serviceAuthOverloadSideEffects) *AuthService
		invoke  func(svc *AuthService, rec *serviceAuthOverloadSideEffects) error
		notWant error
	}{
		{
			name: "register with an address that is already taken",
			build: func(rec *serviceAuthOverloadSideEffects) *AuthService {
				svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
					o.userRepo.GetByEmailFn = func(context.Context, string) (*model.User, error) {
						return &model.User{ID: "user-1", Email: "taken@example.com", PasswordHash: hash}, nil
					}
					o.userRepo.CreateFn = func(context.Context, *model.User) error {
						rec.userCreated.Store(true)
						return nil
					}
				})
				return svc
			},
			invoke: func(svc *AuthService, rec *serviceAuthOverloadSideEffects) error {
				res, err := svc.Register(ctx, RegisterInput{Email: "taken@example.com", Password: password}, "1.2.3.4")
				rec.gotResult.Store(res != nil)
				return err
			},
			notWant: ErrEmailTaken,
		},
		{
			name: "register with a fresh address",
			build: func(rec *serviceAuthOverloadSideEffects) *AuthService {
				svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
					o.userRepo.CreateFn = func(context.Context, *model.User) error {
						rec.userCreated.Store(true)
						return nil
					}
				})
				return svc
			},
			invoke: func(svc *AuthService, rec *serviceAuthOverloadSideEffects) error {
				res, err := svc.Register(ctx, RegisterInput{Email: "fresh@example.com", Password: password}, "1.2.3.4")
				rec.gotResult.Store(res != nil)
				return err
			},
			notWant: ErrInvalidInput,
		},
		{
			name: "login as a honeypot trap user",
			build: func(_ *serviceAuthOverloadSideEffects) *AuthService {
				svc, _ := newMockAuthService(t)
				svc.SetHoneypotAlerter(honeypot.NewAlerter("", []string{"trap@example.com"}, nil))
				return svc
			},
			invoke: func(svc *AuthService, rec *serviceAuthOverloadSideEffects) error {
				res, err := svc.Login(ctx, LoginInput{Email: "trap@example.com", Password: password}, "1.2.3.4", "TestAgent")
				rec.gotResult.Store(res != nil)
				return err
			},
			notWant: nil,
		},
		{
			name: "login as an unknown user",
			build: func(_ *serviceAuthOverloadSideEffects) *AuthService {
				svc, _ := newMockAuthService(t)
				return svc
			},
			invoke: func(svc *AuthService, rec *serviceAuthOverloadSideEffects) error {
				res, err := svc.Login(ctx, LoginInput{Email: "nobody@example.com", Password: password}, "1.2.3.4", "TestAgent")
				rec.gotResult.Store(res != nil)
				return err
			},
			notWant: ErrInvalidCredentials,
		},
		{
			// A soft-deleted account is masked as "no such user"; under load it must
			// answer with the same overload error, not the faster no-burn
			// ErrInvalidCredentials that would re-reveal the soft delete by timing.
			name: "login as a soft-deleted account",
			build: func(_ *serviceAuthOverloadSideEffects) *AuthService {
				svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
					o.userRepo.GetByEmailFn = func(context.Context, string) (*model.User, error) {
						return &model.User{
							ID: "user-1", Email: "deleted@example.com",
							PasswordHash: hash, EmailVerified: true, Deleted: true,
						}, nil
					}
				})
				return svc
			},
			invoke: func(svc *AuthService, rec *serviceAuthOverloadSideEffects) error {
				res, err := svc.Login(ctx, LoginInput{Email: "deleted@example.com", Password: password}, "1.2.3.4", "TestAgent")
				rec.gotResult.Store(res != nil)
				return err
			},
			notWant: ErrInvalidCredentials,
		},
		{
			// A cache auto-locked account answers ErrInvalidCredentials (not a
			// distinct ErrAccountLocked, which would leak that the address exists);
			// under load it must burn the same Argon2 and answer with the overload
			// error, not the faster no-burn path that re-reveals the lock by timing.
			name: "login as an auto-locked account",
			build: func(_ *serviceAuthOverloadSideEffects) *AuthService {
				svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
					o.userRepo.GetByEmailFn = func(context.Context, string) (*model.User, error) {
						return &model.User{ID: "user-1", Email: "locked@example.com", PasswordHash: hash, EmailVerified: true}, nil
					}
					o.cache.GetFn = func(_ context.Context, key string) (string, error) {
						if len(key) > 8 && key[:8] == "lockout:" {
							return "10", nil
						}
						return "0", nil
					}
				})
				return svc
			},
			invoke: func(svc *AuthService, rec *serviceAuthOverloadSideEffects) error {
				res, err := svc.Login(ctx, LoginInput{Email: "locked@example.com", Password: password}, "1.2.3.4", "TestAgent")
				rec.gotResult.Store(res != nil)
				return err
			},
			notWant: ErrInvalidCredentials,
		},
		{
			name: "login as an admin-locked account",
			build: func(_ *serviceAuthOverloadSideEffects) *AuthService {
				svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
					lockUntil := time.Now().Add(time.Hour)
					o.userRepo.GetByEmailFn = func(context.Context, string) (*model.User, error) {
						return &model.User{ID: "user-2", Email: "adminlocked@example.com", PasswordHash: hash, EmailVerified: true, LockedUntil: &lockUntil}, nil
					}
				})
				return svc
			},
			invoke: func(svc *AuthService, rec *serviceAuthOverloadSideEffects) error {
				res, err := svc.Login(ctx, LoginInput{Email: "adminlocked@example.com", Password: password}, "1.2.3.4", "TestAgent")
				rec.gotResult.Store(res != nil)
				return err
			},
			notWant: ErrInvalidCredentials,
		},
		{
			// A banned account is refused only after a successful password
			// verification, so under load VerifyPassword short-circuits to the
			// overload error before the banned check is reached; it must not answer
			// ErrAccountBanned, which would leak that the address exists.
			name: "login as a banned account",
			build: func(_ *serviceAuthOverloadSideEffects) *AuthService {
				svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
					o.userRepo.GetByEmailFn = func(context.Context, string) (*model.User, error) {
						return &model.User{ID: "user-3", Email: "banned@example.com", PasswordHash: hash, EmailVerified: true, Banned: true}, nil
					}
				})
				return svc
			},
			invoke: func(svc *AuthService, rec *serviceAuthOverloadSideEffects) error {
				res, err := svc.Login(ctx, LoginInput{Email: "banned@example.com", Password: password}, "1.2.3.4", "TestAgent")
				rec.gotResult.Store(res != nil)
				return err
			},
			notWant: ErrAccountBanned,
		},
		{
			name: "login as a disabled account",
			build: func(_ *serviceAuthOverloadSideEffects) *AuthService {
				svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
					o.userRepo.GetByEmailFn = func(context.Context, string) (*model.User, error) {
						return &model.User{ID: "user-4", Email: "disabled@example.com", PasswordHash: hash, EmailVerified: true, Disabled: true}, nil
					}
				})
				return svc
			},
			invoke: func(svc *AuthService, rec *serviceAuthOverloadSideEffects) error {
				res, err := svc.Login(ctx, LoginInput{Email: "disabled@example.com", Password: password}, "1.2.3.4", "TestAgent")
				rec.gotResult.Store(res != nil)
				return err
			},
			notWant: ErrAccountDisabled,
		},
		{
			name: "login as an imported account awaiting its claim link",
			build: func(rec *serviceAuthOverloadSideEffects) *AuthService {
				svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
					o.userRepo.GetByEmailFn = func(context.Context, string) (*model.User, error) {
						return &model.User{
							ID: "user-1", Email: "imported@example.com",
							EmailVerified: true, ImportPending: true,
						}, nil
					}
					o.emailSender.SendFn = func(context.Context, string, string, string, string) error {
						rec.emailSent.Store(true)
						return nil
					}
				})
				return svc
			},
			invoke: func(svc *AuthService, rec *serviceAuthOverloadSideEffects) error {
				res, err := svc.Login(ctx, LoginInput{Email: "imported@example.com", Password: password}, "1.2.3.4", "TestAgent")
				rec.gotResult.Store(res != nil)
				return err
			},
			notWant: nil,
		},
		{
			name: "login as an account under a forced password reset",
			build: func(rec *serviceAuthOverloadSideEffects) *AuthService {
				svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
					o.userRepo.GetByEmailFn = func(context.Context, string) (*model.User, error) {
						return &model.User{
							ID: "user-5", Email: "forced@example.com", PasswordHash: hash,
							EmailVerified: true, MustResetPassword: true,
						}, nil
					}
					o.userRepo.IncrementFailedLoginFn = func(context.Context, string) error {
						rec.failureCounted.Store(true)
						return nil
					}
					o.emailSender.SendFn = func(context.Context, string, string, string, string) error {
						rec.emailSent.Store(true)
						return nil
					}
				})
				return svc
			},
			invoke: func(svc *AuthService, rec *serviceAuthOverloadSideEffects) error {
				res, err := svc.Login(ctx, LoginInput{
					Email: "forced@example.com", Password: password, DiscloseStatus: true,
				}, "1.2.3.4", "TestAgent")
				rec.gotResult.Store(res != nil)
				return err
			},
			notWant: ErrPasswordResetRequired,
		},
		{
			name: "login with the correct password",
			build: func(rec *serviceAuthOverloadSideEffects) *AuthService {
				svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
					o.userRepo.GetByEmailFn = func(context.Context, string) (*model.User, error) {
						return &model.User{
							ID: "user-1", Email: "live@example.com",
							PasswordHash: hash, EmailVerified: true,
						}, nil
					}
					o.userRepo.IncrementFailedLoginFn = func(context.Context, string) error {
						rec.failureCounted.Store(true)
						return nil
					}
					o.tokenRepo.CreateFn = func(context.Context, *model.RefreshToken) error {
						rec.tokenStored.Store(true)
						return nil
					}
				})
				return svc
			},
			invoke: func(svc *AuthService, rec *serviceAuthOverloadSideEffects) error {
				res, err := svc.Login(ctx, LoginInput{Email: "live@example.com", Password: password}, "1.2.3.4", "TestAgent")
				rec.gotResult.Store(res != nil)
				return err
			},
			notWant: ErrInvalidCredentials,
		},
	}

	services := make([]*AuthService, len(cases))
	records := make([]*serviceAuthOverloadSideEffects, len(cases))
	for i, tc := range cases {
		records[i] = &serviceAuthOverloadSideEffects{}
		services[i] = tc.build(records[i])
	}

	serviceAuthSaturateArgon2(t)

	errs := make([]error, len(cases))
	var wg sync.WaitGroup
	for i, tc := range cases {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = tc.invoke(services[i], records[i])
		}()
	}
	wg.Wait()

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := records[i]
			if !errors.Is(errs[i], vaultcrypto.ErrArgon2Overloaded) {
				t.Fatalf("err = %v, want ErrArgon2Overloaded: an entry point that answers anything else under load is an enumeration oracle", errs[i])
			}
			if tc.notWant != nil && errors.Is(errs[i], tc.notWant) {
				t.Errorf("err also matches %v, which distinguishes this account state from an overloaded one", tc.notWant)
			}
			if rec.gotResult.Load() {
				t.Error("a result was returned alongside the overload error")
			}
			if rec.userCreated.Load() {
				t.Error("a user row was created while argon2 was rejecting work")
			}
			if rec.failureCounted.Load() {
				t.Error("the overload was counted as a failed login, so load alone would lock the account out")
			}
			if rec.tokenStored.Load() {
				t.Error("a refresh token was persisted for a request that never verified a password")
			}
			if rec.emailSent.Load() {
				t.Error("an account email was sent for a request rejected before any verification")
			}
		})
	}
}
