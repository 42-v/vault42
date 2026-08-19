package handler

import (
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// acctBlockingEntropy parks a caller inside crypto/rand until it is released,
// then serves the real reader. HashPassword reads its salt after it has taken
// an argon2id semaphore slot, so a goroutine parked in here is holding a real
// slot without spending any CPU. That is how these tests reproduce a saturated
// semaphore deterministically instead of by flooding the process with hashes.
type acctBlockingEntropy struct {
	real    io.Reader
	entered chan struct{}
	release chan struct{}
}

func (b *acctBlockingEntropy) Read(p []byte) (int, error) {
	b.entered <- struct{}{}
	<-b.release
	return io.ReadFull(b.real, p)
}

// acctHoldArgon2Slots parks n argon2id semaphore slots and returns once every
// holder is confirmed inside the semaphore. crypto/rand.Reader is restored
// before returning, so the code under test still gets real entropy.
func acctHoldArgon2Slots(t *testing.T, n int) {
	t.Helper()

	holder := &acctBlockingEntropy{
		real:    rand.Reader,
		entered: make(chan struct{}, n),
		release: make(chan struct{}),
	}
	original := rand.Reader
	rand.Reader = holder

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = vaultcrypto.HashPassword("occupy an argon2id slot")
		}()
	}

	for i := 0; i < n; i++ {
		select {
		case <-holder.entered:
		case <-time.After(30 * time.Second):
			rand.Reader = original
			close(holder.release)
			wg.Wait()
			t.Fatalf("only %d of %d argon2 holders reached the semaphore", i, n)
		}
	}
	rand.Reader = original

	t.Cleanup(func() {
		close(holder.release)
		wg.Wait()
	})
}

func acctSaturateArgon2(t *testing.T) {
	t.Helper()
	acctHoldArgon2Slots(t, vaultcrypto.Argon2MaxConcurrent())
}

func acctAuthService(t *testing.T, users *mocks.MockUserRepo, c *mocks.MockCache) *service.AuthService {
	t.Helper()
	tokenSvc, _ := newTestTokenService(t)
	return service.NewAuthService(
		users, &mocks.MockRefreshTokenRepo{}, &mocks.MockDeviceRepo{},
		&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, newTestAuditLogger(),
		nil, c, nil, "https://vault.test", "TestVault", "", 15, false, nil,
	)
}

func acctErrorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	decodeResponse(t, rec, &body)
	return body["error"]
}

// The argon2id semaphore is what stops a login flood from OOM-killing the pod: four
// concurrent hashes, and anything that cannot get a slot within the timeout is
// rejected. Every endpoint that hashes or verifies a password has to turn that
// rejection into a 503 and stop.
//
// The failure mode this guards is not the status code, it is what happens after it.
// ErrArgon2Overloaded arrives as (false, err) from VerifyPassword and ("", err) from
// HashPassword. A handler that looked at the bool and ignored the error would read
// "wrong password" and lock the account out on a server capacity problem; one that
// ignored both would register a user with an empty password hash, delete an account
// whose password was never checked, or write a password nobody typed. So each case
// asserts the mutation did not happen.
//
// All requests are fired against one saturated semaphore so the suite pays a single
// acquire timeout rather than one per endpoint.
func TestPasswordEndpoints_Argon2OverloadFailsClosed(t *testing.T) {
	const password = "correct horse battery staple"
	storedHash, err := vaultcrypto.HashPassword(password)
	if err != nil {
		t.Fatalf("precompute password hash: %v", err)
	}

	registerCreated := false
	registerUsers := &mocks.MockUserRepo{
		GetByEmailFn: func(context.Context, string) (*model.User, error) { return nil, nil },
		CreateFn: func(context.Context, *model.User) error {
			registerCreated = true
			return nil
		},
	}
	registerCache := &mocks.MockCache{}
	registerHandler := NewAuthHandler(acctAuthService(t, registerUsers, registerCache), registerUsers, registerCache, newTestAuditLogger(), "", false, nil)

	loginFailureRecorded := false
	loginUsers := &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, email string) (*model.User, error) {
			return &model.User{ID: "user-login", Email: email, PasswordHash: storedHash, EmailVerified: true}, nil
		},
		IncrementFailedLoginFn: func(context.Context, string) error {
			loginFailureRecorded = true
			return nil
		},
	}
	loginCache := &mocks.MockCache{}
	loginHandler := NewAuthHandler(acctAuthService(t, loginUsers, loginCache), loginUsers, loginCache, newTestAuditLogger(), "", false, nil)

	var confirmMu sync.Mutex
	confirmKeysSet := []string{}
	confirmAttemptsCounted := 0
	confirmCache := &mocks.MockCache{
		SetFn: func(_ context.Context, key, _ string, _ time.Duration) error {
			confirmMu.Lock()
			defer confirmMu.Unlock()
			confirmKeysSet = append(confirmKeysSet, key)
			return nil
		},
		IncrementFn: func(context.Context, string, time.Duration) (int64, error) {
			confirmMu.Lock()
			defer confirmMu.Unlock()
			confirmAttemptsCounted++
			return 1, nil
		},
	}
	confirmUsers := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "confirm@example.com", PasswordHash: storedHash}, nil
		},
	}
	confirmHandler := NewAuthHandler(acctAuthService(t, confirmUsers, confirmCache), confirmUsers, confirmCache, newTestAuditLogger(), "", false, nil)

	accountScrubbed := false
	accountUsers := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "erase@example.com", PasswordHash: storedHash}, nil
		},
		SoftDeleteScrubFn: func(context.Context, string, string) error {
			accountScrubbed = true
			return nil
		},
	}
	accountHandler := newTestAccountHandler(accountUsers)

	changePasswordWritten := false
	changeUsers := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "change@example.com", PasswordHash: storedHash}, nil
		},
		UpdatePasswordFn: func(context.Context, string, string) error {
			changePasswordWritten = true
			return nil
		},
	}
	changeHandler := newTestPasswordHandler(t, changeUsers, &mocks.MockPasswordHistoryRepo{})

	resetPasswordWritten := false
	resetUsers := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "reset@example.com", PasswordHash: storedHash}, nil
		},
		UpdatePasswordFn: func(context.Context, string, string) error {
			resetPasswordWritten = true
			return nil
		},
	}
	resetHandler := NewPasswordHandler(
		resetUsers, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockEmailSender{}, newTestAuditLogger(),
		&mocks.MockCache{
			GetAndDeleteFn: func(context.Context, string) (string, error) { return "user-reset", nil },
		},
		"https://vault.test", "TestVault", "", 15, nil, false,
	)

	cases := []struct {
		name string
		call func(rec *httptest.ResponseRecorder)
	}{
		{
			name: "register",
			call: func(rec *httptest.ResponseRecorder) {
				req := httptest.NewRequest(http.MethodPost, "/auth/register", jsonBody(t, map[string]string{
					"email": "newcomer@example.com", "password": password,
				}))
				registerHandler.Register(rec, req)
			},
		},
		{
			name: "login",
			call: func(rec *httptest.ResponseRecorder) {
				req := httptest.NewRequest(http.MethodPost, "/auth/login", jsonBody(t, map[string]string{
					"email": "user@example.com", "password": password,
				}))
				req.RemoteAddr = "203.0.113.10:4000"
				loginHandler.Login(rec, req)
			},
		},
		{
			name: "confirm",
			call: func(rec *httptest.ResponseRecorder) {
				req := httptest.NewRequest(http.MethodPost, "/auth/confirm", jsonBody(t, map[string]string{
					"password": password,
				}))
				req = setAuthContext(req, "user-confirm")
				confirmHandler.ConfirmPassword(rec, req)
			},
		},
		{
			name: "account_delete",
			call: func(rec *httptest.ResponseRecorder) {
				req := httptest.NewRequest(http.MethodDelete, "/user/account", jsonBody(t, map[string]string{
					"password": password,
				}))
				req = setAuthContext(req, "user-erase")
				accountHandler.Delete(rec, req)
			},
		},
		{
			name: "change_password",
			call: func(rec *httptest.ResponseRecorder) {
				req := httptest.NewRequest(http.MethodPost, "/user/password", jsonBody(t, map[string]string{
					"current_password": password, "new_password": "a brand new passphrase",
				}))
				req = setAuthContext(req, "user-change")
				changeHandler.ChangePassword(rec, req)
			},
		},
		{
			name: "reset_confirm",
			call: func(rec *httptest.ResponseRecorder) {
				req := httptest.NewRequest(http.MethodPost, "/auth/password/reset/confirm", jsonBody(t, map[string]string{
					"token": "a-live-reset-token", "password": "a brand new passphrase",
				}))
				resetHandler.ResetConfirm(rec, req)
			},
		},
	}

	acctSaturateArgon2(t)

	recs := make([]*httptest.ResponseRecorder, len(cases))
	var wg sync.WaitGroup
	for i := range cases {
		recs[i] = httptest.NewRecorder()
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cases[i].call(recs[i])
		}(i)
	}
	wg.Wait()

	for i, tc := range cases {
		rec := recs[i]
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: status = %d, want 503 — an argon2 capacity rejection was reported as something else", tc.name, rec.Code)
			continue
		}
		if got := acctErrorCode(t, rec); got != "server_busy" {
			t.Errorf("%s: error = %q, want server_busy", tc.name, got)
		}
	}

	if registerCreated {
		t.Error("register created a user while the password hash was never computed — the account would have an empty hash")
	}
	if loginFailureRecorded {
		t.Error("login counted a failed attempt against the user — server overload would lock out a correct password")
	}
	confirmMu.Lock()
	for _, k := range confirmKeysSet {
		if strings.HasPrefix(k, "confirm:") {
			t.Error("the elevated confirmation window was granted without the password ever being verified")
		}
	}
	if confirmAttemptsCounted != 0 {
		t.Error("the confirm lockout counter was incremented — server overload would lock the user out of sensitive operations")
	}
	confirmMu.Unlock()
	if accountScrubbed {
		t.Error("the account was erased without the password ever being verified")
	}
	if changePasswordWritten {
		t.Error("the password was changed without the current password ever being verified")
	}
	if resetPasswordWritten {
		t.Error("a reset wrote a password hash that was never produced — the account would have an empty hash")
	}
}

// The change-password flow acquires an argon2 slot twice: once to verify the current
// password, once to hash the new one. Capacity can run out between the two, and that
// second rejection is the dangerous one: the caller has already been authenticated, so
// a handler that shrugged the error off would carry on with the empty string HashPassword
// returns alongside it and store it as the user's password.
//
// The verify is allowed to succeed here and the semaphore is refilled while the handler
// is between the two calls, so only the hash is rejected.
func TestChangePassword_Argon2OverloadOnRehashDoesNotStoreEmptyHash(t *testing.T) {
	const currentPassword = "correct horse battery staple"
	storedHash, err := vaultcrypto.HashPassword(currentPassword)
	if err != nil {
		t.Fatalf("precompute password hash: %v", err)
	}

	var storedNewHash string
	written := false
	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "change@example.com", PasswordHash: storedHash}, nil
		},
		UpdatePasswordFn: func(_ context.Context, _, hash string) error {
			written = true
			storedNewHash = hash
			return nil
		},
	}

	// Called after the current password has been verified and before the new one is
	// hashed: the last free slot is taken here, so the rehash is the call that is
	// rejected.
	history := &mocks.MockPasswordHistoryRepo{
		GetRecentByUserFn: func(context.Context, string, int) ([]*model.PasswordHistory, error) {
			acctHoldArgon2Slots(t, 1)
			return nil, nil
		},
	}

	h := newTestPasswordHandler(t, users, history)

	acctHoldArgon2Slots(t, vaultcrypto.Argon2MaxConcurrent()-1)

	req := httptest.NewRequest(http.MethodPost, "/user/password", jsonBody(t, map[string]string{
		"current_password": currentPassword,
		"new_password":     "an entirely different passphrase",
	}))
	req = setAuthContext(req, "user-change")
	rec := httptest.NewRecorder()

	h.ChangePassword(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body: %s", rec.Code, rec.Body.String())
	}
	if got := acctErrorCode(t, rec); got != "server_busy" {
		t.Errorf("error = %q, want server_busy", got)
	}
	if written {
		t.Fatalf("the password was updated to %q even though hashing was rejected", storedNewHash)
	}
}
