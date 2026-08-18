package handler

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// POST /auth/login answers an account under a forced password reset with the
// ordinary 401, byte for byte what a wrong password gets, unless the caller has
// authenticated with client credentials carrying login:status. That is the whole
// contract, and every one of its edges is an oracle if it slips:
//
//   - disclose to an unauthenticated caller and the endpoint confirms that an
//     address is registered and mid-migration, to anyone who asks;
//   - disclose to a client that authenticated but was never granted the scope and
//     the scope is decoration;
//   - let a wrong client secret change anything about the user's login and the
//     client credential has become a lever on somebody else's account.
//
// The client credential is optional here in a way it is not at POST /client/token:
// a request with none, or with a bad one, is a perfectly ordinary login and must
// succeed on a correct password.

const forcedResetPassword = "correct-horse-battery-staple"

// forcedResetFixture builds a login handler over one account and one client.
type forcedResetFixture struct {
	handler  *AuthHandler
	sessions *int          // refresh-token rows the login created
	audits   *[]auditEvent // audit rows written during the request
	mu       *sync.Mutex
}

type auditEvent struct {
	action string
	detail map[string]interface{}
}

func newForcedResetFixture(t *testing.T, user *model.User, clients repository.ClientRepository) forcedResetFixture {
	t.Helper()

	users := &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, _ string) (*model.User, error) {
			u := *user
			return &u, nil
		},
	}

	var mu sync.Mutex
	sessions := 0
	var audits []auditEvent

	tokens := &mocks.MockRefreshTokenRepo{
		CreateFn: func(_ context.Context, _ *model.RefreshToken) error {
			mu.Lock()
			defer mu.Unlock()
			sessions++
			return nil
		},
		CreateWithinCapFn: func(_ context.Context, _ *model.RefreshToken, _ int) error {
			mu.Lock()
			defer mu.Unlock()
			sessions++
			return nil
		},
	}

	record := func(entries ...*model.AuditEntry) {
		mu.Lock()
		defer mu.Unlock()
		for _, e := range entries {
			audits = append(audits, auditEvent{action: e.EventType, detail: e.Metadata})
		}
	}
	// Flush interval zero: the row is written straight through, so it is
	// observable as soon as the handler returns.
	auditLog := audit.NewLogger(&mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, e *model.AuditEntry) error { record(e); return nil },
		InsertBatchFn: func(_ context.Context, es []*model.AuditEntry) error {
			record(es...)
			return nil
		},
	}, 0)

	tokenSvc, _ := newTestTokenService(t)
	authSvc := service.NewAuthService(
		users, tokens, &mocks.MockDeviceRepo{},
		&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
		nil, &mocks.MockCache{}, &mocks.MockEmailSender{}, "https://vault.test", "TestVault", "", 15, false, nil,
	)

	return forcedResetFixture{
		handler:  NewAuthHandler(authSvc, users, &mocks.MockCache{}, auditLog, "", false, clients),
		sessions: &sessions,
		audits:   &audits,
		mu:       &mu,
	}
}

func (f forcedResetFixture) login(t *testing.T, basicID, basicSecret string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/auth/login",
		jsonBody(t, map[string]string{"email": "rider@legacy.test", "password": forcedResetPassword}))
	req.RemoteAddr = "203.0.113.7:5000"
	if basicID != "" || basicSecret != "" {
		req.Header.Set("Authorization", "Basic "+
			base64.StdEncoding.EncodeToString([]byte(basicID+":"+basicSecret)))
	}
	rec := httptest.NewRecorder()
	f.handler.Login(rec, req)
	return rec
}

func (f forcedResetFixture) auditReasons(action string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, e := range *f.audits {
		if e.action != action {
			continue
		}
		if reason, ok := e.detail["reason"].(string); ok {
			out = append(out, reason)
		}
	}
	return out
}

func flaggedUser(t *testing.T) *model.User {
	t.Helper()
	hash, err := vaultcrypto.HashPassword(forcedResetPassword)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return &model.User{
		ID: "u-forced", Email: "rider@legacy.test", PasswordHash: hash,
		EmailVerified: true, MustResetPassword: true,
	}
}

// scopedClient builds a client row whose secret is secret and whose scope list is
// scopes.
func scopedClient(t *testing.T, secret string, scopes []string, active bool) repository.ClientRepository {
	t.Helper()
	hash, err := vaultcrypto.HashPassword(secret)
	if err != nil {
		t.Fatalf("hash client secret: %v", err)
	}
	return &mocks.MockClientRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.Client, error) {
			if id != "client-1" {
				return nil, nil
			}
			return &model.Client{
				ID: "client-1", Name: "beon3", SecretHash: hash,
				Role: "service", Scopes: scopes, Active: active,
			}, nil
		},
	}
}

func assertNoSession(t *testing.T, f forcedResetFixture, rec *httptest.ResponseRecorder) {
	t.Helper()
	body := rec.Body.String()
	if strings.Contains(body, "access_token") {
		t.Errorf("a refused login handed out an access token: %s", body)
	}
	for _, c := range rec.Result().Cookies() {
		if strings.Contains(c.Name, "refresh_token") && c.Value != "" {
			t.Errorf("a refused login set a refresh cookie: %s", c.Name)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if *f.sessions != 0 {
		t.Errorf("a refused login persisted %d refresh-token rows", *f.sessions)
	}
}

func TestLogin_ForcedReset_PublicCallerSeesTheOrdinary401(t *testing.T) {
	clients := scopedClient(t, "s3cret", []string{LoginStatusScope}, true)
	f := newForcedResetFixture(t, flaggedUser(t), clients)

	rec := f.login(t, "", "") // no client credentials at all

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: the flag is visible to anyone who asks (body: %s)",
			rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "invalid_credentials") ||
		strings.Contains(body, "password_reset_required") {
		t.Errorf("body = %s, want the ordinary invalid_credentials", body)
	}
	assertNoSession(t, f, rec)
}

// Byte-identical, not merely same-status. A different body length or a different
// key order is as good an oracle as a different code.
func TestLogin_ForcedReset_PublicAnswerIsByteIdenticalToAWrongPassword(t *testing.T) {
	clients := scopedClient(t, "s3cret", []string{LoginStatusScope}, true)

	flagged := newForcedResetFixture(t, flaggedUser(t), clients)
	forcedBody := flagged.login(t, "", "")

	plain := flaggedUser(t)
	plain.MustResetPassword = false
	wrong := newForcedResetFixture(t, plain, clients)
	req := httptest.NewRequest(http.MethodPost, "/auth/login",
		jsonBody(t, map[string]string{"email": "rider@legacy.test", "password": "not-the-password"}))
	req.RemoteAddr = "203.0.113.7:5000"
	wrongRec := httptest.NewRecorder()
	wrong.handler.Login(wrongRec, req)

	if forcedBody.Code != wrongRec.Code {
		t.Errorf("status: forced reset = %d, wrong password = %d", forcedBody.Code, wrongRec.Code)
	}
	if forcedBody.Body.String() != wrongRec.Body.String() {
		t.Errorf("body: forced reset = %q, wrong password = %q", forcedBody.Body.String(), wrongRec.Body.String())
	}
}

func TestLogin_ForcedReset_ScopedClientIsToldWhy(t *testing.T) {
	clients := scopedClient(t, "s3cret", []string{"svcdoc:read", LoginStatusScope}, true)
	f := newForcedResetFixture(t, flaggedUser(t), clients)

	rec := f.login(t, "client-1", "s3cret")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "password_reset_required") {
		t.Errorf("body = %s, want password_reset_required", body)
	}
	// The refusal says the account must reset and nothing else: not the address,
	// not the account id, not whether the password was right.
	if body := rec.Body.String(); strings.Contains(body, "rider@legacy.test") ||
		strings.Contains(body, "u-forced") {
		t.Errorf("the distinct status leaked account detail: %s", body)
	}
	assertNoSession(t, f, rec)
}

func TestLogin_ForcedReset_AClientWithoutTheScopeSeesTheOrdinary401(t *testing.T) {
	clients := scopedClient(t, "s3cret", []string{"svcdoc:read"}, true)
	f := newForcedResetFixture(t, flaggedUser(t), clients)

	rec := f.login(t, "client-1", "s3cret")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: authenticating is not the same as being authorized "+
			"(body: %s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "password_reset_required") {
		t.Errorf("body = %s, the scope gate is decoration", rec.Body.String())
	}
	assertNoSession(t, f, rec)
}

func TestLogin_ForcedReset_ABadClientSecretSeesTheOrdinary401(t *testing.T) {
	clients := scopedClient(t, "s3cret", []string{LoginStatusScope}, true)
	f := newForcedResetFixture(t, flaggedUser(t), clients)

	rec := f.login(t, "client-1", "not-the-secret")

	if rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), "password_reset_required") {
		t.Fatalf("status = %d body = %s: a guessed client id was enough to read account state",
			rec.Code, rec.Body.String())
	}
	assertNoSession(t, f, rec)

	if reasons := f.auditReasons("client_auth"); len(reasons) != 1 || reasons[0] != "wrong_secret" {
		t.Errorf("client_auth audit reasons = %v, want [wrong_secret]: a brute force against a "+
			"first-party client secret through the login endpoint would leave no trace", reasons)
	}
}

func TestLogin_ForcedReset_AnUnknownOrInactiveClientSeesTheOrdinary401(t *testing.T) {
	cases := []struct {
		name       string
		clientID   string
		active     bool
		wantReason string
	}{
		{name: "unknown client", clientID: "client-404", active: true, wantReason: "unknown_client"},
		{name: "deactivated client", clientID: "client-1", active: false, wantReason: "inactive_client"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clients := scopedClient(t, "s3cret", []string{LoginStatusScope}, tc.active)
			f := newForcedResetFixture(t, flaggedUser(t), clients)

			rec := f.login(t, tc.clientID, "s3cret")

			if rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), "password_reset_required") {
				t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
			}
			if reasons := f.auditReasons("client_auth"); len(reasons) != 1 || reasons[0] != tc.wantReason {
				t.Errorf("client_auth audit reasons = %v, want [%s]", reasons, tc.wantReason)
			}
		})
	}
}

// The user's own login is what must not move. A wrong client secret, an unknown
// client, no client at all: an account that is not flagged and whose password is
// right still gets its session.
func TestLogin_ForcedReset_ClientCredentialsNeverChangeTheUsersOutcome(t *testing.T) {
	cases := []struct{ name, id, secret string }{
		{name: "no client credentials", id: "", secret: ""},
		{name: "wrong client secret", id: "client-1", secret: "not-the-secret"},
		{name: "unknown client", id: "client-404", secret: "s3cret"},
		{name: "valid scoped client", id: "client-1", secret: "s3cret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clients := scopedClient(t, "s3cret", []string{LoginStatusScope}, true)
			user := flaggedUser(t)
			user.MustResetPassword = false
			f := newForcedResetFixture(t, user, clients)

			rec := f.login(t, tc.id, tc.secret)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: client authentication decided a user login "+
					"(body: %s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "access_token") {
				t.Errorf("no access token was issued: %s", rec.Body.String())
			}
		})
	}
}

// The flag is set on the transport side after the client row is read. A body that
// tries to assert it is a 400, because the login decoder rejects unknown fields,
// and the self-asserted client_id field proves nothing on its own.
func TestLogin_ForcedReset_TheBodyCannotAssertTheDisclosure(t *testing.T) {
	clients := scopedClient(t, "s3cret", []string{LoginStatusScope}, true)
	f := newForcedResetFixture(t, flaggedUser(t), clients)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", jsonBody(t, map[string]interface{}{
		"email": "rider@legacy.test", "password": forcedResetPassword, "disclose_status": true,
	}))
	req.RemoteAddr = "203.0.113.7:5000"
	rec := httptest.NewRecorder()
	f.handler.Login(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown field (body: %s)", rec.Code, rec.Body.String())
	}

	// And naming the client in the body, with no credential, is not authentication.
	req = httptest.NewRequest(http.MethodPost, "/auth/login", jsonBody(t, map[string]interface{}{
		"email": "rider@legacy.test", "password": forcedResetPassword, "client_id": "client-1",
	}))
	req.RemoteAddr = "203.0.113.7:5000"
	rec = httptest.NewRecorder()
	f.handler.Login(rec, req)

	if rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), "password_reset_required") {
		t.Fatalf("status = %d body = %s: a self-asserted client_id unlocked the account status",
			rec.Code, rec.Body.String())
	}
}

// A deployment that wires no client repository (the login handler takes it as an
// optional dependency) must fall back to the public answer rather than panic or
// disclose.
func TestLogin_ForcedReset_NoClientRepositoryMeansNoDisclosure(t *testing.T) {
	f := newForcedResetFixture(t, flaggedUser(t), nil)

	rec := f.login(t, "client-1", "s3cret")

	if rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), "password_reset_required") {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

// Status and body being identical is only half of indistinguishable. The branch
// answers before any password is verified, so unless it burns an Argon2id hash of
// its own it answers faster than a wrong password does -- and a stopwatch is a
// cheaper oracle than a status code, because it needs no error message at all.
//
// The tolerance is wide on purpose (the same shape as
// tests/attack/timing_attack_test.go): this catches a branch that skipped the
// burn entirely, which is a whole hash apart, not a few percent of scheduler
// noise.
func TestLogin_ForcedReset_TakesAsLongAsAWrongPassword(t *testing.T) {
	const rounds = 6

	clients := scopedClient(t, "s3cret", []string{LoginStatusScope}, true)
	flagged := newForcedResetFixture(t, flaggedUser(t), clients)

	plain := flaggedUser(t)
	plain.MustResetPassword = false
	wrong := newForcedResetFixture(t, plain, clients)

	wrongLogin := func() {
		req := httptest.NewRequest(http.MethodPost, "/auth/login",
			jsonBody(t, map[string]string{"email": "rider@legacy.test", "password": "not-the-password"}))
		req.RemoteAddr = "203.0.113.7:5000"
		wrong.handler.Login(httptest.NewRecorder(), req)
	}

	// One of each first: the first call in a process pays for lazy initialization
	// that has nothing to do with either branch.
	flagged.login(t, "", "")
	wrongLogin()

	var forcedTotal, wrongTotal time.Duration
	for i := 0; i < rounds; i++ {
		start := time.Now()
		flagged.login(t, "", "")
		forcedTotal += time.Since(start)

		start = time.Now()
		wrongLogin()
		wrongTotal += time.Since(start)
	}

	forcedAvg := forcedTotal / rounds
	wrongAvg := wrongTotal / rounds
	t.Logf("forced reset avg: %v, wrong password avg: %v", forcedAvg, wrongAvg)

	if wrongAvg == 0 {
		t.Fatal("the wrong-password path measured zero; the clock or the harness is broken")
	}
	ratio := float64(forcedAvg) / float64(wrongAvg)
	if ratio < 0.5 || ratio > 2.0 {
		t.Errorf("forced reset took %v against %v for a wrong password (ratio %.2f): the two "+
			"answers are the same but their timing is not, which is the same oracle read with a "+
			"stopwatch", forcedAvg, wrongAvg, ratio)
	}
}

// Lockout has to progress at exactly the rate a wrong password progresses it,
// whichever answer the caller gets. Faster and the flag is a way to lock someone
// else out cheaply; slower and it is a way to guess against a flagged account
// without ever tripping the ceiling.
func TestLogin_ForcedReset_AdvancesLockoutAtTheSameRate(t *testing.T) {
	count := func(t *testing.T, flag bool, password, basicID, basicSecret string) int {
		t.Helper()
		user := flaggedUser(t)
		user.MustResetPassword = flag

		clients := scopedClient(t, "s3cret", []string{LoginStatusScope}, true)
		var attempts int
		users := &mocks.MockUserRepo{
			GetByEmailFn: func(_ context.Context, _ string) (*model.User, error) {
				u := *user
				return &u, nil
			},
			IncrementFailedLoginFn: func(_ context.Context, _ string) error {
				attempts++
				return nil
			},
		}
		var counters sync.Map
		mockCache := &mocks.MockCache{
			IncrementFn: func(_ context.Context, key string, _ time.Duration) (int64, error) {
				n, _ := counters.LoadOrStore(key, int64(0))
				next := n.(int64) + 1
				counters.Store(key, next)
				return next, nil
			},
		}
		tokenSvc, _ := newTestTokenService(t)
		auditLog := newTestAuditLogger()
		authSvc := service.NewAuthService(
			users, &mocks.MockRefreshTokenRepo{}, &mocks.MockDeviceRepo{},
			&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
			nil, mockCache, &mocks.MockEmailSender{}, "https://vault.test", "TestVault", "", 15, false, nil,
		)
		h := NewAuthHandler(authSvc, users, mockCache, auditLog, "", false, clients)

		for i := 0; i < 3; i++ {
			req := httptest.NewRequest(http.MethodPost, "/auth/login",
				jsonBody(t, map[string]string{"email": "rider@legacy.test", "password": password}))
			req.RemoteAddr = "203.0.113.7:5000"
			if basicID != "" {
				req.Header.Set("Authorization", "Basic "+
					base64.StdEncoding.EncodeToString([]byte(basicID+":"+basicSecret)))
			}
			h.Login(httptest.NewRecorder(), req)
		}
		if v, ok := counters.Load("lockout:u-forced"); ok {
			if n, _ := v.(int64); int(n) != attempts {
				t.Errorf("cache lockout counter %d and durable counter %d disagree", n, attempts)
			}
		}
		return attempts
	}

	// A wrong password on an unflagged account is the reference: three attempts,
	// three failures counted. The flagged account is given the RIGHT password, so
	// any difference is the flag's doing and not the password's.
	reference := count(t, false, "not-the-password", "", "")
	if reference != 3 {
		t.Fatalf("reference wrong-password run counted %d failures, want 3", reference)
	}
	if public := count(t, true, forcedResetPassword, "", ""); public != reference {
		t.Errorf("flagged account counted %d failures against %d for a wrong password", public, reference)
	}
	if scoped := count(t, true, forcedResetPassword, "client-1", "s3cret"); scoped != reference {
		t.Errorf("flagged account counted %d failures for a scoped client against %d for a wrong "+
			"password: holding the scope buys cheaper guesses", scoped, reference)
	}
}

// The whole loop, in the order a migrated user walks it: refused, reset,
// ordinary login. Each piece is pinned above; this is the one test that fails if
// they stop composing -- a reset that clears the flag on a copy of the row, say,
// or a login that keeps reading a stale one.
func TestLogin_ForcedReset_TheAccountWorksAgainAfterTheReset(t *testing.T) {
	hash, err := vaultcrypto.HashPassword(forcedResetPassword)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	// One row, shared by the login handler and the reset handler, so the reset's
	// write is what the next login reads.
	account := &model.User{
		ID: "u-forced", Email: "rider@legacy.test", PasswordHash: hash,
		EmailVerified: true, MustResetPassword: true,
	}

	users := &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, _ string) (*model.User, error) { return account, nil },
		GetByIDFn:    func(_ context.Context, _ string) (*model.User, error) { return account, nil },
		ClearMustResetPwFn: func(_ context.Context, _ string) error {
			account.MustResetPassword = false
			return nil
		},
		UpdatePasswordFn: func(_ context.Context, _, h string) error {
			account.PasswordHash = h
			return nil
		},
	}
	resetCache := &mocks.MockCache{
		GetAndDeleteFn: func(_ context.Context, key string) (string, error) {
			if strings.HasPrefix(key, "reset:") {
				return account.ID, nil
			}
			return "", nil
		},
	}

	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()
	authSvc := service.NewAuthService(
		users, &mocks.MockRefreshTokenRepo{}, &mocks.MockDeviceRepo{},
		&mocks.MockPasswordHistoryRepo{}, tokenSvc, nil, auditLog,
		nil, &mocks.MockCache{}, &mocks.MockEmailSender{}, "https://vault.test", "TestVault", "", 15, false, nil,
	)
	login := NewAuthHandler(authSvc, users, &mocks.MockCache{}, auditLog, "", false, nil)
	passwords := NewPasswordHandler(
		users, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockEmailSender{}, auditLog, resetCache,
		"https://vault.test", "TestVault", "", 15, nil, false,
	)

	attempt := func(password string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/auth/login",
			jsonBody(t, map[string]string{"email": "rider@legacy.test", "password": password}))
		req.RemoteAddr = "203.0.113.7:5000"
		rec := httptest.NewRecorder()
		login.Login(rec, req)
		return rec
	}

	if rec := attempt(forcedResetPassword); rec.Code != http.StatusUnauthorized {
		t.Fatalf("before the reset: status = %d, want 401 (%s)", rec.Code, rec.Body.String())
	}

	rec := httptest.NewRecorder()
	passwords.ResetConfirm(rec, httptest.NewRequest(http.MethodPost, "/auth/password/reset/confirm",
		strings.NewReader(`{"token":"magic-token-abc","password":"aNewStrongPassword!123"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("the reset failed: %d %s", rec.Code, rec.Body.String())
	}

	after := attempt("aNewStrongPassword!123")
	if after.Code != http.StatusOK {
		t.Fatalf("after the reset: status = %d, want 200: the account is still shut out with a "+
			"password it just set (%s)", after.Code, after.Body.String())
	}
	if !strings.Contains(after.Body.String(), "access_token") {
		t.Errorf("after the reset: no session was issued: %s", after.Body.String())
	}
}
