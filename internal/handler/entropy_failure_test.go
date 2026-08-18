package handler

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

var errAcctEntropy = errors.New("entropy exhausted")

// acctScriptedEntropy serves whole reads until its budget runs out, then fails.
// Only paths whose crypto/rand.Read calls are inside the budget may run while it
// is installed: crypto/rand.Read is process-fatal on a failing reader, and it is
// the io.ReadFull(rand.Reader, ...) callers (RandomBytes, Encrypt) that get the
// error handed back. The budget is what selects which generator in a sequence
// fails.
type acctScriptedEntropy struct {
	reads int
}

func (r *acctScriptedEntropy) Read(p []byte) (int, error) {
	if r.reads <= 0 {
		return 0, errAcctEntropy
	}
	r.reads--
	for i := range p {
		p[i] = 0x42
	}
	return len(p), nil
}

func acctStarveEntropy(t *testing.T, budget int) {
	t.Helper()
	original := rand.Reader
	rand.Reader = &acctScriptedEntropy{reads: budget}
	t.Cleanup(func() { rand.Reader = original })
}

// The reset link is the token. If RandomHex cannot produce one, the only safe
// outcome is that no link exists: no cache entry, so nothing can be redeemed, and
// no mail, so nothing is delivered that would not work.
//
// The response still has to be the same 200 everyone else gets. This endpoint
// answers identically for a known and an unknown address on purpose, and an
// entropy failure that turned into a 500 would be a side channel that says "this
// address is registered" — the exact enumeration leak the constant response and
// the dummy-hash burn exist to close.
func TestResetRequest_TokenEntropyFailureMintsNoLink(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(_ context.Context, email string) (*model.User, error) {
			return &model.User{ID: "user-123", Email: email}, nil
		},
	}
	var cachedKeys []string
	c := &mocks.MockCache{
		SetFn: func(_ context.Context, key, _ string, _ time.Duration) error {
			cachedKeys = append(cachedKeys, key)
			return nil
		},
	}
	h := NewPasswordHandler(
		users, &mocks.MockPasswordHistoryRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockEmailSender{}, newTestAuditLogger(), c,
		"https://vault.test", "TestVault", "", 15, nil, false,
	)

	acctStarveEntropy(t, 0)

	req := httptest.NewRequest(http.MethodPost, "/auth/password/reset",
		jsonBody(t, map[string]string{"email": "user@example.com"}))
	req.RemoteAddr = "203.0.113.4:5000"
	rec := httptest.NewRecorder()

	h.ResetRequest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — the failure is observable and distinguishes a known address", rec.Code)
	}
	if len(cachedKeys) != 0 {
		t.Errorf("reset state was cached (%v) although no token could be generated", cachedKeys)
	}
}

// TOTP setup writes a secret the user then enrolls in their authenticator. Every
// piece of it comes from the CSPRNG: the shared secret itself, the GCM nonce that
// encrypts it at rest, and the row ID. A generator that failed silently would hand
// back a predictable secret — an all-zero or repeating one — and the user would
// enroll it, believing they now have a second factor that anyone can compute.
func TestTOTPSetup_EntropyFailureStoresNothing(t *testing.T) {
	cases := []struct {
		name   string
		budget int
	}{
		{name: "shared_secret", budget: 0},
		{name: "row_id", budget: 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			created := false
			totpRepo := &mocks.MockTOTPRepo{
				GetByUserIDFn: func(context.Context, string) (*model.TOTPSecret, error) { return nil, nil },
				CreateFn: func(context.Context, *model.TOTPSecret) error {
					created = true
					return nil
				},
			}
			h := NewTOTPHandler(totpRepo, make([]byte, 32), "VaultTest", &mocks.MockCache{}, nil, false)

			acctStarveEntropy(t, tc.budget)

			req := httptest.NewRequest(http.MethodPost, "/auth/2fa/totp/setup", nil)
			req = setAuthContext(req, "user-123")
			rec := httptest.NewRecorder()

			h.Setup(rec, req)

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
			}
			if got := acctErrorCode(t, rec); got != "internal_error" {
				t.Errorf("error = %q, want internal_error", got)
			}
			if created {
				t.Error("a TOTP secret was stored even though its material could not be generated")
			}
		})
	}
}

// Backup codes are bearer credentials: whoever holds one gets past the second
// factor. Ten of them are generated in a loop, and the loop bails on the first
// generator failure. What must not happen is a short or predictable set being
// stored and shown: the user would write down codes that an attacker can derive,
// and they would be the codes that work.
//
// DeleteAllForUser has already run by this point, so the check that CreateBatch
// never fired is also the check that the user is left with no codes rather than a
// partial set.
func TestBackupCodesGenerate_EntropyFailureStoresNoPartialSet(t *testing.T) {
	cases := []struct {
		name   string
		budget int
	}{
		{name: "code_material", budget: 0},
		{name: "row_id", budget: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			invalidated := false
			stored := false
			repo := &mocks.MockBackupCodeRepo{
				DeleteAllForUserFn: func(context.Context, string) error {
					invalidated = true
					return nil
				},
				CreateBatchFn: func(context.Context, []*model.BackupCode) error {
					stored = true
					return nil
				},
			}
			h := NewBackupCodeHandler(repo, []byte("test-hmac-key"), nil, false)

			acctStarveEntropy(t, tc.budget)

			req := httptest.NewRequest(http.MethodPost, "/auth/2fa/backup-codes", nil)
			req = setAuthContext(req, "user-123")
			rec := httptest.NewRecorder()

			h.Generate(rec, req)

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
			}
			if got := acctErrorCode(t, rec); got != "internal_error" {
				t.Errorf("error = %q, want internal_error", got)
			}
			if !invalidated {
				t.Error("the previous backup codes were never invalidated")
			}
			if stored {
				t.Error("a partial backup code set was stored after entropy ran out")
			}
			if strings.Contains(rec.Body.String(), "\"codes\"") {
				t.Error("codes were returned to the caller despite the generation failure")
			}
		})
	}
}
