package adminapi

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

func TestHashSessionToken_Deterministic(t *testing.T) {
	token := "test-session-token-abc123"
	h1 := hashSessionToken(token)
	h2 := hashSessionToken(token)
	if h1 != h2 {
		t.Errorf("hash should be deterministic: %s != %s", h1, h2)
	}
	if len(h1) != 64 { // SHA-256 hex = 64 chars
		t.Errorf("hash length = %d, want 64", len(h1))
	}
}

func TestHashSessionToken_DifferentTokensDifferentHashes(t *testing.T) {
	h1 := hashSessionToken("token-a")
	h2 := hashSessionToken("token-b")
	if h1 == h2 {
		t.Error("different tokens should produce different hashes")
	}
}

func TestEncryptDecryptTOTPSecret(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	secret := "JBSWY3DPEHPK3PXP"
	const adminID = "00000000-0000-0000-0000-000000000001"
	enc, err := encryptTOTPSecret(secret, key, adminID)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	dec, err := decryptTOTPSecret(enc, key, adminID)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if dec != secret {
		t.Errorf("decrypted = %q, want %q", dec, secret)
	}
}

func TestEncryptDecryptTOTPSecret_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 0xFF

	secret := "JBSWY3DPEHPK3PXP"
	const adminID = "00000000-0000-0000-0000-000000000002"
	enc, err := encryptTOTPSecret(secret, key1, adminID)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	_, err = decryptTOTPSecret(enc, key2, adminID)
	if err == nil {
		t.Error("decrypt with wrong key should fail")
	}
}

// A-4: a TOTP ciphertext encrypted under one admin's ID must NOT decrypt
// under a different admin's ID — the AAD binding prevents the row-swap
// attack documented in the audit.
func TestEncryptDecryptTOTPSecret_AADBoundToAdminID(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	const secret = "JBSWY3DPEHPK3PXP"
	const adminA = "00000000-0000-0000-0000-00000000000A"
	const adminB = "00000000-0000-0000-0000-00000000000B"

	enc, err := encryptTOTPSecret(secret, key, adminA)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Same admin ID — must succeed.
	if dec, err := decryptTOTPSecret(enc, key, adminA); err != nil || dec != secret {
		t.Fatalf("same-admin decrypt: dec=%q err=%v", dec, err)
	}

	// Cross-admin decrypt with a non-empty differing ID — must fail.
	// (Empty adminID would invoke the legacy fallback by design; that's
	// covered by the AcceptsLegacyCiphertext test below.)
	if _, err := decryptTOTPSecret(enc, key, adminB); err == nil {
		t.Fatal("cross-admin decrypt must fail — AAD binding broken")
	}
}

// A-4: pre-A-4 ciphertexts (encrypted without AAD) must NOT decrypt under
// the new code. Pre-1.0 release; we accept the breaking change rather than
// carrying a fallback path that could mask attacks.
func TestDecryptTOTPSecret_RejectsLegacyCiphertext(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	const secret = "JBSWY3DPEHPK3PXP"

	rawEnc, err := vaultcrypto.Encrypt([]byte(secret), key)
	if err != nil {
		t.Fatalf("legacy encrypt: %v", err)
	}
	encHex := hex.EncodeToString(rawEnc)

	const adminID = "00000000-0000-0000-0000-000000000099"
	if _, err := decryptTOTPSecret(encHex, key, adminID); err == nil {
		t.Fatal("legacy non-AAD ciphertext must NOT decrypt under A-4 code")
	}
}

func TestAuthHandler_Status(t *testing.T) {
	tests := []struct {
		name       string
		admin      *model.AdminUser
		wantCode   int
		wantHasID  bool
	}{
		{"no admin in ctx", nil, http.StatusUnauthorized, false},
		{"with admin", &model.AdminUser{ID: "adm-xyz", Username: "bob", Role: "viewer", TOTPVerified: true}, http.StatusOK, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestAuth(nil, nil)
			rec := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
			if tt.admin != nil {
				r = r.WithContext(WithAdmin(r.Context(), tt.admin))
			}
			h.Status(rec, r)
			if rec.Code != tt.wantCode {
				t.Errorf("code = %d, want %d", rec.Code, tt.wantCode)
			}
			if tt.wantHasID && !strings.Contains(rec.Body.String(), tt.admin.ID) {
				t.Errorf("body missing admin ID: %s", rec.Body.String())
			}
		})
	}
}

func TestAuthHandler_Logout(t *testing.T) {
	tests := []struct {
		name     string
		session  *model.AdminSession
		sessRepo repository.AdminSessionRepository
		wantCode int
	}{
		{"no session", nil, nil, http.StatusUnauthorized},
		{"with session revoke ok", &model.AdminSession{ID: "s1"}, nil, http.StatusOK},
		{"revoke error", &model.AdminSession{ID: "s2"}, func() repository.AdminSessionRepository {
			sr := newFakeSessionRepo()
			return &fakeSessionRepoWithErr{fakeSessionRepo: sr, errRevoke: errors.New("db")}
		}(), http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := tt.sessRepo
			if sess == nil {
				sess = newFakeSessionRepo()
			}
			h := newTestAuth(nil, sess)
			rec := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/admin/auth/logout", nil)
			if tt.session != nil {
				r = r.WithContext(WithSession(r.Context(), tt.session))
			}
			h.Logout(rec, r)
			if rec.Code != tt.wantCode {
				t.Errorf("code=%d want=%d body=%s", rec.Code, tt.wantCode, rec.Body.String())
			}
		})
	}
}

func TestEnsureFirstAdmin_NoAdmins(t *testing.T) {
	repo := newFakeAdminRepo()
	err := EnsureFirstAdmin(context.Background(), repo, "")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(repo.users) != 1 {
		t.Errorf("expected 1 admin created, got %d", len(repo.users))
	}
}

func TestEnsureFirstAdmin_AlreadyExists(t *testing.T) {
	repo := newFakeAdminRepo()
	repo.users["existing"] = &model.AdminUser{ID: "existing", Username: "admin"}
	err := EnsureFirstAdmin(context.Background(), repo, "")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(repo.users) != 1 {
		t.Error("should not create duplicate")
	}
}

func TestEnsureFirstAdmin_CountError(t *testing.T) {
	repo := newFakeAdminRepo()
	repo.errCount = errors.New("count fail")
	err := EnsureFirstAdmin(context.Background(), repo, "")
	if err == nil || !strings.Contains(err.Error(), "count admins") {
		t.Errorf("expected count error, got %v", err)
	}
}

// fakeSessionRepoWithErr extends for error injection on Revoke.
type fakeSessionRepoWithErr struct {
	*fakeSessionRepo
	errRevoke error
}

func (f *fakeSessionRepoWithErr) Revoke(ctx context.Context, id string) error {
	if f.errRevoke != nil {
		return f.errRevoke
	}
	return f.fakeSessionRepo.Revoke(ctx, id)
}

var _ repository.AdminSessionRepository = (*fakeSessionRepoWithErr)(nil)

