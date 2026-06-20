package adminapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
)

// ---------------------------------------------------------------------------
// Login — TOTP decrypt-error and replay branches
// ---------------------------------------------------------------------------

// A corrupt stored TOTP secret makes Login fail closed with 500.
func TestLogin_TOTPDecryptError500(t *testing.T) {
	repo := newFakeAdminRepo()
	a := seedAdmin(t, repo, "badsecret", "correct-password-123")
	a.TOTPSecretEnc = "not-valid-ciphertext"
	a.TOTPVerified = true
	h := newTestAuth(repo, nil)
	rec := httptest.NewRecorder()
	h.Login(rec, jsonReq(http.MethodPost, "/admin/auth/login",
		`{"username":"badsecret","password":"correct-password-123","totp_code":"123456"}`))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (TOTP decrypt error)", rec.Code)
	}
}

// A TOTP code at or below the last-accepted counter is rejected (replay).
func TestLogin_TOTPReplayRejected401(t *testing.T) {
	repo := newFakeAdminRepo()
	key := make([]byte, 32)
	secret := "JBSWY3DPEHPK3PXP"
	a := seedAdmin(t, repo, "replay", "correct-password-123")
	enc, _ := encryptTOTPSecret(secret, key, a.ID)
	a.TOTPSecretEnc = enc
	a.TOTPVerified = true
	a.LastTOTPCounter = 1 << 62 // far in the future → any real counter is <=
	h := newTestAuth(repo, nil)
	code, _ := vaultcrypto.GenerateTOTPCode(secret, time.Now())
	rec := httptest.NewRecorder()
	h.Login(rec, jsonReq(http.MethodPost, "/admin/auth/login",
		`{"username":"replay","password":"correct-password-123","totp_code":"`+code+`"}`))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (replayed TOTP)", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// TOTPVerify — decrypt-error, replay, and persist-error branches
// ---------------------------------------------------------------------------

func TestTOTPVerify_DecryptError500(t *testing.T) {
	a := &model.AdminUser{ID: "a1", TOTPSecretEnc: "garbage-ciphertext"}
	h := newTestAuth(nil, nil)
	r := jsonReq(http.MethodPost, "/admin/admins/me/totp/verify", `{"code":"123456"}`)
	r = r.WithContext(WithAdmin(r.Context(), a))
	rec := httptest.NewRecorder()
	h.TOTPVerify(rec, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (decrypt error)", rec.Code)
	}
}

func TestTOTPVerify_ReplayRejected401(t *testing.T) {
	key := make([]byte, 32)
	secret := "JBSWY3DPEHPK3PXP"
	a := &model.AdminUser{ID: "a1", LastTOTPCounter: 1 << 62}
	enc, _ := encryptTOTPSecret(secret, key, a.ID)
	a.TOTPSecretEnc = enc
	h := newTestAuth(nil, nil)
	code, _ := vaultcrypto.GenerateTOTPCode(secret, time.Now())
	r := jsonReq(http.MethodPost, "/admin/admins/me/totp/verify", `{"code":"`+code+`"}`)
	r = r.WithContext(WithAdmin(r.Context(), a))
	rec := httptest.NewRecorder()
	h.TOTPVerify(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (replayed TOTP)", rec.Code)
	}
}

func TestTOTPVerify_UpdateError500(t *testing.T) {
	repo := newFakeAdminRepo()
	repo.errUpdate = errors.New("db write failed")
	key := make([]byte, 32)
	secret := "JBSWY3DPEHPK3PXP"
	a := &model.AdminUser{ID: "a1"}
	enc, _ := encryptTOTPSecret(secret, key, a.ID)
	a.TOTPSecretEnc = enc
	repo.users[a.ID] = a
	h := newTestAuth(repo, nil)
	code, _ := vaultcrypto.GenerateTOTPCode(secret, time.Now())
	r := jsonReq(http.MethodPost, "/admin/admins/me/totp/verify", `{"code":"`+code+`"}`)
	r = r.WithContext(WithAdmin(r.Context(), a))
	rec := httptest.NewRecorder()
	h.TOTPVerify(rec, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (persist failure), body=%s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// CreateClient / CreateAdmin — malformed JSON and persist-error branches
// ---------------------------------------------------------------------------

func TestCreateClient_InvalidJSON400(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	h.CreateClient(rec, withActor(jsonReq(http.MethodPost, "/admin/clients", `{not json`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (invalid JSON)", rec.Code)
	}
}

func TestCreateAdmin_InvalidJSON400(t *testing.T) {
	h := newTestHandler(nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	h.CreateAdmin(rec, withActor(jsonReq(http.MethodPost, "/admin/admins", `{not json`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (invalid JSON)", rec.Code)
	}
}

func TestCreateAdmin_CreateError500(t *testing.T) {
	repo := newFakeAdminRepo()
	repo.errCreate = errors.New("insert failed")
	h := newTestHandler(repo, nil, nil, nil)
	rec := httptest.NewRecorder()
	body := `{"username":"newadmin","password":"aVeryLongPassword12345","role":"viewer"}`
	h.CreateAdmin(rec, withActor(jsonReq(http.MethodPost, "/admin/admins", body)))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (create failure)", rec.Code)
	}
}
