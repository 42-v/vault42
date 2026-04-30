package unit_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

const (
	testIssuer   = "vault-test"
	testAudience = "vault-test-aud"
	testUserID   = "user-123"
)

// signedAuthContext generates a key pair, signs a Bearer JWT, and returns
// everything needed to wire up authenticated handler tests.
func signedAuthContext(t *testing.T) (*rsa.PrivateKey, string, map[string]*rsa.PublicKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	kid, err := vaultcrypto.RandomUUID()
	if err != nil {
		t.Fatalf("generate kid: %v", err)
	}
	keys := map[string]*rsa.PublicKey{kid: &key.PublicKey}
	now := time.Now()
	claims := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    testIssuer,
			Audience:  vjwt.ClaimStrings{testAudience},
			Subject:   testUserID,
			ExpiresAt: vjwt.NewNumericDate(now.Add(15 * time.Minute)),
			NotBefore: vjwt.NewNumericDate(now),
			IssuedAt:  vjwt.NewNumericDate(now),
		},
		TokenType: "Bearer",
	}
	token, err := vaultcrypto.SignToken(claims, key, kid)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return key, kid, keys, token
}

// authedRequest creates an HTTP request with a valid signed JWT Bearer token.
// It returns the request, a ResponseRecorder, and the public key map needed
// by the Auth middleware.
func authedRequest(t *testing.T, method, path string, body interface{}) (*http.Request, *httptest.ResponseRecorder, map[string]*rsa.PublicKey) {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	kid := "a0a0a0a0-b1b1-c2c2-d3d3-e4e4e4e4e4e4"
	now := time.Now()
	claims := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    testIssuer,
			Audience:  vjwt.ClaimStrings{testAudience},
			Subject:   testUserID,
			ExpiresAt: vjwt.NewNumericDate(now.Add(5 * time.Minute)),
			NotBefore: vjwt.NewNumericDate(now),
			IssuedAt:  vjwt.NewNumericDate(now),
			ID:        "test-jti",
		},
		Roles:     []string{"user"},
		TokenType: "Bearer",
	}

	tokenStr, err := vaultcrypto.SignToken(claims, privKey, kid)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	var bodyReader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		bodyReader = bytes.NewReader(b)
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/json")

	keys := map[string]*rsa.PublicKey{
		kid: &privKey.PublicKey,
	}

	return req, httptest.NewRecorder(), keys
}

// testMasterKey returns a deterministic 32-byte key for tests.
func testMasterKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}

// serveWithAuth wraps a handler function with the Auth middleware and serves
// the request through a standard mux.
func serveWithAuth(t *testing.T, pattern string, handlerFunc http.HandlerFunc, keys map[string]*rsa.PublicKey, w *httptest.ResponseRecorder, r *http.Request) {
	t.Helper()
	mux := http.NewServeMux()
	authMW := middleware.Auth(keys, testIssuer, testAudience)
	mux.Handle(pattern, authMW(handlerFunc))
	mux.ServeHTTP(w, r)
}

// ---------------------------------------------------------------------------
// TOTP Setup
// ---------------------------------------------------------------------------

func TestTOTPSetup_Valid(t *testing.T) {
	masterKey := testMasterKey()
	repo := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(_ context.Context, userID string) (*model.TOTPSecret, error) {
			return nil, nil // no existing setup
		},
	}
	c := &mocks.MockCache{}
	h := handler.NewTOTPHandler(repo, masterKey, testIssuer, c, nil, false)

	req, w, keys := authedRequest(t, "POST", "/auth/2fa/totp/setup", nil)
	serveWithAuth(t, "/auth/2fa/totp/setup", h.Setup, keys, w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["secret"] == "" {
		t.Error("response missing 'secret'")
	}
	if resp["otp_url"] == "" {
		t.Error("response missing 'otp_url'")
	}
}

func TestTOTPSetup_AlreadySetup(t *testing.T) {
	masterKey := testMasterKey()
	repo := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(_ context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{
				ID:       "totp-1",
				UserID:   testUserID,
				Verified: true,
			}, nil
		},
	}
	c := &mocks.MockCache{}
	h := handler.NewTOTPHandler(repo, masterKey, testIssuer, c, nil, false)

	req, w, keys := authedRequest(t, "POST", "/auth/2fa/totp/setup", nil)
	serveWithAuth(t, "/auth/2fa/totp/setup", h.Setup, keys, w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusConflict, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "totp_already_setup" {
		t.Errorf("error = %q, want %q", resp["error"], "totp_already_setup")
	}
}

func TestTOTPSetup_Unauthenticated(t *testing.T) {
	masterKey := testMasterKey()
	repo := &mocks.MockTOTPRepo{}
	c := &mocks.MockCache{}
	h := handler.NewTOTPHandler(repo, masterKey, testIssuer, c, nil, false)

	req := httptest.NewRequest("POST", "/auth/2fa/totp/setup", nil)
	w := httptest.NewRecorder()

	// Use empty key map so no valid key exists -- middleware will reject
	keys := map[string]*rsa.PublicKey{}
	serveWithAuth(t, "/auth/2fa/totp/setup", h.Setup, keys, w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusUnauthorized, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// TOTP Verify
// ---------------------------------------------------------------------------

func TestTOTPVerify_ValidCode(t *testing.T) {
	masterKey := testMasterKey()

	// Generate a real TOTP secret
	secret, err := vaultcrypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("generate TOTP secret: %v", err)
	}

	// Encrypt the secret as the handler would store it (AAD = userID)
	encrypted, err := vaultcrypto.Encrypt([]byte(secret), masterKey, []byte(testUserID))
	if err != nil {
		t.Fatalf("encrypt secret: %v", err)
	}
	secretEnc := hex.EncodeToString(encrypted)

	repo := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(_ context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{
				ID:        "totp-1",
				UserID:    testUserID,
				SecretEnc: secretEnc,
				Verified:  false,
			}, nil
		},
	}

	c := &mocks.MockCache{}
	h := handler.NewTOTPHandler(repo, masterKey, testIssuer, c, nil, false)

	// Generate a valid TOTP code for right now
	code, err := vaultcrypto.GenerateTOTPCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}

	body := map[string]string{"code": code}
	req, w, keys := authedRequest(t, "POST", "/auth/2fa/totp/verify", body)
	serveWithAuth(t, "/auth/2fa/totp/verify", h.Verify, keys, w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["verified"] != true {
		t.Errorf("verified = %v, want true", resp["verified"])
	}
}

func TestTOTPVerify_InvalidCode(t *testing.T) {
	masterKey := testMasterKey()

	secret, err := vaultcrypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("generate TOTP secret: %v", err)
	}
	encrypted, err := vaultcrypto.Encrypt([]byte(secret), masterKey, []byte(testUserID))
	if err != nil {
		t.Fatalf("encrypt secret: %v", err)
	}
	secretEnc := hex.EncodeToString(encrypted)

	repo := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(_ context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{
				ID:        "totp-1",
				UserID:    testUserID,
				SecretEnc: secretEnc,
				Verified:  true,
			}, nil
		},
	}

	c := &mocks.MockCache{}
	h := handler.NewTOTPHandler(repo, masterKey, testIssuer, c, nil, false)

	body := map[string]string{"code": "000000"}
	req, w, keys := authedRequest(t, "POST", "/auth/2fa/totp/verify", body)
	serveWithAuth(t, "/auth/2fa/totp/verify", h.Verify, keys, w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusUnauthorized, w.Body.String())
	}
}

func TestTOTPVerify_NoSetup(t *testing.T) {
	masterKey := testMasterKey()
	repo := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(_ context.Context, userID string) (*model.TOTPSecret, error) {
			return nil, nil // no TOTP configured
		},
	}

	c := &mocks.MockCache{}
	h := handler.NewTOTPHandler(repo, masterKey, testIssuer, c, nil, false)

	body := map[string]string{"code": "123456"}
	req, w, keys := authedRequest(t, "POST", "/auth/2fa/totp/verify", body)
	serveWithAuth(t, "/auth/2fa/totp/verify", h.Verify, keys, w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusNotFound, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "totp_not_setup" {
		t.Errorf("error = %q, want %q", resp["error"], "totp_not_setup")
	}
}

// ---------------------------------------------------------------------------
// Backup Codes
// ---------------------------------------------------------------------------

func TestBackupCodes_Generate(t *testing.T) {
	repo := &mocks.MockBackupCodeRepo{}
	h := handler.NewBackupCodeHandler(repo, []byte("test-hmac-key"), nil, false)

	req, w, keys := authedRequest(t, "POST", "/auth/2fa/backup-codes", nil)
	serveWithAuth(t, "/auth/2fa/backup-codes", h.Generate, keys, w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	codes, ok := resp["codes"].([]interface{})
	if !ok {
		t.Fatal("response missing 'codes' array")
	}
	if len(codes) != 10 {
		t.Errorf("len(codes) = %d, want 10", len(codes))
	}

	// Each code should be 16 hex chars (8 random bytes, 64-bit entropy)
	for i, c := range codes {
		s, ok := c.(string)
		if !ok || len(s) != 16 {
			t.Errorf("codes[%d] = %v, want 16-char hex string", i, c)
		}
	}

	if _, ok := resp["warning"]; !ok {
		t.Error("response missing 'warning'")
	}
}

func TestBackupCodes_Unauthenticated(t *testing.T) {
	repo := &mocks.MockBackupCodeRepo{}
	h := handler.NewBackupCodeHandler(repo, []byte("test-hmac-key"), nil, false)

	req := httptest.NewRequest("POST", "/auth/2fa/backup-codes", nil)
	w := httptest.NewRecorder()

	keys := map[string]*rsa.PublicKey{}
	serveWithAuth(t, "/auth/2fa/backup-codes", h.Generate, keys, w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusUnauthorized, w.Body.String())
	}
}
