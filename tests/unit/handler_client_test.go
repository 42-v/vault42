package unit_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// newTestTokenService creates a TokenService backed by a fresh RSA key pair.
func newTestTokenService(t *testing.T) *service.TokenService {
	t.Helper()
	privKey, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	kid, _ := vaultcrypto.RandomUUID()
	return service.NewTokenService(
		privKey, kid,
		testIssuer, testAudience,
		15*time.Minute, // access TTL
		24*time.Hour,   // refresh TTL
		7*24*time.Hour, // remember-me TTL
	)
}

// newTestAuditLogger creates a synchronous audit logger backed by a no-op mock.
func newTestAuditLogger() *audit.Logger {
	return audit.NewLogger(&mocks.MockAuditRepo{}, 0)
}

// basicAuth encodes client_id:client_secret into a Basic auth header value.
func basicAuth(clientID, clientSecret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret))
}

func TestClientToken_Valid(t *testing.T) {
	clientID := "client-001"
	clientSecret := "test-secret-value"

	secretHash, err := vaultcrypto.HashPassword(clientSecret)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	repo := &mocks.MockClientRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.Client, error) {
			if id != clientID {
				return nil, nil
			}
			return &model.Client{
				ID:         clientID,
				Name:       "test-frontend",
				SecretHash: secretHash,
				Role:       "frontend",
				Scopes:     []string{"user:read", "user:write"},
				Active:     true,
				CreatedAt:  time.Now(),
			}, nil
		},
	}

	tokenSvc := newTestTokenService(t)
	auditLog := newTestAuditLogger()
	h := handler.NewClientHandler(repo, tokenSvc, auditLog)

	req := httptest.NewRequest("POST", "/client/token", strings.NewReader("grant_type=client_credentials"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", basicAuth(clientID, clientSecret))

	w := httptest.NewRecorder()
	h.Token(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Error("response missing 'access_token'")
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", resp["token_type"])
	}
}

func TestClientToken_WrongSecret(t *testing.T) {
	clientID := "client-001"
	correctSecret := "correct-secret"

	secretHash, err := vaultcrypto.HashPassword(correctSecret)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	repo := &mocks.MockClientRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.Client, error) {
			return &model.Client{
				ID:         clientID,
				Name:       "test-frontend",
				SecretHash: secretHash,
				Role:       "frontend",
				Scopes:     []string{"user:read"},
				Active:     true,
			}, nil
		},
	}

	tokenSvc := newTestTokenService(t)
	h := handler.NewClientHandler(repo, tokenSvc, nil)

	req := httptest.NewRequest("POST", "/client/token", nil)
	req.Header.Set("Authorization", basicAuth(clientID, "wrong-secret"))

	w := httptest.NewRecorder()
	h.Token(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusUnauthorized, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "invalid_client_credentials" {
		t.Errorf("error = %q, want %q", resp["error"], "invalid_client_credentials")
	}
}

func TestClientToken_RevokedClient(t *testing.T) {
	clientID := "client-revoked"
	clientSecret := "test-secret"

	secretHash, err := vaultcrypto.HashPassword(clientSecret)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	repo := &mocks.MockClientRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.Client, error) {
			return &model.Client{
				ID:         clientID,
				Name:       "revoked-client",
				SecretHash: secretHash,
				Role:       "backend",
				Scopes:     []string{"user:read"},
				Active:     false, // revoked
			}, nil
		},
	}

	tokenSvc := newTestTokenService(t)
	h := handler.NewClientHandler(repo, tokenSvc, nil)

	req := httptest.NewRequest("POST", "/client/token", nil)
	req.Header.Set("Authorization", basicAuth(clientID, clientSecret))

	w := httptest.NewRecorder()
	h.Token(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusUnauthorized, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "invalid_client_credentials" {
		t.Errorf("error = %q, want %q", resp["error"], "invalid_client_credentials")
	}
}

func TestClientToken_InvalidBasicAuth(t *testing.T) {
	repo := &mocks.MockClientRepo{}
	tokenSvc := newTestTokenService(t)
	h := handler.NewClientHandler(repo, tokenSvc, nil)

	tests := []struct {
		name      string
		authValue string
	}{
		{"no auth header", ""},
		{"malformed base64", "Basic !!!not-base64!!!"},
		{"no colon separator", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocredentials"))},
		{"bearer instead of basic", "Bearer some-token"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/client/token", nil)
			if tc.authValue != "" {
				req.Header.Set("Authorization", tc.authValue)
			}

			w := httptest.NewRecorder()
			h.Token(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusUnauthorized, w.Body.String())
			}
		})
	}
}

func TestClientToken_ScopeRestriction(t *testing.T) {
	clientID := "client-limited"
	clientSecret := "test-secret"

	secretHash, err := vaultcrypto.HashPassword(clientSecret)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	repo := &mocks.MockClientRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.Client, error) {
			return &model.Client{
				ID:         clientID,
				Name:       "limited-client",
				SecretHash: secretHash,
				Role:       "frontend",
				Scopes:     []string{"user:read"}, // only user:read allowed
				Active:     true,
			}, nil
		},
	}

	tokenSvc := newTestTokenService(t)
	h := handler.NewClientHandler(repo, tokenSvc, nil)

	// Request a scope the client does not have
	req := httptest.NewRequest("POST", "/client/token",
		strings.NewReader("scope=admin:write"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", basicAuth(clientID, clientSecret))

	w := httptest.NewRecorder()
	h.Token(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "invalid_scope" {
		t.Errorf("error = %q, want %q", resp["error"], "invalid_scope")
	}
}
