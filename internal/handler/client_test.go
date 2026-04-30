package handler

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// ---------------------------------------------------------------------------
// ClientHandler helpers
// ---------------------------------------------------------------------------

func newTestClientHandler(t *testing.T, clients *mocks.MockClientRepo) *ClientHandler {
	t.Helper()
	tokenSvc, _ := newTestTokenService(t)
	auditLog := newTestAuditLogger()
	return NewClientHandler(clients, tokenSvc, auditLog)
}

// makeClientWithSecret returns a Client with the given secret hashed.
func makeClientWithSecret(t *testing.T, id, name, secret, role string, scopes []string, active bool) *model.Client {
	t.Helper()
	hash, err := vaultcrypto.HashPassword(secret)
	if err != nil {
		t.Fatalf("hash client secret: %v", err)
	}
	return &model.Client{
		ID:         id,
		Name:       name,
		SecretHash: hash,
		Role:       role,
		Scopes:     scopes,
		Active:     active,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
}

// ---------------------------------------------------------------------------
// Token endpoint tests
// ---------------------------------------------------------------------------

func TestClientToken_BasicAuth_Success(t *testing.T) {
	clientSecret := "my-client-secret-123"
	client := makeClientWithSecret(t, "client-001", "frontend", clientSecret, "frontend", []string{"user:read", "user:write"}, true)

	clients := &mocks.MockClientRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Client, error) {
			if id == "client-001" {
				return client, nil
			}
			return nil, nil
		},
	}

	h := newTestClientHandler(t, clients)

	req := httptest.NewRequest(http.MethodPost, "/client/token", nil)
	creds := base64.StdEncoding.EncodeToString([]byte("client-001:" + clientSecret))
	req.Header.Set("Authorization", "Basic "+creds)
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["access_token"] == nil || result["access_token"] == "" {
		t.Fatal("expected access_token in response")
	}
	if result["token_type"] != "Bearer" {
		t.Fatalf("expected token_type=Bearer, got %v", result["token_type"])
	}
	expiresIn, ok := result["expires_in"].(float64)
	if !ok || expiresIn <= 0 {
		t.Fatalf("expected positive expires_in, got %v", result["expires_in"])
	}
}

func TestClientToken_FormBody_Success(t *testing.T) {
	clientSecret := "form-body-secret-123"
	client := makeClientWithSecret(t, "client-002", "backend", clientSecret, "backend", []string{"admin:read"}, true)

	clients := &mocks.MockClientRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Client, error) {
			if id == "client-002" {
				return client, nil
			}
			return nil, nil
		},
	}

	h := newTestClientHandler(t, clients)

	body := strings.NewReader("client_id=client-002&client_secret=" + clientSecret)
	req := httptest.NewRequest(http.MethodPost, "/client/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	if result["access_token"] == nil || result["access_token"] == "" {
		t.Fatal("expected access_token in response")
	}
}

func TestClientToken_MissingCredentials(t *testing.T) {
	h := newTestClientHandler(t, &mocks.MockClientRepo{})

	req := httptest.NewRequest(http.MethodPost, "/client/token", nil)
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_client_credentials" {
		t.Fatalf("expected error=invalid_client_credentials, got %q", result["error"])
	}
}

func TestClientToken_InvalidBasicAuth_NoParts(t *testing.T) {
	h := newTestClientHandler(t, &mocks.MockClientRepo{})

	req := httptest.NewRequest(http.MethodPost, "/client/token", nil)
	// Set Basic auth with only one part (no colon)
	creds := base64.StdEncoding.EncodeToString([]byte("onlyid"))
	req.Header.Set("Authorization", "Basic "+creds)
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestClientToken_InvalidBasicAuth_BadBase64(t *testing.T) {
	h := newTestClientHandler(t, &mocks.MockClientRepo{})

	req := httptest.NewRequest(http.MethodPost, "/client/token", nil)
	req.Header.Set("Authorization", "Basic !!!invalid-base64!!!")
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestClientToken_ClientNotFound(t *testing.T) {
	clients := &mocks.MockClientRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Client, error) {
			return nil, nil
		},
	}

	h := newTestClientHandler(t, clients)

	req := httptest.NewRequest(http.MethodPost, "/client/token", nil)
	creds := base64.StdEncoding.EncodeToString([]byte("nonexistent:secret"))
	req.Header.Set("Authorization", "Basic "+creds)
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestClientToken_ClientRepoError(t *testing.T) {
	clients := &mocks.MockClientRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Client, error) {
			return nil, errors.New("db connection refused")
		},
	}

	h := newTestClientHandler(t, clients)

	req := httptest.NewRequest(http.MethodPost, "/client/token", nil)
	creds := base64.StdEncoding.EncodeToString([]byte("client-001:secret"))
	req.Header.Set("Authorization", "Basic "+creds)
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestClientToken_ClientInactive(t *testing.T) {
	clientSecret := "inactive-secret-123"
	client := makeClientWithSecret(t, "client-disabled", "disabled", clientSecret, "frontend", []string{"read"}, false)

	clients := &mocks.MockClientRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Client, error) {
			return client, nil
		},
	}

	h := newTestClientHandler(t, clients)

	req := httptest.NewRequest(http.MethodPost, "/client/token", nil)
	creds := base64.StdEncoding.EncodeToString([]byte("client-disabled:" + clientSecret))
	req.Header.Set("Authorization", "Basic "+creds)
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_client_credentials" {
		t.Fatalf("expected error=invalid_client_credentials, got %q", result["error"])
	}
}

func TestClientToken_WrongSecret(t *testing.T) {
	clientSecret := "correct-secret-12345"
	client := makeClientWithSecret(t, "client-003", "app", clientSecret, "frontend", []string{"read"}, true)

	clients := &mocks.MockClientRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Client, error) {
			return client, nil
		},
	}

	h := newTestClientHandler(t, clients)

	req := httptest.NewRequest(http.MethodPost, "/client/token", nil)
	creds := base64.StdEncoding.EncodeToString([]byte("client-003:wrong-secret-99999"))
	req.Header.Set("Authorization", "Basic "+creds)
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_client_credentials" {
		t.Fatalf("expected error=invalid_client_credentials, got %q", result["error"])
	}
}

func TestClientToken_ScopeIntersection(t *testing.T) {
	clientSecret := "scope-test-secret-1"
	client := makeClientWithSecret(t, "client-scope", "scoped", clientSecret, "frontend", []string{"user:read", "user:write", "admin:read"}, true)

	clients := &mocks.MockClientRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Client, error) {
			return client, nil
		},
	}

	h := newTestClientHandler(t, clients)

	// Request only a subset of scopes
	body := strings.NewReader("scope=user:read admin:read")
	req := httptest.NewRequest(http.MethodPost, "/client/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	creds := base64.StdEncoding.EncodeToString([]byte("client-scope:" + clientSecret))
	req.Header.Set("Authorization", "Basic "+creds)
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	scope, _ := result["scope"].(string)
	if !strings.Contains(scope, "user:read") || !strings.Contains(scope, "admin:read") {
		t.Fatalf("expected scope to contain user:read and admin:read, got %q", scope)
	}
	if strings.Contains(scope, "user:write") {
		t.Fatalf("scope should NOT contain user:write (not requested), got %q", scope)
	}
}

func TestClientToken_InvalidScope(t *testing.T) {
	clientSecret := "scope-invalid-secret"
	client := makeClientWithSecret(t, "client-s2", "scoped2", clientSecret, "frontend", []string{"user:read"}, true)

	clients := &mocks.MockClientRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Client, error) {
			return client, nil
		},
	}

	h := newTestClientHandler(t, clients)

	// Request scopes that do not overlap with allowed scopes
	body := strings.NewReader("scope=super:admin dangerous:write")
	req := httptest.NewRequest(http.MethodPost, "/client/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	creds := base64.StdEncoding.EncodeToString([]byte("client-s2:" + clientSecret))
	req.Header.Set("Authorization", "Basic "+creds)
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "invalid_scope" {
		t.Fatalf("expected error=invalid_scope, got %q", result["error"])
	}
}

func TestClientToken_NoScopeRequested_DefaultsToAll(t *testing.T) {
	clientSecret := "default-scope-secret"
	client := makeClientWithSecret(t, "client-def", "defaultscope", clientSecret, "frontend", []string{"user:read", "user:write"}, true)

	clients := &mocks.MockClientRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Client, error) {
			return client, nil
		},
	}

	h := newTestClientHandler(t, clients)

	req := httptest.NewRequest(http.MethodPost, "/client/token", nil)
	creds := base64.StdEncoding.EncodeToString([]byte("client-def:" + clientSecret))
	req.Header.Set("Authorization", "Basic "+creds)
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	decodeResponse(t, rec, &result)
	scope, _ := result["scope"].(string)
	if !strings.Contains(scope, "user:read") || !strings.Contains(scope, "user:write") {
		t.Fatalf("expected all client scopes in response, got %q", scope)
	}
}

func TestClientToken_NilAuditLog(t *testing.T) {
	clientSecret := "audit-nil-secret123"
	client := makeClientWithSecret(t, "client-noaudit", "noaudit", clientSecret, "frontend", []string{"read"}, true)

	clients := &mocks.MockClientRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Client, error) {
			return client, nil
		},
	}

	tokenSvc, _ := newTestTokenService(t)
	h := NewClientHandler(clients, tokenSvc, nil) // nil audit log

	req := httptest.NewRequest(http.MethodPost, "/client/token", nil)
	creds := base64.StdEncoding.EncodeToString([]byte("client-noaudit:" + clientSecret))
	req.Header.Set("Authorization", "Basic "+creds)
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestClientToken_OnlyClientID_NoSecret_InFormBody(t *testing.T) {
	h := newTestClientHandler(t, &mocks.MockClientRepo{})

	body := strings.NewReader("client_id=some-id")
	req := httptest.NewRequest(http.MethodPost, "/client/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestClientToken_OnlySecret_NoID_InFormBody(t *testing.T) {
	h := newTestClientHandler(t, &mocks.MockClientRepo{})

	body := strings.NewReader("client_secret=some-secret")
	req := httptest.NewRequest(http.MethodPost, "/client/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestClientToken_BearerAuth_NotAccepted(t *testing.T) {
	h := newTestClientHandler(t, &mocks.MockClientRepo{})

	req := httptest.NewRequest(http.MethodPost, "/client/token", nil)
	req.Header.Set("Authorization", "Bearer some-bearer-token")
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestClientToken_BasicAuth_WithColonInPassword(t *testing.T) {
	clientSecret := "secret:with:colons"
	client := makeClientWithSecret(t, "client-colon", "colontest", clientSecret, "frontend", []string{"read"}, true)

	clients := &mocks.MockClientRepo{
		GetByIDFn: func(ctx context.Context, id string) (*model.Client, error) {
			if id == "client-colon" {
				return client, nil
			}
			return nil, nil
		},
	}

	h := newTestClientHandler(t, clients)

	req := httptest.NewRequest(http.MethodPost, "/client/token", nil)
	creds := base64.StdEncoding.EncodeToString([]byte("client-colon:" + clientSecret))
	req.Header.Set("Authorization", "Basic "+creds)
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// parseClientCredentials tests
// ---------------------------------------------------------------------------

func TestParseClientCredentials_BasicAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	creds := base64.StdEncoding.EncodeToString([]byte("myid:mysecret"))
	req.Header.Set("Authorization", "Basic "+creds)

	id, secret, ok := parseClientCredentials(req)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if id != "myid" {
		t.Fatalf("expected id=myid, got %q", id)
	}
	if secret != "mysecret" {
		t.Fatalf("expected secret=mysecret, got %q", secret)
	}
}

func TestParseClientCredentials_FormBody(t *testing.T) {
	body := strings.NewReader("client_id=formid&client_secret=formsecret")
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	id, secret, ok := parseClientCredentials(req)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if id != "formid" {
		t.Fatalf("expected id=formid, got %q", id)
	}
	if secret != "formsecret" {
		t.Fatalf("expected secret=formsecret, got %q", secret)
	}
}

func TestParseClientCredentials_Empty(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)

	_, _, ok := parseClientCredentials(req)
	if ok {
		t.Fatal("expected ok=false for empty request")
	}
}

func TestParseClientCredentials_BasicAuthPriority(t *testing.T) {
	// When both Basic auth and form body are present, Basic auth should take priority
	body := strings.NewReader("client_id=formid&client_secret=formsecret")
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	creds := base64.StdEncoding.EncodeToString([]byte("basicid:basicsecret"))
	req.Header.Set("Authorization", "Basic "+creds)

	id, secret, ok := parseClientCredentials(req)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if id != "basicid" {
		t.Fatalf("expected id=basicid (from Basic auth), got %q", id)
	}
	if secret != "basicsecret" {
		t.Fatalf("expected secret=basicsecret (from Basic auth), got %q", secret)
	}
}

func TestParseClientCredentials_ColonInSecret(t *testing.T) {
	// RFC 7617: password may contain colons
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	creds := base64.StdEncoding.EncodeToString([]byte("myid:secret:with:colons"))
	req.Header.Set("Authorization", "Basic "+creds)

	id, secret, ok := parseClientCredentials(req)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if id != "myid" {
		t.Fatalf("expected id=myid, got %q", id)
	}
	if secret != "secret:with:colons" {
		t.Fatalf("expected secret=secret:with:colons, got %q", secret)
	}
}
