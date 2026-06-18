package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// fakeIssuer serves a minimal OIDC discovery doc + token/userinfo endpoints.
// issuerOverride lets a test force an issuer-mismatch in the discovery doc.
func fakeIssuer(t *testing.T, issuerOverride string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	issuer := srv.URL
	if issuerOverride != "" {
		issuer = issuerOverride
	}
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"userinfo_endpoint":      srv.URL + "/userinfo",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at-123", "id_token": "idt-123", "token_type": "Bearer", "expires_in": 3600,
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at-123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub": "okta-user-9", "email": "rider@corp.test", "email_verified": true, "name": "Rider",
		})
	})
	t.Cleanup(srv.Close)
	return srv
}

func TestOIDCProvider_AuthURL(t *testing.T) {
	srv := fakeIssuer(t, "")
	p := NewOIDCProvider("okta", srv.URL, "cid", "secret", "https://app/cb", "")
	raw := p.AuthURL("state-1", "nonce-1", "challenge-1")
	if raw == "" {
		t.Fatal("AuthURL empty (discovery failed?)")
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	for k, want := range map[string]string{
		"client_id": "cid", "redirect_uri": "https://app/cb", "response_type": "code",
		"scope": "openid email profile", "state": "state-1", "nonce": "nonce-1",
		"code_challenge": "challenge-1", "code_challenge_method": "S256",
	} {
		if q.Get(k) != want {
			t.Errorf("authorize param %s = %q, want %q", k, q.Get(k), want)
		}
	}
	if u.Host != mustHost(srv.URL) {
		t.Errorf("authorize host = %q, want issuer host", u.Host)
	}
}

func TestOIDCProvider_ExchangeAndUserInfo(t *testing.T) {
	srv := fakeIssuer(t, "")
	p := NewOIDCProvider("okta", srv.URL, "cid", "secret", "https://app/cb", "")

	tok, err := p.Exchange(context.Background(), "code-1", "verifier-1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "at-123" || tok.IDToken != "idt-123" {
		t.Fatalf("unexpected token response: %+v", tok)
	}

	info, err := p.UserInfo(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if info.ID != "okta-user-9" || info.Email != "rider@corp.test" || !info.EmailVerified || info.Provider != "okta" {
		t.Fatalf("unexpected userinfo: %+v", info)
	}
}

// Discovery must reject an issuer that doesn't match the configured one (OIDC §3.1.3.7).
func TestOIDCProvider_IssuerMismatchRejected(t *testing.T) {
	srv := fakeIssuer(t, "https://evil.example.com")
	p := NewOIDCProvider("okta", srv.URL, "cid", "secret", "https://app/cb", "")
	if _, err := p.Exchange(context.Background(), "code", "verifier"); err == nil {
		t.Fatal("expected issuer-mismatch error from discovery")
	}
	if p.AuthURL("s", "n", "c") != "" {
		t.Fatal("AuthURL must be empty when discovery fails on issuer mismatch")
	}
}

func mustHost(raw string) string {
	u, _ := url.Parse(raw)
	return u.Host
}

// TestOIDCProvider_Name_Table covers Name() for different providers.
func TestOIDCProvider_Name_Table(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		want     string
	}{
		{"generic", "generic", "generic"},
		{"google", "google", "google"},
		{"empty name", "", ""},
		{"custom", "my-oidc", "my-oidc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewOIDCProvider(tt.provider, "https://iss", "cid", "sec", "https://cb", "")
			if got := p.Name(); got != tt.want {
				t.Errorf("Name() = %q, want %q", got, tt.want)
			}
		})
	}
}
