package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestGoogleNewProvider(t *testing.T) {
	p := NewGoogleProvider("gcid", "gsec", "https://example.com/google/cb")
	if p.clientID != "gcid" {
		t.Fatalf("clientID = %q, want %q", p.clientID, "gcid")
	}
	if p.clientSecret != "gsec" {
		t.Fatalf("clientSecret = %q, want %q", p.clientSecret, "gsec")
	}
	if p.redirectURI != "https://example.com/google/cb" {
		t.Fatalf("redirectURI = %q, want %q", p.redirectURI, "https://example.com/google/cb")
	}
}

func TestGoogleName(t *testing.T) {
	p := NewGoogleProvider("", "", "")
	if got := p.Name(); got != "google" {
		t.Fatalf("Name() = %q, want %q", got, "google")
	}
}

// Compile-time conformance; see the note in facebook_test.go.
var _ Provider = (*GoogleProvider)(nil)

func TestGoogleAuthURL(t *testing.T) {
	tests := []struct {
		name          string
		clientID      string
		redirectURI   string
		state         string
		nonce         string
		codeChallenge string
		wantParam     map[string]string
	}{
		{
			name:          "contains all OIDC params including PKCE",
			clientID:      "google-client",
			redirectURI:   "https://app.example.com/auth/google/callback",
			state:         "rand-state",
			nonce:         "rand-nonce",
			codeChallenge: "base64url-challenge",
			wantParam: map[string]string{
				"client_id":             "google-client",
				"redirect_uri":          "https://app.example.com/auth/google/callback",
				"response_type":         "code",
				"scope":                 "openid email profile",
				"state":                 "rand-state",
				"nonce":                 "rand-nonce",
				"code_challenge":        "base64url-challenge",
				"code_challenge_method": "S256",
				"access_type":           "offline",
			},
		},
		{
			name:          "encodes special characters",
			clientID:      "id&special",
			redirectURI:   "https://example.com/cb?a=b",
			state:         "s=1&t=2",
			nonce:         "n&n",
			codeChallenge: "c+c",
			wantParam: map[string]string{
				"client_id":      "id&special",
				"redirect_uri":   "https://example.com/cb?a=b",
				"state":          "s=1&t=2",
				"nonce":          "n&n",
				"code_challenge": "c+c",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewGoogleProvider(tt.clientID, "", tt.redirectURI)
			rawURL := p.AuthURL(tt.state, tt.nonce, tt.codeChallenge)

			u, err := url.Parse(rawURL)
			if err != nil {
				t.Fatalf("AuthURL returned invalid URL: %v", err)
			}

			base := u.Scheme + "://" + u.Host + u.Path
			wantBase := "https://accounts.google.com/o/oauth2/v2/auth"
			if base != wantBase {
				t.Fatalf("base URL = %q, want %q", base, wantBase)
			}

			q := u.Query()
			for k, v := range tt.wantParam {
				if got := q.Get(k); got != v {
					t.Errorf("param %q = %q, want %q", k, got, v)
				}
			}
		})
	}
}

func TestGoogleAuthURL_HasPKCEParams(t *testing.T) {
	p := NewGoogleProvider("cid", "sec", "https://example.com/cb")
	rawURL := p.AuthURL("state", "nonce", "challenge")
	u, _ := url.Parse(rawURL)
	q := u.Query()

	required := []string{"code_challenge", "code_challenge_method", "nonce", "access_type", "response_type"}
	for _, param := range required {
		if !q.Has(param) {
			t.Errorf("Google AuthURL should contain %q param, but it does not", param)
		}
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}
	if q.Get("access_type") != "offline" {
		t.Errorf("access_type = %q, want offline", q.Get("access_type"))
	}
}

func TestGoogleExchange(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		body        string
		wantErr     bool
		wantToken   string
		wantRefresh string
		wantIDToken string
		wantType    string
		wantExpires int
	}{
		{
			name:        "success with all fields",
			statusCode:  http.StatusOK,
			body:        `{"access_token":"ya29.abc","refresh_token":"1//refresh","id_token":"eyJ.header.sig","token_type":"Bearer","expires_in":3600}`,
			wantToken:   "ya29.abc",
			wantRefresh: "1//refresh",
			wantIDToken: "eyJ.header.sig",
			wantType:    "Bearer",
			wantExpires: 3600,
		},
		{
			name:        "success without refresh token",
			statusCode:  http.StatusOK,
			body:        `{"access_token":"ya29.xyz","token_type":"Bearer","expires_in":3600}`,
			wantToken:   "ya29.xyz",
			wantType:    "Bearer",
			wantExpires: 3600,
		},
		{
			name:       "error status 400",
			statusCode: http.StatusBadRequest,
			body:       `{"error":"invalid_grant","error_description":"Code expired"}`,
			wantErr:    true,
		},
		{
			name:       "error status 401",
			statusCode: http.StatusUnauthorized,
			body:       `{"error":"invalid_client"}`,
			wantErr:    true,
		},
		{
			name:       "error status 500",
			statusCode: http.StatusInternalServerError,
			body:       `Internal Server Error`,
			wantErr:    true,
		},
		{
			name:       "malformed JSON with 200",
			statusCode: http.StatusOK,
			body:       `{broken json`,
			wantErr:    true,
		},
		{
			name:       "empty body with 200",
			statusCode: http.StatusOK,
			body:       ``,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			p := &GoogleProvider{
				clientID:     "gcid",
				clientSecret: "gsec",
				redirectURI:  "https://example.com/cb",
				tokenURL:     srv.URL,
			}

			tok, err := p.Exchange(context.Background(), "auth-code", "code-verifier")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tok.AccessToken != tt.wantToken {
				t.Errorf("AccessToken = %q, want %q", tok.AccessToken, tt.wantToken)
			}
			if tok.RefreshToken != tt.wantRefresh {
				t.Errorf("RefreshToken = %q, want %q", tok.RefreshToken, tt.wantRefresh)
			}
			if tok.IDToken != tt.wantIDToken {
				t.Errorf("IDToken = %q, want %q", tok.IDToken, tt.wantIDToken)
			}
			if tok.TokenType != tt.wantType {
				t.Errorf("TokenType = %q, want %q", tok.TokenType, tt.wantType)
			}
			if tok.ExpiresIn != tt.wantExpires {
				t.Errorf("ExpiresIn = %d, want %d", tok.ExpiresIn, tt.wantExpires)
			}
		})
	}
}

func TestGoogleExchange_PostBody(t *testing.T) {
	var captured url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		captured = r.PostForm
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	p := &GoogleProvider{
		clientID:     "the-google-client",
		clientSecret: "the-google-secret",
		redirectURI:  "https://example.com/callback",
		tokenURL:     srv.URL,
	}

	_, err := p.Exchange(context.Background(), "the-code", "the-verifier")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	checks := map[string]string{
		"client_id":     "the-google-client",
		"client_secret": "the-google-secret",
		"code":          "the-code",
		"code_verifier": "the-verifier",
		"grant_type":    "authorization_code",
		"redirect_uri":  "https://example.com/callback",
	}
	for k, v := range checks {
		if got := captured.Get(k); got != v {
			t.Errorf("POST param %q = %q, want %q", k, got, v)
		}
	}
}

func TestGoogleExchange_ConnectionRefused(t *testing.T) {
	p := &GoogleProvider{
		clientID:     "gcid",
		clientSecret: "gsec",
		redirectURI:  "https://example.com/cb",
		tokenURL:     "http://127.0.0.1:1",
	}
	_, err := p.Exchange(context.Background(), "code", "verifier")
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
	if !strings.Contains(err.Error(), "google exchange") {
		t.Errorf("error should be wrapped with 'google exchange': %v", err)
	}
}

func TestGoogleExchange_ErrorStatusIncludesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()

	p := &GoogleProvider{clientID: "gcid", clientSecret: "gsec", redirectURI: "https://example.com/cb", tokenURL: srv.URL}
	_, err := p.Exchange(context.Background(), "code", "verifier")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error should contain status code 400: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("error should contain response body: %v", err)
	}
}

func TestGoogleUserInfo(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		body         string
		wantErr      bool
		wantID       string
		wantEmail    string
		wantVerified bool
		wantName     string
		wantPicture  string
	}{
		{
			name:         "full user profile verified",
			statusCode:   http.StatusOK,
			body:         `{"id":"123456","email":"user@gmail.com","verified_email":true,"name":"Test User","picture":"https://lh3.example.com/photo.jpg"}`,
			wantID:       "123456",
			wantEmail:    "user@gmail.com",
			wantVerified: true,
			wantName:     "Test User",
			wantPicture:  "https://lh3.example.com/photo.jpg",
		},
		{
			name:         "unverified email",
			statusCode:   http.StatusOK,
			body:         `{"id":"789","email":"unverified@example.com","verified_email":false,"name":"Unverified","picture":""}`,
			wantID:       "789",
			wantEmail:    "unverified@example.com",
			wantVerified: false,
			wantName:     "Unverified",
		},
		{
			name:       "minimal response",
			statusCode: http.StatusOK,
			body:       `{"id":"100"}`,
			wantID:     "100",
		},
		{
			name:       "malformed JSON",
			statusCode: http.StatusOK,
			body:       `{not-valid-json}`,
			wantErr:    true,
		},
		{
			name:       "empty body",
			statusCode: http.StatusOK,
			body:       ``,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET, got %s", r.Method)
				}
				if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
					t.Error("missing Bearer token in Authorization header")
				}
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			p := &GoogleProvider{
				clientID:    "gcid",
				userInfoURL: srv.URL,
			}

			info, err := p.UserInfo(context.Background(), "test-token")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if info.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", info.ID, tt.wantID)
			}
			if info.Email != tt.wantEmail {
				t.Errorf("Email = %q, want %q", info.Email, tt.wantEmail)
			}
			if info.EmailVerified != tt.wantVerified {
				t.Errorf("EmailVerified = %v, want %v", info.EmailVerified, tt.wantVerified)
			}
			if info.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", info.Name, tt.wantName)
			}
			if info.AvatarURL != tt.wantPicture {
				t.Errorf("AvatarURL = %q, want %q", info.AvatarURL, tt.wantPicture)
			}
			if info.Provider != "google" {
				t.Errorf("Provider = %q, want %q", info.Provider, "google")
			}
		})
	}
}

func TestGoogleUserInfo_VerifiedEmailMapping(t *testing.T) {
	tests := []struct {
		name         string
		verified     bool
		wantVerified bool
	}{
		{
			name:         "verified_email true maps to EmailVerified true",
			verified:     true,
			wantVerified: true,
		},
		{
			name:         "verified_email false maps to EmailVerified false",
			verified:     false,
			wantVerified: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{
				"id":             "42",
				"email":          "test@example.com",
				"verified_email": tt.verified,
				"name":           "Test",
			})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write(body)
			}))
			defer srv.Close()

			p := &GoogleProvider{clientID: "gcid", userInfoURL: srv.URL}
			info, err := p.UserInfo(context.Background(), "tok")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if info.EmailVerified != tt.wantVerified {
				t.Errorf("EmailVerified = %v, want %v", info.EmailVerified, tt.wantVerified)
			}
		})
	}
}

func TestGoogleUserInfo_ConnectionRefused(t *testing.T) {
	p := &GoogleProvider{
		clientID:    "gcid",
		userInfoURL: "http://127.0.0.1:1",
	}
	_, err := p.UserInfo(context.Background(), "tok")
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
	if !strings.Contains(err.Error(), "google userinfo") {
		t.Errorf("error should be wrapped with 'google userinfo': %v", err)
	}
}

func TestGoogleUserInfo_AuthHeaderSent(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"1"}`))
	}))
	defer srv.Close()

	p := &GoogleProvider{clientID: "gcid", userInfoURL: srv.URL}
	_, err := p.UserInfo(context.Background(), "my-google-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "Bearer my-google-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer my-google-token")
	}
}

func TestGoogleUserInfo_PictureMapsToAvatarURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"1","picture":"https://lh3.example.com/photo.jpg"}`))
	}))
	defer srv.Close()

	p := &GoogleProvider{clientID: "gcid", userInfoURL: srv.URL}
	info, err := p.UserInfo(context.Background(), "tok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.AvatarURL != "https://lh3.example.com/photo.jpg" {
		t.Errorf("AvatarURL = %q, want picture URL mapped to AvatarURL", info.AvatarURL)
	}
}

func TestGoogleUserInfo_IDIsString(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"118234567890123456789","email":"user@gmail.com","verified_email":true,"name":"User"}`))
	}))
	defer srv.Close()

	p := &GoogleProvider{clientID: "gcid", userInfoURL: srv.URL}
	info, err := p.UserInfo(context.Background(), "tok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ID != "118234567890123456789" {
		t.Errorf("ID = %q, want long numeric string preserved", info.ID)
	}
}
