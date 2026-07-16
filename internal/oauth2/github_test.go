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

func TestGitHubNewProvider(t *testing.T) {
	p := NewGitHubProvider("cid", "csec", "https://example.com/cb")
	if p.clientID != "cid" {
		t.Fatalf("clientID = %q, want %q", p.clientID, "cid")
	}
	if p.clientSecret != "csec" {
		t.Fatalf("clientSecret = %q, want %q", p.clientSecret, "csec")
	}
	if p.redirectURI != "https://example.com/cb" {
		t.Fatalf("redirectURI = %q, want %q", p.redirectURI, "https://example.com/cb")
	}
}

func TestGitHubName(t *testing.T) {
	p := NewGitHubProvider("", "", "")
	if got := p.Name(); got != "github" {
		t.Fatalf("Name() = %q, want %q", got, "github")
	}
}

func TestGitHubImplementsProvider(t *testing.T) {
	var _ Provider = (*GitHubProvider)(nil)
}

func TestGitHubAuthURL(t *testing.T) {
	tests := []struct {
		name          string
		clientID      string
		redirectURI   string
		state         string
		nonce         string
		codeChallenge string
		wantParam     map[string]string
		wantBase      string
	}{
		{
			name:        "contains all required params",
			clientID:    "my-client",
			redirectURI: "https://app.example.com/callback",
			state:       "random-state-123",
			wantParam: map[string]string{
				"client_id":    "my-client",
				"redirect_uri": "https://app.example.com/callback",
				"scope":        "user:email read:user",
				"state":        "random-state-123",
			},
			wantBase: "https://github.com/login/oauth/authorize",
		},
		{
			name:        "url-encodes special characters",
			clientID:    "id with spaces",
			redirectURI: "https://example.com/cb?foo=bar",
			state:       "state&with=special",
			wantParam: map[string]string{
				"client_id":    "id with spaces",
				"redirect_uri": "https://example.com/cb?foo=bar",
				"state":        "state&with=special",
			},
			wantBase: "https://github.com/login/oauth/authorize",
		},
		{
			name:          "includes PKCE, ignores nonce",
			clientID:      "cid",
			redirectURI:   "https://example.com/cb",
			state:         "s",
			nonce:         "should-be-ignored",
			codeChallenge: "my-challenge",
			wantParam: map[string]string{
				"client_id":             "cid",
				"state":                 "s",
				"code_challenge":        "my-challenge",
				"code_challenge_method": "S256",
			},
			wantBase: "https://github.com/login/oauth/authorize",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewGitHubProvider(tt.clientID, "", tt.redirectURI)
			rawURL := p.AuthURL(tt.state, tt.nonce, tt.codeChallenge)

			u, err := url.Parse(rawURL)
			if err != nil {
				t.Fatalf("AuthURL returned invalid URL: %v", err)
			}

			base := u.Scheme + "://" + u.Host + u.Path
			if base != tt.wantBase {
				t.Fatalf("base URL = %q, want %q", base, tt.wantBase)
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

func TestGitHubAuthURL_PKCE(t *testing.T) {
	p := NewGitHubProvider("cid", "sec", "https://example.com/cb")
	rawURL := p.AuthURL("state", "nonce", "challenge-value")
	u, _ := url.Parse(rawURL)
	q := u.Query()

	// GitHub supports PKCE S256 since July 2025
	if got := q.Get("code_challenge"); got != "challenge-value" {
		t.Errorf("code_challenge = %q, want %q", got, "challenge-value")
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want %q", got, "S256")
	}

	// These should still not be present (GitHub is not OIDC)
	for _, param := range []string{"nonce", "access_type", "response_type"} {
		if q.Has(param) {
			t.Errorf("GitHub AuthURL should not contain %q param, but it does: %q", param, q.Get(param))
		}
	}
}

func TestGitHubExchange(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantErr    bool
		wantToken  string
		wantType   string
	}{
		{
			name:       "success",
			statusCode: http.StatusOK,
			body:       `{"access_token":"gho_abc123","token_type":"bearer","scope":"user:email read:user"}`,
			wantToken:  "gho_abc123",
			wantType:   "bearer",
		},
		{
			name:       "success with minimal fields",
			statusCode: http.StatusOK,
			body:       `{"access_token":"gho_min","token_type":"bearer"}`,
			wantToken:  "gho_min",
			wantType:   "bearer",
		},
		{
			name:       "empty access token rejected",
			statusCode: http.StatusOK,
			body:       `{"access_token":"","token_type":"bearer"}`,
			wantErr:    true,
		},
		{
			name:       "malformed JSON body",
			statusCode: http.StatusOK,
			body:       `{not json}`,
			wantErr:    true,
		},
		{
			name:       "empty body",
			statusCode: http.StatusOK,
			body:       ``,
			wantErr:    true,
		},
		{
			name:       "HTML error page",
			statusCode: http.StatusInternalServerError,
			body:       `<html>Server Error</html>`,
			wantErr:    true,
		},
		{
			name:       "error status with valid JSON returns error",
			statusCode: http.StatusBadRequest,
			body:       `{"access_token":"","token_type":"","error":"bad_verification_code"}`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
					t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", ct)
				}
				if accept := r.Header.Get("Accept"); accept != "application/json" {
					t.Errorf("Accept = %q, want application/json", accept)
				}
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			p := &GitHubProvider{
				clientID:     "cid",
				clientSecret: "csec",
				redirectURI:  "https://example.com/cb",
				tokenURL:     srv.URL,
			}

			tok, err := p.Exchange(context.Background(), "auth-code", "")
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
			if tok.TokenType != tt.wantType {
				t.Errorf("TokenType = %q, want %q", tok.TokenType, tt.wantType)
			}
		})
	}
}

func TestGitHubExchange_PostBody(t *testing.T) {
	var captured url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		captured = r.PostForm
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"access_token": "tok", "token_type": "bearer"})
	}))
	defer srv.Close()

	p := &GitHubProvider{
		clientID:     "the-client-id",
		clientSecret: "the-secret",
		redirectURI:  "https://example.com/callback",
		tokenURL:     srv.URL,
	}

	_, err := p.Exchange(context.Background(), "the-code", "ignored-verifier")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	checks := map[string]string{
		"client_id":     "the-client-id",
		"client_secret": "the-secret",
		"code":          "the-code",
		"redirect_uri":  "https://example.com/callback",
	}
	for k, v := range checks {
		if got := captured.Get(k); got != v {
			t.Errorf("POST param %q = %q, want %q", k, got, v)
		}
	}
	// GitHub supports PKCE — code_verifier must be sent
	if got := captured.Get("code_verifier"); got != "ignored-verifier" {
		t.Errorf("code_verifier = %q, want %q", got, "ignored-verifier")
	}
}

func TestGitHubExchange_ConnectionRefused(t *testing.T) {
	p := &GitHubProvider{
		clientID:     "cid",
		clientSecret: "csec",
		redirectURI:  "https://example.com/cb",
		tokenURL:     "http://127.0.0.1:1", // nothing listens here
	}
	_, err := p.Exchange(context.Background(), "code", "")
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
	if !strings.Contains(err.Error(), "github exchange") {
		t.Errorf("error should be wrapped with 'github exchange': %v", err)
	}
}

func TestGitHubExchange_BuildRequestError(t *testing.T) {
	p := &GitHubProvider{
		clientID:     "cid",
		clientSecret: "csec",
		redirectURI:  "https://example.com/cb",
		tokenURL:     ":",
	}
	_, err := p.Exchange(context.Background(), "code", "verifier")
	if err == nil {
		t.Fatal("expected build request error, got nil")
	}
	want := `github token exchange: build request: parse ":": missing protocol scheme`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestGitHubExchange_RefreshAndIDTokenNotSet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access_token":"tok","token_type":"bearer","scope":"user:email"}`))
	}))
	defer srv.Close()

	p := &GitHubProvider{clientID: "cid", clientSecret: "csec", redirectURI: "https://example.com/cb", tokenURL: srv.URL}
	tok, err := p.Exchange(context.Background(), "code", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.RefreshToken != "" {
		t.Errorf("GitHub should not return RefreshToken, got %q", tok.RefreshToken)
	}
	if tok.IDToken != "" {
		t.Errorf("GitHub should not return IDToken, got %q", tok.IDToken)
	}
	if tok.ExpiresIn != 0 {
		t.Errorf("GitHub should not return ExpiresIn, got %d", tok.ExpiresIn)
	}
}

func TestGitHubUserInfo(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantErr    bool
		wantID     string
		wantEmail  string
		wantName   string
		wantAvatar string
	}{
		{
			name:       "full user profile",
			statusCode: http.StatusOK,
			body:       `{"id":12345,"login":"octocat","name":"The Octocat","email":"octocat@github.com","avatar_url":"https://avatars.example.com/u/12345"}`,
			wantID:     "12345",
			wantEmail:  "octocat@github.com",
			wantName:   "The Octocat",
			wantAvatar: "https://avatars.example.com/u/12345",
		},
		{
			name:       "user with no email",
			statusCode: http.StatusOK,
			body:       `{"id":99,"login":"nomail","name":"No Mail","email":"","avatar_url":"https://avatars.example.com/u/99"}`,
			wantID:     "99",
			wantEmail:  "",
			wantName:   "No Mail",
			wantAvatar: "https://avatars.example.com/u/99",
		},
		{
			name:       "minimal response",
			statusCode: http.StatusOK,
			body:       `{"id":1,"login":"min"}`,
			wantID:     "1",
		},
		{
			name:       "malformed JSON",
			statusCode: http.StatusOK,
			body:       `not-json`,
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
				if accept := r.Header.Get("Accept"); accept != "application/vnd.github.v3+json" {
					t.Errorf("Accept = %q, want application/vnd.github.v3+json", accept)
				}
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			p := &GitHubProvider{
				clientID:    "cid",
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
			if info.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", info.Name, tt.wantName)
			}
			if info.AvatarURL != tt.wantAvatar {
				t.Errorf("AvatarURL = %q, want %q", info.AvatarURL, tt.wantAvatar)
			}
			if info.Provider != "github" {
				t.Errorf("Provider = %q, want %q", info.Provider, "github")
			}
		})
	}
}

func TestGitHubUserInfo_EmailVerified(t *testing.T) {
	tests := []struct {
		name         string
		email        string
		emails       []map[string]any // /user/emails response
		wantVerified bool
		wantEmail    string
	}{
		{
			name:  "verified primary email",
			email: "user@example.com",
			emails: []map[string]any{
				{"email": "user@example.com", "primary": true, "verified": true},
			},
			wantVerified: true,
			wantEmail:    "user@example.com",
		},
		{
			name:  "unverified primary email",
			email: "user@example.com",
			emails: []map[string]any{
				{"email": "user@example.com", "primary": true, "verified": false},
			},
			wantVerified: false,
			wantEmail:    "user@example.com",
		},
		{
			name:         "empty email and no emails endpoint",
			email:        "",
			emails:       nil,
			wantVerified: false,
			wantEmail:    "",
		},
		{
			name:  "multiple emails, primary is verified",
			email: "other@example.com",
			emails: []map[string]any{
				{"email": "other@example.com", "primary": false, "verified": true},
				{"email": "primary@example.com", "primary": true, "verified": true},
			},
			wantVerified: true,
			wantEmail:    "primary@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userBody, _ := json.Marshal(map[string]any{
				"id":    42,
				"login": "user",
				"name":  "User",
				"email": tt.email,
			})
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write(userBody)
			})
			if tt.emails != nil {
				emailsBody, _ := json.Marshal(tt.emails)
				mux.HandleFunc("/emails", func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write(emailsBody)
				})
			}
			srv := httptest.NewServer(mux)
			defer srv.Close()

			p := &GitHubProvider{clientID: "cid", userInfoURL: srv.URL}
			info, err := p.UserInfo(context.Background(), "tok")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if info.EmailVerified != tt.wantVerified {
				t.Errorf("EmailVerified = %v, want %v", info.EmailVerified, tt.wantVerified)
			}
			if info.Email != tt.wantEmail {
				t.Errorf("Email = %q, want %q", info.Email, tt.wantEmail)
			}
		})
	}
}

func TestGitHubUserInfo_BuildRequestError(t *testing.T) {
	p := &GitHubProvider{clientID: "cid", userInfoURL: ":"}
	_, err := p.UserInfo(context.Background(), "tok")
	if err == nil {
		t.Fatal("expected build request error, got nil")
	}
	want := `github userinfo: build request: parse ":": missing protocol scheme`
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestGitHubUserInfo_ConnectionRefused(t *testing.T) {
	p := &GitHubProvider{
		clientID:    "cid",
		userInfoURL: "http://127.0.0.1:1",
	}
	_, err := p.UserInfo(context.Background(), "tok")
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
	if !strings.Contains(err.Error(), "github userinfo") {
		t.Errorf("error should be wrapped with 'github userinfo': %v", err)
	}
}

func TestGitHubUserInfo_AuthHeaderSent(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":1,"login":"x"}`))
	}))
	defer srv.Close()

	p := &GitHubProvider{clientID: "cid", userInfoURL: srv.URL}
	_, err := p.UserInfo(context.Background(), "my-secret-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "Bearer my-secret-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer my-secret-token")
	}
}

func TestGitHubUserInfo_LargeID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":2147483647,"login":"maxint","name":"Max Int","email":"max@example.com"}`))
	}))
	defer srv.Close()

	p := &GitHubProvider{clientID: "cid", userInfoURL: srv.URL}
	info, err := p.UserInfo(context.Background(), "tok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ID != "2147483647" {
		t.Errorf("ID = %q, want %q", info.ID, "2147483647")
	}
}

func TestGitHubUserInfo_ZeroID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":0,"login":"zero"}`))
	}))
	defer srv.Close()

	p := &GitHubProvider{clientID: "cid", userInfoURL: srv.URL}
	info, err := p.UserInfo(context.Background(), "tok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ID != "0" {
		t.Errorf("ID = %q, want %q", info.ID, "0")
	}
}
