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

func TestFacebookNewProvider(t *testing.T) {
	p := NewFacebookProvider("cid", "csec", "https://example.com/cb")
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

func TestFacebookName(t *testing.T) {
	p := NewFacebookProvider("", "", "")
	if got := p.Name(); got != "facebook" {
		t.Fatalf("Name() = %q, want %q", got, "facebook")
	}
}

func TestFacebookImplementsProvider(t *testing.T) {
	var _ Provider = (*FacebookProvider)(nil)
}

func TestFacebookAuthURL(t *testing.T) {
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
				"scope":        "email,public_profile",
				"state":        "random-state-123",
			},
			wantBase: "https://www.facebook.com/v19.0/dialog/oauth",
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
			wantBase: "https://www.facebook.com/v19.0/dialog/oauth",
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
			wantBase: "https://www.facebook.com/v19.0/dialog/oauth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewFacebookProvider(tt.clientID, "", tt.redirectURI)
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

func TestFacebookAuthURL_PKCE(t *testing.T) {
	p := NewFacebookProvider("cid", "sec", "https://example.com/cb")
	rawURL := p.AuthURL("state", "nonce", "challenge-value")
	u, _ := url.Parse(rawURL)
	q := u.Query()

	if got := q.Get("code_challenge"); got != "challenge-value" {
		t.Errorf("code_challenge = %q, want %q", got, "challenge-value")
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want %q", got, "S256")
	}

	// These should not be present (Facebook is not OIDC)
	for _, param := range []string{"nonce", "access_type", "response_type"} {
		if q.Has(param) {
			t.Errorf("Facebook AuthURL should not contain %q param, but it does: %q", param, q.Get(param))
		}
	}
}

func TestFacebookExchange(t *testing.T) {
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
			body:       `{"access_token":"EAAabc123","token_type":"bearer"}`,
			wantToken:  "EAAabc123",
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
			body:       `{"error":{"message":"Invalid verification code","type":"OAuthException","code":100}}`,
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

			p := &FacebookProvider{
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

func TestFacebookExchange_PostBody(t *testing.T) {
	var captured url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		captured = r.PostForm
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"access_token": "tok", "token_type": "bearer"})
	}))
	defer srv.Close()

	p := &FacebookProvider{
		clientID:     "the-client-id",
		clientSecret: "the-secret",
		redirectURI:  "https://example.com/callback",
		tokenURL:     srv.URL,
	}

	_, err := p.Exchange(context.Background(), "the-code", "the-verifier")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	checks := map[string]string{
		"client_id":     "the-client-id",
		"client_secret": "the-secret",
		"code":          "the-code",
		"redirect_uri":  "https://example.com/callback",
		"code_verifier": "the-verifier",
	}
	for k, v := range checks {
		if got := captured.Get(k); got != v {
			t.Errorf("POST param %q = %q, want %q", k, got, v)
		}
	}
}

func TestFacebookExchange_ConnectionRefused(t *testing.T) {
	p := &FacebookProvider{
		clientID:     "cid",
		clientSecret: "csec",
		redirectURI:  "https://example.com/cb",
		tokenURL:     "http://127.0.0.1:1", // nothing listens here
	}
	_, err := p.Exchange(context.Background(), "code", "")
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
	if !strings.Contains(err.Error(), "facebook exchange") {
		t.Errorf("error should be wrapped with 'facebook exchange': %v", err)
	}
}

func TestFacebookUserInfo(t *testing.T) {
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
			body:       `{"id":"123456789","name":"Jane Doe","email":"jane@example.com","picture":{"data":{"url":"https://graph.facebook.com/123456789/picture"}}}`,
			wantID:     "123456789",
			wantEmail:  "jane@example.com",
			wantName:   "Jane Doe",
			wantAvatar: "https://graph.facebook.com/123456789/picture",
		},
		{
			name:       "user with no email",
			statusCode: http.StatusOK,
			body:       `{"id":"99","name":"No Mail","picture":{"data":{"url":"https://graph.facebook.com/99/picture"}}}`,
			wantID:     "99",
			wantEmail:  "",
			wantName:   "No Mail",
			wantAvatar: "https://graph.facebook.com/99/picture",
		},
		{
			name:       "minimal response",
			statusCode: http.StatusOK,
			body:       `{"id":"1","name":"Min"}`,
			wantID:     "1",
			wantName:   "Min",
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
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			p := &FacebookProvider{
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
			if info.Provider != "facebook" {
				t.Errorf("Provider = %q, want %q", info.Provider, "facebook")
			}
		})
	}
}

func TestFacebookUserInfo_PictureNested(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"42","name":"Test","picture":{"data":{"url":"https://platform-lookaside.fbsbx.com/photo.jpg"}}}`))
	}))
	defer srv.Close()

	p := &FacebookProvider{clientID: "cid", userInfoURL: srv.URL}
	info, err := p.UserInfo(context.Background(), "tok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.AvatarURL != "https://platform-lookaside.fbsbx.com/photo.jpg" {
		t.Errorf("AvatarURL = %q, want nested picture.data.url", info.AvatarURL)
	}
}

func TestFacebookUserInfo_EmailVerified(t *testing.T) {
	tests := []struct {
		name         string
		email        string
		wantVerified bool
	}{
		{
			name:         "email present means verified",
			email:        "user@example.com",
			wantVerified: true,
		},
		{
			name:         "no email means not verified",
			email:        "",
			wantVerified: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{
				"id":    "42",
				"name":  "User",
				"email": tt.email,
			})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write(body)
			}))
			defer srv.Close()

			p := &FacebookProvider{clientID: "cid", userInfoURL: srv.URL}
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

func TestFacebookUserInfo_ConnectionRefused(t *testing.T) {
	p := &FacebookProvider{
		clientID:    "cid",
		userInfoURL: "http://127.0.0.1:1",
	}
	_, err := p.UserInfo(context.Background(), "tok")
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
	if !strings.Contains(err.Error(), "facebook userinfo") {
		t.Errorf("error should be wrapped with 'facebook userinfo': %v", err)
	}
}

func TestFacebookUserInfo_AuthHeaderSent(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"1","name":"x"}`))
	}))
	defer srv.Close()

	p := &FacebookProvider{clientID: "cid", userInfoURL: srv.URL}
	_, err := p.UserInfo(context.Background(), "my-secret-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "Bearer my-secret-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer my-secret-token")
	}
}
