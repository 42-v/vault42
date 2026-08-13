package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GoogleProvider implements the [Provider] interface for Google OAuth2/OIDC.
// It uses PKCE S256 code challenge and requests offline access for refresh tokens.
type GoogleProvider struct {
	clientID     string
	clientSecret string
	redirectURI  string
	tokenURL     string // override for testing; empty = default
	userInfoURL  string // override for testing; empty = default
	client       *http.Client
}

// httpClient returns the configured HTTP client, falling back to http.DefaultClient.
func (g *GoogleProvider) httpClient() *http.Client {
	if g.client != nil {
		return g.client
	}
	return http.DefaultClient
}

// NewGoogleProvider creates a Google OAuth2/OIDC provider with the given
// credentials and redirect URI.
func NewGoogleProvider(clientID, clientSecret, redirectURI string) *GoogleProvider {
	return &GoogleProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
		client:       &http.Client{Timeout: 10 * time.Second},
	}
}

// Name returns "google".
func (g *GoogleProvider) Name() string { return "google" }

// AuthURL returns the Google OAuth2 authorization URL with PKCE S256 code
// challenge, nonce for OIDC, and offline access type for refresh tokens.
func (g *GoogleProvider) AuthURL(state, nonce, codeChallenge string) string {
	u, _ := url.Parse("https://accounts.google.com/o/oauth2/v2/auth")
	q := u.Query()
	q.Set("client_id", g.clientID)
	q.Set("redirect_uri", g.redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("access_type", "offline")
	u.RawQuery = q.Encode()
	return u.String()
}

// Exchange trades an authorization code for tokens via Google's token endpoint,
// using the PKCE code verifier for validation.
func (g *GoogleProvider) Exchange(ctx context.Context, code, codeVerifier string) (*TokenResponse, error) {
	data := url.Values{
		"client_id":     {g.clientID},
		"client_secret": {g.clientSecret},
		"code":          {code},
		"code_verifier": {codeVerifier},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {g.redirectURI},
	}

	tokenURL := "https://oauth2.googleapis.com/token" // #nosec G101 -- well-known OAuth endpoint URL, not a credential
	if g.tokenURL != "" {
		tokenURL = g.tokenURL
	}
	resp, err := g.httpClient().Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode())) // #nosec G107 -- tokenURL defaults to hardcoded Google OAuth constant; only overridden in tests
	if err != nil {
		return nil, fmt.Errorf("google exchange: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxProviderResponse))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google exchange: status %d: %s", resp.StatusCode, body)
	}

	var result struct {
		AccessToken  string `json:"access_token"`  // #nosec G117 -- OAuth2 response field name per RFC 6749
		RefreshToken string `json:"refresh_token"` // #nosec G117 -- OAuth2 response field name per RFC 6749
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("google exchange: decode: %w", err)
	}

	if result.AccessToken == "" {
		return nil, fmt.Errorf("google exchange: empty access_token in response")
	}

	return &TokenResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		IDToken:      result.IDToken,
		TokenType:    result.TokenType,
		ExpiresIn:    result.ExpiresIn,
	}, nil
}

// UserInfo fetches the authenticated user's profile from Google's userinfo endpoint.
func (g *GoogleProvider) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	userInfoURL := "https://www.googleapis.com/oauth2/v2/userinfo"
	if g.userInfoURL != "" {
		userInfoURL = g.userInfoURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("google userinfo: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := g.httpClient().Do(req) // #nosec G107 -- userInfoURL defaults to hardcoded Google API constant; only overridden in tests
	if err != nil {
		return nil, fmt.Errorf("google userinfo: %w", err)
	}
	defer resp.Body.Close()
	// Same rule the exchange applies: a status other than 200 is not a profile.
	// Google's error bodies decode cleanly into this struct and leave every field
	// zeroed, which is a UserInfo carrying no subject and email_verified false
	// returned with a nil error.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google userinfo: status %d", resp.StatusCode)
	}

	var info struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxProviderResponse)).Decode(&info); err != nil {
		return nil, fmt.Errorf("google userinfo: decode: %w", err)
	}

	return &UserInfo{
		ID:            info.ID,
		Email:         info.Email,
		EmailVerified: info.VerifiedEmail,
		Name:          info.Name,
		AvatarURL:     info.Picture,
		Provider:      "google",
	}, nil
}
