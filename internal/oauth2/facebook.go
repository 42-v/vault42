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

// FacebookProvider implements the [Provider] interface for Facebook OAuth2.
// Uses PKCE S256 code challenge for authorization code exchange security.
type FacebookProvider struct {
	clientID     string
	clientSecret string
	redirectURI  string
	tokenURL     string // override for testing; empty = default
	userInfoURL  string // override for testing; empty = default
	client       *http.Client
}

// httpClient returns the configured HTTP client, falling back to http.DefaultClient.
func (f *FacebookProvider) httpClient() *http.Client {
	if f.client != nil {
		return f.client
	}
	return http.DefaultClient
}

// NewFacebookProvider creates a Facebook OAuth2 provider with the given credentials
// and redirect URI.
func NewFacebookProvider(clientID, clientSecret, redirectURI string) *FacebookProvider {
	return &FacebookProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
		client:       &http.Client{Timeout: 10 * time.Second},
	}
}

// Name returns "facebook".
func (f *FacebookProvider) Name() string { return "facebook" }

// AuthURL returns the Facebook OAuth2 authorization URL with PKCE S256 code challenge.
// The nonce parameter is ignored as Facebook does not support OIDC.
func (f *FacebookProvider) AuthURL(state, nonce, codeChallenge string) string {
	u, _ := url.Parse("https://www.facebook.com/v19.0/dialog/oauth")
	q := u.Query()
	q.Set("client_id", f.clientID)
	q.Set("redirect_uri", f.redirectURI)
	q.Set("scope", "email,public_profile")
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String()
}

// Exchange trades an authorization code for an access token via Facebook's token endpoint,
// using the PKCE code verifier for validation.
func (f *FacebookProvider) Exchange(ctx context.Context, code, codeVerifier string) (*TokenResponse, error) {
	data := url.Values{
		"client_id":     {f.clientID},
		"client_secret": {f.clientSecret},
		"code":          {code},
		"code_verifier": {codeVerifier},
		"redirect_uri":  {f.redirectURI},
	}

	tokenURL := "https://graph.facebook.com/v19.0/oauth/access_token" // #nosec G101 -- well-known OAuth endpoint URL, not a credential
	if f.tokenURL != "" {
		tokenURL = f.tokenURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("facebook token exchange: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := f.httpClient().Do(req) // #nosec G107 -- tokenURL defaults to hardcoded Facebook OAuth constant; only overridden in tests
	if err != nil {
		return nil, fmt.Errorf("facebook exchange: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("facebook exchange: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		AccessToken string `json:"access_token"` // #nosec G117 -- OAuth2 response field name per RFC 6749
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("facebook exchange: decode: %w", err)
	}

	if result.AccessToken == "" {
		return nil, fmt.Errorf("facebook exchange: empty access token in response")
	}

	return &TokenResponse{
		AccessToken: result.AccessToken,
		TokenType:   result.TokenType,
	}, nil
}

// UserInfo fetches the authenticated user's profile from Facebook's Graph API.
func (f *FacebookProvider) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	userInfoURL := "https://graph.facebook.com/me?fields=id,name,email,picture.type(large)"
	if f.userInfoURL != "" {
		userInfoURL = f.userInfoURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("facebook userinfo: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := f.httpClient().Do(req) // #nosec G107 -- userInfoURL defaults to hardcoded Facebook Graph API constant; only overridden in tests
	if err != nil {
		return nil, fmt.Errorf("facebook userinfo: %w", err)
	}
	defer resp.Body.Close()

	var info struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Picture struct {
			Data struct {
				URL string `json:"url"`
			} `json:"data"`
		} `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("facebook userinfo: decode: %w", err)
	}

	return &UserInfo{
		ID:    info.ID,
		Email: info.Email,
		// Facebook publishes no per-address verification signal. The Graph user
		// node documents `email` as the address listed on the profile, which is a
		// string the account holder set, and the only `verified` field it ever had
		// is deprecated and answers a different question: whether the account was
		// confirmed by mobile or credit card, not whether anyone proved they own
		// this address. There is nothing here to check, so nothing is claimed.
		//
		// This used to be `info.Email != ""`, which made a non-empty string the
		// whole proof of ownership. Whoever could make Graph return a victim's
		// address satisfied the both-sides-verified rule in
		// internal/handler/oauth.go, had (facebook, their own provider id) linked
		// to the victim's user, and received the victim's tokens on every later
		// Facebook login. Google, GitHub and the OIDC providers each read an
		// explicit verification answer instead; Facebook has none to read.
		//
		// Facebook logins still work: they sign in, create accounts, and link by
		// (provider, provider_user_id). The single thing they cannot do is claim
		// an existing local account by naming its address.
		EmailVerified: false,
		Name:          info.Name,
		AvatarURL:     info.Picture.Data.URL,
		Provider:      "facebook",
	}, nil
}
