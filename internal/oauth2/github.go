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

// GitHubProvider implements the [Provider] interface for GitHub OAuth2.
// Uses PKCE S256 code challenge for authorization code exchange security.
type GitHubProvider struct {
	clientID     string
	clientSecret string
	redirectURI  string
	tokenURL     string // override for testing; empty = default
	userInfoURL  string // override for testing; empty = default
	client       *http.Client
}

// httpClient returns the configured HTTP client, falling back to http.DefaultClient.
func (g *GitHubProvider) httpClient() *http.Client {
	if g.client != nil {
		return g.client
	}
	return http.DefaultClient
}

// NewGitHubProvider creates a GitHub OAuth2 provider with the given credentials
// and redirect URI.
func NewGitHubProvider(clientID, clientSecret, redirectURI string) *GitHubProvider {
	return &GitHubProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
		client:       &http.Client{Timeout: 10 * time.Second},
	}
}

// Name returns "github".
func (g *GitHubProvider) Name() string { return "github" }

// AuthURL returns the GitHub OAuth2 authorization URL with PKCE S256 code challenge.
// The nonce parameter is ignored as GitHub does not support OIDC.
func (g *GitHubProvider) AuthURL(state, nonce, codeChallenge string) string {
	u, _ := url.Parse("https://github.com/login/oauth/authorize")
	q := u.Query()
	q.Set("client_id", g.clientID)
	q.Set("redirect_uri", g.redirectURI)
	q.Set("scope", "user:email read:user")
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String()
}

// Exchange trades an authorization code for an access token via GitHub's token endpoint,
// using the PKCE code verifier for validation.
func (g *GitHubProvider) Exchange(ctx context.Context, code, codeVerifier string) (*TokenResponse, error) {
	data := url.Values{
		"client_id":     {g.clientID},
		"client_secret": {g.clientSecret},
		"code":          {code},
		"code_verifier": {codeVerifier},
		"redirect_uri":  {g.redirectURI},
	}

	tokenURL := "https://github.com/login/oauth/access_token" // #nosec G101 -- well-known OAuth endpoint URL, not a credential
	if g.tokenURL != "" {
		tokenURL = g.tokenURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("github token exchange: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := g.httpClient().Do(req) // #nosec G107 -- tokenURL defaults to hardcoded GitHub OAuth constant; only overridden in tests
	if err != nil {
		return nil, fmt.Errorf("github exchange: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxProviderResponse))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github exchange: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		AccessToken string `json:"access_token"` // #nosec G117 -- OAuth2 response field name per RFC 6749
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("github exchange: decode: %w", err)
	}

	if result.AccessToken == "" {
		return nil, fmt.Errorf("github exchange: empty access token in response")
	}

	return &TokenResponse{
		AccessToken: result.AccessToken,
		TokenType:   result.TokenType,
	}, nil
}

// UserInfo fetches the authenticated user's profile from GitHub's /user API
// and their verified primary email from /user/emails.
func (g *GitHubProvider) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	userInfoURL := "https://api.github.com/user"
	if g.userInfoURL != "" {
		userInfoURL = g.userInfoURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("github userinfo: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := g.httpClient().Do(req) // #nosec G107 -- userInfoURL defaults to hardcoded GitHub API constant; only overridden in tests
	if err != nil {
		return nil, fmt.Errorf("github userinfo: %w", err)
	}
	defer resp.Body.Close()
	// The exchange above refuses a non-200 and this call did not, so a response
	// GitHub declined to give was decoded as a profile anyway. Its error bodies
	// are JSON objects, so the decode succeeds, every field lands on its zero
	// value, and the caller receives a profile with a nil error.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github userinfo: status %d", resp.StatusCode)
	}

	var info struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxProviderResponse)).Decode(&info); err != nil {
		return nil, fmt.Errorf("github userinfo: decode: %w", err)
	}
	// id is an int here, so a body that carries none decodes to 0 and formats to
	// the subject "0". That is not the empty string internal/handler/oauth.go
	// refuses, so it passes the subject guard and resolves against the one row
	// UNIQUE(provider, provider_user_id) allows for github/0: whoever reaches it
	// first claims that row, and every later unnamed response is answered with
	// their session. GitHub numbers accounts from 1, so 0 never names anybody and
	// no real login is refused by this.
	if info.ID == 0 {
		return nil, fmt.Errorf("github userinfo: response names no user")
	}

	// Fetch verified primary email from /user/emails since /user doesn't
	// distinguish verified vs unverified email addresses.
	emailVerified := false
	primaryEmail := info.Email
	emailsURL := "https://api.github.com/user/emails"
	if g.userInfoURL != "" {
		emailsURL = g.userInfoURL + "/emails" // test override
	}
	emailReq, err := http.NewRequestWithContext(ctx, http.MethodGet, emailsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("github userinfo: build emails request: %w", err)
	}
	emailReq.Header.Set("Authorization", "Bearer "+accessToken)
	emailReq.Header.Set("Accept", "application/vnd.github.v3+json")

	emailResp, err := g.httpClient().Do(emailReq) // #nosec G107 -- emailsURL defaults to hardcoded GitHub API constant; only overridden in tests
	if err == nil {
		defer emailResp.Body.Close()
		var emails []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if err := json.NewDecoder(io.LimitReader(emailResp.Body, maxProviderResponse)).Decode(&emails); err == nil {
			for _, e := range emails {
				if e.Primary && e.Verified {
					primaryEmail = e.Email
					emailVerified = true
					break
				}
			}
		}
	}

	return &UserInfo{
		ID:            fmt.Sprintf("%d", info.ID),
		Email:         primaryEmail,
		EmailVerified: emailVerified,
		Name:          info.Name,
		AvatarURL:     info.AvatarURL,
		Provider:      "github",
	}, nil
}
