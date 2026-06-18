package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OIDCProvider implements [Provider] for any standards-compliant OpenID Connect
// issuer (Okta, Auth0, Authentik, Keycloak, Entra, Google-OIDC, …). Endpoints are
// resolved via OIDC discovery ({issuer}/.well-known/openid-configuration), cached
// after the first fetch. Uses PKCE S256 + a nonce on the authorize request.
type OIDCProvider struct {
	name         string
	issuer       string
	clientID     string
	clientSecret string
	redirectURI  string
	scopes       string // space-delimited; defaults to "openid email profile"
	client       *http.Client

	mu         sync.RWMutex
	discovered *oidcDiscovery
	jwks       jwksCache
}

// oidcDiscovery is the subset of the discovery document vault42 consumes.
type oidcDiscovery struct {
	Issuer        string `json:"issuer"`
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`
	UserInfoEndp  string `json:"userinfo_endpoint"`
	JWKSURI       string `json:"jwks_uri"`
}

// NewOIDCProvider builds a generic OIDC provider. name is the provider key used
// in routes/state (e.g. "okta"); scopes is optional (space-delimited).
func NewOIDCProvider(name, issuer, clientID, clientSecret, redirectURI, scopes string) *OIDCProvider {
	if scopes == "" {
		scopes = "openid email profile"
	}
	return &OIDCProvider{
		name:         name,
		issuer:       strings.TrimRight(issuer, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
		scopes:       scopes,
		client:       &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *OIDCProvider) httpClient() *http.Client {
	if p.client != nil {
		return p.client
	}
	return http.DefaultClient
}

// Name returns the provider key.
func (p *OIDCProvider) Name() string { return p.name }

// discover fetches and caches the issuer's discovery document.
func (p *OIDCProvider) discover(ctx context.Context) (*oidcDiscovery, error) {
	p.mu.RLock()
	d := p.discovered
	p.mu.RUnlock()
	if d != nil {
		return d, nil
	}

	wellKnown := p.issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc discover: build request: %w", err)
	}
	resp, err := p.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc discover: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discover: status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var doc oidcDiscovery
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("oidc discover: decode: %w", err)
	}
	// The issuer in the document MUST match the configured issuer (OIDC §3.1.3.7).
	if strings.TrimRight(doc.Issuer, "/") != p.issuer {
		return nil, fmt.Errorf("oidc discover: issuer mismatch: doc=%q configured=%q", doc.Issuer, p.issuer)
	}
	if doc.AuthEndpoint == "" || doc.TokenEndpoint == "" {
		return nil, fmt.Errorf("oidc discover: missing authorization/token endpoint")
	}

	p.mu.Lock()
	p.discovered = &doc
	p.mu.Unlock()
	return &doc, nil
}

// AuthURL builds the authorize URL. Returns "" if discovery fails (the handler's
// redirect guard rejects an empty/invalid URL).
func (p *OIDCProvider) AuthURL(state, nonce, codeChallenge string) string {
	d, err := p.discover(context.Background())
	if err != nil {
		return ""
	}
	u, err := url.Parse(d.AuthEndpoint)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("client_id", p.clientID)
	q.Set("redirect_uri", p.redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", p.scopes)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String()
}

// Exchange swaps an authorization code for tokens at the discovered token endpoint.
func (p *OIDCProvider) Exchange(ctx context.Context, code, codeVerifier string) (*TokenResponse, error) {
	d, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}
	data := url.Values{
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
		"code":          {code},
		"code_verifier": {codeVerifier},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {p.redirectURI},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oidc exchange: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc exchange: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc exchange: status %d: %s", resp.StatusCode, body)
	}
	var result struct {
		AccessToken  string `json:"access_token"`  // #nosec G117 -- OAuth2 response field per RFC 6749
		RefreshToken string `json:"refresh_token"` // #nosec G117 -- OAuth2 response field per RFC 6749
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("oidc exchange: decode: %w", err)
	}
	if result.AccessToken == "" {
		return nil, fmt.Errorf("oidc exchange: empty access_token")
	}
	return &TokenResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		IDToken:      result.IDToken,
		TokenType:    result.TokenType,
		ExpiresIn:    result.ExpiresIn,
	}, nil
}

// UserInfo fetches the normalized profile from the discovered userinfo endpoint.
func (p *OIDCProvider) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	d, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}
	if d.UserInfoEndp == "" {
		return nil, fmt.Errorf("oidc userinfo: issuer exposes no userinfo endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.UserInfoEndp, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc userinfo: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := p.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc userinfo: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc userinfo: status %d", resp.StatusCode)
	}
	var info struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info); err != nil {
		return nil, fmt.Errorf("oidc userinfo: decode: %w", err)
	}
	return &UserInfo{
		ID:            info.Sub,
		Email:         info.Email,
		EmailVerified: info.EmailVerified,
		Name:          info.Name,
		AvatarURL:     info.Picture,
		Provider:      p.name,
	}, nil
}

var _ Provider = (*OIDCProvider)(nil)
