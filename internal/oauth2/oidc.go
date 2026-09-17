package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/42-v/vault42/internal/outbound"
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
	// guard widens the destination rule applied to the endpoints this
	// provider's discovery document names, and installs the dial-time address
	// check. A nil guard is the strict case rather than the absent one:
	// outbound.Policy's nil behavior still holds the endpoints to the issuer's
	// own domain, so the rule is in force with no wiring at all and SetGuard
	// only ever permits more.
	guard *outbound.Policy

	mu         sync.RWMutex
	discovered *oidcDiscovery
	jwks       jwksCache
}

// expectedIDTokenIssuer is the value an id_token's iss claim must equal.
//
// OIDC Core 3.1.3.7 step 2 requires an exact match against the issuer
// identifier -- as the provider publishes it, not as the operator typed it and
// not as vault42 normalized it. Those three differ by exactly one character
// often enough to matter: a provider whose identifier ends in "/" publishes
// that slash in every iss claim it mints, and p.issuer has had it trimmed by
// NewOIDCProvider.
//
// Before this, the trim made discovery pass -- discover compares both sides
// trimmed (oidc.go:185) -- and then failed every id_token, because internal/jwt compares iss
// byte for byte with no normalization. Discovery succeeding and login failing
// on every attempt reads as a provider outage, and no configuration escapes it,
// because TrimRight strips whatever the operator writes.
//
// The published value is preferred and the configured one is the fallback for
// the path where discovery has not run. Trimming stays where it is: it is the
// right normalization for *comparing* two spellings of one identifier, which is
// what discover does. It is the wrong thing to hand a verifier that must
// match exactly.
func (p *OIDCProvider) expectedIDTokenIssuer() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.discovered != nil && p.discovered.Issuer != "" {
		return p.discovered.Issuer
	}
	return p.issuer
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

// fetchableEndpoint reports whether this package will talk to a URL.
//
// https everywhere, with one exception: plaintext to the loopback interface,
// which is where a developer's own issuer and this package's tests run and where
// there is no path for anyone to sit on. The exception is deliberately narrow:
// a hostname that merely resolves to a loopback address does not qualify, since
// that resolution is not this process's to trust.
func fetchableEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return true
		}
		ip := net.ParseIP(host)
		return ip != nil && ip.IsLoopback()
	default:
		return false
	}
}

// SetGuard installs the deployment's outbound destination policy on this
// provider: the operator's additions to the set of hosts its discovery document
// may name, and the dial-time check on the addresses those hosts resolve to.
//
// It replaces the provider's client, because the dial-time half is a property
// of the transport and cannot be applied any other way. The end-to-end timeout
// is unchanged.
func (p *OIDCProvider) SetGuard(g *outbound.Policy) {
	p.guard = g
	// ClientForIssuer, not Client: a discovery-admitted endpoint that 302s to
	// another public host would otherwise bypass the domain rule. DialContext
	// only refuses private/link-local addresses, so the hop has to be judged
	// again under the issuer that CheckDerived already bound the document to.
	p.client = g.ClientForIssuer(p.issuer, providerTimeout)
}

func (p *OIDCProvider) httpClient() *http.Client {
	if p.client != nil {
		return p.client
	}
	return fallbackClient
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

	// Refused before the fetch, not after: a document collected over plaintext
	// cannot vouch for anything it says, including its own issuer claim.
	if !fetchableEndpoint(p.issuer) {
		return nil, fmt.Errorf("oidc discover: issuer %q is not https", p.issuer)
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
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxProviderResponse))
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
	// The document is the trust root for every other URL this provider uses, so
	// what it names has to be reachable securely or not at all. jwks_uri is the
	// one that decides identity: it supplies the keys every id_token signature is
	// checked against, and an issuer that advertises it over plaintext (a proxy
	// with the wrong X-Forwarded-Proto is enough) hands anyone on that path the
	// ability to serve their own key set and mint a token for any subject. The
	// token endpoint carries the client secret over the same wire.
	//
	// Scheme is one axis and destination is another. These four are the only
	// URLs vault42 fetches that came out of a response rather than out of
	// configuration or a literal, so they are also the only ones where "https"
	// leaves the question of *whose* https host unanswered. outbound.Policy
	// answers it: the issuer's own domain, a loopback destination, or a host
	// the operator named.
	for field, endpoint := range map[string]string{
		"authorization_endpoint": doc.AuthEndpoint,
		"token_endpoint":         doc.TokenEndpoint,
		"userinfo_endpoint":      doc.UserInfoEndp,
		"jwks_uri":               doc.JWKSURI,
	} {
		if endpoint == "" {
			continue
		}
		if !fetchableEndpoint(endpoint) {
			return nil, fmt.Errorf("oidc discover: %s %q is not https", field, endpoint)
		}
		if err := p.guard.CheckDerived(p.issuer, field, endpoint); err != nil {
			return nil, fmt.Errorf("oidc discover: %w", err)
		}
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
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxProviderResponse))
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxProviderResponse)).Decode(&info); err != nil {
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
