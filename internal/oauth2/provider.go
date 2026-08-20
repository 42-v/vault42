// Package oauth2 provides a pluggable OAuth2/OIDC provider abstraction for
// social login. Each provider implements the [Provider] interface to handle
// authorization URL generation, token exchange, and user info retrieval.
// Implementations include [GoogleProvider] (with PKCE S256), [GitHubProvider],
// and [FacebookProvider].
package oauth2

import (
	"context"
	"time"
)

// maxProviderResponse caps every response body this package reads.
//
// The provider is the one peer in the login flow that is neither vault42 nor the
// browser, and the flow that talks to it is unauthenticated, so the size of the
// allocation must not be the provider's to choose. One megabyte is far past any
// real token, profile or discovery document and far short of a response that
// costs the auth service anything to drop.
const maxProviderResponse = 1 << 20

// Provider defines the interface for OAuth2/OIDC providers. Implementations
// must handle authorization URL construction, authorization code exchange,
// and user profile retrieval from the provider's API.
type Provider interface {
	// Name returns the provider key used in routes, the signed state parameter
	// and the social-account rows, for example "google" or "github".
	Name() string

	// AuthURL builds the provider's authorization endpoint URL. state is the
	// HMAC-signed CSRF/session binding, codeChallenge is the PKCE S256
	// challenge, and nonce binds the resulting OIDC ID token to this login
	// attempt. Non-OIDC providers ignore nonce, but callers must still pass a
	// unique value: [OIDCProvider.VerifyIDToken] rejects a login whose nonce is
	// empty. An implementation returns "" when it cannot build a URL, which the
	// handler's redirect guard treats as a failure.
	AuthURL(state, nonce, codeChallenge string) string

	// Exchange swaps an authorization code for tokens, presenting codeVerifier
	// as the PKCE proof. It never returns a partially populated TokenResponse:
	// a non-nil result means the provider accepted the code.
	Exchange(ctx context.Context, code, codeVerifier string) (*TokenResponse, error)

	// UserInfo retrieves the profile behind accessToken and normalizes it to
	// [UserInfo]. For OIDC issuers this is the fallback path; a verified ID
	// token is preferred because it is signed and nonce-bound, while a userinfo
	// response is only as trustworthy as the transport.
	UserInfo(ctx context.Context, accessToken string) (*UserInfo, error)
}

// TokenResponse holds the OAuth2 token exchange response from a provider.
type TokenResponse struct {
	// AccessToken is the provider-issued access token (RFC 6749).
	AccessToken string // #nosec G117 -- OAuth2 response field per RFC 6749
	// RefreshToken is the provider-issued refresh token, if granted (RFC 6749).
	RefreshToken string // #nosec G117 -- OAuth2 response field per RFC 6749
	// IDToken is the OIDC ID token, present only for OIDC providers (e.g., Google).
	IDToken string
	// TokenType is the token type, typically "Bearer".
	TokenType string
	// ExpiresIn is the access token lifetime in seconds.
	ExpiresIn int
}

// UserInfo holds normalized user profile information retrieved from a provider.
// Fields are populated to a common schema regardless of the upstream provider.
type UserInfo struct {
	// ID is the user's unique identifier at the provider.
	ID string
	// Email is the user's primary email address.
	Email string
	// EmailVerified indicates whether the provider has confirmed the email address.
	EmailVerified bool
	// Name is the user's display name.
	Name string
	// AvatarURL is a URL to the user's profile picture.
	AvatarURL string
	// Provider is the name of the OAuth2 provider (e.g., "google", "github").
	Provider string
	// AuthTime is the instant the provider states it authenticated the user,
	// from the OIDC auth_time claim. It is the zero time whenever the provider
	// stated none: the claim is OPTIONAL in OIDC Core §2 unless the request sent
	// max_age or asked for auth_time as an essential claim, and no non-OIDC
	// provider has an equivalent, so most logins leave it zero.
	//
	// A caller must read the zero value as "not stated" and substitute an
	// instant it can vouch for. Passing it on as a timestamp dates the session
	// to the Unix epoch, which is the reading internal/service/token.go already
	// refuses to emit.
	AuthTime time.Time
}
