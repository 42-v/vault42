// Package oauth2 provides a pluggable OAuth2/OIDC provider abstraction for
// social login. Each provider implements the [Provider] interface to handle
// authorization URL generation, token exchange, and user info retrieval.
// Implementations include [GoogleProvider] (with PKCE S256), [GitHubProvider],
// and [FacebookProvider].
package oauth2

import "context"

// Provider defines the interface for OAuth2/OIDC providers. Implementations
// must handle authorization URL construction, authorization code exchange,
// and user profile retrieval from the provider's API.
type Provider interface {
	Name() string
	AuthURL(state, nonce, codeChallenge string) string
	Exchange(ctx context.Context, code, codeVerifier string) (*TokenResponse, error)
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
}
