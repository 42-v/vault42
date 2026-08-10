package jwt

import "errors"

// The sentinel errors every parse and verification path wraps. Callers branch
// on them with errors.Is, so each one names a distinct condition and the
// boundaries below are part of the package's contract rather than an accident
// of where a return statement sits.
//
// The distinction that matters most is unverifiable versus signature-invalid.
// Unverifiable means the token could not be checked at all: no key was
// available, or the algorithm is one this package does not implement. Invalid
// means the check ran and the signature did not match the key. Both deny the
// request, but only the first indicates a key-management problem on this side,
// which is why internal/middleware/auth.go maps an unknown kid onto
// ErrTokenSignatureInvalid: an attacker must not be able to tell a
// misconfigured verifier apart from a forged token by the response it gets.
var (
	// ErrTokenMalformed is returned when the token cannot be decomposed into a
	// JWT at all: the wrong number of dot-separated segments, base64url that
	// will not decode, or a header or claims segment that is not JSON. Nothing
	// cryptographic has been attempted when this is returned.
	ErrTokenMalformed = errors.New("token is malformed")

	// ErrTokenUnverifiable is returned when the token is well-formed but could
	// not be checked: the alg header is missing, no Keyfunc was supplied, the
	// Keyfunc failed to produce a key (an unknown kid, typically), or the alg
	// is not one of the implemented signature algorithms. This is the
	// fail-closed branch that rejects "none" and every symmetric algorithm.
	ErrTokenUnverifiable = errors.New("token is unverifiable")

	// ErrTokenSignatureInvalid is returned when verification ran against a real
	// key and the signature did not match, and when the alg is outside a
	// caller-supplied allowlist. Callers that want to conceal key-management
	// state from an attacker collapse ErrTokenUnverifiable into this one before
	// answering the request.
	ErrTokenSignatureInvalid = errors.New("token signature is invalid")

	// ErrTokenExpired is returned when the exp claim is at or before the
	// current time. The comparison has no leeway, so a token whose exp equals
	// now is already expired.
	ErrTokenExpired = errors.New("token is expired")

	// ErrTokenNotValidYet is returned when the nbf claim is in the future. As
	// with exp, no clock skew is tolerated.
	ErrTokenNotValidYet = errors.New("token is not valid yet")

	// ErrTokenUsedBeforeIssued is returned when the iat claim is in the future.
	// It is only ever produced when the caller opts in with WithIssuedAt.
	ErrTokenUsedBeforeIssued = errors.New("token used before issued")

	// ErrTokenInvalidAudience is returned when the aud claim does not contain
	// the audience the caller required with WithAudience. A token minted for a
	// different service is rejected here, not silently accepted.
	ErrTokenInvalidAudience = errors.New("token has invalid audience")

	// ErrTokenInvalidIssuer is returned when the iss claim does not equal the
	// issuer the caller required with WithIssuer.
	ErrTokenInvalidIssuer = errors.New("token has invalid issuer")

	// ErrTokenRequiredClaimMissing is returned when a claim the caller demanded
	// is absent. Today only WithExpirationRequired demands one, which turns a
	// token with no exp from "never expires" into a rejection.
	ErrTokenRequiredClaimMissing = errors.New("token is missing required claim")

	// ErrInvalidKeyType is returned when the key the Keyfunc produced does not
	// match the token's algorithm, for instance an ECDSA key for an RS256
	// token, or when a nil key reaches a sign or verify call. It signals a
	// caller or configuration bug rather than a hostile token.
	ErrInvalidKeyType = errors.New("key is of invalid type")
)
