package jwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"
)

// ParseOption configures parse-time behavior.
type ParseOption func(*validationConfig)

// WithValidMethods narrows the set of accepted "alg" header values to methods.
//
// It only ever narrows. The hard allowlist is the signature switch in
// [ParseWithClaims], which implements RS256 and ES256 and rejects everything
// else through its default branch; naming an algorithm here that the switch
// does not implement does not make it verifiable. Omitting the option leaves
// that switch as the sole gate rather than disabling algorithm checking.
func WithValidMethods(methods []string) ParseOption {
	return func(cfg *validationConfig) {
		cfg.validMethods = methods
	}
}

// WithIssuer requires iss to match the expected issuer.
func WithIssuer(iss string) ParseOption {
	return func(cfg *validationConfig) {
		cfg.expectedIssuer = iss
	}
}

// WithAudience requires aud to contain the expected audience.
func WithAudience(aud string) ParseOption {
	return func(cfg *validationConfig) {
		cfg.expectedAud = aud
	}
}

// WithExpirationRequired requires the exp claim to be present.
func WithExpirationRequired() ParseOption {
	return func(cfg *validationConfig) {
		cfg.requireExp = true
	}
}

// WithIssuedAt enables iat validation (iat <= now).
func WithIssuedAt() ParseOption {
	return func(cfg *validationConfig) {
		cfg.verifyIat = true
	}
}

// WithoutClaimsValidation skips all claims validation (useful for DPoP).
func WithoutClaimsValidation() ParseOption {
	return func(cfg *validationConfig) {
		cfg.skipValidation = true
	}
}

// splitToken splits a JWT into exactly 3 segments. Returns an error if the
// token does not contain exactly two delimiters.
func splitToken(raw string) (header, payload, sig string, err error) {
	h, remain, ok := strings.Cut(raw, ".")
	if !ok {
		return "", "", "", ErrTokenMalformed
	}
	p, remain, ok := strings.Cut(remain, ".")
	if !ok {
		return "", "", "", ErrTokenMalformed
	}
	// Reject if there are more dots
	_, _, extra := strings.Cut(remain, ".")
	if extra {
		return "", "", "", ErrTokenMalformed
	}
	return h, p, remain, nil
}

// ParseWithClaims parses and fully validates a JWT string, in this order:
// segment/header decoding, the caller's optional algorithm allowlist, the
// signature switch that is the real algorithm gate, and finally claims
// validation.
//
// The fail-closed guarantee lives in the signature switch below, not in the
// [WithValidMethods] allowlist: the switch implements RS256 and ES256 and its
// default branch rejects every other alg as unverifiable, so "none" and the
// symmetric algorithms behind CVE-2015-9235 are refused even when no allowlist
// is configured. [WithValidMethods] narrows that set earlier and with a
// clearer error; it can never widen it.
//
// On any error the returned *Token may be non-nil but its Valid field is
// false and its claims are unverified, attacker-controlled data. Callers must
// branch on err, never on the token being non-nil.
func ParseWithClaims(tokenString string, claims Claims, keyFunc Keyfunc, opts ...ParseOption) (*Token, error) {
	cfg := &validationConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	// Split token
	headerSeg, payloadSeg, sigSeg, err := splitToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid segment count", ErrTokenMalformed)
	}

	// Decode header
	headerBytes, err := decodeSegment(headerSeg)
	if err != nil {
		return nil, fmt.Errorf("%w: bad header encoding", ErrTokenMalformed)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: bad header JSON", ErrTokenMalformed)
	}

	// Optional caller allowlist. An empty validMethods does not disable
	// algorithm verification: it defers the decision to the signature switch
	// below, whose default branch rejects everything that is not RS256 or
	// ES256. That switch is where "none" and the symmetric algorithms die, so
	// this block can only tighten the accepted set, never loosen it.
	alg, _ := header["alg"].(string)
	if alg == "" {
		return nil, fmt.Errorf("%w: missing alg", ErrTokenUnverifiable)
	}
	if len(cfg.validMethods) > 0 {
		valid := false
		for _, m := range cfg.validMethods {
			if m == alg {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("%w: alg %q not allowed", ErrTokenSignatureInvalid, alg)
		}
	}

	// Decode claims
	claimsBytes, err := decodeSegment(payloadSeg)
	if err != nil {
		return nil, fmt.Errorf("%w: bad claims encoding", ErrTokenMalformed)
	}
	if err := json.Unmarshal(claimsBytes, claims); err != nil {
		return nil, fmt.Errorf("%w: bad claims JSON", ErrTokenMalformed)
	}

	// Decode signature
	sigBytes, err := decodeSegment(sigSeg)
	if err != nil {
		return nil, fmt.Errorf("%w: bad signature encoding", ErrTokenMalformed)
	}

	token := &Token{
		Header:    header,
		Claims:    claims,
		Signature: sigBytes,
		Raw:       tokenString,
	}

	// Get verification key
	if keyFunc == nil {
		return token, fmt.Errorf("%w: no keyfunc provided", ErrTokenUnverifiable)
	}
	key, err := keyFunc(token)
	if err != nil {
		return token, fmt.Errorf("%w: keyfunc error: %w", ErrTokenUnverifiable, err)
	}

	// The hard algorithm allowlist. Only the cases below can verify a
	// signature; the default branch is the fail-closed guarantee that an
	// unrecognized alg (including "none" and any HMAC variant, which would
	// otherwise let a public JWKS key be replayed as a shared secret) is
	// refused. token.Valid stays false on every branch that returns here.
	signingString := headerSeg + "." + payloadSeg
	switch alg {
	case "RS256":
		pubKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return token, fmt.Errorf("%w: expected *rsa.PublicKey", ErrInvalidKeyType)
		}
		if err := VerifyRS256(signingString, sigBytes, pubKey); err != nil {
			return token, fmt.Errorf("%w", ErrTokenSignatureInvalid)
		}
	case "ES256":
		pubKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return token, fmt.Errorf("%w: expected *ecdsa.PublicKey", ErrInvalidKeyType)
		}
		if err := VerifyES256(signingString, sigBytes, pubKey); err != nil {
			return token, fmt.Errorf("%w", ErrTokenSignatureInvalid)
		}
	default:
		return token, fmt.Errorf("%w: unsupported algorithm %q", ErrTokenUnverifiable, alg)
	}

	// Validate claims
	if !cfg.skipValidation {
		if err := validateClaims(claims, cfg); err != nil {
			return token, err
		}
	}

	token.Valid = true
	return token, nil
}

// ParseUnverified parses a JWT without signature verification or claims validation.
// Only use for header inspection (e.g., DPoP jwk extraction).
func ParseUnverified(tokenString string, claims Claims) (*Token, error) {
	headerSeg, payloadSeg, sigSeg, err := splitToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid segment count", ErrTokenMalformed)
	}

	// Decode header
	headerBytes, err := decodeSegment(headerSeg)
	if err != nil {
		return nil, fmt.Errorf("%w: bad header encoding", ErrTokenMalformed)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: bad header JSON", ErrTokenMalformed)
	}

	// Decode claims
	claimsBytes, err := decodeSegment(payloadSeg)
	if err != nil {
		return nil, fmt.Errorf("%w: bad claims encoding", ErrTokenMalformed)
	}
	if err := json.Unmarshal(claimsBytes, claims); err != nil {
		return nil, fmt.Errorf("%w: bad claims JSON", ErrTokenMalformed)
	}

	// Decode signature (best-effort, don't fail on bad sig encoding for unverified parse)
	sigBytes, _ := decodeSegment(sigSeg)

	return &Token{
		Header:    header,
		Claims:    claims,
		Signature: sigBytes,
		Raw:       tokenString,
		Valid:     false,
	}, nil
}
