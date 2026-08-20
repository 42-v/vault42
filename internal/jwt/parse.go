package jwt

import (
	"bytes"
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
	if err := refuseAmbiguousClaimNames(claimsBytes); err != nil {
		return nil, err
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
	if err := refuseAmbiguousClaimNames(claimsBytes); err != nil {
		return nil, err
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

// refuseAmbiguousClaimNames rejects a payload whose top-level object names the
// same claim twice under names that differ only by case.
//
// encoding/json matches a struct tag case-insensitively and takes the LAST
// match, so {"exp":0,"eXP":<future>} unmarshals into RegisteredClaims with the
// future expiry and the real "exp" discarded. A token that has expired then
// verifies. The same trick moves "aud" and "iss", which are the two claims
// validateClaims compares against configured values, so an audience check can
// pass on a claim the payload never carried under that name -- and a caller
// reading claims.Audience back sees a value the signer did not put in "aud".
//
// A duplicate is not something a legitimate issuer emits; RFC 8259 leaves
// duplicate member names undefined and RFC 7519 s4 says a claim name occurs
// once. Refusing is therefore free, and it is the only reading on which two
// verifiers cannot disagree about what a token says.
//
// Case-folded rather than exact, because the exact-duplicate case is already
// last-wins in every JSON implementation and agrees with itself; it is the
// case-insensitive struct match that makes two DIFFERENT names collide into
// one field.
func refuseAmbiguousClaimNames(payload []byte) error {
	dec := json.NewDecoder(bytes.NewReader(payload))
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%w: bad claims JSON", ErrTokenMalformed)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		// Not an object. The unmarshal below will reject it with the message
		// that fits, and there are no member names to collide.
		return nil
	}

	seen := make(map[string]string)
	for dec.More() {
		// The type assertion is folded into the error check rather than
		// standing alone: encoding/json reports a non-string member name as a
		// syntax error from Token, so the assertion can never be the thing that
		// fails, and a branch on it by itself is a statement no input reaches.
		nameTok, nameErr := dec.Token()
		name, ok := nameTok.(string)
		if nameErr != nil || !ok {
			return fmt.Errorf("%w: bad claims JSON", ErrTokenMalformed)
		}
		folded := strings.ToLower(name)
		if first, dup := seen[folded]; dup {
			return fmt.Errorf("%w: claims name %q and %q differ only by case, and a JSON decoder "+
				"matches them to one field", ErrTokenMalformed, first, name)
		}
		seen[folded] = name

		// Skip the value, whatever it is. Decoder.Token walks into composites,
		// so an explicit skip keeps the walk at the top level.
		var skip json.RawMessage
		if decErr := dec.Decode(&skip); decErr != nil {
			return fmt.Errorf("%w: bad claims JSON", ErrTokenMalformed)
		}
	}
	return nil
}
