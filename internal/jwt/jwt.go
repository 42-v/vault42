// Package jwt is a stdlib-only JWT implementation for Vault42:
// RS256 + ES256 sign/verify, claim parsing, algorithm whitelisting, and
// canonical segment decoding.
//
// The rest of the defenses spelled out in docs/spec.md belong to the callers
// and are not enforced here, because this package never sees the policy they
// depend on. The jku/x5u/x5c/jwk and crit rejections and the kid format check
// live in the Keyfunc, which is the only place that knows which keys are
// trusted; the size cap lives at each entry point, 8 KB in
// crypto.ParseAndValidate and 4 KB in crypto.ValidateDPoPProof. A caller that
// reaches ParseWithClaims directly gets none of them.
package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Token represents a parsed or constructed JWT.
//
// A Token obtained from parsing is only trustworthy when the parse returned a
// nil error. [ParseWithClaims] returns a populated Token alongside most of its
// errors so callers can log the offending kid or alg, and [ParseUnverified]
// returns one that was never checked at all. Read Valid, or better, read the
// error.
type Token struct {
	// Header is the decoded JOSE header. It is attacker-controlled until the
	// signature verifies, so a Keyfunc reading it must treat every value as
	// untrusted input; that is where the jku/x5u/x5c/jwk rejections belong.
	Header map[string]any
	// Claims is the decoded payload, unmarshaled into the caller's type. It is
	// populated before verification, so it is attacker-controlled whenever
	// Valid is false.
	Claims Claims
	// Signature is the raw decoded signature bytes.
	Signature []byte
	// Raw is the original compact serialization exactly as received.
	Raw string
	// Valid reports that the signature verified against the key the Keyfunc
	// returned and that claims validation passed. It is set at the very end of
	// [ParseWithClaims] and is false on every error path, including the ones
	// that still return a non-nil Token.
	Valid bool
}

// Keyfunc receives the unverified token and returns the key to verify it with.
//
// It runs before any signature check, so token.Header is attacker-controlled at
// this point. A Keyfunc must select the key from data it trusts, typically by
// looking the kid up in a local key set, and must never fetch or construct a
// key from a URL or an embedded JWK found in the header. Returning an error
// makes the parse fail with ErrTokenUnverifiable.
type Keyfunc func(token *Token) (any, error)

// encodeSegment base64url-encodes a byte slice (no padding).
func encodeSegment(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// segmentEncoding is the strict variant of the RFC 7515 §2 segment encoding.
// Strict makes the decoder refuse a final character whose unused low bits are
// not zero, which is otherwise ignored. It is a package-level value because
// base64.Encoding.Strict returns a copy of the whole encoding, table included,
// and every parse decodes three segments.
var segmentEncoding = base64.RawURLEncoding.Strict()

// decodeSegment base64url-decodes one segment of a compact serialization.
//
// The strictness above the stdlib decoder exists because the compact
// serialization has to name a token uniquely. internal/middleware/dpop.go binds
// a DPoP proof to an access token by hashing the exact bearer string it was
// handed, and a denylist of individually revoked tokens would key on the same
// bytes. Go's decoder is lax in two ways that give one signature many spellings:
// it skips CR and LF wherever they appear, which the alphabet scan rejects here,
// and it ignores the padding bits of the final character, which segmentEncoding
// rejects. Neither is legal input under RFC 7515 §2, and no conforming encoder
// produces either, so nothing that verified before stops verifying.
func decodeSegment(seg string) ([]byte, error) {
	for i := 0; i < len(seg); i++ {
		switch c := seg[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return nil, fmt.Errorf("illegal base64url character %q at offset %d", c, i)
		}
	}
	return segmentEncoding.DecodeString(seg)
}

// EncodeSegment base64url-encodes a byte slice (exported for test helpers).
func EncodeSegment(data []byte) string {
	return encodeSegment(data)
}

// SignRS256 creates a signed RS256 JWT string.
// Header: {"alg":"RS256","typ":"JWT","kid":kid}
func SignRS256(claims Claims, key *rsa.PrivateKey, kid string) (string, error) {
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	signingString := encodeSegment(headerJSON) + "." + encodeSegment(claimsJSON)

	sig, err := SignRS256Bytes(signingString, key)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	return signingString + "." + encodeSegment(sig), nil
}

// SignRS256WithHeader creates a signed RS256 JWT with a caller-provided header map.
// Use for testing with custom/malicious headers (kid overrides, jku, x5u, x5c, jwk).
func SignRS256WithHeader(header map[string]any, claims any, key *rsa.PrivateKey) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	signingString := encodeSegment(headerJSON) + "." + encodeSegment(claimsJSON)

	sig, err := SignRS256Bytes(signingString, key)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	return signingString + "." + encodeSegment(sig), nil
}

// SignTokenCustom creates a token with arbitrary header and signs it with the
// provided function. Use for attack tests that need non-RS256 tokens (ES256,
// HS256, PS256, none).
func SignTokenCustom(header map[string]any, claims any, signFunc func(signingString string) ([]byte, error)) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	signingString := encodeSegment(headerJSON) + "." + encodeSegment(claimsJSON)

	sig, err := signFunc(signingString)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	return signingString + "." + encodeSegment(sig), nil
}

// UnsignedToken creates a token with no signature (for alg:none attack tests).
func UnsignedToken(header map[string]any, claims any) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	return encodeSegment(headerJSON) + "." + encodeSegment(claimsJSON) + ".", nil
}
