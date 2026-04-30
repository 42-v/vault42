// Package jwt is a stdlib-only JWT implementation for Vault42:
// RS256 + ES256 sign/verify, claim parsing, algorithm whitelisting, and
// the security defenses spelled out in docs/spec.md (jku/x5u/x5c rejection,
// 8 KB max size, kid traversal protection).
package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Token represents a parsed or constructed JWT.
type Token struct {
	Header    map[string]any
	Claims    Claims
	Signature []byte
	Raw       string
	Valid     bool
}

// Keyfunc receives the unverified token (for kid lookup) and returns the verification key.
type Keyfunc func(token *Token) (any, error)

// encodeSegment base64url-encodes a byte slice (no padding).
func encodeSegment(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// decodeSegment base64url-decodes a string (no padding).
func decodeSegment(seg string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(seg)
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
