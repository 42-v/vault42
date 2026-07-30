package honeypot

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

var (
	fakeJWTIssuer   = "vault"
	fakeJWTAudience = "vault"
	configOnce      sync.Once

	// randRead is the entropy source for the fake credentials. It is a variable
	// so a test can starve it and pin that a token is never emitted from bytes
	// the CSPRNG did not actually produce.
	randRead = rand.Read
)

// ConfigureFakeJWT sets the iss/aud claims for honeypot fake JWTs.
// Must be called once at startup before the server begins accepting requests.
// Safe for concurrent use; subsequent calls are no-ops.
func ConfigureFakeJWT(issuer, audience string) {
	configOnce.Do(func() {
		fakeJWTIssuer = issuer
		fakeJWTAudience = audience
	})
}

// GenerateFakeJWT creates a real-looking but unsigned JWT. The header and
// payload have valid structure but the signature is random bytes, making
// the token useless for any real API call. Attackers see a plausible
// token that fails silently when used.
func GenerateFakeJWT() (string, error) {
	kid, err := fakeUUID()
	if err != nil {
		return "", err
	}
	sub, err := fakeUUID()
	if err != nil {
		return "", err
	}

	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	payload := map[string]any{
		"sub":   sub,
		"iss":   fakeJWTIssuer,
		"aud":   fakeJWTAudience,
		"exp":   time.Now().Add(15 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
		"roles": []string{"user"},
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Random 256-byte signature (looks like RS256 but is gibberish)
	sig := make([]byte, 256)
	if _, err := randRead(sig); err != nil {
		return "", fmt.Errorf("honeypot: crypto/rand failed: %w", err)
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return headerB64 + "." + payloadB64 + "." + sigB64, nil
}

// GenerateFakeRefresh creates a random hex string that looks like a real
// refresh token.
func GenerateFakeRefresh() (string, error) {
	b := make([]byte, 32)
	if _, err := randRead(b); err != nil {
		return "", fmt.Errorf("honeypot: crypto/rand failed: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func fakeUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := randRead(b); err != nil {
		return "", fmt.Errorf("honeypot: crypto/rand failed: %w", err)
	}
	// Set UUID v4 version and RFC 4122 variant bits
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 2
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
