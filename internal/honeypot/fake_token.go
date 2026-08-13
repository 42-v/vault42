package honeypot

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// fakeJWTClaims is the iss/aud pair every minted fake token carries.
//
// The two strings are one unit. A token whose issuer came from the configured
// value and whose audience was still the default is a fingerprint an attacker
// can use to tell the trap apart from the real vault, so they are published
// together behind a single pointer rather than one variable at a time.
type fakeJWTClaims struct {
	issuer   string
	audience string
}

// defaultFakeJWTClaims is what the honeypot mints with before startup wiring
// configures it.
var defaultFakeJWTClaims = fakeJWTClaims{issuer: "vault", audience: "vault"}

var (
	// currentClaims is an atomic pointer rather than two plain strings because
	// the sync.Once below does not make the publication safe on its own. A Once
	// orders the goroutine inside Do against other goroutines that also call Do,
	// and against nothing else. GenerateFakeJWT only reads and never calls Do,
	// so it inherits no ordering from the Once. cmd/vault calls ConfigureFakeJWT
	// while the trap endpoints are already reachable, so an attacker's first
	// request read these concurrently with the write: a genuine data race, not
	// merely a stale read.
	currentClaims atomic.Pointer[fakeJWTClaims]
	configOnce    sync.Once

	// randRead is the entropy source for the fake credentials. It is a variable
	// so a test can starve it and pin that a token is never emitted from bytes
	// the CSPRNG did not actually produce.
	randRead = rand.Read
)

// currentFakeJWTClaims returns the iss/aud pair a mint must use. It is nil-safe
// so a token minted before any configuration still carries the defaults.
func currentFakeJWTClaims() (issuer, audience string) {
	if c := currentClaims.Load(); c != nil {
		return c.issuer, c.audience
	}
	return defaultFakeJWTClaims.issuer, defaultFakeJWTClaims.audience
}

// storeFakeJWTClaims publishes an iss/aud pair as a single atomic write.
func storeFakeJWTClaims(issuer, audience string) {
	currentClaims.Store(&fakeJWTClaims{issuer: issuer, audience: audience})
}

// ConfigureFakeJWT sets the iss/aud claims for honeypot fake JWTs.
// Must be called once at startup before the server begins accepting requests.
// Safe for concurrent use; subsequent calls are no-ops.
func ConfigureFakeJWT(issuer, audience string) {
	configOnce.Do(func() {
		storeFakeJWTClaims(issuer, audience)
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

	issuer, audience := currentFakeJWTClaims()
	payload := map[string]any{
		"sub":   sub,
		"iss":   issuer,
		"aud":   audience,
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
