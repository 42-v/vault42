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

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// fakeAccessTokenTTL is how long a minted trap token claims to live.
//
// It matches the default VAULT_ACCESS_TOKEN_TTL rather than the configured one,
// because nothing hands this package the configured value. A deployment that
// overrides the TTL therefore answers with an expires_in that disagrees with the
// exp inside the token, which no real login does.
const fakeAccessTokenTTL = 15 * time.Minute

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

// The key id and the device fingerprint are properties of the deployment and of
// the caller, not of the individual token: a vault signs with one active key and
// computes one fingerprint per client, so both hold still across a session. Fresh
// values per mint told an attacker with one trap credential that the issuer had
// invented a new signing key between two consecutive logins, which no real
// deployment does and which costs them one extra request to notice.
//
// They are drawn once per process instead of derived from anything, because
// vault42 is public source: a value an attacker can recompute from what they sent
// is not a disguise. The lock rather than a sync.Once so that a failed CSPRNG read
// is retried on the next mint instead of being cached as a permanent failure.
var (
	processIdentityMu  sync.Mutex
	processKID         string
	processFingerprint string
)

// processIdentity returns the key id and fingerprint every token minted by this
// process carries, drawing them on first use.
func processIdentity() (string, string, error) {
	processIdentityMu.Lock()
	defer processIdentityMu.Unlock()

	if processKID == "" {
		k, err := fakeUUID()
		if err != nil {
			return "", "", err
		}
		// A real fingerprint is SHA-256 hex over the caller's IP, User-Agent,
		// Accept-Language and TLS fingerprint.
		f, err := randomHex(32)
		if err != nil {
			return "", "", err
		}
		processKID, processFingerprint = k, f
	}
	return processKID, processFingerprint, nil
}

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
//
// The payload is built from the same claims struct the real token service signs,
// and the header from the same map internal/jwt.SignRS256 builds, so the two
// agree on which claims exist, on their JSON types and on the order they are
// emitted in. Assembling the payload from a map instead put the claims in
// alphabetical order, spelled aud as a bare string where a real token always
// spells it as an array, and omitted nbf, jti, scopes, the fingerprint and
// token_type outright. vault42 is public source, so any of those is a complete
// answer to "is this the honeypot" from one base64 decode of the token the trap
// just handed over.
func GenerateFakeJWT() (string, error) {
	kid, fingerprint, err := processIdentity()
	if err != nil {
		return "", err
	}
	sub, err := fakeUUID()
	if err != nil {
		return "", err
	}
	jti, err := fakeUUID()
	if err != nil {
		return "", err
	}

	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	}
	// Neither marshal can fail: a map[string]string and a claims struct of
	// strings, slices, ints and NumericDate contain nothing json refuses, and
	// NumericDate's own MarshalJSON has no error path.
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	issuer, audience := currentFakeJWTClaims()
	now := time.Now()
	payloadJSON, _ := json.Marshal(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   sub,
			Audience:  vjwt.ClaimStrings{audience},
			ExpiresAt: vjwt.NewNumericDate(now.Add(fakeAccessTokenTTL)),
			NotBefore: vjwt.NewNumericDate(now),
			IssuedAt:  vjwt.NewNumericDate(now),
			ID:        jti,
		},
		Roles:       []string{"user"},
		Scopes:      []string{"read", "write"},
		Fingerprint: fingerprint,
		TokenType:   "Bearer",
	})
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
// refresh token. The real one is crypto.RandomToken(32), which is the same 32
// bytes of hex.
func GenerateFakeRefresh() (string, error) {
	return randomHex(32)
}

// randomHex returns n CSPRNG bytes as lowercase hex, or an error and no string
// at all. A partial value here would be a credential the attacker can tell apart
// from a real one.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
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
