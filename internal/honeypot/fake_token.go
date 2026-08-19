package honeypot

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// defaultFakeAccessTTL is how long a trap token lives before startup wiring
// publishes the deployment's own VAULT_ACCESS_TOKEN_TTL. It is the same default
// the config package applies, so even an unconfigured mint agrees with the
// expires_in a default deployment quotes.
const defaultFakeAccessTTL = 15 * time.Minute

// fakeJWTConfig is the deployment shape a trap token has to copy.
//
// The three fields are one unit. A token whose issuer came from the configured
// value while its audience or its lifetime was still the built-in default is a
// fingerprint an attacker can use to tell the trap apart from the real vault,
// so they are published together behind a single pointer rather than one
// variable at a time.
type fakeJWTConfig struct {
	issuer    string
	audience  string
	accessTTL time.Duration
}

// defaultFakeJWTConfig is what the honeypot mints with before startup wiring
// configures it.
var defaultFakeJWTConfig = fakeJWTConfig{issuer: "vault", audience: "vault", accessTTL: defaultFakeAccessTTL}

var (
	// currentConfig is an atomic pointer rather than plain fields because the
	// sync.Once below does not make the publication safe on its own. A Once
	// orders the goroutine inside Do against other goroutines that also call Do,
	// and against nothing else. A mint only reads and never calls Do, so it
	// inherits no ordering from the Once. cmd/vault calls ConfigureFakeJWT while
	// the trap endpoints are already reachable, so an attacker's first request
	// read these concurrently with the write: a genuine data race, not merely a
	// stale read.
	currentConfig atomic.Pointer[fakeJWTConfig]
	configOnce    sync.Once

	// randRead is the entropy source for the fake credentials. It is a variable
	// so a test can starve it and pin that a token is never emitted from bytes
	// the CSPRNG did not actually produce.
	randRead = rand.Read

	// newSigningKey is the trap key source, a variable for the same reason: a
	// test has to be able to fail it and pin that no token is emitted from a key
	// that was never generated.
	newSigningKey = vaultcrypto.GenerateRSAKeyPair
)

// The trap's signing key is generated in this process, is never persisted, and
// is deliberately NOT the deployment's own signing key.
//
// It has to be a real key because the trap serves GET /.well-known/jwks.json
// unauthenticated. A token whose signature does not verify against the document
// its own issuer publishes is a tell that costs the attacker nothing: any
// relying party they feed it to reports it for them. Random signature bytes
// under a locally invented kid failed both halves of that at once.
//
// It has to be a key of the honeypot's own, because signing with the vault's
// real key would turn the trap into a mint for tokens that assert a subject
// nobody ever authenticated, valid on any deployment sharing that key. The
// bridge runs the real and the honeypot instance from one binary behind one
// origin, so that is not a hypothetical arrangement.
//
// The lock rather than a sync.Once so a failed generation is retried on the next
// mint instead of being cached as a permanent failure.
var (
	trapKeyMu sync.Mutex
	trapKey   *rsa.PrivateKey
	trapKID   string
)

// trapSigningKey returns the key every trap token in this process is signed
// with, generating it on first use.
func trapSigningKey() (*rsa.PrivateKey, string, error) {
	trapKeyMu.Lock()
	defer trapKeyMu.Unlock()

	if trapKey == nil {
		key, err := newSigningKey()
		if err != nil {
			return nil, "", fmt.Errorf("honeypot: generate trap signing key: %w", err)
		}
		// The same derivation the keystore files every real key under, so the
		// kid in a trap token has the shape a real one has rather than the shape
		// this package felt like inventing.
		trapKey, trapKID = key, vaultcrypto.KIDFromPublicKey(&key.PublicKey)
	}
	return trapKey, trapKID, nil
}

// mintedTrapKID returns the key id trap tokens are signed under, or "" when this
// process has not minted one.
//
// It deliberately does not generate the key the way trapSigningKey does. Its
// caller is the HTTP middleware, running on the attacker's own request, and
// generating a 2048-bit RSA key there would put several hundred milliseconds on
// whichever request happened to arrive first -- the timing tell TrapSigningKey's
// startup call exists to pay off early. It is also unnecessary: no key means no
// trap token has ever been minted, and a token that does not exist cannot be
// replayed.
func mintedTrapKID() string {
	trapKeyMu.Lock()
	defer trapKeyMu.Unlock()
	return trapKID
}

// TrapSigningKey returns the key id and public half of the honeypot-only signing
// key so startup wiring can publish it in the JWKS the trap serves.
//
// Calling it at startup also pays the RSA generation cost before the first
// attacker request rather than inside it, where a first login several hundred
// milliseconds slower than every later one is its own signal.
func TrapSigningKey() (string, *rsa.PublicKey, error) {
	key, kid, err := trapSigningKey()
	if err != nil {
		return "", nil, err
	}
	return kid, &key.PublicKey, nil
}

// trapIdentitySalt keys the derivation of every per-identity claim. It is drawn
// from the CSPRNG once per process rather than derived from anything, because
// vault42 is public source: a value an attacker can recompute from the address
// they sent is not a disguise. Same lock-not-Once reasoning as the signing key.
var (
	trapSaltMu sync.Mutex
	trapSalt   []byte
)

func trapIdentitySalt() ([]byte, error) {
	trapSaltMu.Lock()
	defer trapSaltMu.Unlock()

	if trapSalt == nil {
		s := make([]byte, 32)
		if _, err := randRead(s); err != nil {
			return nil, fmt.Errorf("honeypot: crypto/rand failed: %w", err)
		}
		trapSalt = s
	}
	return trapSalt, nil
}

// trapMAC returns the value one labeled claim takes for one identity. The
// label is separated from the identity by a zero byte so no two labels can be
// made to collide by an address that happens to contain the other's name.
//
// The identity is folded the way Alerter.IsTrapUser folds it, because the two
// spellings of one address are one account everywhere else in the vault.
//
// It takes the salt rather than fetching it, so a mint reads the salt once and
// no caller is left with an error branch that the first successful read has
// already made unreachable.
func trapMAC(salt []byte, label, identity string) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(label))
	mac.Write([]byte{0})
	mac.Write([]byte(strings.ToLower(strings.TrimSpace(identity))))
	return mac.Sum(nil)
}

// TrapSubject returns the user id a trap identity is answered with, on every
// login, for as long as the process lives.
//
// sub is an account id: one address has one and keeps it. jti is the claim that
// is fresh per token. Drawing sub from the CSPRNG per mint meant two logins with
// one planted credential came back as two different accounts, which no real
// deployment does and which an attacker reads off two requests.
//
// The trap path uses it as the user id for its own database round trips too, so
// the id in the token and the id the honeypot looked up are one value.
func TrapSubject(identity string) (string, error) {
	salt, err := trapIdentitySalt()
	if err != nil {
		return "", err
	}
	return uuidShape(trapMAC(salt, "sub", identity)[:16]), nil
}

// currentFakeJWTConfig returns the deployment shape a mint must copy. It is
// nil-safe so a token minted before any configuration still carries the
// defaults.
func currentFakeJWTConfig() fakeJWTConfig {
	if c := currentConfig.Load(); c != nil {
		return *c
	}
	return defaultFakeJWTConfig
}

// storeFakeJWTConfig publishes a configuration as a single atomic write.
func storeFakeJWTConfig(cfg fakeJWTConfig) {
	currentConfig.Store(&cfg)
}

// ConfigureFakeJWT publishes the iss, aud and access-token lifetime every trap
// token must carry. Must be called once at startup before the server begins
// accepting requests. Safe for concurrent use; subsequent calls are no-ops.
//
// The lifetime is here because the login response quotes the configured TTL as
// expires_in while the token carried a hardcoded fifteen minutes. The two agreed
// only on a deployment that had never set VAULT_ACCESS_TOKEN_TTL.
func ConfigureFakeJWT(issuer, audience string, accessTTL time.Duration) {
	configOnce.Do(func() {
		if accessTTL <= 0 {
			accessTTL = defaultFakeAccessTTL
		}
		storeFakeJWTConfig(fakeJWTConfig{issuer: issuer, audience: audience, accessTTL: accessTTL})
	})
}

// TrapCaller is what the trap login path knows about the caller it is
// answering, and it is exactly what a real access token records about them.
type TrapCaller struct {
	// Identity is the address the caller logged in with. It fixes sub.
	Identity string
	// ClientID is the client_id they sent. A real token echoes it and omits the
	// claim entirely when none was sent, so a trap token that always omits it is
	// a payload one member short of the real thing for any caller who sends one.
	ClientID string
	// Fingerprint is crypto.ComputeFingerprint over the request. A real one moves
	// when the caller's IP or User-Agent moves; one value for every client the
	// process ever answers says the issuer never looked at the request.
	Fingerprint string
}

// GenerateFakeJWTForIdentity mints the access token a trap credential is
// answered with.
//
// The claims are the struct the real token service signs and the signature comes
// from the same SignToken call, so the two agree on which claims exist, on their
// JSON types, on the order they are emitted in, and on the header. Assembling
// the payload from a map instead put the claims in alphabetical order, spelled
// aud as a bare string where a real token always spells it as an array, and
// omitted nbf, jti, scopes, the fingerprint and token_type outright. vault42 is
// public source, so any of those is a complete answer to "is this the honeypot"
// from one base64 decode of the token the trap just handed over.
func GenerateFakeJWTForIdentity(caller TrapCaller) (string, error) {
	key, kid, err := trapSigningKey()
	if err != nil {
		return "", err
	}
	salt, err := trapIdentitySalt()
	if err != nil {
		return "", err
	}
	fingerprint := caller.Fingerprint
	if fingerprint == "" {
		// A caller with no request to compute one from still needs a value of the
		// shape ComputeFingerprint returns, SHA-256 hex, and one that holds still
		// per identity the way a real one holds still per client.
		fingerprint = hex.EncodeToString(trapMAC(salt, "fingerprint", caller.Identity))
	}
	jti, err := fakeUUID()
	if err != nil {
		return "", err
	}

	cfg := currentFakeJWTConfig()
	now := time.Now()
	return vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    cfg.issuer,
			Subject:   uuidShape(trapMAC(salt, "sub", caller.Identity)[:16]),
			Audience:  vjwt.ClaimStrings{cfg.audience},
			ExpiresAt: vjwt.NewNumericDate(now.Add(cfg.accessTTL)),
			NotBefore: vjwt.NewNumericDate(now),
			IssuedAt:  vjwt.NewNumericDate(now),
			ID:        jti,
		},
		Roles:       []string{"user"},
		Scopes:      []string{"read", "write"},
		ClientID:    caller.ClientID,
		Fingerprint: fingerprint,
		TokenType:   "Bearer",
	}, key, kid)
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
	return uuidShape(b), nil
}

// uuidShape stamps the v4 version and RFC 4122 variant bits onto 16 bytes and
// formats them, so a derived id is indistinguishable from a drawn one. It
// mutates the slice it is handed.
func uuidShape(b []byte) string {
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 2
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
