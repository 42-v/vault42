package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"

	vjwt "github.com/42-v/vault42/internal/jwt"
)

const (
	// MaxJWTSize is the maximum allowed JWT size in bytes (8KB).
	MaxJWTSize = 8 * 1024
)

// AllowedAlgorithm is the only signing algorithm name we accept.
const AllowedAlgorithm = "RS256"

// VaultClaims extends RegisteredClaims with Vault-specific fields.
type VaultClaims struct {
	vjwt.RegisteredClaims
	Roles        []string      `json:"roles,omitempty"`
	Scopes       []string      `json:"scopes,omitempty"`
	ClientID     string        `json:"client_id,omitempty"`
	Fingerprint  string        `json:"fingerprint,omitempty"`
	Confirmation *Confirmation `json:"cnf,omitempty"`
	TokenType    string        `json:"token_type,omitempty"`
	// MintedBy names the client that requested a minted subject assertion. It
	// is set only by the mint path and carries no authority: it is attribution
	// for a relying party, not a credential. It is deliberately not ClientID,
	// which is the claim that marks a client-credentials caller and is read as
	// such by the service document store.
	MintedBy string `json:"minted_by,omitempty"`

	// ACR is the OIDC Core §2 authentication context class reference: the
	// assurance level this session reached, as "urn:vault42:aal:N". OIDC leaves
	// the value space to the issuer, so the URN is vault42's own and its
	// meaning is the NIST SP 800-63B AAL of the same number.
	ACR string `json:"acr,omitempty"`
	// AMR is the OIDC Core §2 authentication methods reference: the RFC 8176
	// values for the authenticators this session actually presented.
	AMR []string `json:"amr,omitempty"`
	// AuthTime is the OIDC Core §2 auth_time: seconds since the Unix epoch at
	// which the end user authenticated, which for a rotated token is when the
	// refresh family began rather than when the token was minted. Zero means no
	// authentication event is recorded, and the claim is omitted.
	AuthTime int64 `json:"auth_time,omitempty"`
	// Factors lists the vault42 authenticator methods already completed. It
	// appears only on a 2fa_challenge token, where it carries the first factor
	// across to the second-factor verify so the completed login knows whether it
	// began with a password or with an upstream identity provider. It is not an
	// authorization claim and no access token carries it.
	Factors []string `json:"factors,omitempty"`

	// Email is an assertion the caller made, not a fact vault42 established.
	//
	// It exists for one reason: a relying party that already has its own user
	// table keyed by email cannot use a token that names only an opaque
	// subject. BeOn3's storage worker derives every avatar's owner key as
	// GUID(SHA256(userId+email)), so a missing email there does not fail, it
	// silently detaches the object from its owner.
	//
	// It is set only on the /mint path, only when VAULT_MINT_ALLOW_EMAIL is on,
	// and vault42 never looks the address up: /mint asserts subjects it has
	// never heard of by design, and an email is the same kind of claim about
	// the same unknown subject. A reader must not treat it as verified. The
	// email on a *login* token would be a different thing entirely, and there
	// is not one -- no vault42-issued access token carries this claim.
	Email string `json:"email,omitempty"`
}

// Confirmation holds DPoP proof-of-possession binding (RFC 9449).
type Confirmation struct {
	JKT string `json:"jkt,omitempty"` // JWK SHA-256 Thumbprint
}

// GenerateRSAKeyPair generates a 2048-bit RSA key pair.
func GenerateRSAKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// LoadSigningKeyPEM parses an RSA private key from PKCS#8 PEM data and derives
// a deterministic kid from the public key modulus. Used to share the same
// signing key across all pods for horizontal scaling.
func LoadSigningKeyPEM(pemData []byte) (*rsa.PrivateKey, string, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, "", errors.New("crypto: no PEM block found in signing key")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("crypto: parse signing key: %w", err)
	}

	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, "", errors.New("crypto: signing key is not RSA")
	}

	if key.N.BitLen() < 2048 {
		return nil, "", errors.New("crypto: signing key too small (minimum 2048 bits)")
	}

	kid := KIDFromPublicKey(&key.PublicKey)
	return key, kid, nil
}

// MarshalSigningKeyPEM encodes an RSA private key as PKCS#8 PEM.
func MarshalSigningKeyPEM(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal signing key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// KIDFromPublicKey derives a deterministic key ID from the RSA public key.
// Format: first 16 hex chars of SHA-256 over the PKIX DER encoding, split as
// xxxxxxxx-xxxxxxxx.
//
// The DER covers both the modulus and the exponent. Hashing N alone meant two
// keys sharing a modulus but differing in exponent produced the same kid, and
// keystore.Import upserts ON CONFLICT (kid) DO UPDATE, so importing the second
// overwrote the first key's private material in place. Reaching it needs admin
// import of a crafted key, which is why this is hardening rather than a live
// break, but the fix costs nothing.
//
// Changing the derivation does not disturb existing keys. Both call sites derive
// the kid once, when a key is generated or imported, and store it; nothing
// recomputes a kid and compares it against a stored one, so keys already in the
// keystore keep the id they were filed under and the JWKS keeps publishing it.
func KIDFromPublicKey(pub *rsa.PublicKey) string {
	// MarshalPKIXPublicKey fails only for a key type it does not understand, and
	// this one is *rsa.PublicKey. Falling back to the modulus keeps the function
	// total rather than introducing an error return that no caller can act on.
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		der = pub.N.Bytes()
	}
	h := sha256.Sum256(der)
	s := hex.EncodeToString(h[:8])
	return s[:8] + "-" + s[8:]
}

// SignToken creates a signed RS256 JWT with the given claims and key ID.
func SignToken(claims VaultClaims, privateKey *rsa.PrivateKey, kid string) (string, error) {
	return vjwt.SignRS256(claims, privateKey, kid)
}

// ParseAndValidate parses a JWT string, enforcing:
// - Max size (8KB)
// - Algorithm whitelist (RS256 only)
// - kid is present and non-empty
// - jku/x5u/x5c/jwk headers are rejected
// - any crit header is rejected (RFC 7515 4.1.11: no JOSE extensions implemented)
// - Standard claims (exp, nbf, iss, aud) are validated
func ParseAndValidate(tokenString string, keyFunc vjwt.Keyfunc, issuer string, audience string) (*VaultClaims, error) {
	if len(tokenString) > MaxJWTSize {
		return nil, errors.New("jwt: token exceeds maximum size")
	}

	claims := &VaultClaims{}
	token, err := vjwt.ParseWithClaims(tokenString, claims, func(t *vjwt.Token) (any, error) {
		// Reject dangerous headers
		for _, h := range []string{"jku", "x5u", "x5c", "jwk"} {
			if _, exists := t.Header[h]; exists {
				return nil, fmt.Errorf("jwt: rejected header %q", h)
			}
		}

		// `crit` lists header parameters the producer requires the recipient to
		// understand and act on, and RFC 7515 4.1.11 says a recipient MUST reject
		// a JWS carrying one it does not fully implement. vault42 implements no
		// JOSE extensions, so every crit qualifies, whatever it names and whether
		// or not it is even a list. The RFC forbids an empty array outright,
		// which is the case a "nothing is listed, so nothing is required" reading
		// would wave through.
		//
		// Not exploitable on its own, since the header is inside the signature
		// and forging one needs the signing key. It matters because these tokens
		// are consumed elsewhere: a relying party that honors crit would refuse
		// a token this vault called valid, and two verifiers disagreeing about
		// what a valid token is is the kind of gap that later gets built on.
		if _, exists := t.Header["crit"]; exists {
			return nil, errors.New("jwt: rejected crit header, no JOSE extensions are implemented")
		}

		// Validate kid presence
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New("jwt: missing or empty kid")
		}

		// kid must be UUID-safe — reject path traversal
		if !isValidKID(kid) {
			return nil, errors.New("jwt: invalid kid format")
		}

		return keyFunc(t)
	},
		vjwt.WithValidMethods([]string{AllowedAlgorithm}),
		vjwt.WithIssuer(issuer),
		vjwt.WithAudience(audience),
		vjwt.WithExpirationRequired(),
		vjwt.WithIssuedAt(),
	)
	if err != nil {
		return nil, fmt.Errorf("jwt: %w", err)
	}

	_ = token // claims already populated via pointer
	return claims, nil
}

// isValidKID checks that a kid contains only hex digits and dashes (UUID format).
func isValidKID(kid string) bool {
	if len(kid) == 0 || len(kid) > 64 {
		return false
	}
	for _, c := range kid {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '-') {
			return false
		}
	}
	return true
}

// JWK represents a JSON Web Key for JWKS serialization.
type JWK struct {
	KTY string `json:"kty"`
	Use string `json:"use"`
	KID string `json:"kid"`
	ALG string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// SerializeJWKS converts RSA public keys into a JWKS structure.
// Keys are sorted by kid for deterministic output.
func SerializeJWKS(keys map[string]*rsa.PublicKey) JWKS {
	// Collect and sort kids for deterministic ordering
	kids := make([]string, 0, len(keys))
	for kid := range keys {
		kids = append(kids, kid)
	}
	sort.Strings(kids)

	jwks := JWKS{Keys: make([]JWK, 0, len(keys))}
	for _, kid := range kids {
		pub := keys[kid]
		jwks.Keys = append(jwks.Keys, JWK{
			KTY: "RSA",
			Use: "sig",
			KID: kid,
			ALG: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(encodeRSAExponent(pub.E)),
		})
	}
	return jwks
}

// encodeRSAExponent encodes an RSA public exponent as a minimal big-endian
// unsigned integer byte slice, which is the correct representation for JWK.
// Handles exponents up to 2^32-1 (standard RSA uses 65537, but we don't
// silently truncate larger values).
func encodeRSAExponent(e int) []byte {
	if e < 256 {
		return []byte{byte(e & 0xff)} // #nosec G115 -- bounded by e < 256
	}
	if e < 65536 {
		return []byte{byte((e >> 8) & 0xff), byte(e & 0xff)} // #nosec G115 -- bounded by e < 65536
	}
	if e < 1<<24 {
		return []byte{byte((e >> 16) & 0xff), byte((e >> 8) & 0xff), byte(e & 0xff)} // #nosec G115 -- bounded by e < 2^24
	}
	return []byte{byte((e >> 24) & 0xff), byte((e >> 16) & 0xff), byte((e >> 8) & 0xff), byte(e & 0xff)} // #nosec G115 -- int exponent fits 4 bytes
}

// SerializeJWKSJSON returns the JWKS as JSON bytes.
func SerializeJWKSJSON(keys map[string]*rsa.PublicKey) ([]byte, error) {
	return json.Marshal(SerializeJWKS(keys))
}
