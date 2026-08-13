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
		// are consumed elsewhere: a relying party that honours crit would refuse
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
