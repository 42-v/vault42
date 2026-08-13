package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestValidateDPoPProofRejectsAnES256ProofCarryingAP384Key covers the case
// TestDPoPValidProofECP384NotAllowed only appears to cover.
//
// That test labels its proof alg ES384, so WithValidMethods refuses it before
// any key is looked at and the assertion holds no matter what the ES256
// verifier does with a P-384 key. The reachable shape is the one below: alg
// ES256, which is on the DPoP allowlist, over a jwk that declares crv P-384.
// parseJWKHeader accepts P-384 for ES384-style proofs, so the key reaches the
// ES256 verifier, and if that verifier sizes the raw signature from the key's
// own curve instead of the one the algorithm names, a 96-byte P-384 signature
// verifies under an ES256 header.
//
// What that costs in production: the thumbprint this function returns is the
// binding an access token's cnf.jkt is compared against, and RFC 7638 includes
// the curve name in the thumbprint. Accepting a proof whose algorithm and key
// describe different curves means vault42 confirms proofs that no other RFC
// 9449 implementation will, so the two sides stop agreeing on which key a token
// is bound to.
func TestValidateDPoPProofRejectsAnES256ProofCarryingAP384Key(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	x, y := ecCoords(&key.PublicKey)

	claims := &DPoPClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			IssuedAt: vjwt.NewNumericDate(time.Now()),
			ID:       "jti-es256-over-p384",
		},
		HTM: "POST",
		HTU: "https://vault.example.com/auth/token",
	}

	proof, err := vjwt.SignTokenCustom(map[string]any{
		"alg": "ES256",
		"typ": "dpop+jwt",
		"jwk": map[string]any{
			"kty": "EC",
			"crv": "P-384",
			"x":   base64.RawURLEncoding.EncodeToString(x),
			"y":   base64.RawURLEncoding.EncodeToString(y),
		},
	}, claims, func(signingString string) ([]byte, error) {
		digest := sha256.Sum256([]byte(signingString))
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			return nil, err
		}
		raw := make([]byte, 96)
		r.FillBytes(raw[:48])
		s.FillBytes(raw[48:])
		return raw, nil
	})
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}

	thumbprint, jti, err := ValidateDPoPProof(proof, "POST", "https://vault.example.com/auth/token", "")
	if err == nil {
		t.Fatalf("an ES256 proof signed on P-384 was accepted (thumbprint %q, jti %q)", thumbprint, jti)
	}
	if thumbprint != "" || jti != "" {
		t.Errorf("a rejected proof returned thumbprint %q and jti %q, want both empty", thumbprint, jti)
	}
}

// TestValidateDPoPProofStillAcceptsAnES256ProofOnP256 is the counterweight: the
// curve check must reject only the mismatched pairing. If it also rejected
// P-256, every browser WebCrypto DPoP client would stop being able to present a
// proof.
func TestValidateDPoPProofStillAcceptsAnES256ProofOnP256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	proof := createDPoPProof(t, key, "GET", "https://vault.example.com/user/profile")

	thumbprint, jti, err := ValidateDPoPProof(proof, "GET", "https://vault.example.com/user/profile", "")
	if err != nil {
		t.Fatalf("a genuine P-256 ES256 proof was rejected: %v", err)
	}
	if thumbprint == "" || jti == "" {
		t.Errorf("thumbprint = %q, jti = %q, want both non-empty", thumbprint, jti)
	}
}
