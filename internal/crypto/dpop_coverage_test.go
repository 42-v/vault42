package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	vjwt "github.com/42-v/vault42/internal/jwt"
)

// ecCoords returns the padded X and Y byte coordinates of an EC public key via
// the ecdh bridge, avoiding the Go 1.26 ecdsa.PublicKey.X/Y deprecation.
func ecCoords(pub *ecdsa.PublicKey) (x, y []byte) {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	ecdhPub, _ := pub.ECDH()
	raw := ecdhPub.Bytes()
	return raw[1 : 1+byteLen], raw[1+byteLen:]
}

func sha384Hash(data []byte) []byte {
	h := sha512.Sum384(data)
	return h[:]
}

// ---------------------------------------------------------------------------
// ValidateDPoPProof edge cases
// ---------------------------------------------------------------------------

func TestDPoPProofTooLarge(t *testing.T) {
	// Proof exceeding DPoPMaxSize (4096 bytes)
	oversized := strings.Repeat("A", DPoPMaxSize+1)
	_, _, err := ValidateDPoPProof(oversized, "POST", "https://example.com/token", "")
	if err == nil {
		t.Error("oversized proof should be rejected")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("error should mention max size, got: %v", err)
	}
}

func TestDPoPProofExactMaxSize(t *testing.T) {
	// A string of exactly DPoPMaxSize — won't be valid JWT but should not be rejected for size
	exact := strings.Repeat("A", DPoPMaxSize)
	_, _, err := ValidateDPoPProof(exact, "POST", "https://example.com/token", "")
	if err == nil {
		t.Error("invalid JWT should still fail, just not for size")
	}
	if strings.Contains(err.Error(), "exceeds maximum size") {
		t.Error("exactly DPoPMaxSize should not trigger size error")
	}
}

func TestDPoPMalformedJWT(t *testing.T) {
	_, _, err := ValidateDPoPProof("not.a.jwt", "GET", "https://example.com/", "")
	if err == nil {
		t.Error("malformed JWT should be rejected")
	}
}

func TestDPoPMissingTypHeader(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Create a proof without the typ header
	proof := createDPoPProof(t, key, "POST", "https://example.com/token",
		func(header map[string]any, claims *DPoPClaims) {
			delete(header, "typ")
		})

	_, _, err := ValidateDPoPProof(proof, "POST", "https://example.com/token", "")
	if err == nil {
		t.Error("missing typ header should be rejected")
	}
	if !strings.Contains(err.Error(), "invalid typ") {
		t.Errorf("error should mention typ, got: %v", err)
	}
}

func TestDPoPWrongTypHeader(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	proof := createDPoPProof(t, key, "POST", "https://example.com/token",
		func(header map[string]any, claims *DPoPClaims) {
			header["typ"] = "JWT" // wrong typ
		})

	_, _, err := ValidateDPoPProof(proof, "POST", "https://example.com/token", "")
	if err == nil {
		t.Error("wrong typ header should be rejected")
	}
}

func TestDPoPKidHeaderRejected(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	proof := createDPoPProof(t, key, "POST", "https://example.com/token",
		func(header map[string]any, claims *DPoPClaims) {
			header["kid"] = "some-kid"
		})

	_, _, err := ValidateDPoPProof(proof, "POST", "https://example.com/token", "")
	if err == nil {
		t.Error("kid header should not be allowed in DPoP proof")
	}
	if !strings.Contains(err.Error(), "kid header not allowed") {
		t.Errorf("error should mention kid, got: %v", err)
	}
}

func TestDPoPMissingJWKHeader(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	proof := createDPoPProof(t, key, "POST", "https://example.com/token",
		func(header map[string]any, claims *DPoPClaims) {
			delete(header, "jwk")
		})

	_, _, err := ValidateDPoPProof(proof, "POST", "https://example.com/token", "")
	if err == nil {
		t.Error("missing jwk header should be rejected")
	}
	if !strings.Contains(err.Error(), "missing jwk") {
		t.Errorf("error should mention missing jwk, got: %v", err)
	}
}

func TestDPoPMissingJTIClaim(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	proof := createDPoPProof(t, key, "POST", "https://example.com/token",
		func(header map[string]any, claims *DPoPClaims) {
			claims.ID = ""
		})

	_, _, err := ValidateDPoPProof(proof, "POST", "https://example.com/token", "")
	if err == nil {
		t.Error("missing jti should be rejected")
	}
	if !strings.Contains(err.Error(), "missing jti") {
		t.Errorf("error should mention jti, got: %v", err)
	}
}

func TestDPoPProofFutureIAT(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	proof := createDPoPProof(t, key, "POST", "https://example.com/token",
		func(header map[string]any, claims *DPoPClaims) {
			claims.IssuedAt = vjwt.NewNumericDate(time.Now().Add(10 * time.Minute))
		})

	_, _, err := ValidateDPoPProof(proof, "POST", "https://example.com/token", "")
	if err == nil {
		t.Error("proof with future iat should be rejected")
	}
	if !strings.Contains(err.Error(), "too old or too far in future") {
		t.Errorf("error should mention age, got: %v", err)
	}
}

func TestDPoPProofJustExpired(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	// iat just over 5 minutes ago
	proof := createDPoPProof(t, key, "POST", "https://example.com/token",
		func(header map[string]any, claims *DPoPClaims) {
			claims.IssuedAt = vjwt.NewNumericDate(time.Now().Add(-(DPoPMaxAge + 10*time.Second)))
		})

	_, _, err := ValidateDPoPProof(proof, "POST", "https://example.com/token", "")
	if err == nil {
		t.Error("proof just over max age should be rejected")
	}
}

func TestDPoPProofFreshIAT(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	// iat just under DPoPMaxAge ago — should be accepted
	proof := createDPoPProof(t, key, "POST", "https://example.com/token",
		func(header map[string]any, claims *DPoPClaims) {
			claims.IssuedAt = vjwt.NewNumericDate(time.Now().Add(-(DPoPMaxAge - 30*time.Second)))
		})

	_, _, err := ValidateDPoPProof(proof, "POST", "https://example.com/token", "")
	if err != nil {
		t.Errorf("proof within max age should be accepted: %v", err)
	}
}

func TestDPoPHTMCaseSensitive(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	proof := createDPoPProof(t, key, "post", "https://example.com/token")
	_, _, err := ValidateDPoPProof(proof, "POST", "https://example.com/token", "")
	if err == nil {
		t.Error("htm comparison should be case-sensitive")
	}
}

func TestDPoPHTUPathMismatch(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	proof := createDPoPProof(t, key, "POST", "https://example.com/auth/token")
	_, _, err := ValidateDPoPProof(proof, "POST", "https://example.com/auth/refresh", "")
	if err == nil {
		t.Error("different path should fail htu check")
	}
}

func TestDPoPHTUSchemeMismatch(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	proof := createDPoPProof(t, key, "POST", "http://example.com/token")
	_, _, err := ValidateDPoPProof(proof, "POST", "https://example.com/token", "")
	if err == nil {
		t.Error("scheme mismatch should fail htu check")
	}
}

func TestDPoPJWKMismatchSignatureKey(t *testing.T) {
	// Sign with key1 but put key2's JWK in the header
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)

	claims := &DPoPClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			IssuedAt: vjwt.NewNumericDate(time.Now()),
			ID:       "test-jti-mismatch",
		},
		HTM: "POST",
		HTU: "https://example.com/token",
	}

	// Put key2's public key in the jwk header, but sign with key1
	proofStr, err := vjwt.SignRS256WithHeader(map[string]any{
		"alg": "RS256",
		"typ": "dpop+jwt",
		"jwk": map[string]any{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(key2.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key2.PublicKey.E)).Bytes()),
		},
	}, claims, key1)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = ValidateDPoPProof(proofStr, "POST", "https://example.com/token", "")
	if err == nil {
		t.Error("JWK not matching signing key should be rejected")
	}
}

// TestDPoPProofNamingES384IsRejectedByTheAlgorithmAllowlist pins that the
// allowlist refuses ES384 outright, before any key is looked at.
//
// The name matters because this test cannot say anything about curves. The
// proof is labelled ES384, so WithValidMethods rejects it while the P-384 key
// below is still unread, and the test passes with the ES256 curve check deleted
// entirely. It was previously named for the curve, which read as coverage of a
// property nothing here exercises.
//
// The curve property lives in TestValidateDPoPProofRejectsAnES256ProofCarrying
// AP384Key, where the proof claims ES256 and the key is the thing that has to be
// caught.
func TestDPoPProofNamingES384IsRejectedByTheAlgorithmAllowlist(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	// ES384 is not in the allowed methods, which is what this asserts.
	claims := &DPoPClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			IssuedAt: vjwt.NewNumericDate(time.Now()),
			ID:       "test-jti-p384",
		},
		HTM: "POST",
		HTU: "https://example.com/token",
	}

	xPadded, yPadded := ecCoords(&key.PublicKey)

	proofStr, _ := vjwt.SignTokenCustom(map[string]any{
		"alg": "ES384",
		"typ": "dpop+jwt",
		"jwk": map[string]any{
			"kty": "EC",
			"crv": "P-384",
			"x":   base64.RawURLEncoding.EncodeToString(xPadded),
			"y":   base64.RawURLEncoding.EncodeToString(yPadded),
		},
	}, claims, func(signingString string) ([]byte, error) {
		hash := sha384Hash([]byte(signingString))
		return ecdsa.SignASN1(rand.Reader, key, hash)
	})

	_, _, err := ValidateDPoPProof(proofStr, "POST", "https://example.com/token", "")
	if err == nil {
		t.Error("ES384 should not be in allowed methods for DPoP")
	}
}

func TestDPoPATHMismatchConstantTime(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	proof := createDPoPProof(t, key, "POST", "https://example.com/token",
		func(header map[string]any, claims *DPoPClaims) {
			claims.ATH = "aaaa"
		})

	_, _, err := ValidateDPoPProof(proof, "POST", "https://example.com/token", "bbbb")
	if err == nil {
		t.Error("ath mismatch should be rejected")
	}
	if !strings.Contains(err.Error(), "ath mismatch") {
		t.Errorf("error should mention ath, got: %v", err)
	}
}

func TestDPoPValidECProofThumbprintDeterministic(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	proof1 := createDPoPProof(t, key, "GET", "https://example.com/api")
	tp1, _, err := ValidateDPoPProof(proof1, "GET", "https://example.com/api", "")
	if err != nil {
		t.Fatal(err)
	}

	proof2 := createDPoPProof(t, key, "GET", "https://example.com/api")
	tp2, _, err := ValidateDPoPProof(proof2, "GET", "https://example.com/api", "")
	if err != nil {
		t.Fatal(err)
	}

	if tp1 != tp2 {
		t.Error("same key should produce same thumbprint across proofs")
	}
}

// ---------------------------------------------------------------------------
// parseJWKHeader tests
// ---------------------------------------------------------------------------

func TestParseJWKHeaderValidRSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := map[string]interface{}{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}

	pubKey, err := parseJWKHeader(jwk)
	if err != nil {
		t.Fatalf("valid RSA JWK should parse: %v", err)
	}
	rsaKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("should return *rsa.PublicKey")
	}
	if rsaKey.N.Cmp(key.N) != 0 {
		t.Error("N mismatch")
	}
	if rsaKey.E != key.E {
		t.Error("E mismatch")
	}
}

func TestParseJWKHeaderValidECP256(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	xPadded, yPadded := ecCoords(&key.PublicKey)

	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xPadded),
		"y":   base64.RawURLEncoding.EncodeToString(yPadded),
	}

	pubKey, err := parseJWKHeader(jwk)
	if err != nil {
		t.Fatalf("valid EC P-256 JWK should parse: %v", err)
	}
	ecKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("should return *ecdsa.PublicKey")
	}
	ecX, ecY := ecCoords(ecKey)
	if !bytes.Equal(ecX, xPadded) || !bytes.Equal(ecY, yPadded) {
		t.Error("EC key coordinates mismatch")
	}
	if ecKey.Curve != elliptic.P256() {
		t.Error("curve should be P-256")
	}
}

func TestParseJWKHeaderValidECP384(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	xPadded, yPadded := ecCoords(&key.PublicKey)

	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-384",
		"x":   base64.RawURLEncoding.EncodeToString(xPadded),
		"y":   base64.RawURLEncoding.EncodeToString(yPadded),
	}

	pubKey, err := parseJWKHeader(jwk)
	if err != nil {
		t.Fatalf("valid EC P-384 JWK should parse: %v", err)
	}
	ecKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("should return *ecdsa.PublicKey")
	}
	if ecKey.Curve != elliptic.P384() {
		t.Error("curve should be P-384")
	}
}

func TestParseJWKHeaderMissingKTY(t *testing.T) {
	jwk := map[string]interface{}{
		"n": base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}),
		"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}

	_, err := parseJWKHeader(jwk)
	if err == nil {
		t.Error("missing kty should fail")
	}
	if !strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("error should mention key type, got: %v", err)
	}
}

func TestParseJWKHeaderInvalidKTY(t *testing.T) {
	jwk := map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}),
	}

	_, err := parseJWKHeader(jwk)
	if err == nil {
		t.Error("unsupported kty should fail")
	}
	if !strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("error should mention unsupported, got: %v", err)
	}
}

func TestParseJWKHeaderRSAMissingN(t *testing.T) {
	jwk := map[string]interface{}{
		"kty": "RSA",
		"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}

	// Missing N produces a zero-bit RSA key, which is now correctly rejected
	// by the minimum 2048-bit key size validation (H-2 fix).
	_, err := parseJWKHeader(jwk)
	if err == nil {
		t.Error("empty N should error due to RSA key size validation")
	}
}

func TestParseJWKHeaderRSAMissingE(t *testing.T) {
	jwk := map[string]interface{}{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}),
	}

	// Missing E produces a zero exponent (and the small N also fails size check),
	// both of which are now correctly rejected by validation (H-2/H-4 fix).
	_, err := parseJWKHeader(jwk)
	if err == nil {
		t.Error("empty E with small N should error due to key validation")
	}
}

func TestParseJWKHeaderRSAMalformedN(t *testing.T) {
	jwk := map[string]interface{}{
		"kty": "RSA",
		"n":   "!!!invalid-base64!!!",
		"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}

	_, err := parseJWKHeader(jwk)
	if err == nil {
		t.Error("malformed N base64 should fail")
	}
	if !strings.Contains(err.Error(), "decode n") {
		t.Errorf("error should mention n decode, got: %v", err)
	}
}

func TestParseJWKHeaderRSAMalformedE(t *testing.T) {
	jwk := map[string]interface{}{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}),
		"e":   "!!!invalid-base64!!!",
	}

	_, err := parseJWKHeader(jwk)
	if err == nil {
		t.Error("malformed E base64 should fail")
	}
	if !strings.Contains(err.Error(), "decode e") {
		t.Errorf("error should mention e decode, got: %v", err)
	}
}

func TestParseJWKHeaderECMissingX(t *testing.T) {
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"y":   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}

	// Zero X is not on the curve — IsOnCurve check rejects it
	_, err := parseJWKHeader(jwk)
	if err == nil {
		t.Error("missing X should error due to invalid EC point")
	}
}

func TestParseJWKHeaderECMissingY(t *testing.T) {
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}

	// Zero Y is not on the curve — IsOnCurve check rejects it
	_, err := parseJWKHeader(jwk)
	if err == nil {
		t.Error("missing Y should error due to invalid EC point")
	}
}

func TestParseJWKHeaderECMalformedX(t *testing.T) {
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "!!!bad-base64!!!",
		"y":   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}

	_, err := parseJWKHeader(jwk)
	if err == nil {
		t.Error("malformed X base64 should fail")
	}
	if !strings.Contains(err.Error(), "decode x") {
		t.Errorf("error should mention x decode, got: %v", err)
	}
}

func TestParseJWKHeaderECMalformedY(t *testing.T) {
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		"y":   "!!!bad-base64!!!",
	}

	_, err := parseJWKHeader(jwk)
	if err == nil {
		t.Error("malformed Y base64 should fail")
	}
	if !strings.Contains(err.Error(), "decode y") {
		t.Errorf("error should mention y decode, got: %v", err)
	}
}

func TestParseJWKHeaderUnsupportedCurve(t *testing.T) {
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-521",
		"x":   base64.RawURLEncoding.EncodeToString(make([]byte, 66)),
		"y":   base64.RawURLEncoding.EncodeToString(make([]byte, 66)),
	}

	_, err := parseJWKHeader(jwk)
	if err == nil {
		t.Error("unsupported curve should fail")
	}
	if !strings.Contains(err.Error(), "unsupported curve") {
		t.Errorf("error should mention unsupported curve, got: %v", err)
	}
}

func TestParseJWKHeaderECMissingCRV(t *testing.T) {
	jwk := map[string]interface{}{
		"kty": "EC",
		"x":   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		"y":   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}

	_, err := parseJWKHeader(jwk)
	if err == nil {
		t.Error("missing crv should fail")
	}
	if !strings.Contains(err.Error(), "unsupported curve") {
		t.Errorf("error should mention curve, got: %v", err)
	}
}

func TestParseJWKHeaderNotAMap(t *testing.T) {
	_, err := parseJWKHeader("not-a-map")
	if err == nil {
		t.Error("non-map input should fail")
	}
	if !strings.Contains(err.Error(), "invalid jwk header format") {
		t.Errorf("error should mention format, got: %v", err)
	}
}

func TestParseJWKHeaderNilInput(t *testing.T) {
	_, err := parseJWKHeader(nil)
	if err == nil {
		t.Error("nil input should fail")
	}
}

func TestParseJWKHeaderEmptyMap(t *testing.T) {
	jwk := map[string]interface{}{}
	_, err := parseJWKHeader(jwk)
	if err == nil {
		t.Error("empty map should fail (no kty)")
	}
}

func TestParseJWKHeaderRSARoundTrip(t *testing.T) {
	// Generate key, encode to JWK, parse back, verify match
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := map[string]interface{}{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}

	pubKey, err := parseJWKHeader(jwk)
	if err != nil {
		t.Fatal(err)
	}

	rsaPub := pubKey.(*rsa.PublicKey)
	if rsaPub.N.Cmp(key.N) != 0 {
		t.Error("round-trip N mismatch")
	}
	if rsaPub.E != key.E {
		t.Error("round-trip E mismatch")
	}
}

func TestParseJWKHeaderECRoundTrip(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	xPadded, yPadded := ecCoords(&key.PublicKey)

	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xPadded),
		"y":   base64.RawURLEncoding.EncodeToString(yPadded),
	}

	pubKey, err := parseJWKHeader(jwk)
	if err != nil {
		t.Fatal(err)
	}

	ecPub := pubKey.(*ecdsa.PublicKey)
	roundX, roundY := ecCoords(ecPub)
	if !bytes.Equal(roundX, xPadded) || !bytes.Equal(roundY, yPadded) {
		t.Error("round-trip EC coordinates mismatch")
	}
}

// ---------------------------------------------------------------------------
// ComputeJWKThumbprint edge cases
// ---------------------------------------------------------------------------

func TestComputeJWKThumbprintUnsupportedKeyType(t *testing.T) {
	// Pass a non-RSA, non-EC key type
	type fakeKey struct{}
	_, err := ComputeJWKThumbprint(fakeKey{})
	if err == nil {
		t.Error("unsupported key type should fail")
	}
	if !strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("error should mention unsupported, got: %v", err)
	}
}

func TestComputeJWKThumbprintECDifferentCurves(t *testing.T) {
	key256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	tp256, err := ComputeJWKThumbprint(&key256.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tp384, err := ComputeJWKThumbprint(&key384.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if tp256 == tp384 {
		t.Error("different curves should produce different thumbprints")
	}
}

func TestComputeJWKThumbprintECSameKeyStable(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	tp1, err := ComputeJWKThumbprint(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tp2, _ := ComputeJWKThumbprint(&key.PublicKey)
	if tp1 != tp2 {
		t.Error("same P-384 key should produce same thumbprint")
	}
}

func TestDPoPProofEmptyString(t *testing.T) {
	_, _, err := ValidateDPoPProof("", "GET", "https://example.com/", "")
	if err == nil {
		t.Error("empty proof string should be rejected")
	}
}

func TestParseJWKHeaderIntegerInput(t *testing.T) {
	_, err := parseJWKHeader(42)
	if err == nil {
		t.Error("integer input should fail")
	}
}

func TestParseJWKHeaderSliceInput(t *testing.T) {
	_, err := parseJWKHeader([]string{"not", "a", "map"})
	if err == nil {
		t.Error("slice input should fail")
	}
}

func TestComputeJWKThumbprintRSADifferentSizes(t *testing.T) {
	key2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	key4096, _ := rsa.GenerateKey(rand.Reader, 4096)

	tp2048, err := ComputeJWKThumbprint(&key2048.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tp4096, err := ComputeJWKThumbprint(&key4096.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if tp2048 == tp4096 {
		t.Error("different key sizes should (almost certainly) produce different thumbprints")
	}
}
