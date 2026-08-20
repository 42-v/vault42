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

// A proof that is not a JWT at all never reaches the claim checks, so the size
// guard and the parse failure are pinned on raw strings.
func TestValidateDPoPProofRejectsNonJWTInput(t *testing.T) {
	tests := []struct {
		name  string
		proof string
		// wantErr is the message the case must produce; wantNotErr is one it must
		// not, for the boundary case that has to fail for a different reason.
		wantErr, wantNotErr string
	}{
		{
			name:    "one byte over the size cap",
			proof:   strings.Repeat("A", DPoPMaxSize+1),
			wantErr: "exceeds maximum size",
		},
		{
			// Exactly at the cap is still garbage, but it must be refused for being
			// unparseable rather than for its length, or the cap is off by one.
			name:       "exactly at the size cap",
			proof:      strings.Repeat("A", DPoPMaxSize),
			wantNotErr: "exceeds maximum size",
		},
		{name: "three segments that are not base64 JWT parts", proof: "not.a.jwt"},
		{name: "the empty string", proof: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ValidateDPoPProof(tt.proof, "POST", "https://example.com/token", "")
			if err == nil {
				t.Fatal("ValidateDPoPProof accepted something that is not a proof")
			}
			if tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want one mentioning %q", err, tt.wantErr)
			}
			if tt.wantNotErr != "" && strings.Contains(err.Error(), tt.wantNotErr) {
				t.Errorf("error = %v, want one NOT mentioning %q", err, tt.wantNotErr)
			}
		})
	}
}

// Every dimension a DPoP proof commits to gets its own row: the typ and kid and
// jwk headers, the jti, the iat window, and the htm/htu the proof is bound to.
// They are separate rows and not one "malformed proof" case because each is a
// different attack -- a reused jti is a replay, a wrong htu is the proof being
// forwarded to another endpoint, and a missing jwk is no binding at all.
//
// One key for the whole table: the cases are about the claims, and the twelve
// separate 2048-bit generations this replaced were the slowest thing in the
// package's unit tests.
func TestValidateDPoPProofRejectsBadClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	const uri = "https://example.com/token"

	tests := []struct {
		name string
		// proofMethod and proofURI are what the proof commits to; method and uri
		// are what it is presented against. They differ only in the htm/htu rows.
		proofMethod, proofURI string
		method, uri           string
		ath                   string
		mutate                func(header map[string]any, claims *DPoPClaims)
		wantErr               string
	}{
		{
			name:    "no typ header",
			mutate:  func(h map[string]any, _ *DPoPClaims) { delete(h, "typ") },
			wantErr: "invalid typ",
		},
		{
			// A plain "JWT" typ is what an attacker gets by replaying an ordinary
			// token in the DPoP header slot.
			name:    "a typ of JWT rather than dpop+jwt",
			mutate:  func(h map[string]any, _ *DPoPClaims) { h["typ"] = "JWT" },
			wantErr: "invalid typ",
		},
		{
			// kid points at a key the server holds; the proof key must be the one
			// carried in jwk and nothing else.
			name:    "a kid header",
			mutate:  func(h map[string]any, _ *DPoPClaims) { h["kid"] = "some-kid" },
			wantErr: "kid header not allowed",
		},
		{
			name:    "no jwk header",
			mutate:  func(h map[string]any, _ *DPoPClaims) { delete(h, "jwk") },
			wantErr: "missing jwk",
		},
		{
			// Without a jti there is nothing to record, so every proof replays.
			name:    "no jti claim",
			mutate:  func(_ map[string]any, c *DPoPClaims) { c.ID = "" },
			wantErr: "missing jti",
		},
		{
			name: "an iat in the future",
			mutate: func(_ map[string]any, c *DPoPClaims) {
				c.IssuedAt = vjwt.NewNumericDate(time.Now().Add(10 * time.Minute))
			},
			wantErr: "too old or too far in future",
		},
		{
			name: "an iat just past the age limit",
			mutate: func(_ map[string]any, c *DPoPClaims) {
				c.IssuedAt = vjwt.NewNumericDate(time.Now().Add(-(DPoPMaxAge + 10*time.Second)))
			},
			wantErr: "too old or too far in future",
		},
		{
			name:        "an htm differing only in case",
			proofMethod: "post",
		},
		{
			name:     "an htu naming another path on the same host",
			proofURI: "https://example.com/auth/token",
			uri:      "https://example.com/auth/refresh",
		},
		{
			// http vs https matters: a proof minted for the plaintext endpoint must
			// not be replayable against the TLS one.
			name:     "an htu differing only in scheme",
			proofURI: "http://example.com/token",
		},
		{
			// ath binds the proof to one access token; a mismatch means the proof
			// was minted for a different token than the one presented.
			name:    "an ath over a different access token",
			ath:     "bbbb",
			mutate:  func(_ map[string]any, c *DPoPClaims) { c.ATH = "aaaa" },
			wantErr: "ath mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proofMethod, proofURI := tt.proofMethod, tt.proofURI
			if proofMethod == "" {
				proofMethod = "POST"
			}
			if proofURI == "" {
				proofURI = uri
			}
			method, wantURI := tt.method, tt.uri
			if method == "" {
				method = "POST"
			}
			if wantURI == "" {
				wantURI = uri
			}

			var opts []func(map[string]any, *DPoPClaims)
			if tt.mutate != nil {
				opts = append(opts, tt.mutate)
			}
			proof := createDPoPProof(t, key, proofMethod, proofURI, opts...)

			_, _, err := ValidateDPoPProof(proof, method, wantURI, tt.ath)
			if err == nil {
				t.Fatalf("ValidateDPoPProof accepted a proof with %s", tt.name)
			}
			if tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want one mentioning %q", err, tt.wantErr)
			}
		})
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
// proof is labeled ES384, so WithValidMethods rejects it while the P-384 key
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

// The round-trip variants of these two used to sit further down the file with
// the same key generation and the same N/E and x/y comparisons; they are the
// same case, so they are gone rather than duplicated.
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

// The P-384 case this test used to assert now lives in
// TestParseJWKHeaderRejectsACurveNoDPoPAlgorithmCanVerify, which asserts the
// opposite: parseJWKHeader admits only the curve the algorithms its single
// caller allows can verify. See dpop_jose_test.go for why.

// The jwk header is the attacker's half of a DPoP proof: whatever key it names
// becomes the key the signature is checked against and the key the thumbprint is
// taken over. Every malformed shape has to be refused outright, because the one
// that slips through is a proof carrying a key nobody validated.
//
// The specific message is asserted where the parser has one, since these
// branches sit in a chain and a case that failed for the wrong reason would
// still return an error and still look green.
func TestParseJWKHeaderRejectsMalformedKeys(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString
	zeros := func(n int) string { return b64(make([]byte, n)) }

	tests := []struct {
		name    string
		jwk     interface{}
		wantErr string
	}{
		{name: "not a map at all", jwk: "not-a-map", wantErr: "invalid jwk header format"},
		{name: "nil", jwk: nil, wantErr: "invalid jwk header format"},
		{name: "an integer", jwk: 42, wantErr: "invalid jwk header format"},
		{name: "a slice", jwk: []string{"not", "a", "map"}, wantErr: "invalid jwk header format"},
		{name: "an empty map", jwk: map[string]interface{}{}, wantErr: "unsupported key type"},
		{
			name:    "no kty",
			jwk:     map[string]interface{}{"n": b64([]byte{1, 2, 3}), "e": b64([]byte{1, 0, 1})},
			wantErr: "unsupported key type",
		},
		{
			// OKP/Ed25519 is a real JWK type, just not one any DPoP algorithm here
			// can verify.
			name:    "a kty outside RSA and EC",
			jwk:     map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": b64([]byte{1, 2, 3})},
			wantErr: "unsupported key type",
		},
		{
			// Absent n leaves a zero modulus, caught by the 2048-bit minimum.
			name: "RSA with no modulus",
			jwk:  map[string]interface{}{"kty": "RSA", "e": b64([]byte{1, 0, 1})},
		},
		{
			// Absent e leaves a zero exponent, and the token modulus is undersized too.
			name: "RSA with no exponent",
			jwk:  map[string]interface{}{"kty": "RSA", "n": b64([]byte{1, 2, 3})},
		},
		{
			name:    "RSA with a modulus that is not base64",
			jwk:     map[string]interface{}{"kty": "RSA", "n": "!!!invalid-base64!!!", "e": b64([]byte{1, 0, 1})},
			wantErr: "decode n",
		},
		{
			name:    "RSA with an exponent that is not base64",
			jwk:     map[string]interface{}{"kty": "RSA", "n": b64([]byte{1, 2, 3}), "e": "!!!invalid-base64!!!"},
			wantErr: "decode e",
		},
		{
			// A zero coordinate is not a point on P-256, so the IsOnCurve check
			// catches an absent x or y rather than admitting the origin.
			name: "EC with no x coordinate",
			jwk:  map[string]interface{}{"kty": "EC", "crv": "P-256", "y": zeros(32)},
		},
		{
			name: "EC with no y coordinate",
			jwk:  map[string]interface{}{"kty": "EC", "crv": "P-256", "x": zeros(32)},
		},
		{
			name:    "EC with an x coordinate that is not base64",
			jwk:     map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "!!!bad-base64!!!", "y": zeros(32)},
			wantErr: "decode x",
		},
		{
			name:    "EC with a y coordinate that is not base64",
			jwk:     map[string]interface{}{"kty": "EC", "crv": "P-256", "x": zeros(32), "y": "!!!bad-base64!!!"},
			wantErr: "decode y",
		},
		{
			name:    "EC on a curve no DPoP algorithm can verify",
			jwk:     map[string]interface{}{"kty": "EC", "crv": "P-521", "x": zeros(66), "y": zeros(66)},
			wantErr: "unsupported curve",
		},
		{
			name:    "EC with no crv",
			jwk:     map[string]interface{}{"kty": "EC", "x": zeros(32), "y": zeros(32)},
			wantErr: "unsupported curve",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := parseJWKHeader(tt.jwk)
			if err == nil {
				t.Fatalf("parseJWKHeader returned key %T for a malformed jwk header", key)
			}
			if tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want one mentioning %q", err, tt.wantErr)
			}
		})
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
