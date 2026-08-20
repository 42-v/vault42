package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// ValidateTOTPCode must surface a decode error when the stored secret is not
// valid base32, rather than silently treating it as a non-match.
func TestValidateTOTPCodeBadSecret(t *testing.T) {
	step, err := ValidateTOTPCode("!!!not-base32!!!", "123456", time.Unix(0, 0))
	if err == nil {
		t.Fatal("expected decode error for non-base32 secret")
	}
	if step != -1 {
		t.Errorf("step = %d, want -1 on decode failure", step)
	}
}

// LoadSigningKeyPEM must reject a PEM block whose bytes are not a valid PKCS#8
// private key.
func TestLoadSigningKeyPEMBadDER(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage-der")})
	_, _, err := LoadSigningKeyPEM(pemData)
	if err == nil {
		t.Fatal("expected parse error for non-PKCS8 bytes")
	}
	if !strings.Contains(err.Error(), "parse signing key") {
		t.Errorf("error = %v, want parse signing key", err)
	}
}

// LoadSigningKeyPEM must reject a well-formed PKCS#8 key that is not RSA.
func TestLoadSigningKeyPEMNotRSA(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	_, _, err = LoadSigningKeyPEM(pemData)
	if err == nil {
		t.Fatal("expected error for non-RSA key")
	}
	if !strings.Contains(err.Error(), "not RSA") {
		t.Errorf("error = %v, want not RSA", err)
	}
}

// LoadSigningKeyPEM must reject an RSA key below the 2048-bit minimum.
func TestLoadSigningKeyPEMTooSmall(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(weak)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	_, _, err = LoadSigningKeyPEM(pemData)
	if err == nil {
		t.Fatal("expected error for sub-2048-bit key")
	}
	if !strings.Contains(err.Error(), "too small") {
		t.Errorf("error = %v, want too small", err)
	}
}

// MarshalSigningKeyPEM must surface the PKCS#8 marshal error: x509 validates
// RSA keys during marshaling, so a structurally inconsistent key (a single
// prime) has to be rejected instead of encoded.
func TestMarshalSigningKeyPEMInvalidKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	bad := &rsa.PrivateKey{PublicKey: key.PublicKey, D: key.D, Primes: key.Primes[:1]}

	_, err = MarshalSigningKeyPEM(bad)
	if err == nil {
		t.Fatal("expected marshal error for a single-prime key")
	}
	if !strings.Contains(err.Error(), "marshal signing key") {
		t.Errorf("error = %v, want marshal signing key", err)
	}
}

// encodeRSAExponent must emit four big-endian bytes for exponents that do not
// fit in three bytes.
func TestEncodeRSAExponentFourBytes(t *testing.T) {
	got := encodeRSAExponent(0x01020304)
	want := []byte{0x01, 0x02, 0x03, 0x04}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("byte %d = %d, want %d", i, got[i], want[i])
		}
	}
}

// parseArgon2Hash reaches VerifyPassword's caller only through the error, so
// each malformed segment has to surface its own message rather than one generic
// failure -- an operator reading "invalid hash" cannot tell a corrupted column
// from a wrong algorithm.
//
// The parallelism case is separate from the bounds table in
// argon2_security_test.go because 256 is caught by the uint8 conversion guard,
// before the spec maximum is ever compared.
func TestVerifyPasswordRejectsMalformedHashSegments(t *testing.T) {
	tests := []struct {
		name    string
		hash    string
		wantErr string
	}{
		{
			name:    "parallelism past the uint8 range",
			hash:    "$argon2id$v=19$m=47104,t=1,p=256$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			wantErr: "uint8 range",
		},
		{
			name:    "a salt segment that is not base64",
			hash:    "$argon2id$v=19$m=47104,t=1,p=1$****invalid****$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			wantErr: "decode salt",
		},
		{
			name:    "a digest segment that is not base64",
			hash:    "$argon2id$v=19$m=47104,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$****invalid****",
			wantErr: "decode hash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := VerifyPassword("test-user", tt.hash)
			if ok {
				t.Error("the password verified against a hash that could not be parsed")
			}
			if err == nil {
				t.Fatalf("VerifyPassword returned no error, want one mentioning %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want one mentioning %q", err, tt.wantErr)
			}
		})
	}
}

// parseJWKHeader must reject an RSA JWK whose exponent is below the minimum
// accepted value.
func TestParseJWKHeaderExponentTooSmall(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]interface{}{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString([]byte{0x02}), // e=2, below the minimum of 3
	}
	_, err = parseJWKHeader(jwk)
	if err == nil {
		t.Fatal("expected error for out-of-range RSA exponent")
	}
	if !strings.Contains(err.Error(), "invalid RSA exponent") {
		t.Errorf("error = %v, want invalid RSA exponent", err)
	}
}

// ValidateDPoPProof must reject a signed proof whose jwk header carries an
// undersized RSA modulus, failing during key extraction.
func TestDPoPProofUndersizedJWKModulus(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	// Sign with a valid key but advertise a 1024-bit modulus in the jwk header.
	proof := createDPoPProof(t, key, "POST", "https://example.com/token",
		func(header map[string]any, _ *DPoPClaims) {
			header["jwk"] = map[string]any{
				"kty": "RSA",
				"n":   base64.RawURLEncoding.EncodeToString(weak.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(weak.E)).Bytes()),
			}
		})

	_, _, err = ValidateDPoPProof(proof, "POST", "https://example.com/token", "")
	if err == nil {
		t.Fatal("expected error for undersized jwk modulus")
	}
	if !strings.Contains(err.Error(), "too small") {
		t.Errorf("error = %v, want too small", err)
	}
}

// ValidateDPoPProof must reject a correctly-signed proof that omits the iat
// claim, since proof freshness cannot be established without it.
func TestDPoPProofMissingIAT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	proof := createDPoPProof(t, key, "POST", "https://example.com/token",
		func(_ map[string]any, claims *DPoPClaims) {
			claims.IssuedAt = nil
		})

	_, _, err = ValidateDPoPProof(proof, "POST", "https://example.com/token", "")
	if err == nil {
		t.Fatal("expected error for missing iat claim")
	}
	if !strings.Contains(err.Error(), "missing iat") {
		t.Errorf("error = %v, want missing iat", err)
	}
}
