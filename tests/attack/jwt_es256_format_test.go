package attack

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"

	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestJWT_ES256_MalformedDER verifies that random bytes fail ES256 verification.
func TestJWT_ES256_MalformedDER(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Random bytes that aren't valid DER or raw R||S
	sig := make([]byte, 71) // DER-ish length but random
	if _, err := rand.Read(sig); err != nil {
		t.Fatal(err)
	}

	err = vjwt.VerifyES256("test-signing-string", sig, &key.PublicKey)
	if err == nil {
		t.Fatal("Malformed DER signature should be rejected")
	}
}

// TestJWT_ES256_LeadingZeros verifies handling of signature with leading zero bytes.
func TestJWT_ES256_LeadingZeros(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create a valid signature first, then prepend zeros to the raw R||S format
	signingString := "test-signing-string"
	hash := sha256.Sum256([]byte(signingString))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatal(err)
	}

	// Build raw R||S with leading zeros (32 bytes each, zero-padded)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	rawSig := make([]byte, 64)
	copy(rawSig[32-len(rBytes):32], rBytes)
	copy(rawSig[64-len(sBytes):64], sBytes)

	err = vjwt.VerifyES256(signingString, rawSig, &key.PublicKey)
	if err != nil {
		t.Fatalf("Valid ES256 signature with zero-padded R||S should verify: %v", err)
	}
}

// TestJWT_ES256_WrongCurve verifies that a P-384 key fails ES256 verification.
func TestJWT_ES256_WrongCurve(t *testing.T) {
	// Generate P-384 key (wrong curve for ES256 which uses P-256)
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Generate P-256 key for signing
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signingString := "test-signing-string"
	hash := sha256.Sum256([]byte(signingString))
	r, s, err := ecdsa.Sign(rand.Reader, p256Key, hash[:])
	if err != nil {
		t.Fatal(err)
	}

	// Build raw R||S (P-256 = 32 bytes each)
	rawSig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(rawSig[32-len(rBytes):32], rBytes)
	copy(rawSig[64-len(sBytes):64], sBytes)

	// Verify with P-384 key — should fail
	err = vjwt.VerifyES256(signingString, rawSig, &p384Key.PublicKey)
	if err == nil {
		t.Fatal("ES256 verification with P-384 key should fail")
	}
}

// TestJWT_ES256_ZeroSignature verifies that 64 zero bytes fail verification.
func TestJWT_ES256_ZeroSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// 64 zero bytes (raw R||S format, both R and S are zero)
	sig := make([]byte, 64)

	err = vjwt.VerifyES256("test-signing-string", sig, &key.PublicKey)
	if err == nil {
		t.Fatal("Zero signature should be rejected")
	}
}

// TestJWT_ES256_Truncated verifies that a truncated signature (32 bytes) is rejected.
func TestJWT_ES256_Truncated(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Only 32 bytes — half of what's needed for R||S
	sig := make([]byte, 32)
	if _, err := rand.Read(sig); err != nil {
		t.Fatal(err)
	}

	err = vjwt.VerifyES256("test-signing-string", sig, &key.PublicKey)
	if err == nil {
		t.Fatal("Truncated 32-byte signature should be rejected")
	}
}

// TestJWT_ES256_Oversized verifies that a 128-byte signature is rejected.
func TestJWT_ES256_Oversized(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// 128 bytes — too long for P-256 raw R||S (64 bytes) or typical DER (~70 bytes)
	// Build a valid-ish DER structure but with oversized values
	r := new(big.Int).SetBytes(make([]byte, 48)) // too large for P-256
	s := new(big.Int).SetBytes(make([]byte, 48))
	r.SetBit(r, 380, 1) // make non-zero
	s.SetBit(s, 380, 1)
	derSig, _ := asn1.Marshal(struct{ R, S *big.Int }{r, s})

	err = vjwt.VerifyES256("test-signing-string", derSig, &key.PublicKey)
	if err == nil {
		t.Fatal("Oversized signature should be rejected")
	}
}
