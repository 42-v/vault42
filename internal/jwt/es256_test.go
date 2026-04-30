package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
)

func mustGenECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	return key
}

func signES256ASN1(t *testing.T, msg string, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	hash := sha256.Sum256([]byte(msg))
	sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

func TestES256_Verify(t *testing.T) {
	key := mustGenECKey(t)
	msg := "header.payload"
	sig := signES256ASN1(t, msg, key)

	if err := VerifyES256(msg, sig, &key.PublicKey); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestES256_WrongKey(t *testing.T) {
	key1 := mustGenECKey(t)
	key2 := mustGenECKey(t)
	msg := "header.payload"
	sig := signES256ASN1(t, msg, key1)

	if err := VerifyES256(msg, sig, &key2.PublicKey); err == nil {
		t.Fatal("expected error with wrong key, got nil")
	}
}

func TestES256_TamperedSignature(t *testing.T) {
	key := mustGenECKey(t)
	msg := "header.payload"
	sig := signES256ASN1(t, msg, key)

	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[len(tampered)-1] ^= 0xff

	if err := VerifyES256(msg, tampered, &key.PublicKey); err == nil {
		t.Fatal("expected error with tampered signature, got nil")
	}
}

func TestES256_RawRS_Format(t *testing.T) {
	key := mustGenECKey(t)
	msg := "header.payload"

	// Sign with ASN.1 first, then convert to raw R||S
	hash := sha256.Sum256([]byte(msg))
	derSig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Parse ASN.1 to get R and S
	var rs struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(derSig, &rs); err != nil {
		t.Fatalf("unmarshal ASN1: %v", err)
	}

	// Build raw R||S (32 bytes each for P-256)
	rawSig := make([]byte, 64)
	rBytes := rs.R.Bytes()
	sBytes := rs.S.Bytes()
	copy(rawSig[32-len(rBytes):32], rBytes)
	copy(rawSig[64-len(sBytes):64], sBytes)

	if err := VerifyES256(msg, rawSig, &key.PublicKey); err != nil {
		t.Fatalf("verify raw R||S: %v", err)
	}
}

func TestES256_ASN1DER_Format(t *testing.T) {
	key := mustGenECKey(t)
	msg := "test.data"
	sig := signES256ASN1(t, msg, key)

	// ASN1 DER should work directly
	if err := VerifyES256(msg, sig, &key.PublicKey); err != nil {
		t.Fatalf("verify ASN1 DER: %v", err)
	}
}

func TestES256_NilKey(t *testing.T) {
	if err := VerifyES256("test", []byte("sig"), nil); err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestES256_TamperedData(t *testing.T) {
	key := mustGenECKey(t)
	msg := "header.payload"
	sig := signES256ASN1(t, msg, key)

	if err := VerifyES256("header.TAMPERED", sig, &key.PublicKey); err == nil {
		t.Fatal("expected error with tampered data, got nil")
	}
}
