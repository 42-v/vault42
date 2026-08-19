package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

// TestVerifyES256RejectsAKeyOnACurveOtherThanP256 pins the one curve RFC 7518
// 3.4 assigns to the ES256 identifier. Without the check, VerifyES256 derives
// the expected raw signature length from whatever curve the caller's key
// happens to sit on, so a P-384 or P-521 key verifies a signature the token
// still labels ES256.
//
// What that costs in production: the ES256 path exists for DPoP, where the
// proof carries its own key in the jwk header and the binding to the access
// token is the RFC 7638 thumbprint of that key. The thumbprint covers the curve
// name, so vault42 and any conforming relying party would disagree about which
// proofs are valid the moment cnf.jkt binding is switched on, and a proof
// vault42 accepted would be refused everywhere else. Pinning the curve also
// removes the more general shape of the bug, where the algorithm label and the
// key that answers it are allowed to describe different primitives.
func TestVerifyES256RejectsAKeyOnACurveOtherThanP256(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P384(), elliptic.P521()} {
		name := curve.Params().Name
		t.Run(name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatalf("generate %s key: %v", name, err)
			}
			msg := "header.payload"
			digest := sha256.Sum256([]byte(msg))

			byteLen := (curve.Params().BitSize + 7) / 8
			r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			raw := make([]byte, 2*byteLen)
			r.FillBytes(raw[:byteLen])
			s.FillBytes(raw[byteLen:])

			if err := VerifyES256(msg, raw, &key.PublicKey); !errors.Is(err, ErrInvalidKeyType) {
				t.Errorf("raw r||s on %s: err = %v, want ErrInvalidKeyType", name, err)
			}

			der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
			if err != nil {
				t.Fatalf("sign ASN.1: %v", err)
			}
			if err := VerifyES256(msg, der, &key.PublicKey); !errors.Is(err, ErrInvalidKeyType) {
				t.Errorf("ASN.1 signature on %s: err = %v, want ErrInvalidKeyType", name, err)
			}
		})
	}
}

// TestParseWithClaimsRejectsAnES256TokenSignedOverANonP256Curve drives the same
// property through the parser, which is the surface an attacker reaches. A DPoP
// proof header names alg ES256 and hands the verifier a P-384 key of the
// attacker's choosing; the parse must fail rather than confirm a proof no other
// RFC 9449 implementation would honor.
func TestParseWithClaimsRejectsAnES256TokenSignedOverANonP256Curve(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	claims := &RegisteredClaims{
		Subject:   "user-1",
		ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
	}
	token, err := SignTokenCustom(map[string]any{"alg": "ES256", "typ": "dpop+jwt"}, claims,
		func(signingString string) ([]byte, error) {
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
		t.Fatalf("build token: %v", err)
	}

	parsed, err := ParseWithClaims(token, &RegisteredClaims{}, func(*Token) (any, error) {
		return &key.PublicKey, nil
	}, WithValidMethods([]string{"RS256", "ES256"}))
	if err == nil {
		t.Fatal("an ES256 token verified against a P-384 key was accepted")
	}
	if parsed != nil && parsed.Valid {
		t.Error("a token verified on the wrong curve was marked valid")
	}
}

// TestVerifyES256StillAcceptsAGenuineP256Signature is the counterweight to the
// curve check. If pinning the curve also rejected P-256, DPoP proofs from every
// browser WebCrypto client would stop verifying.
func TestVerifyES256StillAcceptsAGenuineP256Signature(t *testing.T) {
	key := mustGenECKey(t)
	msg := "header.payload"
	if err := VerifyES256(msg, signES256ASN1(t, msg, key), &key.PublicKey); err != nil {
		t.Fatalf("a genuine P-256 signature was rejected: %v", err)
	}

	digest := sha256.Sum256([]byte(msg))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	if err := VerifyES256(msg, raw, &key.PublicKey); err != nil {
		t.Fatalf("a genuine raw r||s P-256 signature was rejected: %v", err)
	}
}
