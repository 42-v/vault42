package attack

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestJWTConfusion_RS256ToHS256_PublicKeyBytes tests the classic RSA/HMAC
// confusion attack where the attacker signs with HS256 using the raw RSA
// public key bytes as the HMAC secret.
func TestJWTConfusion_RS256ToHS256_PublicKeyBytes(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	// Use raw modulus bytes as HMAC key (common attack vector)
	pubKeyBytes := key.N.Bytes()

	header := map[string]string{"alg": "HS256", "typ": "JWT", "kid": kid}
	claims := map[string]interface{}{
		"sub": "admin",
		"iss": "vault",
		"aud": "app",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	payload := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	mac := hmac.New(sha256.New, pubKeyBytes)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	confusedToken := payload + "." + sig

	_, err := vaultcrypto.ParseAndValidate(confusedToken, keyFunc, "vault", "app")
	if err == nil {
		t.Fatal("RS256-to-HS256 confusion attack (raw key bytes) was NOT rejected")
	}
}

// TestJWTConfusion_RS256ToHS256_PKCS1PEM tests confusion with PKCS#1 PEM-encoded
// public key as the HMAC secret.
func TestJWTConfusion_RS256ToHS256_PKCS1PEM(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	pubKeyBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubKeyBytes})

	header := map[string]string{"alg": "HS256", "typ": "JWT", "kid": kid}
	claims := map[string]interface{}{
		"sub": "admin", "iss": "vault", "aud": "app",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	mac := hmac.New(sha256.New, pubKeyPEM)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	_, err := vaultcrypto.ParseAndValidate(payload+"."+sig, keyFunc, "vault", "app")
	if err == nil {
		t.Fatal("RS256-to-HS256 confusion attack (PKCS1 PEM) was NOT rejected")
	}
}

// TestJWTConfusion_RS256ToHS256_PKIX tests confusion with PKIX (SubjectPublicKeyInfo)
// DER-encoded public key as the HMAC secret.
func TestJWTConfusion_RS256ToHS256_PKIX(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	pubKeyDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)

	header := map[string]string{"alg": "HS256", "typ": "JWT", "kid": kid}
	claims := map[string]interface{}{
		"sub": "admin", "iss": "vault", "aud": "app",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	mac := hmac.New(sha256.New, pubKeyDER)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	_, err := vaultcrypto.ParseAndValidate(payload+"."+sig, keyFunc, "vault", "app")
	if err == nil {
		t.Fatal("RS256-to-HS256 confusion attack (PKIX DER) was NOT rejected")
	}
}

// TestJWTConfusion_EmbeddedJWK verifies that a token with an embedded JWK
// header (containing the attacker's public key) is rejected. An attacker
// could sign with their own key and embed it in the JWK header, hoping
// the server uses it for verification.
func TestJWTConfusion_EmbeddedJWK(t *testing.T) {
	serverKey, _ := vaultcrypto.GenerateRSAKeyPair()
	attackerKey, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()

	serverKeyFunc := func(t *vjwt.Token) (any, error) {
		return &serverKey.PublicKey, nil
	}

	// Build a token with embedded JWK header containing attacker's public key
	claims := vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject: "admin", Issuer: "vault", Audience: vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
		Roles: []string{"admin"},
	}

	tokenStr, err := vjwt.SignRS256WithHeader(map[string]any{
		"alg": "RS256", "typ": "JWT", "kid": kid,
		"jwk": map[string]string{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(attackerKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		},
	}, claims, attackerKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Server should reject tokens with jwk header
	_, err = vaultcrypto.ParseAndValidate(tokenStr, serverKeyFunc, "vault", "app")
	if err == nil {
		t.Fatal("Token with embedded JWK header should be rejected")
	}
	if !strings.Contains(err.Error(), "jwk") {
		t.Logf("Error: %v (expected to mention jwk header rejection)", err)
	}
}

// TestJWTConfusion_KeySourceHeaders covers the three headers that name a key
// somewhere other than the local JWKS. Each one is a way to ask the parser to
// fetch or trust attacker-chosen key material, and the token is otherwise valid
// and signed by the key the verifier already holds, so the only thing that can
// refuse it is the header itself.
func TestJWTConfusion_KeySourceHeaders(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	cases := []struct {
		header string
		value  any
	}{
		{"jku", "https://evil.example.com/.well-known/jwks.json"},
		{"x5u", "https://evil.example.com/cert.pem"},
		{"x5c", []string{"MIIC...(fake cert)..."}},
	}

	for _, tc := range cases {
		t.Run(tc.header, func(t *testing.T) {
			tokenStr, err := vjwt.SignRS256WithHeader(map[string]any{
				"alg": "RS256", "typ": "JWT", "kid": kid,
				tc.header: tc.value,
			}, &vaultcrypto.VaultClaims{
				RegisteredClaims: vjwt.RegisteredClaims{
					Subject: "user", Issuer: "vault", Audience: vjwt.ClaimStrings{"app"},
					ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
					IssuedAt:  vjwt.NewNumericDate(time.Now()),
				},
			}, key)
			if err != nil {
				t.Fatalf("SignRS256WithHeader failed: %v", err)
			}

			if _, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "vault", "app"); err == nil {
				t.Fatalf("token carrying a %q header was accepted", tc.header)
			}
		})
	}
}

// TestJWTConfusion_ES256Token verifies that a token signed with ES256
// (ECDSA P-256) is rejected by the RS256-only parser.
func TestJWTConfusion_ES256Token(t *testing.T) {
	rsaKey, _ := vaultcrypto.GenerateRSAKeyPair()
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid, _ := vaultcrypto.RandomUUID()

	keyFunc := func(t *vjwt.Token) (any, error) {
		return &rsaKey.PublicKey, nil
	}

	tokenStr, _ := vjwt.SignTokenCustom(map[string]any{
		"alg": "ES256", "typ": "JWT", "kid": kid,
	}, &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject: "user", Issuer: "vault", Audience: vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, func(s string) ([]byte, error) {
		h := sha256.Sum256([]byte(s))
		return ecdsa.SignASN1(rand.Reader, ecKey, h[:])
	})

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "vault", "app")
	if err == nil {
		t.Fatal("ES256 token should be rejected by RS256-only parser")
	}
}

// TestJWTConfusion_PS256Token verifies that PS256 (RSA-PSS) tokens are rejected.
func TestJWTConfusion_PS256Token(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, _ := vjwt.SignTokenCustom(map[string]any{
		"alg": "PS256", "typ": "JWT", "kid": kid,
	}, &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject: "user", Issuer: "vault", Audience: vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, func(s string) ([]byte, error) {
		h := sha256.Sum256([]byte(s))
		return rsa.SignPSS(rand.Reader, key, crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	})

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "vault", "app")
	if err == nil {
		t.Fatal("PS256 token should be rejected by RS256-only parser")
	}
}

// TestJWTConfusion_HS384Token verifies that HS384 tokens are rejected.
func TestJWTConfusion_HS384Token(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	hmacSecret := []byte("attacker-hmac-secret-for-hs384-test")
	tokenStr, _ := vjwt.SignTokenCustom(map[string]any{
		"alg": "HS384", "typ": "JWT", "kid": kid,
	}, vjwt.MapClaims{
		"sub": "admin", "iss": "vault", "aud": "app",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}, func(s string) ([]byte, error) {
		mac := hmac.New(sha512.New384, hmacSecret)
		mac.Write([]byte(s))
		return mac.Sum(nil), nil
	})

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "vault", "app")
	if err == nil {
		t.Fatal("HS384 token should be rejected")
	}
}

// TestJWTConfusion_HS512Token verifies that HS512 tokens are rejected.
func TestJWTConfusion_HS512Token(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	hmacSecret := []byte("attacker-hmac-secret-for-hs512-test-long-enough")
	tokenStr, _ := vjwt.SignTokenCustom(map[string]any{
		"alg": "HS512", "typ": "JWT", "kid": kid,
	}, vjwt.MapClaims{
		"sub": "admin", "iss": "vault", "aud": "app",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}, func(s string) ([]byte, error) {
		mac := hmac.New(sha512.New, hmacSecret)
		mac.Write([]byte(s))
		return mac.Sum(nil), nil
	})

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "vault", "app")
	if err == nil {
		t.Fatal("HS512 token should be rejected")
	}
}

// TestJWTConfusion_AllDangerousHeadersCombined verifies that a token with
// multiple dangerous headers simultaneously is rejected.
func TestJWTConfusion_AllDangerousHeadersCombined(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	tokenStr, err := vjwt.SignRS256WithHeader(map[string]any{
		"alg": "RS256", "typ": "JWT", "kid": kid,
		"jku": "https://evil.com/jwks",
		"x5u": "https://evil.com/cert",
		"x5c": []string{"fakecert"},
		"jwk": map[string]string{"kty": "RSA"},
	}, &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject: "user", Issuer: "vault", Audience: vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	_, err = vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "vault", "app")
	if err == nil {
		t.Fatal("Token with all dangerous headers should be rejected")
	}
}
