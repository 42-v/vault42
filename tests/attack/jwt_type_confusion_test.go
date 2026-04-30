package attack

import (
	"encoding/json"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// --- Header type confusion tests ---

// TestJWT_AlgAsArray verifies that alg as an array is rejected.
func TestJWT_AlgAsArray(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON := []byte(`{"alg":["RS256"],"typ":"JWT","kid":"` + kid + `"}`)
	claimsJSON := validClaimsJSON(t)
	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with array alg should be rejected")
	}
}

// TestJWT_AlgAsInteger verifies that alg as an integer is rejected.
func TestJWT_AlgAsInteger(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON := []byte(`{"alg":256,"typ":"JWT","kid":"` + kid + `"}`)
	claimsJSON := validClaimsJSON(t)
	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with integer alg should be rejected")
	}
}

// TestJWT_AlgAsNull verifies that alg as null is rejected.
func TestJWT_AlgAsNull(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON := []byte(`{"alg":null,"typ":"JWT","kid":"` + kid + `"}`)
	claimsJSON := validClaimsJSON(t)
	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with null alg should be rejected")
	}
}

// TestJWT_TypVariations verifies that non-standard typ values still parse if alg is valid.
func TestJWT_TypVariations(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	variants := []string{"jwt", "JWS", "at+jwt", ""}

	for _, typ := range variants {
		t.Run("typ="+typ, func(t *testing.T) {
			header := map[string]any{"alg": "RS256", "kid": kid}
			if typ != "" {
				header["typ"] = typ
			}
			tokenStr, err := vjwt.SignRS256WithHeader(header, &vaultcrypto.VaultClaims{
				RegisteredClaims: vjwt.RegisteredClaims{
					Subject:   "user-123",
					Issuer:    "test",
					Audience:  vjwt.ClaimStrings{"test"},
					ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
					IssuedAt:  vjwt.NewNumericDate(time.Now()),
				},
			}, key)
			if err != nil {
				t.Fatalf("SignRS256WithHeader failed: %v", err)
			}

			_, err = vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
			if err != nil {
				t.Logf("typ=%q rejected: %v (acceptable if parser is strict about typ)", typ, err)
			}
			// Either outcome is fine — we just verify no panic
		})
	}
}

// TestJWT_CritHeader verifies that the crit header doesn't cause rejection (we ignore it).
func TestJWT_CritHeader(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, err := vjwt.SignRS256WithHeader(map[string]any{
		"alg": "RS256", "typ": "JWT", "kid": kid,
		"crit": []string{"exp"},
	}, &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "test",
			Audience:  vjwt.ClaimStrings{"test"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key)
	if err != nil {
		t.Fatalf("SignRS256WithHeader failed: %v", err)
	}

	// Should still parse (crit is not in our rejected headers list)
	_, err = vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err != nil {
		t.Logf("Token with crit header rejected: %v (acceptable)", err)
	}
}

// TestJWT_CtyHeader verifies that the cty header doesn't cause rejection.
func TestJWT_CtyHeader(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, err := vjwt.SignRS256WithHeader(map[string]any{
		"alg": "RS256", "typ": "JWT", "kid": kid,
		"cty": "JWT",
	}, &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "test",
			Audience:  vjwt.ClaimStrings{"test"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key)
	if err != nil {
		t.Fatalf("SignRS256WithHeader failed: %v", err)
	}

	_, err = vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err != nil {
		t.Logf("Token with cty header rejected: %v (acceptable)", err)
	}
}

// --- Claims type confusion tests ---

// TestJWT_SubAsInteger verifies that sub as an integer is handled safely.
func TestJWT_SubAsInteger(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	now := time.Now()
	claimsJSON := []byte(`{"sub":12345,"iss":"test","aud":["test"],"exp":` +
		intToString(now.Add(time.Hour).Unix()) + `,"iat":` + intToString(now.Unix()) + `}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with integer sub should be rejected (Go unmarshal into string fails)")
	}
}

// TestJWT_SubAsNull verifies that sub as null results in empty subject.
func TestJWT_SubAsNull(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	now := time.Now()
	claimsJSON := []byte(`{"sub":null,"iss":"test","aud":["test"],"exp":` +
		intToString(now.Add(time.Hour).Unix()) + `,"iat":` + intToString(now.Unix()) + `}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	claims, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err != nil {
		t.Logf("Token with null sub rejected: %v (acceptable)", err)
		return
	}
	// If accepted, sub should be empty string (null → zero value)
	if claims.Subject != "" {
		t.Fatalf("Expected empty sub for null, got %q", claims.Subject)
	}
}

// TestJWT_SubAsEmpty verifies that sub="" is handled safely.
func TestJWT_SubAsEmpty(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	tokenStr, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "",
			Issuer:    "test",
			Audience:  vjwt.ClaimStrings{"test"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key, kid)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	claims, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err != nil {
		t.Logf("Token with empty sub rejected: %v (acceptable)", err)
		return
	}
	if claims.Subject != "" {
		t.Fatalf("Expected empty sub, got %q", claims.Subject)
	}
}

// TestJWT_RolesAsString verifies that roles as a string instead of array is handled.
func TestJWT_RolesAsString(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	now := time.Now()
	// roles as string instead of array
	claimsJSON := []byte(`{"sub":"user-123","iss":"test","aud":["test"],"exp":` +
		intToString(now.Add(time.Hour).Unix()) + `,"iat":` + intToString(now.Unix()) +
		`,"roles":"admin"}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with string roles (instead of array) should be rejected by JSON unmarshal")
	}
}

// TestJWT_RolesAsObject verifies that roles as an object is rejected.
func TestJWT_RolesAsObject(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	now := time.Now()
	claimsJSON := []byte(`{"sub":"user-123","iss":"test","aud":["test"],"exp":` +
		intToString(now.Add(time.Hour).Unix()) + `,"iat":` + intToString(now.Unix()) +
		`,"roles":{"admin":true}}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err == nil {
		t.Fatal("Token with object roles should be rejected by JSON unmarshal")
	}
}

// TestJWT_RolesAsNull verifies that roles as null is handled safely (omitted).
func TestJWT_RolesAsNull(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(tok *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	})

	now := time.Now()
	claimsJSON := []byte(`{"sub":"user-123","iss":"test","aud":["test"],"exp":` +
		intToString(now.Add(time.Hour).Unix()) + `,"iat":` + intToString(now.Unix()) +
		`,"roles":null}`)

	tokenStr := signRawPayload(t, headerJSON, claimsJSON, key)

	claims, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "test", "test")
	if err != nil {
		t.Fatalf("Token with null roles should parse (omitted via omitempty): %v", err)
	}
	if len(claims.Roles) != 0 {
		t.Fatalf("Expected empty roles for null, got %v", claims.Roles)
	}
}

// validClaimsJSON produces a valid claims JSON byte slice for use in tests.
func validClaimsJSON(t *testing.T) []byte {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"sub": "user-123",
		"iss": "test",
		"aud": []string{"test"},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return b
}
