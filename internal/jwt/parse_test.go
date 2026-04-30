package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func makeValidToken(t *testing.T, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	claims := &RegisteredClaims{
		Issuer:    "vault",
		Subject:   "user-1",
		Audience:  ClaimStrings{"api"},
		ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
		NotBefore: NewNumericDate(time.Now().Add(-time.Minute)),
		IssuedAt:  NewNumericDate(time.Now().Add(-time.Minute)),
		ID:        "jti-test",
	}
	tok, err := SignRS256(claims, key, kid)
	if err != nil {
		t.Fatalf("make token: %v", err)
	}
	return tok
}

func TestParseMalformed_WrongSegmentCount(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no dots", "nodots"},
		{"one dot", "one.dot"},
		{"four segments", "a.b.c.d"},
		{"five segments", "a.b.c.d.e"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseWithClaims(tt.token, &RegisteredClaims{}, nil)
			if !errors.Is(err, ErrTokenMalformed) {
				t.Errorf("got %v, want ErrTokenMalformed", err)
			}
		})
	}
}

func TestParseMalformed_BadBase64(t *testing.T) {
	// Valid base64url uses A-Za-z0-9-_
	tests := []struct {
		name  string
		token string
	}{
		{"bad header", "!!!.eyJ0ZXN0IjoxfQ.sig"},
		{"bad payload", "eyJhbGciOiJSUzI1NiJ9.!!!.sig"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseWithClaims(tt.token, &RegisteredClaims{}, func(t *Token) (any, error) {
				return nil, nil
			})
			if !errors.Is(err, ErrTokenMalformed) {
				t.Errorf("got %v, want ErrTokenMalformed", err)
			}
		})
	}
}

func TestParseMalformed_BadJSON(t *testing.T) {
	// Valid base64url encoding of non-JSON
	notJSON := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	validHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))

	tests := []struct {
		name  string
		token string
	}{
		{"bad header json", notJSON + "." + notJSON + ".sig"},
		{"bad payload json", validHeader + "." + notJSON + ".sig"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseWithClaims(tt.token, &RegisteredClaims{}, func(t *Token) (any, error) {
				return nil, nil
			}, WithValidMethods([]string{"RS256"}))
			if !errors.Is(err, ErrTokenMalformed) {
				t.Errorf("got %v, want ErrTokenMalformed", err)
			}
		})
	}
}

func TestParseMalformed_TrailingData(t *testing.T) {
	_, err := ParseWithClaims("a.b.c.trailing", &RegisteredClaims{}, nil)
	if !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("got %v, want ErrTokenMalformed", err)
	}
}

func TestParseWithClaims_ValidToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokenStr := makeValidToken(t, key, "kid-1")

	parsed := &RegisteredClaims{}
	tok, err := ParseWithClaims(tokenStr, parsed, func(t *Token) (any, error) {
		return &key.PublicKey, nil
	}, WithValidMethods([]string{"RS256"}), WithIssuer("vault"), WithAudience("api"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !tok.Valid {
		t.Error("token not valid")
	}
	if parsed.Issuer != "vault" {
		t.Errorf("issuer = %q, want vault", parsed.Issuer)
	}
}

func TestParseWithClaims_WrongAlgorithm(t *testing.T) {
	// Craft a token with HS256 header
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user"}`))
	fake := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString([]byte("fakesig"))

	_, err := ParseWithClaims(fake, &RegisteredClaims{}, func(t *Token) (any, error) {
		return nil, nil
	}, WithValidMethods([]string{"RS256"}))

	if !errors.Is(err, ErrTokenSignatureInvalid) {
		t.Errorf("got %v, want ErrTokenSignatureInvalid", err)
	}
}

func TestParseWithClaims_NoneAlgorithm(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user"}`))
	fake := header + "." + payload + "."

	_, err := ParseWithClaims(fake, &RegisteredClaims{}, func(t *Token) (any, error) {
		return nil, nil
	}, WithValidMethods([]string{"RS256"}))

	if !errors.Is(err, ErrTokenSignatureInvalid) {
		t.Errorf("got %v, want ErrTokenSignatureInvalid", err)
	}
}

func TestParseWithClaims_NoneAlgorithm_NoWhitelist(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user"}`))
	fake := header + "." + payload + "."

	_, err := ParseWithClaims(fake, &RegisteredClaims{}, func(t *Token) (any, error) {
		return nil, nil
	})

	// Without whitelist, "none" should still fail because it's not RS256 or ES256
	if !errors.Is(err, ErrTokenUnverifiable) {
		t.Errorf("got %v, want ErrTokenUnverifiable", err)
	}
}

func TestParseWithClaims_WrongKey(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)

	tokenStr := makeValidToken(t, key1, "kid-1")

	_, err := ParseWithClaims(tokenStr, &RegisteredClaims{}, func(t *Token) (any, error) {
		return &key2.PublicKey, nil
	}, WithValidMethods([]string{"RS256"}))

	if !errors.Is(err, ErrTokenSignatureInvalid) {
		t.Errorf("got %v, want ErrTokenSignatureInvalid", err)
	}
}

func TestParseWithClaims_TamperedPayload(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokenStr := makeValidToken(t, key, "kid-1")

	// Tamper with the payload
	parts := strings.SplitN(tokenStr, ".", 3)
	// Decode, modify, re-encode
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	json.Unmarshal(payloadBytes, &claims)
	claims["sub"] = "admin"
	newPayload, _ := json.Marshal(claims)
	parts[1] = base64.RawURLEncoding.EncodeToString(newPayload)
	tampered := strings.Join(parts, ".")

	_, err := ParseWithClaims(tampered, &RegisteredClaims{}, func(t *Token) (any, error) {
		return &key.PublicKey, nil
	}, WithValidMethods([]string{"RS256"}))

	if !errors.Is(err, ErrTokenSignatureInvalid) {
		t.Errorf("got %v, want ErrTokenSignatureInvalid", err)
	}
}

func TestParseWithClaims_TamperedSignature(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokenStr := makeValidToken(t, key, "kid-1")

	parts := strings.SplitN(tokenStr, ".", 3)
	sigBytes, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sigBytes[0] ^= 0xff
	parts[2] = base64.RawURLEncoding.EncodeToString(sigBytes)
	tampered := strings.Join(parts, ".")

	_, err := ParseWithClaims(tampered, &RegisteredClaims{}, func(t *Token) (any, error) {
		return &key.PublicKey, nil
	}, WithValidMethods([]string{"RS256"}))

	if !errors.Is(err, ErrTokenSignatureInvalid) {
		t.Errorf("got %v, want ErrTokenSignatureInvalid", err)
	}
}

func TestParseWithClaims_EmptySignature(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user"}`))
	token := header + "." + payload + "."

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err := ParseWithClaims(token, &RegisteredClaims{}, func(t *Token) (any, error) {
		return &key.PublicKey, nil
	}, WithValidMethods([]string{"RS256"}))

	if !errors.Is(err, ErrTokenSignatureInvalid) {
		t.Errorf("got %v, want ErrTokenSignatureInvalid", err)
	}
}

func TestParseUnverified_ExtractsHeader(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokenStr := makeValidToken(t, key, "kid-abc")

	parsed := &RegisteredClaims{}
	tok, err := ParseUnverified(tokenStr, parsed)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	alg, _ := tok.Header["alg"].(string)
	if alg != "RS256" {
		t.Errorf("alg = %q, want RS256", alg)
	}
	typ, _ := tok.Header["typ"].(string)
	if typ != "JWT" {
		t.Errorf("typ = %q, want JWT", typ)
	}
	kid, _ := tok.Header["kid"].(string)
	if kid != "kid-abc" {
		t.Errorf("kid = %q, want kid-abc", kid)
	}
}

func TestParseUnverified_DoesNotValidate(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	// Create an expired token
	claims := &RegisteredClaims{
		ExpiresAt: NewNumericDate(time.Now().Add(-time.Hour)),
	}
	tokenStr, _ := SignRS256(claims, key, "k")

	parsed := &RegisteredClaims{}
	tok, err := ParseUnverified(tokenStr, parsed)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tok.Valid {
		t.Error("token should not be marked valid")
	}
	// Should have parsed expired claims without error
	if parsed.ExpiresAt == nil {
		t.Error("ExpiresAt should be set")
	}
}

func TestParseUnverified_ExtractsClaims(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokenStr := makeValidToken(t, key, "k")

	parsed := &RegisteredClaims{}
	_, err := ParseUnverified(tokenStr, parsed)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", parsed.Subject)
	}
}

func TestParseWithClaims_KeyfuncError(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokenStr := makeValidToken(t, key, "k")

	_, err := ParseWithClaims(tokenStr, &RegisteredClaims{}, func(t *Token) (any, error) {
		return nil, errors.New("key not found")
	}, WithValidMethods([]string{"RS256"}))

	if !errors.Is(err, ErrTokenUnverifiable) {
		t.Errorf("got %v, want ErrTokenUnverifiable", err)
	}
}

func TestParseWithClaims_NilKeyfunc(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokenStr := makeValidToken(t, key, "k")

	_, err := ParseWithClaims(tokenStr, &RegisteredClaims{}, nil, WithValidMethods([]string{"RS256"}))
	if !errors.Is(err, ErrTokenUnverifiable) {
		t.Errorf("got %v, want ErrTokenUnverifiable", err)
	}
}

func TestParseWithClaims_MissingAlg(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user"}`))
	token := header + "." + payload + ".sig"

	_, err := ParseWithClaims(token, &RegisteredClaims{}, func(t *Token) (any, error) {
		return nil, nil
	})
	if !errors.Is(err, ErrTokenUnverifiable) {
		t.Errorf("got %v, want ErrTokenUnverifiable", err)
	}
}

func TestParseWithClaims_WithoutClaimsValidation(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	// Expired token
	claims := &RegisteredClaims{
		ExpiresAt: NewNumericDate(time.Now().Add(-time.Hour)),
		Issuer:    "wrong",
	}
	tokenStr, _ := SignRS256(claims, key, "k")

	parsed := &RegisteredClaims{}
	tok, err := ParseWithClaims(tokenStr, parsed, func(t *Token) (any, error) {
		return &key.PublicKey, nil
	}, WithValidMethods([]string{"RS256"}), WithoutClaimsValidation())
	if err != nil {
		t.Fatalf("expected no error with skip validation, got %v", err)
	}
	if !tok.Valid {
		t.Error("token should be valid when validation is skipped")
	}
}

func TestParseWithClaims_HeaderAccess(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokenStr := makeValidToken(t, key, "my-kid-123")

	var headerKid string
	parsed := &RegisteredClaims{}
	_, err := ParseWithClaims(tokenStr, parsed, func(t *Token) (any, error) {
		headerKid, _ = t.Header["kid"].(string)
		return &key.PublicKey, nil
	}, WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if headerKid != "my-kid-123" {
		t.Errorf("kid from keyfunc = %q, want my-kid-123", headerKid)
	}
}

func TestParseWithClaims_ExpirationRequired(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	claims := &RegisteredClaims{
		Subject: "user-1",
	}
	tokenStr, _ := SignRS256(claims, key, "k")

	_, err := ParseWithClaims(tokenStr, &RegisteredClaims{}, func(t *Token) (any, error) {
		return &key.PublicKey, nil
	}, WithValidMethods([]string{"RS256"}), WithExpirationRequired())

	if !errors.Is(err, ErrTokenRequiredClaimMissing) {
		t.Errorf("got %v, want ErrTokenRequiredClaimMissing", err)
	}
}
