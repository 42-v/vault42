package attack

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/honeypot"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestHoneypotToken_StructureMatchesRealJWT verifies that fake JWTs have
// the same three-part base64url structure as real JWTs.
func TestHoneypotToken_StructureMatchesRealJWT(t *testing.T) {
	// Generate a real JWT for comparison
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	realToken, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "real-user",
			Issuer:    "vault",
			Audience:  vjwt.ClaimStrings{"vault"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
		Roles: []string{"user"},
	}, key, kid)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	fakeToken, err := honeypot.GenerateFakeJWT()
	if err != nil {
		t.Fatalf("GenerateFakeJWT failed: %v", err)
	}

	// Both should have 3 dot-separated parts
	realParts := strings.Split(realToken, ".")
	fakeParts := strings.Split(fakeToken, ".")

	if len(realParts) != 3 {
		t.Fatalf("Real token has %d parts, expected 3", len(realParts))
	}
	if len(fakeParts) != 3 {
		t.Fatalf("Fake token has %d parts, expected 3", len(fakeParts))
	}

	// Each part should be valid base64url
	for i, part := range fakeParts {
		_, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			t.Fatalf("Fake token part %d is not valid base64url: %v", i, err)
		}
	}
}

// TestHoneypotToken_HeaderMatchesRealFormat verifies that the fake JWT header
// contains the same fields as a real RS256 JWT header.
func TestHoneypotToken_HeaderMatchesRealFormat(t *testing.T) {
	fakeToken, err := honeypot.GenerateFakeJWT()
	if err != nil {
		t.Fatalf("GenerateFakeJWT failed: %v", err)
	}

	parts := strings.Split(fakeToken, ".")
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("Failed to decode fake header: %v", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("Failed to unmarshal fake header: %v", err)
	}

	// Must have alg, typ, kid
	if header["alg"] != "RS256" {
		t.Fatalf("Expected alg=RS256, got %v", header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Fatalf("Expected typ=JWT, got %v", header["typ"])
	}
	kid, ok := header["kid"].(string)
	if !ok || kid == "" {
		t.Fatal("Expected non-empty kid in fake header")
	}
	// kid should be UUID format (8-4-4-4-12 hex chars)
	if len(kid) < 32 {
		t.Fatalf("kid too short for UUID format: %q", kid)
	}
}

// TestHoneypotToken_ClaimsLookRealistic verifies that fake JWT claims contain
// the standard fields that a real vault JWT would have.
func TestHoneypotToken_ClaimsLookRealistic(t *testing.T) {
	fakeToken, err := honeypot.GenerateFakeJWT()
	if err != nil {
		t.Fatalf("GenerateFakeJWT failed: %v", err)
	}

	parts := strings.Split(fakeToken, ".")
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("Failed to decode fake payload: %v", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		t.Fatalf("Failed to unmarshal fake claims: %v", err)
	}

	// Must have sub, iss, aud, exp, iat
	requiredFields := []string{"sub", "iss", "aud", "exp", "iat"}
	for _, field := range requiredFields {
		if _, exists := claims[field]; !exists {
			t.Fatalf("Fake JWT missing required claim %q", field)
		}
	}

	// sub should be UUID-like
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		t.Fatal("Expected non-empty string sub claim")
	}
	if len(sub) < 32 {
		t.Fatalf("sub too short for UUID format: %q", sub)
	}

	// exp should be in the future
	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Fatal("Expected numeric exp claim")
	}
	if time.Unix(int64(exp), 0).Before(time.Now()) {
		t.Fatal("Fake JWT exp should be in the future")
	}

	// iat should be approximately now
	iat, ok := claims["iat"].(float64)
	if !ok {
		t.Fatal("Expected numeric iat claim")
	}
	iatTime := time.Unix(int64(iat), 0)
	if time.Since(iatTime) > 5*time.Second {
		t.Fatalf("Fake JWT iat too far from now: %v", iatTime)
	}

	// Should have roles (to look like a real vault token)
	roles, ok := claims["roles"]
	if !ok {
		t.Fatal("Fake JWT should have roles claim for realism")
	}
	rolesArr, ok := roles.([]interface{})
	if !ok || len(rolesArr) == 0 {
		t.Fatal("Fake JWT roles should be a non-empty array")
	}
}

// TestHoneypotToken_SignatureDoesNotVerify verifies that the fake JWT signature
// fails verification against a real RSA key pair.
func TestHoneypotToken_SignatureDoesNotVerify(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()

	fakeToken, err := honeypot.GenerateFakeJWT()
	if err != nil {
		t.Fatalf("GenerateFakeJWT failed: %v", err)
	}

	// Extract the fake kid from the token header
	parts := strings.Split(fakeToken, ".")
	headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]interface{}
	json.Unmarshal(headerJSON, &header)
	fakeKID, _ := header["kid"].(string)

	// Try to validate with any key — should fail
	keys := map[string]*vaultcrypto.VaultClaims{}
	_ = keys

	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	// Use a key map that includes both the real kid and the fake kid
	_ = kid
	_ = fakeKID

	_, err = vaultcrypto.ParseAndValidate(fakeToken, keyFunc, "vault", "vault")
	if err == nil {
		t.Fatal("Fake honeypot JWT should NEVER validate against a real key")
	}
}

// TestHoneypotToken_UniquePerGeneration verifies that consecutive fake JWTs
// are unique — each call produces a different token with different claims.
func TestHoneypotToken_UniquePerGeneration(t *testing.T) {
	const iterations = 50
	seen := make(map[string]bool, iterations)
	subs := make(map[string]bool, iterations)

	for i := 0; i < iterations; i++ {
		token, err := honeypot.GenerateFakeJWT()
		if err != nil {
			t.Fatalf("GenerateFakeJWT iteration %d: %v", i, err)
		}

		if seen[token] {
			t.Fatalf("Duplicate fake JWT at iteration %d", i)
		}
		seen[token] = true

		// Extract sub to verify unique subjects
		parts := strings.Split(token, ".")
		payloadJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims map[string]interface{}
		json.Unmarshal(payloadJSON, &claims)
		sub, _ := claims["sub"].(string)

		if subs[sub] {
			t.Fatalf("Duplicate sub %q at iteration %d", sub, i)
		}
		subs[sub] = true
	}
}

// TestHoneypotToken_SignatureLengthRealistic verifies that the fake signature
// has a realistic length for an RS256 signature (256 bytes = 342-344 base64url chars).
func TestHoneypotToken_SignatureLengthRealistic(t *testing.T) {
	fakeToken, err := honeypot.GenerateFakeJWT()
	if err != nil {
		t.Fatalf("GenerateFakeJWT failed: %v", err)
	}

	parts := strings.Split(fakeToken, ".")
	sigB64 := parts[2]

	// RS256 signature is 256 bytes. Base64url encoding of 256 bytes:
	// ceil(256 / 3) * 4 = 344 chars with padding, 342 without
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("Failed to decode fake signature: %v", err)
	}

	if len(sigBytes) != 256 {
		t.Fatalf("Fake signature is %d bytes, expected 256 (RS256 standard)", len(sigBytes))
	}
}

// TestHoneypotToken_FakeLoginResponse verifies that the full fake login
// response has the expected structure.
func TestHoneypotToken_FakeLoginResponse(t *testing.T) {
	resp, err := honeypot.FakeLoginResponse()
	if err != nil {
		t.Fatalf("FakeLoginResponse failed: %v", err)
	}

	// Must have access_token, token_type, expires_in
	accessToken, ok := resp["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatal("Missing or empty access_token in fake login response")
	}

	tokenType, ok := resp["token_type"].(string)
	if !ok || tokenType != "Bearer" {
		t.Fatalf("Expected token_type=Bearer, got %v", resp["token_type"])
	}

	expiresIn, ok := resp["expires_in"]
	if !ok {
		t.Fatal("Missing expires_in in fake login response")
	}
	// Verify it's a reasonable value (typically 900 seconds = 15 minutes)
	if ei, ok := expiresIn.(int); ok && (ei < 60 || ei > 3600) {
		t.Fatalf("Unexpected expires_in value: %d", ei)
	}

	// The access_token should be a valid-looking JWT
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("access_token should be JWT format (3 parts), got %d parts", len(parts))
	}
}

// TestHoneypotToken_FakeRefreshTokenFormat verifies fake refresh tokens
// have the correct format (64 hex characters).
func TestHoneypotToken_FakeRefreshTokenFormat(t *testing.T) {
	rt, err := honeypot.FakeLoginCookie()
	if err != nil {
		t.Fatalf("FakeLoginCookie failed: %v", err)
	}

	if len(rt) != 64 {
		t.Fatalf("Expected 64-char hex refresh token, got %d chars", len(rt))
	}

	// Verify it is valid hex
	for _, c := range rt {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("Refresh token contains non-hex character: %c", c)
		}
	}
}
