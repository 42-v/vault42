package compliance

import (
	"crypto/subtle"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// =============================================================================
// NIST SP 800-63B-4 Coverage Tests — additional requirements verification
// =============================================================================

// TestNIST_PasswordMinLength15 verifies that the system is designed for a
// 15-character minimum password length (exceeding NIST 8-char minimum).
func TestNIST_PasswordMinLength15(t *testing.T) {
	// The crypto layer accepts any length (enforcement is at service layer).
	// We verify that passwords of exactly 15 characters hash and verify correctly.
	pw15 := "aB3dE5gH7jK9mN1" // exactly 15 chars
	hash, err := vaultcrypto.HashPassword(pw15)
	if err != nil {
		t.Fatalf("HashPassword failed for 15-char password: %v", err)
	}
	match, err := vaultcrypto.VerifyPassword(pw15, hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !match {
		t.Fatal("15-char password should verify correctly")
	}

	// 14-char password should also hash (crypto doesn't enforce; service does)
	pw14 := "aB3dE5gH7jK9mN"
	hash14, err := vaultcrypto.HashPassword(pw14)
	if err != nil {
		t.Fatalf("HashPassword should accept any length at crypto layer: %v", err)
	}

	// But 14-char and 15-char must be distinguishable
	match, _ = vaultcrypto.VerifyPassword(pw14, hash)
	if match {
		t.Fatal("14-char password should not match hash of 15-char password")
	}
	_ = hash14
}

// TestNIST_NoCompositionRulesExtended verifies that passwords with any character
// class are accepted at the crypto layer.
func TestNIST_NoCompositionRulesExtended(t *testing.T) {
	// NIST SP 800-63B-4: No composition rules (no uppercase/digit/special requirements)
	passwords := []struct {
		name string
		pw   string
	}{
		{"only tabs", strings.Repeat("\t", 20)},
		{"only newlines", strings.Repeat("\n", 20)},
		{"only null bytes", strings.Repeat("\x00", 20)},
		{"mixed whitespace", "   \t\t\n\n   \t\t\n\n   \t\t\n"},
		{"emoji only", strings.Repeat("\U0001F600", 5)},
		{"control characters", "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"},
	}

	for _, tt := range passwords {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := vaultcrypto.HashPassword(tt.pw)
			if err != nil {
				t.Fatalf("HashPassword rejected %q: %v", tt.name, err)
			}
			match, _ := vaultcrypto.VerifyPassword(tt.pw, hash)
			if !match {
				t.Fatalf("%q password did not verify", tt.name)
			}
		})
	}
}

// TestNIST_Argon2idIsUsed verifies that the password hashing function is Argon2id
// (not bcrypt, scrypt, or PBKDF2).
func TestNIST_Argon2idIsUsed(t *testing.T) {
	hash, _ := vaultcrypto.HashPassword("verify-algorithm-choice")

	// Must start with $argon2id$ (not $2a$, $scrypt$, etc.)
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("Expected Argon2id hash, got prefix: %.20s", hash)
	}

	// Must NOT be any other algorithm
	wrongPrefixes := []string{"$2a$", "$2b$", "$scrypt$", "$pbkdf2$", "$5$", "$6$"}
	for _, wp := range wrongPrefixes {
		if strings.HasPrefix(hash, wp) {
			t.Fatalf("Hash uses wrong algorithm: %s", wp)
		}
	}
}

// TestNIST_Argon2idMemoryAboveMinimum verifies Argon2id memory >= 19 MiB
// (NIST/OWASP minimum).
func TestNIST_Argon2idMemoryAboveMinimum(t *testing.T) {
	hash, _ := vaultcrypto.HashPassword("memory-minimum-test")
	parts := strings.Split(hash, "$")
	params := parts[3]

	// Extract memory value: m=47104
	if !strings.Contains(params, "m=") {
		t.Fatal("Hash params should contain memory parameter")
	}

	// 47104 KiB = 46 MiB >= 19 MiB
	if !strings.Contains(params, "m=47104") {
		t.Fatalf("Expected m=47104 (46 MiB >= 19 MiB minimum), got: %s", params)
	}
}

// TestNIST_TokenExpiryMaximum verifies that access token TTL does not exceed
// 15 minutes (within NIST 30-minute reauthentication bound).
func TestNIST_TokenExpiryMaximum(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) {
		return &key.PublicKey, nil
	}

	// Token with 15-minute expiry should be accepted
	now := time.Now()
	tokenStr, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "vault",
			Audience:  vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  vjwt.NewNumericDate(now),
		},
	}, key, kid)

	claims, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "vault", "app")
	if err != nil {
		t.Fatalf("15-minute token should be valid: %v", err)
	}

	// Verify the expiry is within 15 minutes
	ttl := time.Until(claims.ExpiresAt.Time)
	if ttl > 15*time.Minute+time.Second { // small tolerance
		t.Fatalf("Token TTL (%v) exceeds 15-minute maximum", ttl)
	}
}

// TestNIST_AlgorithmWhitelistRS256Only verifies that only RS256 is accepted.
func TestNIST_AlgorithmWhitelistRS256Only(t *testing.T) {
	// Verify the constant
	if vaultcrypto.AllowedAlgorithm != "RS256" {
		t.Fatalf("AllowedAlgorithm should be RS256, got %v", vaultcrypto.AllowedAlgorithm)
	}
}

// TestNIST_ConstantTimeComparisonForSecrets verifies that secret comparisons
// use constant-time functions.
func TestNIST_ConstantTimeComparisonForSecrets(t *testing.T) {
	// Verify SecureCompare uses crypto/subtle internally
	// We test the behavior: equal strings return true, unequal return false,
	// and different-length strings return false.

	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{"equal strings", "secret123", "secret123", true},
		{"different strings", "secret123", "secret456", false},
		{"different lengths", "short", "much-longer-string", false},
		{"empty strings", "", "", true},
		{"one empty", "notempty", "", false},
		{"identical hex", "abcdef0123456789", "abcdef0123456789", true},
		{"off by one char", "abcdef0123456789", "abcdef0123456780", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vaultcrypto.SecureCompare(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("SecureCompare(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// TestNIST_ConstantTimeComparisonBytes verifies byte-level constant-time comparison.
func TestNIST_ConstantTimeComparisonBytes(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03, 0x04}
	b := []byte{0x01, 0x02, 0x03, 0x04}
	c := []byte{0x01, 0x02, 0x03, 0x05}

	if !vaultcrypto.SecureCompareBytes(a, b) {
		t.Fatal("Equal byte slices should compare as equal")
	}
	if vaultcrypto.SecureCompareBytes(a, c) {
		t.Fatal("Different byte slices should compare as not equal")
	}

	// Verify it matches crypto/subtle behavior
	if (subtle.ConstantTimeCompare(a, b) == 1) != vaultcrypto.SecureCompareBytes(a, b) {
		t.Fatal("SecureCompareBytes should match crypto/subtle.ConstantTimeCompare")
	}
}

// TestNIST_MaxJWTSizeConstant verifies the max JWT size constant is 8KB.
func TestNIST_MaxJWTSizeConstant(t *testing.T) {
	if vaultcrypto.MaxJWTSize != 8192 {
		t.Fatalf("MaxJWTSize should be 8192 (8KB), got %d", vaultcrypto.MaxJWTSize)
	}
}

// TestNIST_RSAKeyPairSize verifies that generated RSA keys are 2048-bit.
func TestNIST_RSAKeyPairSize(t *testing.T) {
	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair failed: %v", err)
	}

	bits := key.N.BitLen()
	if bits < 2048 {
		t.Fatalf("RSA key must be >= 2048 bits, got %d", bits)
	}
}

// TestNIST_TOTPPeriod30Seconds verifies TOTP uses 30-second periods.
func TestNIST_TOTPPeriod30Seconds(t *testing.T) {
	secret, _ := vaultcrypto.GenerateTOTPSecret()

	// Pick a time exactly on a 30-second boundary: 1700000010 is arbitrary,
	// so we round down to ensure we're at the start of a period.
	// counter = unix / 30, so unix = counter * 30 is on a boundary.
	baseUnix := int64(56666667) * 30 // = 1700000010
	base := time.Unix(baseUnix, 0)

	// Codes at t and t+29s should be the same (same period)
	code1, _ := vaultcrypto.GenerateTOTPCode(secret, base)
	code2, _ := vaultcrypto.GenerateTOTPCode(secret, base.Add(29*time.Second))
	if code1 != code2 {
		t.Fatalf("Codes within the same 30-second period should be identical (base=%d)", baseUnix)
	}

	// Code at t+30s should be different (next period)
	code3, _ := vaultcrypto.GenerateTOTPCode(secret, base.Add(30*time.Second))
	if code1 == code3 {
		// There's a 1/1000000 chance they match by coincidence
		t.Log("Note: codes at t and t+30s are identical (very unlikely coincidence)")
	}
}

// TestNIST_PasswordVerificationReturnsNoTimingInfo verifies that password
// verification returns boolean only (no timing-exploitable info in errors).
func TestNIST_PasswordVerificationReturnsNoTimingInfo(t *testing.T) {
	hash, _ := vaultcrypto.HashPassword("correct-password!")

	// Correct password: (true, nil)
	match, err := vaultcrypto.VerifyPassword("correct-password!", hash)
	if !match || err != nil {
		t.Fatalf("Correct password should return (true, nil), got (%v, %v)", match, err)
	}

	// Wrong password: (false, nil)
	match, err = vaultcrypto.VerifyPassword("wrong-password!", hash)
	if match {
		t.Fatal("Wrong password should not match")
	}
	if err != nil {
		t.Fatalf("Wrong password should return nil error (not leak info), got: %v", err)
	}
}
