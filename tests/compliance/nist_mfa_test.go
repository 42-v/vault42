package compliance

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// =============================================================================
// NIST SP 800-63B — Multi-Factor Authentication (MFA) Requirements
// https://pages.nist.gov/800-63-4/sp800-63b.html
// =============================================================================

// --- Section 3.1.4: Single-Factor OTP Device ---

func TestNIST_MFA_TOTPSecretMinEntropy(t *testing.T) {
	// NIST SP 800-63B-4 §3.1.4.1: "The secret key SHALL be at least 128 bits."
	// Vault generates 160-bit (20-byte) secrets.
	for i := 0; i < 20; i++ {
		secret, err := vaultcrypto.GenerateTOTPSecret()
		if err != nil {
			t.Fatalf("GenerateTOTPSecret failed: %v", err)
		}

		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
		if err != nil {
			t.Fatalf("Failed to decode TOTP secret: %v", err)
		}

		bits := len(decoded) * 8
		if bits < 128 {
			t.Fatalf("NIST MFA: TOTP secret must be >= 128 bits, got %d bits", bits)
		}
	}
}

func TestNIST_MFA_TOTPSecretUniqueness(t *testing.T) {
	// Each user must get a unique TOTP secret.
	secrets := make(map[string]bool)
	for i := 0; i < 100; i++ {
		secret, _ := vaultcrypto.GenerateTOTPSecret()
		if secrets[secret] {
			t.Fatalf("NIST MFA: Duplicate TOTP secret at iteration %d", i)
		}
		secrets[secret] = true
	}
}

func TestNIST_MFA_TOTPValidPeriod(t *testing.T) {
	// NIST SP 800-63B-4 §3.1.4.1: OTP SHALL be valid for a limited time.
	// Vault uses 30-second periods with ±1 skew (90-second total window).
	secret, _ := vaultcrypto.GenerateTOTPSecret()
	now := time.Now()

	// Current period: valid
	code, _ := vaultcrypto.GenerateTOTPCode(secret, now)
	step, _ := vaultcrypto.ValidateTOTPCode(secret, code, now)
	if step < 0 {
		t.Fatal("NIST MFA: Current TOTP code should be valid")
	}

	// 3 periods old: rejected
	oldCode, _ := vaultcrypto.GenerateTOTPCode(secret, now.Add(-90*time.Second))
	step, _ = vaultcrypto.ValidateTOTPCode(secret, oldCode, now)
	if step >= 0 {
		t.Fatal("NIST MFA: Code 3 periods old should be rejected")
	}

	// 5 minutes old: rejected
	veryOldCode, _ := vaultcrypto.GenerateTOTPCode(secret, now.Add(-5*time.Minute))
	step, _ = vaultcrypto.ValidateTOTPCode(secret, veryOldCode, now)
	if step >= 0 {
		t.Fatal("NIST MFA: Code 5 minutes old should be rejected")
	}
}

func TestNIST_MFA_TOTPCodeFormat(t *testing.T) {
	// NIST SP 800-63B-4 §3.1.4.1: OTP SHALL be at least 6 digits.
	secret, _ := vaultcrypto.GenerateTOTPSecret()
	now := time.Now()

	code, _ := vaultcrypto.GenerateTOTPCode(secret, now)

	// Must be exactly 6 digits
	if len(code) != 6 {
		t.Fatalf("NIST MFA: TOTP code must be 6 digits, got %d chars", len(code))
	}

	for _, c := range code {
		if c < '0' || c > '9' {
			t.Fatalf("NIST MFA: TOTP code must be digits only, got char %c", c)
		}
	}
}

func TestNIST_MFA_TOTPRejectionOfInvalidCodes(t *testing.T) {
	// NIST SP 800-63B-4 §3.1.4.1: Verifier SHALL reject invalid OTPs.
	secret, _ := vaultcrypto.GenerateTOTPSecret()
	now := time.Now()

	invalidCodes := []struct {
		name string
		code string
	}{
		{"all_zeros", "000000"},
		{"all_nines", "999999"},
		{"random_1", "123456"},
		{"random_2", "654321"},
		{"random_3", "111111"},
	}

	// Generate the valid code for comparison
	validCode, err := vaultcrypto.GenerateTOTPCode(secret, now)
	if err != nil {
		t.Fatalf("NIST MFA: GenerateTOTPCode failed: %v", err)
	}

	// Positive control. Every assertion below is a refusal, and a verifier that
	// refuses everything satisfies all of them while locking out every user, so
	// the acceptance has to be pinned in the same test as the rejections.
	if step, _ := vaultcrypto.ValidateTOTPCode(secret, validCode, now); step < 0 {
		t.Fatalf("NIST MFA: the code generated for this instant was itself refused (step=%d); "+
			"the rejections below would pass against a verifier that accepts nothing", step)
	}

	for _, tc := range invalidCodes {
		if tc.code == validCode {
			continue // Skip if happens to be the valid code
		}
		t.Run(tc.name, func(t *testing.T) {
			step, _ := vaultcrypto.ValidateTOTPCode(secret, tc.code, now)
			if step >= 0 {
				t.Fatalf("NIST MFA: Invalid code %q should be rejected", tc.code)
			}
		})
	}
}

// --- Section 3.1.4.2: Multi-Factor OTP Device ---

func TestNIST_MFA_TOTPSecretEncryption(t *testing.T) {
	// NIST SP 800-63B-4 §3.1.4.2: "TOTP secrets SHALL be protected at rest."
	// Vault encrypts TOTP secrets with AES-256-GCM.
	secret, _ := vaultcrypto.GenerateTOTPSecret()
	masterKey := make([]byte, 32)
	rand.Read(masterKey)

	encrypted, err := vaultcrypto.Encrypt([]byte(secret), masterKey)
	if err != nil {
		t.Fatalf("NIST MFA: Encrypt TOTP secret failed: %v", err)
	}

	// Encrypted form must not contain plaintext
	if strings.Contains(string(encrypted), secret) {
		t.Fatal("NIST MFA: Encrypted secret contains plaintext")
	}

	// Correct key recovers the secret
	decrypted, err := vaultcrypto.Decrypt(encrypted, masterKey)
	if err != nil {
		t.Fatalf("NIST MFA: Decrypt TOTP secret failed: %v", err)
	}
	if string(decrypted) != secret {
		t.Fatal("NIST MFA: Decrypted secret does not match original")
	}

	// Wrong key cannot recover
	wrongKey := make([]byte, 32)
	rand.Read(wrongKey)
	_, err = vaultcrypto.Decrypt(encrypted, wrongKey)
	if err == nil {
		t.Fatal("NIST MFA: Decryption with wrong key should fail")
	}
}

// --- Section 3.1.2: Look-Up Secrets (Backup Codes) ---

func TestNIST_MFA_BackupCodeEntropy(t *testing.T) {
	// NIST SP 800-63B-4 §3.1.2.1: "Look-up secrets SHALL have at least 20 bits
	// of entropy if rate limiting is applied."
	// Vault: RandomHex(6) = 48 bits.
	code, _ := vaultcrypto.RandomHex(6)
	entropyBits := len(code) / 2 * 8 // hex chars / 2 = bytes * 8 = bits
	if entropyBits < 20 {
		t.Fatalf("NIST MFA: Backup code entropy (%d bits) < 20 bits", entropyBits)
	}
	if entropyBits < 48 {
		t.Fatalf("NIST MFA: Expected 48-bit backup codes, got %d bits", entropyBits)
	}
}

func TestNIST_MFA_BackupCodeHashStorage(t *testing.T) {
	// NIST SP 800-63B-4 §3.1.2.2: "Look-up secrets SHALL be hashed and salted."
	codes := make([]string, 10)
	hashes := make([]string, 10)

	for i := 0; i < 10; i++ {
		codes[i], _ = vaultcrypto.RandomHex(6)
		var err error
		hashes[i], err = vaultcrypto.HashPassword(codes[i])
		if err != nil {
			t.Fatalf("NIST MFA: HashPassword for backup code failed: %v", err)
		}

		// Verify Argon2id is used
		if !strings.HasPrefix(hashes[i], "$argon2id$") {
			t.Fatal("NIST MFA: Backup codes must be hashed with Argon2id")
		}
	}

	// Each hash must be unique (unique salts)
	seen := make(map[string]bool)
	for _, h := range hashes {
		if seen[h] {
			t.Fatal("NIST MFA: Backup code hashes must use unique salts")
		}
		seen[h] = true
	}
}

func TestNIST_MFA_BackupCodeVerification(t *testing.T) {
	// NIST SP 800-63B-4 §3.1.2.2: Verify that backup codes can be verified
	// against their hashes and wrong codes are rejected.
	code, _ := vaultcrypto.RandomHex(6)
	hash, _ := vaultcrypto.HashPassword(code)

	// Correct code verifies
	match, _ := vaultcrypto.VerifyPassword(code, hash)
	if !match {
		t.Fatal("NIST MFA: Correct backup code should verify")
	}

	// Wrong code rejected
	wrongCode, _ := vaultcrypto.RandomHex(6)
	match, _ = vaultcrypto.VerifyPassword(wrongCode, hash)
	if match && wrongCode != code {
		t.Fatal("NIST MFA: Wrong backup code should not verify")
	}
}

// --- Section 3.2: General Authenticator Requirements ---

func TestNIST_MFA_AuthenticatorOutputSecure(t *testing.T) {
	// NIST SP 800-63B-4 §5.2.1: "Authenticator outputs SHALL be compared using
	// approved methods" (constant-time comparison).
	code1 := "123456"
	code2 := "123456"
	code3 := "654321"

	if !vaultcrypto.SecureCompare(code1, code2) {
		t.Fatal("NIST MFA: Equal codes should compare true")
	}
	if vaultcrypto.SecureCompare(code1, code3) {
		t.Fatal("NIST MFA: Different codes should compare false")
	}
}

func TestNIST_MFA_TOTPWindowStrictness(t *testing.T) {
	// NIST SP 800-63B-4 §5.2.8: The window of time for OTP acceptance should be
	// as small as possible. Vault allows ±1 period (minimal).
	secret, _ := vaultcrypto.GenerateTOTPSecret()
	now := time.Now()

	// Test various time offsets
	offsets := []struct {
		name     string
		offset   time.Duration
		mustFail bool
	}{
		{"current", 0, false},
		{"minus_15s", -15 * time.Second, false},  // Same or adjacent period
		{"minus_60s", -60 * time.Second, false},  // Adjacent period (±1)
		{"minus_90s", -90 * time.Second, true},   // Beyond ±1 window
		{"minus_120s", -120 * time.Second, true}, // Way beyond window
		{"minus_5min", -5 * time.Minute, true},
		{"plus_60s", 60 * time.Second, false}, // Future period (±1)
		{"plus_90s", 90 * time.Second, true},  // Beyond ±1 window
	}

	for _, tc := range offsets {
		t.Run(tc.name, func(t *testing.T) {
			codeTime := now.Add(tc.offset)
			code, _ := vaultcrypto.GenerateTOTPCode(secret, codeTime)
			step, _ := vaultcrypto.ValidateTOTPCode(secret, code, now)

			if tc.mustFail && step >= 0 {
				t.Fatalf("NIST MFA: Code from offset %v should be rejected", tc.offset)
			}
		})
	}
}

func TestNIST_MFA_TOTPDeterministicGeneration(t *testing.T) {
	// NIST SP 800-63B-4 §3.1.4: The same secret + same time must always produce
	// the same code (deterministic).
	secret := "JBSWY3DPEHPK3PXP"
	fixedTime := time.Unix(1700000000, 0)

	code1, _ := vaultcrypto.GenerateTOTPCode(secret, fixedTime)
	for i := 0; i < 50; i++ {
		code, _ := vaultcrypto.GenerateTOTPCode(secret, fixedTime)
		if code != code1 {
			t.Fatalf("NIST MFA: TOTP not deterministic at iteration %d: %s vs %s", i, code, code1)
		}
	}
}

func TestNIST_MFA_TOTPNegativeTimestamp(t *testing.T) {
	// Edge case: timestamps before Unix epoch should be handled gracefully.
	secret, _ := vaultcrypto.GenerateTOTPSecret()
	negativeTime := time.Unix(-100, 0)

	_, err := vaultcrypto.GenerateTOTPCode(secret, negativeTime)
	if err == nil {
		t.Fatal("NIST MFA: Negative timestamp should return error")
	}
}

func TestNIST_MFA_OTPAuthURLFormat(t *testing.T) {
	// NIST: OTP provisioning URI must follow the standard format.
	secret := "JBSWY3DPEHPK3PXP"
	url := vaultcrypto.BuildOTPAuthURL(secret, "TheVault", "user@example.com")

	required := []string{
		"otpauth://totp/",
		"secret=" + secret,
		"issuer=TheVault",
		"algorithm=SHA1",
		"digits=6",
		"period=30",
	}

	for _, req := range required {
		if !strings.Contains(url, req) {
			t.Fatalf("NIST MFA: OTPAuth URL missing %q in %s", req, url)
		}
	}
}
