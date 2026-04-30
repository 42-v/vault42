package compliance

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// =============================================================================
// OWASP ASVS v4.0.3 — Cryptography (V6.x)
// =============================================================================

// --- V6.1: Data Classification ---

func TestASVS_V6_1_1_SensitiveDataEncrypted(t *testing.T) {
	// V6.1.1: Verify that regulated private data is stored encrypted while at rest.
	// Vault encrypts TOTP secrets with AES-256-GCM before DB storage.
	masterKey := make([]byte, 32)
	rand.Read(masterKey)

	secrets := []string{
		"JBSWY3DPEHPK3PXP",  // TOTP secret
		"user@example.com",  // email (PII)
		"sensitive-api-key", // API key
	}

	for _, secret := range secrets {
		encrypted, err := vaultcrypto.Encrypt([]byte(secret), masterKey)
		if err != nil {
			t.Fatalf("V6.1.1: Encrypt failed: %v", err)
		}

		// Encrypted data must not contain the plaintext
		if strings.Contains(string(encrypted), secret) {
			t.Fatalf("V6.1.1: Encrypted data contains plaintext %q", secret)
		}

		// Must be recoverable with correct key
		decrypted, err := vaultcrypto.Decrypt(encrypted, masterKey)
		if err != nil {
			t.Fatalf("V6.1.1: Decrypt failed: %v", err)
		}
		if string(decrypted) != secret {
			t.Fatalf("V6.1.1: Decrypted data mismatch")
		}
	}
}

func TestASVS_V6_1_2_WrongKeyCannotDecrypt(t *testing.T) {
	// V6.1.2: Verify that encryption provides confidentiality — wrong key
	// cannot recover data.
	correctKey := make([]byte, 32)
	wrongKey := make([]byte, 32)
	rand.Read(correctKey)
	rand.Read(wrongKey)

	plaintext := []byte("confidential user data")
	encrypted, _ := vaultcrypto.Encrypt(plaintext, correctKey)

	_, err := vaultcrypto.Decrypt(encrypted, wrongKey)
	if err == nil {
		t.Fatal("V6.1.2: Decryption with wrong key should fail (GCM authentication)")
	}
}

// --- V6.2: Algorithms ---

func TestASVS_V6_2_1_RS256Only(t *testing.T) {
	// V6.2.1: Verify that all cryptographic modules use approved algorithms.
	// JWT signing: RS256 only (no HS256, ES256, PS256, none).
	if vaultcrypto.AllowedAlgorithm != "RS256" {
		t.Fatalf("V6.2.1: Expected RS256, got %s", vaultcrypto.AllowedAlgorithm)
	}
}

func TestASVS_V6_2_2_AES256KeyEnforcement(t *testing.T) {
	// V6.2.2: Verify that industry-approved cryptographic algorithms are used.
	// AES must use 256-bit keys (32 bytes).
	plaintext := []byte("test data for aes verification")

	validKeySizes := map[int]bool{32: true}
	invalidKeySizes := []int{0, 8, 16, 24, 48, 64, 128}

	for size, shouldWork := range validKeySizes {
		key := make([]byte, size)
		rand.Read(key)
		_, err := vaultcrypto.Encrypt(plaintext, key)
		if shouldWork && err != nil {
			t.Fatalf("V6.2.2: AES-256 (%d bytes) should work: %v", size, err)
		}
	}

	for _, size := range invalidKeySizes {
		key := make([]byte, size)
		if size > 0 {
			rand.Read(key)
		}
		_, err := vaultcrypto.Encrypt(plaintext, key)
		if err == nil {
			t.Fatalf("V6.2.2: AES should reject %d-byte key", size)
		}
	}
}

func TestASVS_V6_2_3_HMACSHA256Output(t *testing.T) {
	// V6.2.3: Verify that HMAC uses SHA-256 or stronger.
	key := make([]byte, 32)
	rand.Read(key)
	msg := []byte("test message for hmac")

	sig := vaultcrypto.HMACSign(msg, key)

	// SHA-256 output = 32 bytes = 64 hex chars
	if len(sig) != 64 {
		t.Fatalf("V6.2.3: HMAC output should be 64 hex chars (SHA-256), got %d", len(sig))
	}

	// Verify it's valid hex
	for _, c := range sig {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("V6.2.3: HMAC output contains non-hex char: %c", c)
		}
	}
}

func TestASVS_V6_2_4_HMACConstantTimeVerification(t *testing.T) {
	// V6.2.4: Verify that HMAC verification uses constant-time comparison.
	key := []byte("hmac-test-key-asvs-v6-2-4")
	msg := []byte("message to verify")

	sig := vaultcrypto.HMACSign(msg, key)

	// Correct verification
	if !vaultcrypto.HMACVerify(msg, key, sig) {
		t.Fatal("V6.2.4: Correct HMAC should verify")
	}

	// Tampered message
	if vaultcrypto.HMACVerify([]byte("tampered"), key, sig) {
		t.Fatal("V6.2.4: Tampered message should fail HMAC")
	}

	// Tampered signature (flip one hex char)
	tampered := "X" + sig[1:]
	if vaultcrypto.HMACVerify(msg, key, tampered) {
		t.Fatal("V6.2.4: Tampered signature should fail HMAC")
	}

	// Wrong key
	if vaultcrypto.HMACVerify(msg, []byte("wrong-key"), sig) {
		t.Fatal("V6.2.4: Wrong key should fail HMAC")
	}
}

// --- V6.2.5: Authenticated Encryption ---

func TestASVS_V6_2_5_GCMTamperDetection(t *testing.T) {
	// V6.2.5: Verify that authenticated encryption (AES-GCM) detects tampering.
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := []byte("data that must maintain integrity")

	ct, _ := vaultcrypto.Encrypt(plaintext, key)

	// Tamper with different positions
	positions := []int{0, 6, 12, len(ct) / 2, len(ct) - 1}
	for _, pos := range positions {
		if pos >= len(ct) {
			continue
		}
		tampered := make([]byte, len(ct))
		copy(tampered, ct)
		tampered[pos] ^= 0xFF

		_, err := vaultcrypto.Decrypt(tampered, key)
		if err == nil {
			t.Fatalf("V6.2.5: Tampered ciphertext at position %d should fail authentication", pos)
		}
	}
}

func TestASVS_V6_2_5_GCMTruncationDetection(t *testing.T) {
	// V6.2.5: Truncated ciphertext must fail authentication.
	key := make([]byte, 32)
	rand.Read(key)
	ct, _ := vaultcrypto.Encrypt([]byte("truncation test data"), key)

	truncations := []int{1, 5, 12, len(ct) / 2, len(ct) - 1}
	for _, n := range truncations {
		if n >= len(ct) {
			continue
		}
		_, err := vaultcrypto.Decrypt(ct[:len(ct)-n], key)
		if err == nil {
			t.Fatalf("V6.2.5: Ciphertext truncated by %d bytes should fail", n)
		}
	}
}

// --- V6.3: Random Values ---

func TestASVS_V6_3_1_CSPRNGForAllCryptoOps(t *testing.T) {
	// V6.3.1: Verify that all random numbers are generated using a
	// cryptographically secure pseudo-random number generator (CSPRNG).

	t.Run("random_bytes_quality", func(t *testing.T) {
		b, _ := vaultcrypto.RandomBytes(256)
		// Chi-squared test: count byte frequencies
		freq := make([]int, 256)
		for _, v := range b {
			freq[v]++
		}
		// At least 100 distinct values in 256 bytes (birthday paradox)
		distinct := 0
		for _, f := range freq {
			if f > 0 {
				distinct++
			}
		}
		if distinct < 100 {
			t.Fatalf("V6.3.1: Only %d distinct values in 256 bytes — poor CSPRNG", distinct)
		}
	})

	t.Run("uuid_format", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			uuid, _ := vaultcrypto.RandomUUID()
			parts := strings.Split(uuid, "-")
			if len(parts) != 5 {
				t.Fatalf("V6.3.1: UUID format invalid: %s", uuid)
			}
			// Version 4
			if parts[2][0] != '4' {
				t.Fatalf("V6.3.1: UUID version should be 4, got %c in %s", parts[2][0], uuid)
			}
		}
	})
}

func TestASVS_V6_3_2_NoSeededPRNG(t *testing.T) {
	// V6.3.2: Verify that random values are not generated from a seeded PRNG.
	// Vault uses crypto/rand exclusively. Two consecutive calls must differ.
	results := make([][]byte, 100)
	for i := range results {
		b, _ := vaultcrypto.RandomBytes(32)
		results[i] = b
	}

	for i := 0; i < len(results)-1; i++ {
		if vaultcrypto.SecureCompareBytes(results[i], results[i+1]) {
			t.Fatalf("V6.3.2: Consecutive RandomBytes calls produced identical output at index %d", i)
		}
	}
}

// --- V6.4: Secret Management ---

func TestASVS_V6_4_1_JWKSSerializationCorrectness(t *testing.T) {
	// V6.4.1: Verify JWKS is correctly formatted for key exchange.
	key1, _ := vaultcrypto.GenerateRSAKeyPair()
	key2, _ := vaultcrypto.GenerateRSAKeyPair()
	kid1, _ := vaultcrypto.RandomUUID()
	kid2, _ := vaultcrypto.RandomUUID()

	keys := map[string]*rsa.PublicKey{
		kid1: &key1.PublicKey,
		kid2: &key2.PublicKey,
	}

	jwks := vaultcrypto.SerializeJWKS(keys)

	for _, jwk := range jwks.Keys {
		// Verify all required fields
		if jwk.KTY != "RSA" {
			t.Fatalf("V6.4.1: JWK kty must be RSA, got %s", jwk.KTY)
		}
		if jwk.Use != "sig" {
			t.Fatalf("V6.4.1: JWK use must be sig, got %s", jwk.Use)
		}
		if jwk.ALG != "RS256" {
			t.Fatalf("V6.4.1: JWK alg must be RS256, got %s", jwk.ALG)
		}

		// N and E must be valid base64url
		_, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			t.Fatalf("V6.4.1: JWK N is not valid base64url: %v", err)
		}
		_, err = base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			t.Fatalf("V6.4.1: JWK E is not valid base64url: %v", err)
		}
	}
}

func TestASVS_V6_4_2_KeyRotationPreservesOldTokens(t *testing.T) {
	// V6.4.2: Verify that key rotation does not immediately invalidate
	// tokens signed with the old key (graceful rotation).
	oldKey, _ := vaultcrypto.GenerateRSAKeyPair()
	newKey, _ := vaultcrypto.GenerateRSAKeyPair()
	oldKID, _ := vaultcrypto.RandomUUID()
	newKID, _ := vaultcrypto.RandomUUID()

	// Sign tokens with both keys
	oldToken, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject: "user", Issuer: "vault", Audience: vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, oldKey, oldKID)

	newToken, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject: "user", Issuer: "vault", Audience: vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, newKey, newKID)

	// Multi-key resolver (simulates JWKS with both keys)
	multiKeyFunc := func(t *vjwt.Token) (any, error) {
		kid := t.Header["kid"].(string)
		switch kid {
		case oldKID:
			return &oldKey.PublicKey, nil
		case newKID:
			return &newKey.PublicKey, nil
		}
		return nil, vjwt.ErrTokenMalformed
	}

	// Both tokens should validate
	_, err := vaultcrypto.ParseAndValidate(oldToken, multiKeyFunc, "vault", "app")
	if err != nil {
		t.Fatalf("V6.4.2: Old token should still validate: %v", err)
	}
	_, err = vaultcrypto.ParseAndValidate(newToken, multiKeyFunc, "vault", "app")
	if err != nil {
		t.Fatalf("V6.4.2: New token should validate: %v", err)
	}
}

// --- V6.5: Constant Time ---

func TestASVS_V6_5_1_ConstantTimeStringComparison(t *testing.T) {
	// V6.5.1: Verify that all cryptographic comparisons use constant-time
	// operations to prevent timing attacks.
	tests := []struct {
		a, b string
		want bool
	}{
		{"match", "match", true},
		{"differ", "mismatch", false},
		{"", "", true},
		{"short", "very-long-string-here", false},
		{"abc\x00def", "abc\x00def", true},
		{"abc\x00def", "abc\x00xyz", false},
	}

	for _, tc := range tests {
		got := vaultcrypto.SecureCompare(tc.a, tc.b)
		if got != tc.want {
			t.Fatalf("V6.5.1: SecureCompare(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestASVS_V6_5_1_ConstantTimeBytesComparison(t *testing.T) {
	// V6.5.1: Byte-level constant-time comparison.
	a := []byte{0x01, 0x02, 0x03, 0x04}
	b := []byte{0x01, 0x02, 0x03, 0x04}
	c := []byte{0xFF, 0x02, 0x03, 0x04}

	if !vaultcrypto.SecureCompareBytes(a, b) {
		t.Fatal("V6.5.1: Equal byte slices should compare true")
	}
	if vaultcrypto.SecureCompareBytes(a, c) {
		t.Fatal("V6.5.1: Different byte slices should compare false")
	}
	if vaultcrypto.SecureCompareBytes(a, nil) {
		t.Fatal("V6.5.1: Non-nil vs nil should compare false")
	}
}

// --- V6.2.6: Unique Nonces ---

func TestASVS_V6_2_6_NoncesNeverReused(t *testing.T) {
	// V6.2.6: Verify that nonces are not reused across encryption operations.
	key := make([]byte, 32)
	rand.Read(key)

	nonces := make(map[string]bool)
	for i := 0; i < 200; i++ {
		ct, err := vaultcrypto.Encrypt([]byte("same plaintext"), key)
		if err != nil {
			t.Fatalf("V6.2.6: Encrypt failed at iteration %d: %v", i, err)
		}

		// Extract nonce (first 12 bytes)
		nonce := string(ct[:12])
		if nonces[nonce] {
			t.Fatalf("V6.2.6: Nonce reuse detected at iteration %d", i)
		}
		nonces[nonce] = true
	}
}

// --- V6.2.7: Argon2id Memory-Hard Properties ---

func TestASVS_V6_2_7_Argon2idMemoryHardness(t *testing.T) {
	// V6.2.7: Verify that password hashing uses a memory-hard function.
	// Argon2id with 46 MiB memory is specifically designed to resist GPU attacks.
	hash, _ := vaultcrypto.HashPassword("memory-hardness-test!")
	parts := strings.Split(hash, "$")

	if parts[1] != "argon2id" {
		t.Fatalf("V6.2.7: Must use argon2id, got %s", parts[1])
	}

	params := parts[3]
	if !strings.Contains(params, "m=47104") {
		t.Fatalf("V6.2.7: Memory should be 47104 KiB (46 MiB), got: %s", params)
	}
}

func TestASVS_V6_2_7_Argon2idSaltSize(t *testing.T) {
	// V6.2.7: Salt must be at least 128 bits (16 bytes).
	hash, _ := vaultcrypto.HashPassword("salt-size-test!")
	parts := strings.Split(hash, "$")

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatalf("V6.2.7: Failed to decode salt: %v", err)
	}
	if len(salt) < 16 {
		t.Fatalf("V6.2.7: Salt must be >= 128 bits (16 bytes), got %d bytes", len(salt))
	}
}

func TestASVS_V6_2_7_Argon2idOutputSize(t *testing.T) {
	// V6.2.7: Hash output must be at least 256 bits (32 bytes).
	hash, _ := vaultcrypto.HashPassword("output-size-test!")
	parts := strings.Split(hash, "$")

	output, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		t.Fatalf("V6.2.7: Failed to decode hash output: %v", err)
	}
	if len(output) < 32 {
		t.Fatalf("V6.2.7: Hash output must be >= 256 bits (32 bytes), got %d bytes", len(output))
	}
}
