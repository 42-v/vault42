package crypto

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
	"time"

	vjwt "github.com/42-v/vault42/internal/jwt"
)

// ===========================================================================
// ParseAndValidate edge cases — malformed tokens, unknown algorithms
// ===========================================================================

// TestParseAndValidate_CompletelyMalformedTokens tests tokens that are not even
// close to valid JWTs but have the right number of dots.
func TestParseAndValidate_CompletelyMalformedTokens(t *testing.T) {
	key, _ := setupTestKeys(t)

	cases := []struct {
		name  string
		token string
	}{
		{"random_ascii", "aaa.bbb.ccc"},
		{"whitespace_parts", " . . "},
		{"very_long_header", strings.Repeat("A", 4000) + ".payload.sig"},
		{"very_long_payload", "header." + strings.Repeat("B", 4000) + ".sig"},
		{"very_long_signature", "header.payload." + strings.Repeat("C", 4000)},
		{"json_but_wrong_alg", "eyJhbGciOiJ1bmtub3duIn0.eyJzdWIiOiIxMjMifQ.sig"},
		{"only_dots", "..."},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseAndValidate(tc.token, keyFunc(key), testIssuer, testAudience)
			if err == nil {
				t.Fatalf("malformed token %q should be rejected", tc.name)
			}
		})
	}
}

// TestParseAndValidate_UnknownAlgorithms tests that tokens signed with
// algorithms other than RS256 are rejected.
func TestParseAndValidate_UnknownAlgorithms(t *testing.T) {
	key, _ := setupTestKeys(t)

	algorithms := []struct {
		name string
		alg  string
	}{
		{"ES256", "ES256"},
		{"ES384", "ES384"},
		{"ES512", "ES512"},
		{"PS256", "PS256"},
		{"PS384", "PS384"},
		{"PS512", "PS512"},
		{"RS384", "RS384"},
		{"RS512", "RS512"},
		{"HS384", "HS384"},
		{"HS512", "HS512"},
		{"EdDSA", "EdDSA"},
		{"empty_alg", ""},
		{"custom_alg", "CUSTOM-256"},
	}

	for _, tc := range algorithms {
		t.Run(tc.name, func(t *testing.T) {
			// Build a token with the given alg in header, sign with RS256 key anyway
			// The parser should reject based on algorithm whitelist before signature check
			tokenStr, err := vjwt.SignRS256WithHeader(map[string]any{
				"alg": tc.alg, "typ": "JWT", "kid": "test-kid-aa",
			}, validClaims(), key)
			if err != nil {
				// Some algorithms may fail to sign — that's fine, skip
				return
			}

			_, err = ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
			if err == nil {
				t.Fatalf("algorithm %q should be rejected", tc.alg)
			}
		})
	}
}

// TestParseAndValidate_CorruptedSignature tests that a valid token with a
// corrupted signature byte is rejected.
func TestParseAndValidate_CorruptedSignature(t *testing.T) {
	key, kid := setupTestKeys(t)
	claims := validClaims()
	tokenStr, err := SignToken(claims, key, kid)
	if err != nil {
		t.Fatal(err)
	}

	// Split into parts and corrupt the last byte of the signature
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 || len(parts[2]) < 2 {
		t.Fatal("unexpected token structure")
	}

	// Decode the base64url signature, flip actual bytes, and re-encode.
	// Flipping base64 characters (the old approach) could affect only padding
	// bits, leaving the decoded RSA signature unchanged.
	rawSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	rawSig[0] ^= 0xFF // flip all bits of the first byte
	corruptedToken := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(rawSig)

	_, err = ParseAndValidate(corruptedToken, keyFunc(key), testIssuer, testAudience)
	if err == nil {
		t.Fatal("token with corrupted signature should be rejected")
	}
}

// TestParseAndValidate_DifferentRSAKey tests that a token signed with one RSA
// key is rejected when validated against a different key.
func TestParseAndValidate_DifferentRSAKey(t *testing.T) {
	key1, kid := setupTestKeys(t)
	key2, _ := setupTestKeys(t)

	tokenStr, err := SignToken(validClaims(), key1, kid)
	if err != nil {
		t.Fatal(err)
	}

	// Use key2's public key for validation
	kf := func(t *vjwt.Token) (any, error) {
		return &key2.PublicKey, nil
	}

	_, err = ParseAndValidate(tokenStr, kf, testIssuer, testAudience)
	if err == nil {
		t.Fatal("token signed with key1 should be rejected when validated with key2")
	}
}

// TestParseAndValidate_OversizedExactBoundary tests tokens at exactly the 8KB
// boundary.
func TestParseAndValidate_OversizedExactBoundary(t *testing.T) {
	key, _ := setupTestKeys(t)

	// Token at exactly MaxJWTSize should not trigger the size error
	exactSizeToken := strings.Repeat("x", MaxJWTSize)
	_, err := ParseAndValidate(exactSizeToken, keyFunc(key), testIssuer, testAudience)
	if err != nil && strings.Contains(err.Error(), "maximum size") {
		t.Fatal("token at exactly MaxJWTSize should not fail with size error")
	}

	// Token at MaxJWTSize+1 should trigger size error
	oversizedToken := strings.Repeat("x", MaxJWTSize+1)
	_, err = ParseAndValidate(oversizedToken, keyFunc(key), testIssuer, testAudience)
	if err == nil || !strings.Contains(err.Error(), "maximum size") {
		t.Fatalf("token at MaxJWTSize+1 should fail with maximum size error, got: %v", err)
	}
}

// TestParseAndValidate_KeyFuncError tests that errors from keyFunc propagate.
func TestParseAndValidate_KeyFuncError(t *testing.T) {
	key, kid := setupTestKeys(t)

	tokenStr, err := SignToken(validClaims(), key, kid)
	if err != nil {
		t.Fatal(err)
	}

	// keyFunc that returns nil key
	nilKeyFunc := func(t *vjwt.Token) (any, error) {
		return nil, vjwt.ErrTokenSignatureInvalid
	}

	_, err = ParseAndValidate(tokenStr, nilKeyFunc, testIssuer, testAudience)
	if err == nil {
		t.Fatal("keyFunc error should propagate and reject token")
	}
}

// TestParseAndValidate_MissingExpiration tests that tokens without exp claim
// are rejected.
func TestParseAndValidate_MissingExpiration(t *testing.T) {
	key, kid := setupTestKeys(t)

	claims := VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:   testIssuer,
			Audience: vjwt.ClaimStrings{testAudience},
			IssuedAt: vjwt.NewNumericDate(time.Now()),
			// No ExpiresAt
		},
	}

	tokenStr, err := vjwt.SignRS256WithHeader(map[string]any{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	}, claims, key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseAndValidate(tokenStr, keyFunc(key), testIssuer, testAudience)
	if err == nil {
		t.Fatal("token without expiration should be rejected")
	}
}

// ===========================================================================
// ComputeFingerprint additional edge cases
// ===========================================================================

// TestComputeFingerprint_NilEquivalent tests that zero-value FingerprintInput
// produces a stable, non-empty hash.
func TestComputeFingerprint_NilEquivalent(t *testing.T) {
	fp1 := ComputeFingerprint(FingerprintInput{})
	fp2 := ComputeFingerprint(FingerprintInput{})

	if fp1 != fp2 {
		t.Fatal("same zero-value input should produce identical fingerprints")
	}
	if len(fp1) != 64 {
		t.Fatalf("fingerprint should be 64 hex chars, got %d", len(fp1))
	}

	// Verify it's valid hex
	_, err := hex.DecodeString(fp1)
	if err != nil {
		t.Fatalf("fingerprint should be valid hex: %v", err)
	}
}

// TestComputeFingerprint_SingleFieldChanges verifies that changing any single
// field produces a different fingerprint.
func TestComputeFingerprint_SingleFieldChanges(t *testing.T) {
	base := FingerprintInput{
		IP:             "1.2.3.4",
		UserAgent:      "TestAgent/1.0",
		AcceptLanguage: "en-US",
		TLSFingerprint: "tls-fp",
	}
	baseFP := ComputeFingerprint(base)

	modifications := []struct {
		name  string
		input FingerprintInput
	}{
		{"different_ip", FingerprintInput{IP: "5.6.7.8", UserAgent: "TestAgent/1.0", AcceptLanguage: "en-US", TLSFingerprint: "tls-fp"}},
		{"different_ua", FingerprintInput{IP: "1.2.3.4", UserAgent: "OtherAgent/2.0", AcceptLanguage: "en-US", TLSFingerprint: "tls-fp"}},
		{"different_lang", FingerprintInput{IP: "1.2.3.4", UserAgent: "TestAgent/1.0", AcceptLanguage: "de-DE", TLSFingerprint: "tls-fp"}},
		{"different_tls", FingerprintInput{IP: "1.2.3.4", UserAgent: "TestAgent/1.0", AcceptLanguage: "en-US", TLSFingerprint: "different-tls"}},
		{"ip_extra_char", FingerprintInput{IP: "1.2.3.4x", UserAgent: "TestAgent/1.0", AcceptLanguage: "en-US", TLSFingerprint: "tls-fp"}},
	}

	for _, tc := range modifications {
		t.Run(tc.name, func(t *testing.T) {
			fp := ComputeFingerprint(tc.input)
			if fp == baseFP {
				t.Fatalf("changing %s should produce a different fingerprint", tc.name)
			}
		})
	}
}

// TestComputeFingerprint_BinaryData tests fingerprinting with binary/non-UTF8 data.
func TestComputeFingerprint_BinaryData(t *testing.T) {
	fp := ComputeFingerprint(FingerprintInput{
		IP:             "\x00\x01\x02\x03",
		UserAgent:      "\xff\xfe\xfd",
		AcceptLanguage: "null\x00byte",
		TLSFingerprint: "\xde\xad\xbe\xef",
	})

	if len(fp) != 64 {
		t.Fatalf("binary input fingerprint should be 64 hex chars, got %d", len(fp))
	}

	// Should be deterministic
	fp2 := ComputeFingerprint(FingerprintInput{
		IP:             "\x00\x01\x02\x03",
		UserAgent:      "\xff\xfe\xfd",
		AcceptLanguage: "null\x00byte",
		TLSFingerprint: "\xde\xad\xbe\xef",
	})
	if fp != fp2 {
		t.Fatal("identical binary inputs should produce identical fingerprints")
	}
}

// ===========================================================================
// RandomBytes / RandomUUID additional edge cases
// ===========================================================================

// TestRandomBytes_ZeroLength tests that requesting 0 bytes returns empty slice.
func TestRandomBytes_ZeroLength(t *testing.T) {
	b, err := RandomBytes(0)
	if err != nil {
		t.Fatalf("RandomBytes(0) should not error: %v", err)
	}
	if len(b) != 0 {
		t.Fatalf("RandomBytes(0) should return empty slice, got %d bytes", len(b))
	}
}

// TestRandomBytes_LargeAllocation tests a large random byte request.
func TestRandomBytes_LargeAllocation(t *testing.T) {
	b, err := RandomBytes(1024)
	if err != nil {
		t.Fatalf("RandomBytes(1024) should not error: %v", err)
	}
	if len(b) != 1024 {
		t.Fatalf("RandomBytes(1024) should return 1024 bytes, got %d", len(b))
	}
}

// TestRandomBytes_OneByteNonZero tests that single random bytes are generated
// (basic sanity: over 100 calls, not all should be zero).
func TestRandomBytes_OneByteNonZero(t *testing.T) {
	allZero := true
	for i := 0; i < 100; i++ {
		b, err := RandomBytes(1)
		if err != nil {
			t.Fatal(err)
		}
		if b[0] != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("100 single random bytes were all zero — extremely unlikely with real randomness")
	}
}

// TestRandomUUID_FormatValidation tests UUID v4 format in detail.
func TestRandomUUID_FormatValidation(t *testing.T) {
	// UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
	// where y is 8, 9, a, or b
	uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

	for i := 0; i < 20; i++ {
		u, err := RandomUUID()
		if err != nil {
			t.Fatal(err)
		}
		if !uuidRegex.MatchString(u) {
			t.Fatalf("UUID %q does not match v4 format", u)
		}
	}
}

// TestRandomUUID_Uniqueness tests that multiple UUIDs are unique.
func TestRandomUUID_Uniqueness(t *testing.T) {
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		u, err := RandomUUID()
		if err != nil {
			t.Fatal(err)
		}
		if seen[u] {
			t.Fatalf("duplicate UUID generated: %s", u)
		}
		seen[u] = true
	}
}

// TestRandomHex_OutputIsHex tests that RandomHex produces valid hex strings.
func TestRandomHex_OutputIsHex(t *testing.T) {
	for _, n := range []int{1, 8, 16, 32, 64} {
		h, err := RandomHex(n)
		if err != nil {
			t.Fatal(err)
		}
		if len(h) != n*2 {
			t.Fatalf("RandomHex(%d) should return %d chars, got %d", n, n*2, len(h))
		}
		_, err = hex.DecodeString(h)
		if err != nil {
			t.Fatalf("RandomHex(%d) produced invalid hex: %v", n, err)
		}
	}
}

// TestRandomToken_MatchesRandomHex tests that RandomToken is equivalent to RandomHex.
func TestRandomToken_MatchesRandomHex(t *testing.T) {
	for _, n := range []int{16, 32, 64} {
		tok, err := RandomToken(n)
		if err != nil {
			t.Fatal(err)
		}
		if len(tok) != n*2 {
			t.Fatalf("RandomToken(%d) should return %d chars, got %d", n, n*2, len(tok))
		}
	}
}

// ===========================================================================
// AES-256-GCM additional edge cases
// ===========================================================================

// TestAES_NilPlaintext tests encrypting nil plaintext (should behave like empty).
func TestAES_NilPlaintext(t *testing.T) {
	key := make([]byte, 32)
	ct, err := Encrypt(nil, key)
	if err != nil {
		t.Fatalf("Encrypt(nil) should not error: %v", err)
	}
	pt, err := Decrypt(ct, key)
	if err != nil {
		t.Fatalf("Decrypt should succeed: %v", err)
	}
	if len(pt) != 0 {
		t.Fatalf("decrypted nil plaintext should be empty, got %d bytes", len(pt))
	}
}

// TestAES_WrongKeySize tests that keys of various incorrect sizes are rejected.
func TestAES_WrongKeySize(t *testing.T) {
	sizes := []int{0, 1, 8, 15, 16, 24, 31, 33, 48, 64, 128}
	for _, sz := range sizes {
		t.Run(strings.Repeat("x", 0)+string(rune('0'+sz%10)), func(t *testing.T) {
			key := make([]byte, sz)
			_, err := Encrypt([]byte("data"), key)
			if err == nil {
				t.Fatalf("key size %d should be rejected for Encrypt", sz)
			}
			_, err = Decrypt([]byte("data-plus-nonce-fake"), key)
			if err == nil {
				t.Fatalf("key size %d should be rejected for Decrypt", sz)
			}
		})
	}
}

// TestAES_NilKey tests that nil key is rejected.
func TestAES_NilKey(t *testing.T) {
	_, err := Encrypt([]byte("data"), nil)
	if err == nil {
		t.Fatal("nil key should be rejected for Encrypt")
	}
	_, err = Decrypt([]byte("data-with-fake-nonce"), nil)
	if err == nil {
		t.Fatal("nil key should be rejected for Decrypt")
	}
}

// TestAES_TamperedCiphertextByte tests that flipping any byte in the ciphertext
// causes decryption to fail (GCM authentication).
func TestAES_TamperedCiphertextByte(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("sensitive data that must be authenticated")

	ct, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}

	// Flip the last byte
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[len(tampered)-1] ^= 0xFF

	_, err = Decrypt(tampered, key)
	if err == nil {
		t.Fatal("tampered ciphertext should fail GCM authentication")
	}
}

// TestAES_EmptyCiphertext tests that empty/short ciphertexts are rejected.
func TestAES_EmptyCiphertext(t *testing.T) {
	key := make([]byte, 32)

	cases := []struct {
		name string
		ct   []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"one_byte", []byte{0x42}},
		{"twelve_bytes", make([]byte, 12)}, // exactly nonce size, no actual ciphertext
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decrypt(tc.ct, key)
			if err == nil {
				t.Fatalf("Decrypt(%s) should fail", tc.name)
			}
		})
	}
}

// TestAES_AADMismatch tests that decryption fails when AAD doesn't match.
func TestAES_AADMismatch(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("context-bound data")
	aad := []byte("user-id-123")

	ct, err := Encrypt(plaintext, key, aad)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt with wrong AAD
	_, err = Decrypt(ct, key, []byte("user-id-456"))
	if err == nil {
		t.Fatal("decryption with wrong AAD should fail")
	}

	// Decrypt with correct AAD should work
	pt, err := Decrypt(ct, key, aad)
	if err != nil {
		t.Fatalf("decryption with correct AAD should succeed: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("got %q, want %q", pt, plaintext)
	}

	// Decrypt with no AAD should fail
	_, err = Decrypt(ct, key)
	if err == nil {
		t.Fatal("decryption without AAD should fail when AAD was used for encryption")
	}
}

// TestAES_LargePlaintext tests encryption/decryption of large data.
func TestAES_LargePlaintext(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := make([]byte, 1024*1024) // 1MB
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ct, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}

	pt, err := Decrypt(ct, key)
	if err != nil {
		t.Fatal(err)
	}

	if len(pt) != len(plaintext) {
		t.Fatalf("decrypted length %d, want %d", len(pt), len(plaintext))
	}
	for i := range pt {
		if pt[i] != plaintext[i] {
			t.Fatalf("byte mismatch at index %d", i)
		}
	}
}

// ===========================================================================
// HMAC edge cases
// ===========================================================================

// TestHMAC_EmptyMessage tests HMAC with empty message.
func TestHMAC_EmptyMessage(t *testing.T) {
	key := []byte("secret-key")
	sig := HMACSign([]byte{}, key)
	if sig == "" {
		t.Fatal("HMAC of empty message should not be empty string")
	}
	if len(sig) != 64 { // SHA-256 = 32 bytes = 64 hex chars
		t.Fatalf("HMAC signature should be 64 hex chars, got %d", len(sig))
	}
	if !HMACVerify([]byte{}, key, sig) {
		t.Fatal("empty message HMAC should verify")
	}
}

// TestHMAC_NilMessage tests HMAC with nil message.
func TestHMAC_NilMessage(t *testing.T) {
	key := []byte("secret-key")
	sig := HMACSign(nil, key)
	if sig == "" {
		t.Fatal("HMAC of nil message should not be empty string")
	}
	if !HMACVerify(nil, key, sig) {
		t.Fatal("nil message HMAC should verify")
	}
}

// TestHMAC_EmptyKey tests HMAC with empty key.
func TestHMAC_EmptyKey(t *testing.T) {
	msg := []byte("some message")
	sig := HMACSign(msg, []byte{})
	if sig == "" {
		t.Fatal("HMAC with empty key should produce a signature")
	}
	if !HMACVerify(msg, []byte{}, sig) {
		t.Fatal("empty key HMAC should verify with same empty key")
	}
	// Different key should not verify
	if HMACVerify(msg, []byte("different"), sig) {
		t.Fatal("empty key HMAC should not verify with non-empty key")
	}
}

// TestHMAC_NilKey tests HMAC with nil key.
func TestHMAC_NilKey(t *testing.T) {
	msg := []byte("test message")
	sig := HMACSign(msg, nil)
	if sig == "" {
		t.Fatal("HMAC with nil key should produce a signature")
	}
	if !HMACVerify(msg, nil, sig) {
		t.Fatal("nil key HMAC should verify with nil key")
	}
}

// TestHMAC_EmptySignature tests HMACVerify with empty signature string.
func TestHMAC_EmptySignature(t *testing.T) {
	msg := []byte("message")
	key := []byte("key")
	if HMACVerify(msg, key, "") {
		t.Fatal("empty signature should never verify")
	}
}

// TestHMAC_InvalidHexSignature tests HMACVerify with non-hex signature strings.
func TestHMAC_InvalidHexSignature(t *testing.T) {
	msg := []byte("message")
	key := []byte("key")

	badSigs := []string{
		"not-hex-at-all",
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
		"DEADBEEF", // uppercase (valid hex but different from lowercase output)
		"short",
	}

	for _, sig := range badSigs {
		if HMACVerify(msg, key, sig) {
			t.Fatalf("invalid hex signature %q should not verify", sig)
		}
	}
}

// TestHMAC_Deterministic tests that HMAC with same inputs always produces same output.
func TestHMAC_Deterministic(t *testing.T) {
	msg := []byte("deterministic test")
	key := []byte("consistent key")

	sig1 := HMACSign(msg, key)
	sig2 := HMACSign(msg, key)
	sig3 := HMACSign(msg, key)

	if sig1 != sig2 || sig2 != sig3 {
		t.Fatal("HMAC should be deterministic")
	}
}

// TestHMAC_KeyDifference tests that even a single bit difference in key
// produces a different signature.
func TestHMAC_KeyDifference(t *testing.T) {
	msg := []byte("same message")
	key1 := []byte("key-version-1")
	key2 := []byte("key-version-2")

	sig1 := HMACSign(msg, key1)
	sig2 := HMACSign(msg, key2)

	if sig1 == sig2 {
		t.Fatal("different keys should produce different signatures")
	}
}

// ===========================================================================
// SecureCompare / SecureCompareBytes edge cases
// ===========================================================================

// TestSecureCompare_NilBytes tests SecureCompareBytes with nil inputs.
func TestSecureCompare_NilBytes(t *testing.T) {
	if !SecureCompareBytes(nil, nil) {
		t.Fatal("nil vs nil should be equal")
	}
	if !SecureCompareBytes(nil, []byte{}) {
		t.Fatal("nil vs empty should be equal (both zero length)")
	}
	if SecureCompareBytes(nil, []byte{0}) {
		t.Fatal("nil vs non-empty should not be equal")
	}
}

// TestSecureCompare_LongStrings tests constant-time comparison with long strings.
func TestSecureCompare_LongStrings(t *testing.T) {
	a := strings.Repeat("a", 10000)
	b := strings.Repeat("a", 10000)
	c := strings.Repeat("a", 9999) + "b"

	if !SecureCompare(a, b) {
		t.Fatal("identical long strings should match")
	}
	if SecureCompare(a, c) {
		t.Fatal("long strings differing in last char should not match")
	}
}

// ===========================================================================
// SHA256 additional edge cases
// ===========================================================================

// TestSHA256Hex_LargeInput tests SHA256 of a large input.
func TestSHA256Hex_LargeInput(t *testing.T) {
	large := strings.Repeat("x", 1024*1024)
	h := SHA256Hex(large)
	if len(h) != 64 {
		t.Fatalf("SHA256 of large input should be 64 hex chars, got %d", len(h))
	}
}

// TestSHA256Base64URL_Format tests that SHA256Base64URL returns valid base64url.
func TestSHA256Base64URL_Format(t *testing.T) {
	h := SHA256Base64URL("test")
	if strings.ContainsAny(h, "+/=") {
		t.Fatalf("SHA256Base64URL should not contain +, /, or = (base64url): got %q", h)
	}
	if len(h) != 43 { // 32 bytes base64url-encoded without padding = 43 chars
		t.Fatalf("SHA256Base64URL should be 43 chars, got %d", len(h))
	}
}

// TestSHA256Bytes_NilInput tests SHA256 of nil.
func TestSHA256Bytes_NilInput(t *testing.T) {
	h := SHA256Bytes(nil)
	if len(h) != 32 {
		t.Fatalf("SHA256 of nil should be 32 bytes, got %d", len(h))
	}
	// Should match SHA256 of empty string
	hEmpty := SHA256Bytes([]byte{})
	if !SecureCompareBytes(h, hEmpty) {
		t.Fatal("SHA256(nil) should equal SHA256(empty)")
	}
}

// ===========================================================================
// JWKS edge cases
// ===========================================================================

// TestSerializeJWKS_MultipleKeys tests JWKS with multiple keys is deterministic.
func TestSerializeJWKS_MultipleKeys(t *testing.T) {
	key1, _ := GenerateRSAKeyPair()
	key2, _ := GenerateRSAKeyPair()
	key3, _ := GenerateRSAKeyPair()

	keys := map[string]*rsa.PublicKey{
		"ccc": &key1.PublicKey,
		"aaa": &key2.PublicKey,
		"bbb": &key3.PublicKey,
	}

	jwks1 := SerializeJWKS(keys)
	jwks2 := SerializeJWKS(keys)

	if len(jwks1.Keys) != 3 {
		t.Fatalf("JWKS should have 3 keys, got %d", len(jwks1.Keys))
	}

	// Keys should be sorted by kid
	if jwks1.Keys[0].KID != "aaa" {
		t.Fatalf("first key should be 'aaa', got %q", jwks1.Keys[0].KID)
	}
	if jwks1.Keys[1].KID != "bbb" {
		t.Fatalf("second key should be 'bbb', got %q", jwks1.Keys[1].KID)
	}
	if jwks1.Keys[2].KID != "ccc" {
		t.Fatalf("third key should be 'ccc', got %q", jwks1.Keys[2].KID)
	}

	// Deterministic
	for i := range jwks1.Keys {
		if jwks1.Keys[i].N != jwks2.Keys[i].N {
			t.Fatalf("JWKS serialization should be deterministic at index %d", i)
		}
	}
}

// TestGenerateRSAKeyPair_KeySize tests that generated keys are 2048-bit.
func TestGenerateRSAKeyPair_KeySize(t *testing.T) {
	key, err := GenerateRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if key.N.BitLen() != 2048 {
		t.Fatalf("RSA key should be 2048 bits, got %d", key.N.BitLen())
	}
}
