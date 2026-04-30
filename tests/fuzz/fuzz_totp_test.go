package fuzz

import (
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// FuzzValidateTOTP feeds random codes to the TOTP validator.
func FuzzValidateTOTP(f *testing.F) {
	secret, _ := vaultcrypto.GenerateTOTPSecret()

	f.Add("000000")
	f.Add("999999")
	f.Add("")
	f.Add("123456")
	f.Add("abcdef")
	f.Add("12345678901234567890")

	f.Fuzz(func(t *testing.T, code string) {
		// Should never panic
		vaultcrypto.ValidateTOTPCode(secret, code, time.Now())
	})
}
