package fuzz

import (
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// FuzzDPoPProof feeds random input to the DPoP proof validator.
func FuzzDPoPProof(f *testing.F) {
	f.Add("eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2In0.eyJqdGkiOiJ0ZXN0In0.invalid")
	f.Add("")
	f.Add("not-a-jwt")
	f.Add("a.b.c")
	f.Add("\x00\x01\x02")

	f.Fuzz(func(t *testing.T, proof string) {
		// Should never panic
		vaultcrypto.ValidateDPoPProof(proof, "POST", "https://example.com/token", "")
	})
}
