package fuzz

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	vjwt "github.com/42-v/vault42/internal/jwt"
)

// FuzzES256SignatureFormat feeds random bytes as ES256 signatures.
// Goal: no panics on malformed signatures.
func FuzzES256SignatureFormat(f *testing.F) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Seed corpus
	f.Add(make([]byte, 64))                                       // raw R||S (64 bytes, all zeros)
	f.Add(make([]byte, 0))                                        // empty
	f.Add([]byte{0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00}) // minimal DER
	f.Add(make([]byte, 32))                                       // half signature
	f.Add(make([]byte, 128))                                      // oversized

	f.Fuzz(func(t *testing.T, sig []byte) {
		// Should never panic regardless of input
		vjwt.VerifyES256("test.payload", sig, &key.PublicKey)
	})
}
