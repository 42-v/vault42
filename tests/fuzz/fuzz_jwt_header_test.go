package fuzz

import (
	"encoding/json"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// FuzzJWTHeaderParsing feeds random JSON as JWT header.
// Goal: no panics on malformed headers.
func FuzzJWTHeaderParsing(f *testing.F) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	keyFunc := func(t *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	// Seed corpus
	f.Add([]byte(`{"alg":"RS256","typ":"JWT","kid":"abc-123"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"alg":"none"}`))
	f.Add([]byte(`{"alg":123}`))
	f.Add([]byte(`{"alg":"RS256","kid":"","jku":"http://evil.com"}`))
	f.Add([]byte(`null`))

	f.Fuzz(func(t *testing.T, headerJSON []byte) {
		// Build valid claims
		claims, _ := json.Marshal(map[string]any{
			"sub": "test", "iss": "test", "aud": []string{"test"},
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		})

		headerSeg := vjwt.EncodeSegment(headerJSON)
		claimsSeg := vjwt.EncodeSegment(claims)
		signingString := headerSeg + "." + claimsSeg

		sig, err := vjwt.SignRS256Bytes(signingString, key)
		if err != nil {
			return
		}

		token := signingString + "." + vjwt.EncodeSegment(sig)
		vaultcrypto.ParseAndValidate(token, keyFunc, "test", "test")
	})
}
