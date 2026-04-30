package fuzz

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// FuzzKIDValidation feeds random strings as kid header values.
// Goal: no panics, no path traversal.
// Since isValidKID is unexported, test indirectly through ParseAndValidate.
func FuzzKIDValidation(f *testing.F) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	keyFunc := func(t *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	f.Add("abc-123-def")
	f.Add("")
	f.Add("../../etc/passwd")
	f.Add(strings.Repeat("a", 64))
	f.Add(strings.Repeat("a", 65))
	f.Add("\x00\x01\x02")
	f.Add("key\ninjection")

	f.Fuzz(func(t *testing.T, kid string) {
		// Build token with fuzzed kid
		header, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
		claims, _ := json.Marshal(map[string]any{
			"sub": "test", "iss": "test", "aud": []string{"test"},
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		})

		headerSeg := vjwt.EncodeSegment(header)
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
