package fuzz

import (
	"encoding/json"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// FuzzJWTClaimsParsing feeds random JSON as JWT claims payload.
// Goal: no panics on any claim structure.
// Approach: Take random bytes as the claims JSON, build a well-formed JWT header,
// sign it with RS256, and feed through ParseAndValidate.
func FuzzJWTClaimsParsing(f *testing.F) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	keyFunc := func(t *vjwt.Token) (any, error) { return &key.PublicKey, nil }
	kid, _ := vaultcrypto.RandomUUID()

	// Seed corpus with valid + edge-case JSON payloads
	f.Add([]byte(`{"sub":"test","iss":"test","aud":["test"],"exp":9999999999,"iat":1000000000}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"exp":null}`))
	f.Add([]byte(`{"sub":123}`))
	f.Add([]byte(`{"aud":"single"}`))
	f.Add([]byte(`{"roles":null,"scopes":[]}`))
	f.Add([]byte(`null`))

	f.Fuzz(func(t *testing.T, claimsJSON []byte) {
		// Build valid header
		header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})

		// Encode segments
		headerSeg := vjwt.EncodeSegment(header)
		claimsSeg := vjwt.EncodeSegment(claimsJSON)
		signingString := headerSeg + "." + claimsSeg

		// Sign
		sig, err := vjwt.SignRS256Bytes(signingString, key)
		if err != nil {
			return
		}

		token := signingString + "." + vjwt.EncodeSegment(sig)

		// Must not panic
		vaultcrypto.ParseAndValidate(token, keyFunc, "test", "test")
	})
}
