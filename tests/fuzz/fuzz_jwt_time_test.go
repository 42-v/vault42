package fuzz

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// FuzzTimeBoundaries feeds random int64 values for exp/nbf/iat.
// Goal: no panics on extreme time values.
func FuzzTimeBoundaries(f *testing.F) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	f.Add(int64(0), int64(0), int64(0))
	f.Add(int64(-1), int64(-1), int64(-1))
	f.Add(int64(math.MaxInt64), int64(math.MaxInt64), int64(math.MaxInt64))
	f.Add(int64(math.MinInt64), int64(math.MinInt64), int64(math.MinInt64))
	f.Add(time.Now().Add(time.Hour).Unix(), time.Now().Unix(), time.Now().Unix())

	f.Fuzz(func(t *testing.T, exp, nbf, iat int64) {
		claims, _ := json.Marshal(map[string]any{
			"sub": "test", "iss": "test", "aud": []string{"test"},
			"exp": exp, "nbf": nbf, "iat": iat,
		})
		header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})

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
