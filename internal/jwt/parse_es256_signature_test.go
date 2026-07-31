package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// ES256 is reachable through the parser only from the DPoP path, which calls
// ParseWithClaims with the RS256+ES256 whitelist and a public key lifted from
// the proof's own jwk header. That makes the ES256 signature check the single
// thing standing between an attacker-supplied proof and a bound token: a proof
// whose signature does not match the key it advertises must be rejected, and
// the returned token must not be marked valid.

// cryptoKeysES256Token builds an ES256 JWT whose signature is produced by
// signKey while the header advertises alg ES256. Passing a different key than
// the one the parser will verify with yields a forged proof.
func cryptoKeysES256Token(t *testing.T, claims any, signKey *ecdsa.PrivateKey) string {
	t.Helper()

	headerJSON, err := json.Marshal(map[string]string{"alg": "ES256", "typ": "dpop+jwt"})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	signingString := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	digest := sha256.Sum256([]byte(signingString))
	sig, err := ecdsa.SignASN1(rand.Reader, signKey, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingString + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// cryptoKeysSwapPayload replaces the claims segment of a signed token, leaving
// the original signature in place.
func cryptoKeysSwapPayload(t *testing.T, token, claimsJSON string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(claimsJSON))
	return strings.Join(parts, ".")
}

func cryptoKeysECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	return key
}

func TestParseWithClaims_ES256SignatureMismatchDenies(t *testing.T) {
	holder := cryptoKeysECKey(t)
	attacker := cryptoKeysECKey(t)
	claims := &RegisteredClaims{
		Subject:   "user-1",
		ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
	}

	cases := []struct {
		name     string
		token    string
		verifyPK *ecdsa.PublicKey
	}{
		{
			name:     "signed by another key",
			token:    cryptoKeysES256Token(t, claims, attacker),
			verifyPK: &holder.PublicKey,
		},
		{
			name:     "payload swapped after signing",
			token:    cryptoKeysSwapPayload(t, cryptoKeysES256Token(t, claims, holder), `{"sub":"admin"}`),
			verifyPK: &holder.PublicKey,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ParseWithClaims(tc.token, &RegisteredClaims{}, func(*Token) (any, error) {
				return tc.verifyPK, nil
			}, WithValidMethods([]string{"RS256", "ES256"}))

			if !errors.Is(err, ErrTokenSignatureInvalid) {
				t.Fatalf("err = %v, want ErrTokenSignatureInvalid", err)
			}
			if parsed == nil {
				t.Fatal("no token returned; callers inspect the header of a rejected proof")
			}
			if parsed.Valid {
				t.Error("a token with an unverifiable ES256 signature was marked valid")
			}
		})
	}
}

// The rejection above must come from the signature check and not from ES256
// being unparseable in general, or the test would pass with the verification
// deleted.
func TestParseWithClaims_ES256GenuineSignatureAccepted(t *testing.T) {
	holder := cryptoKeysECKey(t)
	token := cryptoKeysES256Token(t, &RegisteredClaims{
		Subject:   "user-1",
		ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
	}, holder)

	parsed, err := ParseWithClaims(token, &RegisteredClaims{}, func(*Token) (any, error) {
		return &holder.PublicKey, nil
	}, WithValidMethods([]string{"RS256", "ES256"}))
	if err != nil {
		t.Fatalf("ParseWithClaims: %v", err)
	}
	if !parsed.Valid {
		t.Error("a correctly signed ES256 token was not marked valid")
	}
}
