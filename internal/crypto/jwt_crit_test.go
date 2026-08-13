package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	vjwt "github.com/42-v/vault42/internal/jwt"
)

// signWithHeader mints a genuinely signed RS256 token carrying extra JOSE
// header parameters.
//
// It signs for real rather than crafting a bogus token, because the property
// under test is what a VALID signature buys an attacker. A token that fails the
// signature check proves nothing about header handling.
func signWithHeader(t *testing.T, key *rsa.PrivateKey, kid string, extra map[string]any) string {
	t.Helper()

	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	for k, v := range extra {
		header[k] = v
	}

	claims := VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-1",
			Issuer:    "https://vault.test",
			Audience:  vjwt.ClaimStrings{"https://vault.test"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
		TokenType: "Bearer",
	}

	token, err := vjwt.SignRS256WithHeader(header, claims, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return token
}

// TestCritHeaderIsRejected closes a gap against RFC 7515 section 4.1.11.
//
// `crit` lists header parameters the producer requires the recipient to
// understand and act on. The RFC is explicit that a recipient MUST reject a JWS
// carrying a `crit` it does not fully implement. vault42 implements no JOSE
// extensions at all, so every `crit` qualifies, and the parser did not look at
// the header.
//
// This is not exploitable on its own: the header is inside the signature, so
// forging one needs the signing key, and an attacker with that has already won.
// It matters because vault42's tokens are consumed elsewhere. A relying party
// that does honor `crit`, or a future verifier here, would refuse a token this
// vault happily accepts, and the two would disagree about what a valid token
// is. Refusing it here keeps every consumer's answer the same.
//
// The empty array is included because RFC 7515 forbids it outright, and it is
// the case a naive "if the list is empty, nothing is required" reading lets
// straight through.
func TestCritHeaderIsRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const kid = "abcdef01-23456789"
	keyFunc := func(*vjwt.Token) (any, error) { return &key.PublicKey, nil }

	for _, tc := range []struct {
		name string
		crit any
	}{
		{"unknown extension", []string{"exp-ext"}},
		{"several unknown extensions", []string{"a", "b"}},
		{"empty array, forbidden by the RFC", []string{}},
		{"naming a header vault42 does understand", []string{"kid"}},
		{"not an array at all", "exp-ext"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := signWithHeader(t, key, kid, map[string]any{"crit": tc.crit})

			_, err := ParseAndValidate(token, keyFunc, "https://vault.test", "https://vault.test")
			if err == nil {
				t.Fatal("a correctly signed token carrying a crit header was accepted. RFC 7515 " +
					"4.1.11 requires refusing a crit the recipient does not implement, and vault42 " +
					"implements no JOSE extensions, so a relying party that honors crit would " +
					"refuse a token this vault called valid.")
			}
			if !strings.Contains(err.Error(), "crit") {
				t.Errorf("error does not mention crit, so the rejection came from somewhere else "+
					"and this test is not measuring what it claims: %v", err)
			}
		})
	}
}

// TestTokenWithoutCritStillValidates is the negative control.
//
// A header check that rejects everything would pass the test above and break
// every login, so the ordinary token has to keep working.
func TestTokenWithoutCritStillValidates(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const kid = "abcdef01-23456789"
	keyFunc := func(*vjwt.Token) (any, error) { return &key.PublicKey, nil }

	token := signWithHeader(t, key, kid, nil)

	claims, err := ParseAndValidate(token, keyFunc, "https://vault.test", "https://vault.test")
	if err != nil {
		t.Fatalf("an ordinary token was rejected: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("subject = %q, want user-1", claims.Subject)
	}
}
