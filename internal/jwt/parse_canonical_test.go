package jwt

import (
	"errors"
	"strings"
	"testing"
)

// A JWT's compact serialization has to be the token's unique name, because
// vault42 hashes it: internal/middleware/dpop.go computes the DPoP "ath"
// binding as SHA-256 over the exact bearer string it was handed, and any
// denylist of individually revoked access tokens would key on the same bytes.
// If one signature has many spellings, the holder of a single token can produce
// a fresh, still-verifying string on demand and every one of those controls
// misses it.
//
// Two decoder behaviors break that uniqueness and both tests below pin them
// shut. They are gates on the encoding, not on the cryptography: the signature
// bytes are identical in every variant, so the RSA check cannot tell them apart
// and the rejection has to happen in the base64 layer.

// TestParseWithClaimsRejectsASignatureSegmentWithNonZeroPaddingBits proves the
// parser refuses a segment whose final base64 character carries unused bits that
// are not zero. A 256-byte RS256 signature occupies 2048 bits and 342 base64
// characters hold 2052, so the last character has 4 bits that no signature byte
// reaches. A non-strict decoder ignores them, which gives every RS256 token 16
// interchangeable spellings that all verify against the same key.
func TestParseWithClaimsRejectsASignatureSegmentWithNonZeroPaddingBits(t *testing.T) {
	key := mustGenKey(t)
	token := makeValidToken(t, key, "kid-1")
	keyFunc := func(*Token) (any, error) { return &key.PublicKey, nil }

	if _, err := ParseWithClaims(token, &RegisteredClaims{}, keyFunc, WithValidMethods([]string{"RS256"})); err != nil {
		t.Fatalf("the unmodified token must verify or this test proves nothing: %v", err)
	}

	dot := strings.LastIndex(token, ".")
	sig := token[dot+1:]
	head, last := sig[:len(sig)-1], sig[len(sig)-1]

	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	accepted := []string{}
	for _, c := range []byte(alphabet) {
		if c == last {
			continue
		}
		variant := token[:dot+1] + head + string(c)
		if _, err := ParseWithClaims(variant, &RegisteredClaims{}, keyFunc, WithValidMethods([]string{"RS256"})); err == nil {
			accepted = append(accepted, string(c))
		}
	}
	if len(accepted) != 0 {
		t.Fatalf("%d alternate spellings of one signature verified (final char %q also accepted as %v); "+
			"a token hash is then not a stable identity for the token",
			len(accepted), string(last), accepted)
	}
}

// TestParseWithClaimsRejectsLineBreaksInsideASegment proves the parser refuses
// CR and LF inside a base64url segment. Go's base64 decoder skips both silently,
// so appending newlines to the signature segment yields unlimited distinct token
// strings that decode to the same signature bytes and still verify. RFC 7515 2
// defines BASE64URL as the encoding with no line breaks, and vault42 accepts
// tokens in places a newline survives (the OAuth2 "token" form parameter, JSON
// request bodies), where every such string would evade a match on the original.
func TestParseWithClaimsRejectsLineBreaksInsideASegment(t *testing.T) {
	key := mustGenKey(t)
	token := makeValidToken(t, key, "kid-1")
	keyFunc := func(*Token) (any, error) { return &key.PublicKey, nil }

	dot := strings.LastIndex(token, ".")
	for _, br := range []string{"\n", "\r", "\r\n"} {
		spliced := token[:dot+1] + token[dot+1:dot+5] + br + token[dot+5:]
		_, err := ParseWithClaims(spliced, &RegisteredClaims{}, keyFunc, WithValidMethods([]string{"RS256"}))
		if !errors.Is(err, ErrTokenMalformed) {
			t.Errorf("signature segment split by %q: err = %v, want ErrTokenMalformed", br, err)
		}
	}
}

// TestParseWithClaimsStillAcceptsTheCanonicalEncoding is the counterweight: the
// strictness above must reject only the non-canonical spellings. If it also
// rejected the encoding vault42 itself emits, every access token in production
// would stop verifying at once.
func TestParseWithClaimsStillAcceptsTheCanonicalEncoding(t *testing.T) {
	key := mustGenKey(t)
	keyFunc := func(*Token) (any, error) { return &key.PublicKey, nil }
	for i := 0; i < 16; i++ {
		token := makeValidToken(t, key, "kid-1")
		parsed, err := ParseWithClaims(token, &RegisteredClaims{}, keyFunc, WithValidMethods([]string{"RS256"}))
		if err != nil {
			t.Fatalf("token this package signed was rejected by its own parser: %v", err)
		}
		if !parsed.Valid {
			t.Fatal("a correctly signed token was not marked valid")
		}
	}
}
