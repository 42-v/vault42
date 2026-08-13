package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/tests/mocks"
)

// TestADPoPProofIssuedInTheFutureIsAccepted states the premise the replay window
// has to cover. ValidateDPoPProof compares the proof's age against DPoPMaxAge in
// both directions, so a proof stamped with an iat up to DPoPMaxAge ahead of now
// is a valid proof, not a rejected one.
//
// If this ever stops being true the middleware's replay TTL can shrink with it,
// but until then the acceptance window is two-sided and the reuse check has to
// remember a spent jti for the whole of it.
func TestADPoPProofIssuedInTheFutureIsAccepted(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	futureIAT := time.Now().Add(vaultcrypto.DPoPMaxAge - 30*time.Second)
	proof := makeDPoPProofAtForTest(t, key, "GET", "https://vault.test/user/profile", futureIAT, "future-dated-proof")

	called := false
	handler := DPoP(nil, "https://vault.test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req.Host = "vault.test"
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatalf("a proof dated %v ahead of now was refused with %d; "+
			"the rest of this file reasons about a two-sided acceptance window",
			vaultcrypto.DPoPMaxAge-30*time.Second, rec.Code)
	}
}

// TestTheDPoPReplayEntryOutlivesEveryMomentTheProofStaysAcceptable is the reuse
// bound the middleware advertises with its dpop_proof_reused rejection.
//
// A proof is acceptable for the whole span in which ValidateDPoPProof will still
// take it, which runs from DPoPMaxAge before its iat to DPoPMaxAge after it. The
// spent-jti entry has to survive at least that long. Sized to DPoPMaxAge alone,
// the entry expires while the proof is still valid, so a captured proof is
// accepted a second time: present it once at the earliest moment it is valid,
// wait for the entry to lapse, and replay it. The 401 dpop_proof_reused that the
// middleware exists to return never fires, and RFC 9449 §11.1 replay prevention
// is decorative for any caller willing to post-date an iat.
func TestTheDPoPReplayEntryOutlivesEveryMomentTheProofStaysAcceptable(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// The most future-dated iat the validator still takes, less a margin so the
	// test does not race the clock at the window's edge.
	futureIAT := time.Now().Add(vaultcrypto.DPoPMaxAge - 30*time.Second)
	proof := makeDPoPProofAtForTest(t, key, "GET", "https://vault.test/user/profile", futureIAT, "replay-window-proof")

	var recordedTTL time.Duration
	var recorded bool
	c := &mocks.MockCache{
		SetIfNotExistsFn: func(_ context.Context, _, _ string, ttl time.Duration) (bool, error) {
			recordedTTL = ttl
			recorded = true
			return true, nil
		},
	}

	handler := DPoP(c, "https://vault.test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req.Host = "vault.test"
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !recorded {
		t.Fatalf("the middleware never reached the replay check (status %d), so nothing pins the jti", rec.Code)
	}

	// The validator keeps taking this proof until DPoPMaxAge past its iat.
	stillAcceptableUntil := futureIAT.Add(vaultcrypto.DPoPMaxAge)
	needed := time.Until(stillAcceptableUntil)

	if recordedTTL < needed {
		t.Fatalf("spent jti is remembered for %v but the proof stays acceptable for another %v.\n"+
			"A captured proof replayed after the entry lapses is taken as fresh, and the "+
			"dpop_proof_reused rejection never fires.",
			recordedTTL, needed)
	}
}

// makeDPoPProofAtForTest builds a DPoP proof JWT with a caller-chosen iat and
// jti, so a test can place a proof anywhere inside (or outside) the acceptance
// window ValidateDPoPProof implements.
func makeDPoPProofAtForTest(t *testing.T, key *rsa.PrivateKey, method, uri string, issuedAt time.Time, jti string) string {
	t.Helper()

	claims := &vaultcrypto.DPoPClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			IssuedAt: vjwt.NewNumericDate(issuedAt),
			ID:       jti,
		},
		HTM: method,
		HTU: uri,
	}

	header := map[string]any{
		"alg": "RS256",
		"typ": "dpop+jwt",
		"jwk": map[string]any{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		},
	}

	tokenStr, err := vjwt.SignRS256WithHeader(header, claims, key)
	if err != nil {
		t.Fatal(err)
	}
	return tokenStr
}
