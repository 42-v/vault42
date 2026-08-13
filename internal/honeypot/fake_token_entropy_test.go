package honeypot

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

// apStarveEntropyAfter replaces the fake-credential entropy source with one that
// serves n real reads and then fails, so each read inside the generators can be
// starved individually. The returned function reports how many reads were
// attempted, which is what lets a case prove it starved the read it names rather
// than some earlier one.
func apStarveEntropyAfter(t *testing.T, n int) func() int {
	t.Helper()
	orig := randRead
	left := n
	attempts := 0
	randRead = func(b []byte) (int, error) {
		attempts++
		if left <= 0 {
			return 0, errors.New("entropy exhausted")
		}
		left--
		return rand.Read(b)
	}
	t.Cleanup(func() { randRead = orig })
	return func() int { return attempts }
}

// apSetProcessIdentityDrawn puts the per-process key id and fingerprint into the
// state a case needs: already drawn, or not drawn yet so the next mint has to
// draw them. Without this the cases would only mean what they say when run in
// one particular order.
func apSetProcessIdentityDrawn(t *testing.T, drawn bool) {
	t.Helper()

	processIdentityMu.Lock()
	processKID, processFingerprint = "", ""
	processIdentityMu.Unlock()

	if drawn {
		if _, _, err := processIdentity(); err != nil {
			t.Fatalf("drawing the process identity with real entropy: %v", err)
		}
	}
}

// The honeypot's whole value is that the credentials it hands an attacker look
// real. A generator that carried on after a failed CSPRNG read would emit a
// token whose signature is 256 zero bytes and whose kid is the nil UUID: an
// instantly recognizable tell that the vault is a trap, and a token that is the
// same for every attacker who ever hits it. Every read must abort with an error
// and no token at all.
func TestFakeCredentials_StarvedEntropyEmitsNoToken(t *testing.T) {
	tests := []struct {
		name string
		// drawn says whether the per-process key id and fingerprint are already
		// in hand. They are drawn on the first mint of the process, so the reads
		// a later mint makes depend on it; setting it explicitly keeps each case
		// independent of the order the cases run in.
		drawn bool
		reads int
		gen   func() (string, error)
	}{
		{"the JWT key id", false, 0, GenerateFakeJWT},
		{"the JWT device fingerprint", false, 1, GenerateFakeJWT},
		{"the JWT subject", true, 0, GenerateFakeJWT},
		{"the JWT token id", true, 1, GenerateFakeJWT},
		{"the JWT signature", true, 2, GenerateFakeJWT},
		{"the refresh token", false, 0, GenerateFakeRefresh},
		{"a fake UUID", false, 0, fakeUUID},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			apSetProcessIdentityDrawn(t, tc.drawn)
			attempts := apStarveEntropyAfter(t, tc.reads)

			got, err := tc.gen()
			if err == nil {
				t.Fatalf("a credential was generated from entropy that was never produced: %q", got)
			}
			// Without this the case name would be decoration: any earlier read
			// failing produces the same error, and a generator that stopped
			// reading for the named value would still look green here.
			if n := attempts(); n != tc.reads+1 {
				t.Errorf("the generator made %d entropy reads, so read %d is the one that was starved, not %s", n, n, tc.name)
			}
			if got != "" {
				t.Errorf("a partial credential was returned alongside the error: %q", got)
			}
			if !strings.Contains(err.Error(), "crypto/rand failed") {
				t.Errorf("err = %v, want it to name the entropy failure", err)
			}
		})
	}
}

// The fake login response is what an attacker actually receives. If the token it
// wraps could not be built, the handler must be told so it can fall through to a
// normal-looking failure rather than serve a body with an empty access_token,
// which no real login ever returns.
func TestFakeLoginResponse_StarvedEntropyReturnsNoBody(t *testing.T) {
	apStarveEntropyAfter(t, 0)

	resp, err := FakeLoginResponse()
	if err == nil {
		t.Fatal("FakeLoginResponse built a session out of entropy that was never produced")
	}
	if resp != nil {
		t.Errorf("a response body was returned alongside the error: %v", resp)
	}
}
