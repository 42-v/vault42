package honeypot

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

// apStarveEntropyAfter replaces the fake-credential entropy source with one that
// serves n real reads and then fails, so each read inside the generators can be
// starved individually.
func apStarveEntropyAfter(t *testing.T, n int) {
	t.Helper()
	orig := randRead
	left := n
	randRead = func(b []byte) (int, error) {
		if left <= 0 {
			return 0, errors.New("entropy exhausted")
		}
		left--
		return rand.Read(b)
	}
	t.Cleanup(func() { randRead = orig })
}

// The honeypot's whole value is that the credentials it hands an attacker look
// real. A generator that carried on after a failed CSPRNG read would emit a
// token whose signature is 256 zero bytes and whose kid is the nil UUID: an
// instantly recognisable tell that the vault is a trap, and a token that is the
// same for every attacker who ever hits it. Every read must abort with an error
// and no token at all.
func TestFakeCredentials_StarvedEntropyEmitsNoToken(t *testing.T) {
	tests := []struct {
		name  string
		reads int
		gen   func() (string, error)
	}{
		{"the JWT key id", 0, GenerateFakeJWT},
		{"the JWT subject", 1, GenerateFakeJWT},
		{"the JWT signature", 2, GenerateFakeJWT},
		{"the refresh token", 0, GenerateFakeRefresh},
		{"a fake UUID", 0, fakeUUID},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			apStarveEntropyAfter(t, tc.reads)

			got, err := tc.gen()
			if err == nil {
				t.Fatalf("a credential was generated from entropy that was never produced: %q", got)
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
