package honeypot

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
)

// apStarveEntropyAfter replaces the fake-credential entropy source with one that
// serves n real reads and then fails, so each read inside the generators can be
// starved individually. The returned function reports how many reads were
// attempted, which is what lets a case prove it starved the read it names rather
// than some earlier one.
// anonymousTrapToken mints with an empty caller, which is the shape the entropy
// table needs: one mint, no identity to vary the read count.
func anonymousTrapToken() (string, error) { return GenerateFakeJWTForIdentity(TrapCaller{}) }

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

// apPrimeTrapKey makes sure the trap signing key already exists. It is drawn
// from crypto/rand directly rather than through randRead, so without this a
// case would be measuring a generator that had already failed somewhere the
// starvation harness cannot see.
func apPrimeTrapKey(t *testing.T) {
	t.Helper()
	if _, _, err := trapSigningKey(); err != nil {
		t.Fatalf("priming the trap signing key: %v", err)
	}
}

// apSetSaltDrawn puts the per-process identity salt into the state a case needs:
// already drawn, or cleared so the next mint has to draw it. The salt is drawn
// on the first mint of the process, so the reads a later mint makes depend on
// it; setting it explicitly keeps each case independent of the order the cases
// run in.
func apSetSaltDrawn(t *testing.T, drawn bool) {
	t.Helper()

	trapSaltMu.Lock()
	trapSalt = nil
	trapSaltMu.Unlock()

	if drawn {
		if _, err := trapIdentitySalt(); err != nil {
			t.Fatalf("drawing the identity salt with real entropy: %v", err)
		}
	}
}

// The honeypot's whole value is that the credentials it hands an attacker look
// real. A generator that carried on after a failed CSPRNG read would emit a
// token whose jti is the nil UUID and whose subject is derived from a zero salt:
// an instantly recognizable tell, and the same values for every attacker who
// ever hits it. Every read must abort with an error and no token at all.
func TestFakeCredentials_StarvedEntropyEmitsNoToken(t *testing.T) {
	tests := []struct {
		name string
		// saltDrawn says whether the per-process identity salt is already in
		// hand, which decides whether the mint's first read is the salt or the
		// token id.
		saltDrawn bool
		reads     int
		gen       func() (string, error)
	}{
		{"the trap identity salt", false, 0, anonymousTrapToken},
		{"the JWT token id, on a mint that had to draw the salt first", false, 1, anonymousTrapToken},
		{"the JWT token id", true, 0, anonymousTrapToken},
		{"the refresh token", true, 0, GenerateFakeRefresh},
		{"a fake UUID", true, 0, fakeUUID},
		{"the trap subject's salt", false, 0, func() (string, error) { return TrapSubject("admin@trap.example") }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			apPrimeTrapKey(t)
			apSetSaltDrawn(t, tc.saltDrawn)
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

// The trap key is what makes a trap token verify against the JWKS the trap
// publishes. A mint that carried on without one would hand back a token signed
// by nothing, which is the exact tell the key exists to remove, so a failed
// generation must abort the mint and must not be cached as a permanent failure
// either.
func TestFakeToken_AFailedTrapKeyGenerationEmitsNoToken(t *testing.T) {
	trapKeyMu.Lock()
	savedKey, savedKID := trapKey, trapKID
	trapKey, trapKID = nil, ""
	trapKeyMu.Unlock()

	origGen := newSigningKey
	newSigningKey = func() (*rsa.PrivateKey, error) {
		return nil, errors.New("no entropy for a key")
	}
	t.Cleanup(func() {
		newSigningKey = origGen
		trapKeyMu.Lock()
		trapKey, trapKID = savedKey, savedKID
		trapKeyMu.Unlock()
	})

	got, err := GenerateFakeJWTForIdentity(TrapCaller{})
	if err == nil {
		t.Fatalf("a trap token was signed by a key that was never generated: %q", got)
	}
	if got != "" {
		t.Errorf("a partial token was returned alongside the error: %q", got)
	}
	if !strings.Contains(err.Error(), "generate trap signing key") {
		t.Errorf("err = %v, want it to name the key generation failure", err)
	}

	kid, pub, err := TrapSigningKey()
	if err == nil {
		t.Fatal("TrapSigningKey published a key that was never generated")
	}
	if kid != "" || pub != nil {
		t.Errorf("TrapSigningKey returned %q / %v alongside the error", kid, pub)
	}
}

// The refresh token is the other half of what the trap login hands over, and it
// is drawn from the same entropy source. Starved, it must return nothing rather
// than a short or empty value: a login answering with a refresh cookie a real
// one could not have produced is a tell in the response itself.
//
// This assertion used to be made through FakeLoginResponse, which had no caller
// outside these tests. The live trap login builds its body in service.Login from
// GenerateFakeJWTForIdentity and GenerateFakeRefresh; the first is starved by
// the table above, and this is the second.
func TestFakeRefresh_StarvedEntropyReturnsNoToken(t *testing.T) {
	apPrimeTrapKey(t)
	apSetSaltDrawn(t, true)
	apStarveEntropyAfter(t, 0)

	got, err := GenerateFakeRefresh()
	if err == nil {
		t.Fatalf("a trap refresh token was drawn from entropy that was never produced: %q", got)
	}
	if got != "" {
		t.Errorf("a partial refresh token was returned alongside the error: %q", got)
	}
}
