package honeypot

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// The honeypot's fake JWT carries iss and aud claims taken from two package
// variables that startup wiring publishes exactly once, and every fake token
// ever minted reads them. The write is wrapped in a sync.Once, which looks like
// it settles the question and does not: a Once orders the goroutine inside Do
// against other goroutines that also call Do. GenerateFakeJWT never calls Do,
// so it inherits nothing from the Once and its read of the two variables races
// with the publication.
//
// The ordering is real in production. cmd/vault calls ConfigureFakeJWT while
// the honeypot handlers are already reachable, so the first attacker to hit a
// trap endpoint during startup reads the variables concurrently with the write.
// What the honeypot is for is handing back credentials indistinguishable from
// real ones; a claim read through a race is exactly the tell that gives the
// trap away, and a racy string read is undefined behavior rather than merely
// a stale value.
//
// This test puts a publication and a stream of token mints on top of each other
// so -race adjudicates it. It fails if GenerateFakeJWT ever goes back to reading
// the configuration variables directly instead of through an atomic load.

const honeypotPublicationMints = 1500

func TestConfigureFakeJWT_PublicationIsSafeForReadersThatNeverCallOnce(t *testing.T) {
	// ConfigureFakeJWT is one-shot for the process and other tests in this
	// binary observe whatever it settled on. Reset the sentinel to its startup
	// state before the storm and restore it afterwards so test order stays
	// irrelevant.
	original := currentFakeJWTConfig()
	originalIssuer, originalAudience := original.issuer, original.audience
	configOnce = sync.Once{}
	t.Cleanup(func() {
		storeFakeJWTConfig(original)
		configOnce = sync.Once{}
	})

	const wantIssuer = "https://publication-test.invalid"
	const wantAudience = "publication-test-audience"

	var wg sync.WaitGroup
	start := make(chan struct{})

	// The writer: one goroutine doing what cmd/vault does at startup.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		// A short delay lands the publication inside the mint stream rather
		// than ahead of it, which is where the production window is.
		time.Sleep(time.Millisecond)
		ConfigureFakeJWT(wantIssuer, wantAudience, 15*time.Minute)
	}()

	// The readers: goroutines that never call Do, so they take no ordering from
	// the Once.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for n := 0; n < honeypotPublicationMints; n++ {
				token, err := GenerateFakeJWT()
				if err != nil {
					t.Errorf("GenerateFakeJWT during publication: %v", err)
					return
				}
				iss, aud, err := honeypotDecodeClaims(token)
				if err != nil {
					t.Errorf("a token minted during publication did not decode: %v", err)
					return
				}
				// Whichever side of the publication a mint lands on, the claims
				// must be one of the two complete configurations. A token
				// carrying the new issuer next to the old audience would mean
				// the two variables were observed half-published, which is what
				// an attacker fingerprinting the trap would look for.
				oldPair := iss == originalIssuer && aud == originalAudience
				newPair := iss == wantIssuer && aud == wantAudience
				if !oldPair && !newPair {
					t.Errorf("token claims were observed half-published: iss=%q aud=%q, want either (%q,%q) or (%q,%q)",
						iss, aud, originalIssuer, originalAudience, wantIssuer, wantAudience)
					return
				}
			}
		}()
	}

	close(start)
	wg.Wait()

	published := currentFakeJWTConfig()
	iss, aud := published.issuer, published.audience
	if iss != wantIssuer || aud != wantAudience {
		t.Errorf("after publication the claims are (%q,%q), want (%q,%q)", iss, aud, wantIssuer, wantAudience)
	}
}

// honeypotDecodeClaims pulls iss and aud back out of a minted fake token. The
// signature is deliberately gibberish, so only the payload segment is read.
func honeypotDecodeClaims(token string) (issuer, audience string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", errTokenShape
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", err
	}
	// aud arrives as an array, the same shape a real access token carries it in.
	var claims struct {
		Iss string   `json:"iss"`
		Aud []string `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", "", err
	}
	if len(claims.Aud) != 1 {
		return "", "", errTokenAudience
	}
	return claims.Iss, claims.Aud[0], nil
}

// errTokenShape marks a token that is not three dot-separated segments. A fake
// token that failed this check would not look like a JWT to the attacker it is
// meant to fool.
var errTokenShape = errors.New("honeypot: fake token is not three segments")

// errTokenAudience marks a token whose aud is not the single-element array a
// real access token carries. A trap token with a different audience shape is one
// base64 decode away from giving the deployment away.
var errTokenAudience = errors.New("honeypot: fake token aud is not a one-element array")
