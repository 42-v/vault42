// Bridge deception-claim gate.
//
// docs/bridge.md promised "The attacker never knows they've been switched" and
// listed it under "Transparent Switching Guarantees". That was true of the
// deployment it was written for and false of the one this release ships, and
// the thing that falsified it was a security fix.
//
// The honeypot used to mount the production Secret -- master key, HMAC secret,
// pepper, signing key, admin token and database passwords -- so the decoy really
// was byte-identical to the real vault, including the key it signed with. That
// also meant breaking the decoy was breaking the vault, which is why
// vault.honeypotSecretName now refuses to resolve to the production Secret and
// says so in its failure message: "the same keys and different values".
//
// Different signing key means a different kid and a different modulus on
// /.well-known/jwks.json. An attacker who fetched JWKS before the switch and
// again afterwards sees that it changed, and a token minted by the real vault
// fails on the honeypot as an unknown kid rather than as an expiry. The
// separation is the right trade -- the alternative is handing the production
// signing key to the component whose purpose is to be broken into -- but an
// operator planning around an undetectability guarantee would be planning around
// something the deployment does not provide.
//
// This gate ties the prose to the helper. While the chart refuses to let the two
// Secrets collide, docs/bridge.md may not claim the switch is undetectable, and
// it must keep saying which parts are not concealed.
//
// The test is read-only. It never writes to the source tree.
package spec_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// helperFile defines vault.honeypotSecretName, whose refusal to share a Secret
// is what makes the two instances distinguishable.
var helperFile = filepath.Join("charts", "vault", "templates", "_helpers.tpl")

// bridgeDoc is the document that describes the deception to an operator.
var bridgeDoc = filepath.Join("docs", "bridge.md")

// undetectabilityClaims assert the attacker cannot tell which instance answered.
// Each was present verbatim, or near enough, in the copy this gate was written
// against.
var undetectabilityClaims = []*regexp.Regexp{
	regexp.MustCompile(`(?i)never knows they'?ve been switched`),
	regexp.MustCompile(`(?i)transparent switching guarantees`),
	regexp.MustCompile(`(?i)indistinguishable from the (real|production) vault`),
	regexp.MustCompile(`(?i)cannot (tell|detect|determine) (which|that).{0,40}switch`),
}

// disclosures are the facts the document must keep stating, because the whole
// value of correcting the claim is that the limit is written down where an
// operator plans.
var disclosures = []string{
	"jwks",
	"kid",
}

// TestBridgeDocDoesNotPromiseUndetectability fails if docs/bridge.md claims the
// switch is invisible while the chart forces the two instances onto different
// signing keys.
func TestBridgeDocDoesNotPromiseUndetectability(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)

	helper, err := os.ReadFile(filepath.Join(root, helperFile))
	if err != nil {
		t.Fatalf("read %s: %v", helperFile, err)
	}
	// The guard is what makes the instances distinguishable. If it is ever
	// removed the premise changes, and this gate must be revisited rather than
	// silently continuing to police prose about a deployment that no longer
	// exists.
	if !strings.Contains(string(helper), "honeypotSecretName") {
		t.Fatalf("%s no longer defines vault.honeypotSecretName. This gate assumes the honeypot is "+
			"forced onto its own Secret, which is what makes its JWKS differ from production. "+
			"Re-examine docs/bridge.md's claims against whatever replaced it.", helperFile)
	}

	body, err := os.ReadFile(filepath.Join(root, bridgeDoc))
	if err != nil {
		t.Fatalf("read %s: %v", bridgeDoc, err)
	}
	text := string(body)

	for _, claim := range undetectabilityClaims {
		if loc := claim.FindStringIndex(text); loc != nil {
			t.Errorf("%s claims the switch is undetectable (%q), but vault.honeypotSecretName refuses "+
				"to share the production Secret, so the honeypot signs with a different key and "+
				"serves a different kid on /.well-known/jwks.json. State what is concealed and what "+
				"is not, rather than promising a guarantee the deployment does not give.",
				bridgeDoc, strings.TrimSpace(text[loc[0]:loc[1]]))
		}
	}

	lower := strings.ToLower(text)
	for _, want := range disclosures {
		if !strings.Contains(lower, want) {
			t.Errorf("%s no longer mentions %q. The correction is only worth anything if the document "+
				"keeps telling an operator that signing key material distinguishes the two instances.",
				bridgeDoc, want)
		}
	}
}
