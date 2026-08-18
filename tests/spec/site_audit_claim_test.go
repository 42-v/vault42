// Landing-page audit-claim gate.
//
// site/index.html told visitors the audit log was "Append-only. Hash-chained.
// Sealed.", that the ledger "Mirrors the production audit log", and that "Every
// entry references its predecessor; the final root is the chain seal". The first
// clause is true and the rest was not: no table, trigger or Go type in this
// repository has ever stored a predecessor hash. The chain lives entirely in
// site/app.js, where it is computed in the visitor's browser.
//
// That is the same defect class this release spent itself on, arriving through
// the one document nobody diffs against the code, and it is the worst place for
// it: a compliance reader who trusts the landing page reads a stronger integrity
// guarantee than the deployment gives, and the register says so in the same
// breath. docs/compliance-register.json carries CR-24 -- "The audit log is not
// cryptographically chained and is not mirrored off-system" -- as an accepted
// risk, with the reasoning that a chain whose signing key lives in the same
// process is theatre against the only adversary a chain would address.
//
// The gate is coupled to the register in both directions, which is the shape the
// compliance gates in this repository already use. While CR-24 stands, the site
// may not assert chaining as a vault42 property. If CR-24 is ever retired --
// that is, if someone actually implements the chain -- the gate fails too, so
// the marketing copy is revisited by whoever earns the right to make the claim
// rather than staying pessimistic forever.
//
// The test is read-only. It never writes to the source tree.
package spec_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// cr24 is the register's identifier for the absent chain. The gate reads the
// register rather than hardcoding its own copy of the status, so retiring the
// risk is what flips the gate, not an edit here.
const cr24 = "CR-24"

// siteFiles are the visitor-facing files that make claims. site/app.js is
// deliberately excluded: it is the simulation, so chain vocabulary there
// describes what the code in front of you does and is not a claim about
// production.
var siteFiles = []string{
	filepath.Join("site", "index.html"),
	filepath.Join("site", "README.md"),
}

// productionChainClaims are phrasings that assert the chain is a property of the
// shipped system rather than of the browser demo. These are tripwires for the
// exact regression: each one was present verbatim, or near enough, in the copy
// this gate was written against.
var productionChainClaims = []*regexp.Regexp{
	// "Mirrors the production audit log" immediately after chain vocabulary was
	// the sentence that did the damage.
	regexp.MustCompile(`(?i)mirrors the production audit log`),
	// A bare assertion that entries reference predecessors, with no simulation
	// qualifier anywhere in the sentence.
	regexp.MustCompile(`(?i)every entry references its predecessor`),
	// "Hash-chained" as a standalone product attribute in a list of them.
	regexp.MustCompile(`(?i)append-only\.\s*hash-chained\.`),
	// The production log described as chained rather than as immutable.
	regexp.MustCompile(`(?i)production (?:audit )?log is (?:hash-)?chained`),
}

// qualifiers are the words that turn chain vocabulary from a claim into a
// description of the demo. A file may use chain vocabulary freely as long as it
// says, somewhere, which of the two it means.
var qualifiers = []string{
	"simulation",
	"simulated",
	"illustration",
	"in your browser",
	"client-side",
	"not a vault42 feature",
	"not a production property",
}

// registerRisk reports whether the identifier is an open accepted risk.
func registerRisk(t *testing.T, id string) bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "compliance-register.json"))
	if err != nil {
		t.Fatalf("read compliance register: %v", err)
	}
	var reg struct {
		AcceptedRisks map[string]json.RawMessage `json:"accepted_risks"`
		RetiredRisks  map[string]json.RawMessage `json:"retired_risks"`
	}
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatalf("parse compliance register: %v", err)
	}
	if _, retired := reg.RetiredRisks[id]; retired {
		return false
	}
	_, open := reg.AcceptedRisks[id]
	return open
}

// TestSiteAuditClaimMatchesTheRegister holds the landing page to whatever the
// register currently says about the chain, in whichever direction that runs.
//
// It is deliberately one test with a branch rather than two tests that skip past
// each other. tests/compliance/gate_liveness_test.go caught the earlier shape and
// was right to: a skipped test prints the same "ok" as one that ran, so a pair of
// mutually exclusive tests reports a control as active while half of it is off.
// Here every run asserts something.
func TestSiteAuditClaimMatchesTheRegister(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	open := registerRisk(t, cr24)

	read := func(name string) string {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(body)
	}

	if !open {
		// CR-24 has been retired, so the chain exists. The page must not still be
		// disclaiming it: understating a property the code earned is the same
		// class of defect as overstating one it lacks, and the compliance gates
		// here already fire in both directions for exactly this reason.
		text := strings.ToLower(read(filepath.Join("site", "index.html")))
		for _, q := range qualifiers {
			if strings.Contains(text, q) {
				t.Errorf("%s has been retired, so the audit log is chained now, but site/index.html "+
					"still disclaims the ledger as %q. The page is understating a property the code "+
					"earned; rewrite it and drop this qualifier.", cr24, q)
			}
		}
		return
	}

	// CR-24 is open: the chain does not exist, so the site may not claim it.
	for _, name := range siteFiles {
		text := read(name)
		for _, claim := range productionChainClaims {
			if loc := claim.FindStringIndex(text); loc != nil {
				t.Errorf("%s asserts a hash chain as a production property (%q), but %s records that the "+
					"audit log is not cryptographically chained. Say what production holds -- append-only "+
					"enforced by trigger and revoked grants -- and label the ledger as the browser-side "+
					"illustration it is.",
					name, strings.TrimSpace(text[loc[0]:loc[1]]), cr24)
			}
		}
		if !strings.Contains(strings.ToLower(text), "hash-chain") {
			continue
		}
		lower := strings.ToLower(text)
		qualified := false
		for _, q := range qualifiers {
			if strings.Contains(lower, q) {
				qualified = true
				break
			}
		}
		if !qualified {
			t.Errorf("%s uses chain vocabulary with nothing marking it as the browser simulation. A "+
				"reader cannot tell the demo from the deployment, which is how the original claim "+
				"passed review.", name)
		}
	}
}
