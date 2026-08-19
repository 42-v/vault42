package spec_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// =============================================================================
// The device-fingerprint claim in docs/api.md, gated against the chain the
// server installs.
//
// docs/api.md used to carry the line "**Fingerprint:** Verified" under 38 route
// sections and nothing else on the subject. Every one of those routes really
// did mount middleware.Fingerprint, so the claim was not wrong about the wiring;
// it was wrong about the request. middleware.Fingerprint passes a token with no
// `fingerprint` claim straight through, and the tokens issued by POST
// /client/token and POST /mint carry none, so "Verified" was an unconditional
// word for a conditional control. Repeating it 38 times also meant the six
// machine routes that do not mount the check at all were documented only by the
// absence of a line, which is not something a reader can notice.
//
// The claim now lives once, in the Device Fingerprint section, and the half of
// it a machine can check is the route list: which authenticated routes mount the
// middleware and which do not. This gate holds that list to the source.
//
// Both directions matter and for different reasons. A route that loses the
// middleware while the doc still promises it is the security regression. A route
// that gains it while the doc still lists it as exempt is the slower failure:
// the exemption stops describing anything, and the next machine endpoint
// inherits an argument nobody re-made.
// =============================================================================

const (
	fingerprintExemptBegin = "<!-- BEGIN FINGERPRINT EXEMPTIONS -->"
	fingerprintExemptEnd   = "<!-- END FINGERPRINT EXEMPTIONS -->"
)

// apiReferenceDoc is the document whose claims this file gates.
var apiReferenceDoc = filepath.Join("docs", "api.md")

// fingerprintedRouteFloor is the classifier's own tripwire. The user surface is
// 40 routes; a classifier that resolved none of them would report an empty set
// on both sides and agree with an empty table.
const fingerprintedRouteFloor = 30

// TestTheFingerprintExemptionTableMatchesTheInstalledChain compares the table in
// the Device Fingerprint section against setupRoutes.
//
// The source side is chainClassifyRoutes, the same resolver the deployment-chain
// register uses: it walks through authed, confirmed, authedChallenge, docRead
// and docWrite rather than around them, and it identifies middleware by what it
// is constructed from, so renaming fingerprintMw moves the gate with the code
// instead of blinding it.
func TestTheFingerprintExemptionTableMatchesTheInstalledChain(t *testing.T) {
	root := repoRoot(t)
	regs := chainClassifyRoutes(t, filepath.Join(root, serverSource), "setupRoutes")

	checked, fingerprinted := 0, 0
	wantExempt := map[string]bool{}
	for _, reg := range regs {
		if !chainHasRole(reg.guards, roleAuth) && !chainHasRole(reg.guards, roleChallenge) {
			continue // unauthenticated: there is no token to hold a fingerprint
		}
		checked++
		if chainHasRole(reg.guards, roleFingerprint) {
			fingerprinted++
			continue
		}
		wantExempt[reg.pattern] = true
	}

	if fingerprinted < fingerprintedRouteFloor {
		t.Fatalf("only %d of %d authenticated routes classified as fingerprint-checked, below the "+
			"floor of %d. The classifier has stopped recognizing middleware.Fingerprint, and an "+
			"empty source side agrees with whatever the document says.",
			fingerprinted, checked, fingerprintedRouteFloor)
	}

	gotExempt := fingerprintExemptions(t, filepath.Join(root, apiReferenceDoc))

	for _, pattern := range sortedPatterns(wantExempt) {
		if !gotExempt[pattern] {
			t.Errorf("%s mounts %q without middleware.Fingerprint, and the Device Fingerprint "+
				"section of docs/api.md does not list it as exempt. The section tells the reader "+
				"every authenticated route outside that table runs the check, so an unlisted route "+
				"is documented as protected by a control it does not have.", serverSource, pattern)
		}
	}
	for _, pattern := range sortedPatterns(gotExempt) {
		if !wantExempt[pattern] {
			t.Errorf("docs/api.md lists %q as exempt from the device-fingerprint check, but %s "+
				"mounts it behind middleware.Fingerprint (or no longer registers it at all). An "+
				"exemption that describes nothing is an argument the next machine endpoint "+
				"inherits without anyone re-making it.", pattern, serverSource)
		}
	}

	t.Logf("%d authenticated routes: %d fingerprint-checked, %d exempt and named in docs/api.md",
		checked, fingerprinted, len(wantExempt))
}

// TestNoEndpointSectionClaimsAFingerprintTheChainDoesNotGive is the ratchet
// against the old shape coming back.
//
// The per-route line is gone, and the point of removing it was that a claim
// repeated under every section is a claim nobody re-checks. This does not
// forbid one returning -- a future section may have a reason to say something
// about the fingerprint -- but if one does, it has to agree with the chain.
func TestNoEndpointSectionClaimsAFingerprintTheChainDoesNotGive(t *testing.T) {
	root := repoRoot(t)
	regs := chainClassifyRoutes(t, filepath.Join(root, serverSource), "setupRoutes")

	fingerprinted := map[string]bool{}
	for _, reg := range regs {
		if chainHasRole(reg.guards, roleFingerprint) {
			fingerprinted[reg.pattern] = true
		}
	}

	path := filepath.Join(root, apiReferenceDoc)
	body, err := os.ReadFile(path) // #nosec G304 -- fixed path inside the repo
	if err != nil {
		t.Fatalf("read %s: %v", apiReferenceDoc, err)
	}

	sections, claims := 0, 0
	var current string
	for i, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if fields := strings.Fields(trimmed); len(fields) == 3 && fields[0] == "####" && httpMethods[fields[1]] {
			sections++
			current = fields[1] + " " + fields[2]
			continue
		}
		if !strings.HasPrefix(trimmed, "**Fingerprint:**") || current == "" {
			continue
		}
		claims++
		// "not verified", "not mounted", "no fingerprint" -- any negation makes
		// the line a statement that the route does NOT have the control.
		denies := strings.Contains(strings.ToLower(trimmed), " not ") ||
			strings.Contains(strings.ToLower(trimmed), " no ")
		if denies == fingerprinted[current] {
			t.Errorf("docs/api.md:%d says %q under %s, and %s mounts that route %s "+
				"middleware.Fingerprint. Say what the chain does, or delete the line and let the "+
				"Device Fingerprint section carry it.",
				i+1, trimmed, current, serverSource, chainMountedWord(fingerprinted[current]))
		}
	}

	if sections == 0 {
		t.Fatal("docs/api.md: no '#### METHOD /path' endpoint section matched, so no claim was " +
			"read and this gate would report the same green as a clean document")
	}
	t.Logf("%d endpoint sections scanned, %d carried a per-route fingerprint claim", sections, claims)
}

// TestTheFingerprintMiddlewareStillSkipsATokenWithoutTheClaim pins the second
// half of the documented rule, the half no route table can express.
//
// The Device Fingerprint section tells the reader that a token carrying no
// `fingerprint` claim is passed through rather than rejected, and that this is
// why a machine token is unchecked on a route that does mount the middleware.
// If the middleware is ever made fail-closed, that paragraph becomes wrong in
// the direction that matters least for security and most for a client: callers
// holding client-credential tokens would start getting 401s the document says
// they will not.
func TestTheFingerprintMiddlewareStillSkipsATokenWithoutTheClaim(t *testing.T) {
	root := repoRoot(t)
	src := commentFreeSource(t, filepath.Join(root, "internal", "middleware", "fingerprint.go"))

	if !strings.Contains(src, `claims.Fingerprint == ""`) {
		t.Errorf("internal/middleware/fingerprint.go no longer branches on an empty " +
			"claims.Fingerprint. docs/api.md tells the reader that a token without the claim is " +
			"passed through, and names POST /client/token and POST /mint as the issuers of such " +
			"tokens; if that skip is gone the document is describing a control the middleware no " +
			"longer has. Update both together.")
	}
	if !strings.Contains(src, "Fingerprint(softMode bool)") {
		t.Error("internal/middleware/fingerprint.go no longer declares Fingerprint(softMode bool); " +
			"re-derive this gate against whatever replaced it")
	}
}

// fingerprintExemptions reads the route patterns out of the table between the
// sentinels in the Device Fingerprint section.
//
// A missing END sentinel is a Fatal rather than a short read: the table would
// simply appear to end early, and the routes below the cut would read as
// undocumented exemptions when they are documented ones.
func fingerprintExemptions(t *testing.T, path string) map[string]bool {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- fixed path inside the repo
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	out := map[string]bool{}
	var inside, closed bool
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		switch trimmed {
		case fingerprintExemptBegin:
			inside = true
			continue
		case fingerprintExemptEnd:
			inside, closed = false, true
			continue
		}
		if !inside || !strings.HasPrefix(trimmed, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(trimmed, "|"), "|")
		if len(cells) < 2 {
			continue
		}
		pattern := cleanCell(cells[0])
		method, _, ok := strings.Cut(pattern, " ")
		if !ok || !httpMethods[method] {
			continue // the header and separator rows
		}
		out[pattern] = true
	}

	if !closed {
		t.Fatalf("%s: the fingerprint exemption table has no %s sentinel, so the table this gate "+
			"reads is not the table the section shows", path, fingerprintExemptEnd)
	}
	if len(out) == 0 {
		t.Fatalf("%s: no route row parsed between %s and %s. An empty table agrees with an empty "+
			"source side, which is how this gate would pass over a route that lost the check",
			path, fingerprintExemptBegin, fingerprintExemptEnd)
	}
	return out
}

// chainMountedWord renders the verdict as the message needs to read it.
func chainMountedWord(mounted bool) string {
	if mounted {
		return "behind"
	}
	return "without"
}

// sortedPatterns is here so a failure lists routes in a stable order rather than
// map order, which changes between runs and makes two identical failures look
// like different ones.
func sortedPatterns(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
