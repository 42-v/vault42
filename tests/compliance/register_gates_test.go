package compliance

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// =============================================================================
// Gates against the drift that produced every finding this register has had to
// retract.
//
// The original gate — a Met row must name a test that exists — is the reason
// no Met row has ever been silently false. Every defect since has arrived
// through a door that gate does not cover:
//
//   - a Not Applicable row asserting non-existence, which owed no evidence at
//     all. Twenty-one rows, three sentences, and two real gaps inside them.
//   - evidence that resolves to a real line of a real file and describes
//     something else. Both password rows cited a doc comment on an unrelated
//     struct field and a metrics getter.
//   - a test named in prose rather than in a row, which nothing checked. The
//     report named TestNIST63B4_2_2_3_TheAbsoluteBoundIsStillUnwired, which has
//     never existed, as the tracker for a gap that had already closed.
//   - two documents numbering their accepted risks from one sequence, so a
//     cross-reference resolved to a different risk than the author meant, and
//     the report asserted the closure of a risk that was open.
//
// Each of those is a door. This file closes them.
// =============================================================================

// --- Gate 1: an N/A row asserting non-existence must name a test ------------

// naBases is the closed vocabulary of reasons a requirement can be Not
// Applicable. Forcing the author to pick one is most of the value: the three
// false rationales all worked by leaving the *kind* of reason unstated, so a
// claim about the code read like a claim about scope.
var naBases = map[string]string{
	"code-absence": "the capability the requirement addresses is absent from the tree. " +
		"A test has to prove that absence, exactly as a Met row proves a presence.",
	"scope-exclusion": "the requirement is a property of a component the register declares out of " +
		"scope, and the reason must say which one.",
	"role": "the requirement addresses a role vault42 does not occupy, such as an OpenID Provider " +
		"or a GDPR controller.",
	"level": "the requirement sits outside the assurance level the register claims.",
	"covered-elsewhere": "the underlying control exists and is classified under a different " +
		"requirement, which the reason must name.",
}

// codeAbsencePhrases are the shapes a negative existence claim takes in this
// register's own prose. A row whose basis is not code-absence must not use one:
// that combination is precisely how "the SPA is assessed separately" (a scope
// statement) came to carry "vault42 ships no browser-facing application of its
// own" (a false claim about the binary).
var codeAbsencePhrases = []string{
	"ships no", "accepts no", "implements no", "exposes no", "makes no", "opens no",
	"performs no", "sends no", "supports no", "offers no", "operates no", "verifies no",
	"runs no", "has no ", "there is no", "no such", "is not imported", "nowhere in the tree",
	"anywhere in the tree", "never parses", "never stores",
}

func TestComplianceRegister_NotApplicableNonExistenceClaimsNameAnExistingTest(t *testing.T) {
	reg := loadRegister(t)
	existing := complianceTestNames(t)

	counts := map[string]int{}
	for _, r := range reg.Requirements {
		if r.Status != statusNA {
			continue
		}

		basis := r.NABasis
		if basis == "" {
			t.Errorf("%s %s is Not Applicable with no na_basis. Pick one of %v: the kind of reason "+
				"is what decides whether a test is owed, and leaving it unstated is how a claim "+
				"about the code came to read like a claim about scope.",
				r.Standard, r.RequirementID, sortedKeys(naBases))
			continue
		}
		if _, ok := naBases[basis]; !ok {
			t.Errorf("%s %s carries na_basis %q, which is outside the vocabulary %v",
				r.Standard, r.RequirementID, basis, sortedKeys(naBases))
			continue
		}
		counts[basis]++

		if basis == "code-absence" {
			if len(r.Tests) == 0 {
				t.Errorf("%s %s is Not Applicable because something does not exist, and names no "+
					"test. A negative existence claim is exactly as testable as a positive one, "+
					"and this is the gate that would have caught all twenty-one misclassified rows "+
					"on the day they were written.", r.Standard, r.RequirementID)
				continue
			}
			for _, name := range r.Tests {
				if _, ok := existing[name]; !ok {
					t.Errorf("%s %s rests on the absence of something and names %s, which does not "+
						"exist in tests/compliance/", r.Standard, r.RequirementID, name)
				}
			}
			continue
		}

		// Not a code-absence row, so it must not smuggle a code-absence claim in.
		lower := strings.ToLower(r.Notes)
		for _, phrase := range codeAbsencePhrases {
			if strings.Contains(lower, phrase) {
				t.Errorf("%s %s carries na_basis %q but its reason says %q, which is a claim about "+
					"what the code contains. Either the basis is code-absence and a test proves it, "+
					"or the sentence has to go: this is the exact shape of the V3 and V5 rationales.",
					r.Standard, r.RequirementID, basis, phrase)
			}
		}
	}

	for _, b := range sortedKeys(naBases) {
		t.Logf("na_basis %-18s %d", b, counts[b])
	}
}

// --- Gate 2: evidence must be relevant, not merely resolvable ---------------

// evidenceRelevanceExemptions are the (standard, requirement, file) triples
// whose notes argue the control in prose without naming any identifier from the
// cited declaration. Each is a real location; none is wrong the way
// config.go:348 and argon2.go:157 were wrong. They are frozen here rather than
// rewritten in bulk, because rewriting a hundred rows' prose in one change is
// how a register acquires errors rather than loses them.
//
// The set is a ratchet. A new pair fails; a pair that starts passing must be
// deleted, so the list cannot rot into a permanent amnesty. It is keyed on the
// file rather than on file:line so that ordinary code movement does not
// silently widen it.
var evidenceRelevanceExemptions = map[string]struct{}{
	"GDPR|Art. 15|internal/handler/data_export.go":                                     {},
	"GDPR|Art. 20|internal/handler/data_export.go":                                     {},
	"GDPR|Art. 32|internal/crypto/aes.go":                                              {},
	"GDPR|Art. 5(1)(c)|internal/audit/audit.go":                                        {},
	"GDPR|Art. 5(1)(c)|internal/httputil/safelog.go":                                   {},
	"GDPR|Arts. 33, 34|internal/honeypot/honeypot.go":                                  {},
	"IETF RFC / OpenID Connect|OIDC Core 1.0 s3.1.3.7|internal/oauth2/oidc_idtoken.go": {},
	"IETF RFC / OpenID Connect|RFC 7636|internal/handler/oauth.go":                     {},
	"IETF RFC / OpenID Connect|RFC 8725 s3.1|internal/crypto/jwt.go":                   {},
	"IETF RFC / OpenID Connect|RFC 8725 s3.8|internal/crypto/jwt.go":                   {},
	"IETF RFC / OpenID Connect|RFC 8725 s3.9|internal/jwt/validate.go":                 {},
	"IETF RFC / OpenID Connect|RFC 9700 s2.1.1|internal/handler/oauth.go":              {},
	"IETF RFC / OpenID Connect|RFC 9700 s4.1.1|internal/handler/oauth.go":              {},
	"IETF RFC / OpenID Connect|RFC 9700 s4.14.2|internal/service/auth.go":              {},
	"IETF RFC / OpenID Connect|RFC 9700 s4.3.2|internal/handler/oauth.go":              {},
	"IETF RFC / OpenID Connect|RFC 9700 s4.5.3|internal/oauth2/oidc_idtoken.go":        {},
	"NIST SP 800-53|AC-12|internal/repository/postgres/refresh_token.go":               {},
	"NIST SP 800-53|AC-2|internal/adminapi/handler.go":                                 {},
	"NIST SP 800-53|AC-3|internal/rbac/rbac.go":                                        {},
	"NIST SP 800-53|AC-6|internal/rbac/rbac.go":                                        {},
	"NIST SP 800-53|AC-7|internal/service/auth.go":                                     {},
	"NIST SP 800-53|AU-12|internal/audit/audit.go":                                     {},
	"NIST SP 800-53|AU-2|internal/audit/audit.go":                                      {},
	"NIST SP 800-53|AU-3|internal/audit/audit.go":                                      {},
	"NIST SP 800-53|IA-5|internal/crypto/argon2.go":                                    {},
	"NIST SP 800-53|SC-12|internal/keystore/keystore.go":                               {},
	"NIST SP 800-53|SC-12|internal/kms/kms.go":                                         {},
	"NIST SP 800-53|SC-13|internal/crypto/aes.go":                                      {},
	"NIST SP 800-53|SC-23|internal/jwt/parse.go":                                       {},
	"NIST SP 800-53|SC-28|internal/service/identity.go":                                {},
	"NIST SP 800-53|SC-5|internal/crypto/argon2.go":                                    {},
	"NIST SP 800-53|SC-5|internal/server/server.go":                                    {},
	"NIST SP 800-53|SC-7|internal/middleware/ipaccess.go":                              {},
	"NIST SP 800-53|SC-8|internal/server/server.go":                                    {},
	"NIST SP 800-53|SI-10|internal/sanitize/sanitize.go":                               {},
	"NIST SP 800-53|SI-11|internal/httputil/response.go":                               {},
	"NIST SP 800-63B-4|4.4|internal/keystore/keystore.go":                              {},
	"NIST SP 800-63B-4|4.6|internal/service/auth.go":                                   {},
	"NIST SP 800-63B-4|5.1.2|internal/service/token.go":                                {},
	"OWASP ASVS|V10.2.1|internal/handler/oauth.go":                                     {},
	"OWASP ASVS|V10.2.2|internal/handler/oauth.go":                                     {},
	"OWASP ASVS|V10.3.3|internal/service/token.go":                                     {},
	"OWASP ASVS|V10.4.4|internal/handler/wellknown.go":                                 {},
	"OWASP ASVS|V10.4.5|internal/repository/postgres/refresh_token.go":                 {},
	"OWASP ASVS|V10.4.6|internal/oauth2/oidc.go":                                       {},
	"OWASP ASVS|V10.5.4|internal/oauth2/oidc_idtoken.go":                               {},
	"OWASP ASVS|V10.7.1|internal/adminapi/router.go":                                   {},
	"OWASP ASVS|V11.1.1|internal/keystore/keystore.go":                                 {},
	"OWASP ASVS|V11.2.3|internal/crypto/aes.go":                                        {},
	"OWASP ASVS|V11.2.3|internal/crypto/jwt.go":                                        {},
	"OWASP ASVS|V1.1.2|internal/sanitize/sanitize.go":                                  {},
	"OWASP ASVS|V11.3.1|internal/crypto/aes.go":                                        {},
	"OWASP ASVS|V11.3.2|internal/crypto/aes.go":                                        {},
	"OWASP ASVS|V11.4.1|internal/crypto/hmac.go":                                       {},
	"OWASP ASVS|V11.4.3|internal/crypto/hmac.go":                                       {},
	"OWASP ASVS|V11.4.4|internal/kms/kms.go":                                           {},
	"OWASP ASVS|V12.1.2|internal/server/server.go":                                     {},
	"OWASP ASVS|V12.3.4|internal/redis/pool.go":                                        {},
	"OWASP ASVS|V1.2.4|internal/repository/postgres/refresh_token.go":                  {},
	"OWASP ASVS|V1.2.9|internal/sanitize/sanitize.go":                                  {},
	"OWASP ASVS|V13.4.2|internal/config/profiles.go":                                   {},
	"OWASP ASVS|V14.1.1|internal/audit/audit.go":                                       {},
	"OWASP ASVS|V14.2.3|internal/httputil/safelog.go":                                  {},
	"OWASP ASVS|V15.2.2|internal/server/server.go":                                     {},
	"OWASP ASVS|V15.3.4|internal/middleware/ratelimit.go":                              {},
	"OWASP ASVS|V15.3.5|internal/crypto/hmac.go":                                       {},
	"OWASP ASVS|V16.1.1|internal/audit/audit.go":                                       {},
	"OWASP ASVS|V16.2.2|internal/audit/audit.go":                                       {},
	"OWASP ASVS|V16.2.5|internal/audit/audit.go":                                       {},
	"OWASP ASVS|V16.3.1|internal/service/auth.go":                                      {},
	"OWASP ASVS|V16.3.3|internal/audit/audit.go":                                       {},
	"OWASP ASVS|V16.5.2|internal/service/auth.go":                                      {},
	"OWASP ASVS|V2.2.1|internal/sanitize/sanitize.go":                                  {},
	"OWASP ASVS|V2.3.2|internal/handler/data_export.go":                                {},
	"OWASP ASVS|V4.1.3|internal/middleware/ratelimit.go":                               {},
	"OWASP ASVS|V6.2.11|internal/service/hibp.go":                                      {},
	"OWASP ASVS|V6.3.6|internal/service/mfa.go":                                        {},
	"OWASP ASVS|V6.8.1|internal/seed/seed.go":                                          {},
	"OWASP ASVS|V6.8.2|internal/oauth2/oidc_idtoken.go":                                {},
	"OWASP ASVS|V7.4.1|internal/repository/postgres/refresh_token.go":                  {},
	"OWASP ASVS|V7.4.5|internal/adminapi/handler.go":                                   {},
	"OWASP ASVS|V9.1.3|internal/crypto/jwt.go":                                         {},
	"OWASP ASVS|V9.2.1|internal/jwt/validate.go":                                       {},
	"OWASP ASVS|V9.2.2|internal/crypto/jwt.go":                                         {},
	"OWASP ASVS|V9.2.4|internal/service/token.go":                                      {},
	"OWASP Top 10|A01:2025|internal/adminapi/router.go":                                {},
	"OWASP Top 10|A04:2025|internal/crypto/aes.go":                                     {},
	"OWASP Top 10|A05:2025|internal/repository/postgres/refresh_token.go":              {},
	"OWASP Top 10|A06:2025|internal/middleware/ratelimit.go":                           {},
	"OWASP Top 10|A07:2025|internal/service/auth.go":                                   {},
}

var evidenceIdentifier = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]{3,}`)

// TestComplianceRegister_EvidenceIsRelevantAndNotJustResolvable is the gate the
// password rows needed and did not have.
//
// The check every register has is that the cited file exists and the line is in
// range. All 396 evidence references passed it, including the one pointing at a
// doc comment on RecoveryRetentionPeriod and the one pointing at
// Argon2WaitingCount, a backpressure metric getter. Resolvability is not
// relevance, and the gap between them is exactly where an overclaim survives.
//
// The rule: the declaration containing the cited line must share an identifier
// with the row's own notes. It is deliberately generous — the whole enclosing
// declaration counts, plus the file and package name — because the failure it
// is aimed at is a citation that has nothing to do with the sentence, not a
// citation that could have been phrased better.
func TestComplianceRegister_EvidenceIsRelevantAndNotJustResolvable(t *testing.T) {
	reg := loadRegister(t)
	root := repoRoot(t)

	checked, exempted := 0, 0
	stillFailing := map[string]struct{}{}
	exemptionStillNeeded := map[string]struct{}{}

	for _, r := range reg.Requirements {
		for _, ev := range r.Evidence {
			idx := strings.LastIndex(ev, ":")
			if idx < 0 {
				continue
			}
			relPath, lineText := ev[:idx], ev[idx+1:]
			line, err := strconv.Atoi(lineText)
			if err != nil {
				continue
			}

			abs := filepath.Join(root, filepath.FromSlash(relPath))
			raw, readErr := os.ReadFile(abs)
			if readErr != nil {
				t.Errorf("%s %s cites %s, which does not exist", r.Standard, r.RequirementID, ev)
				continue
			}
			lines := strings.Split(string(raw), "\n")
			if line < 1 || line > len(lines) {
				t.Errorf("%s %s cites %s, but the file has %d lines",
					r.Standard, r.RequirementID, ev, len(lines))
				continue
			}
			if strings.TrimSpace(lines[line-1]) == "" {
				t.Errorf("%s %s cites %s, which is a blank line. A blank line is not evidence of "+
					"anything; it is a citation that used to point at something.",
					r.Standard, r.RequirementID, ev)
				continue
			}
			if !strings.HasSuffix(relPath, ".go") {
				continue
			}

			checked++
			key := r.Standard + "|" + r.RequirementID + "|" + relPath
			relevant := evidenceMentionsNotes(t, abs, raw, line, r.Notes, relPath)

			if _, exempt := evidenceRelevanceExemptions[key]; exempt {
				exempted++
				// A row may cite one file twice. The exemption is spent as soon
				// as any one of those citations is irrelevant, so "still needed"
				// is tracked per key rather than per citation.
				if !relevant {
					exemptionStillNeeded[key] = struct{}{}
				}
				continue
			}
			if !relevant {
				stillFailing[key] = struct{}{}
				t.Errorf("%s %s cites %s, and nothing in the declaration at that line appears in the "+
					"row's own notes. Evidence has to be relevant, not merely resolvable: this is "+
					"the check that internal/config/config.go:348 (a doc comment on "+
					"RecoveryRetentionPeriod) and internal/crypto/argon2.go:157 (a metrics getter) "+
					"both passed. Cite the line that implements what the notes describe, or say in "+
					"the notes what this line is doing there.",
					r.Standard, r.RequirementID, ev)
			}
		}
	}

	// The ratchet. An exemption whose row now passes is a standing amnesty for a
	// problem that has already been fixed, so it has to be deleted rather than
	// left to rot.
	for key := range evidenceRelevanceExemptions {
		if _, needed := exemptionStillNeeded[key]; !needed {
			t.Errorf("%s is in evidenceRelevanceExemptions and no longer needs to be. Delete the "+
				"entry: the list may only shrink.", key)
		}
	}

	if checked == 0 {
		t.Fatal("no Go evidence references were checked; the gate is vacuous")
	}
	t.Logf("%d Go evidence references checked, %d citations covered by %d frozen exemptions, %d new failures",
		checked, exempted, len(evidenceRelevanceExemptions), len(stillFailing))
}

// evidenceMentionsNotes reports whether the declaration containing the cited
// line shares an identifier with the notes.
func evidenceMentionsNotes(t *testing.T, abs string, raw []byte, line int, notes, relPath string) bool {
	t.Helper()

	lines := strings.Split(string(raw), "\n")
	scope := lines[line-1]

	fset := token.NewFileSet()
	if parsed, err := parser.ParseFile(fset, abs, raw, 0); err == nil {
		for _, decl := range parsed.Decls {
			start := fset.Position(decl.Pos()).Line
			end := fset.Position(decl.End()).Line
			if line < start || line > end {
				continue
			}
			var sb strings.Builder
			if err := printer.Fprint(&sb, fset, decl); err == nil {
				scope = sb.String()
			}
			if fn, ok := decl.(*ast.FuncDecl); ok {
				scope = fn.Name.Name + " " + scope
			}
			break
		}
		scope += " " + parsed.Name.Name
	}

	base := strings.TrimSuffix(filepath.Base(relPath), ".go")
	scope += " " + base

	lowerNotes := strings.ToLower(notes)
	for _, word := range evidenceIdentifier.FindAllString(scope, -1) {
		if strings.Contains(lowerNotes, strings.ToLower(word)) {
			return true
		}
	}
	return false
}

// --- Gate 3: risk identifier namespaces ------------------------------------

var (
	securityMdRiskHeading = regexp.MustCompile(`(?m)^#+\s*(AR-\d+)\s*:`)
	arReference           = regexp.MustCompile(`\bAR-(\d+)\b`)
	crReference           = regexp.MustCompile(`\bCR-(\d+)\b`)
)

// TestComplianceRegister_RiskIdentifierNamespacesDoNotCollide is the gate for
// the defect that let docs/COMPLIANCE.md assert "AR-16 has since closed" while
// docs/security.md AR-16 — a different, open risk — was open.
//
// Two documents numbered their accepted risks from one sequence. AR-14, AR-15,
// AR-17 and AR-18 each meant two different things depending on which file the
// reader happened to be in. The register's identifiers are now CR-nn, and this
// keeps them that way.
func TestComplianceRegister_RiskIdentifierNamespacesDoNotCollide(t *testing.T) {
	reg := loadRegister(t)
	root := repoRoot(t)

	// The AR-nn namespace belongs to docs/security.md.
	securityMd := readProductionSource(t, "docs/security.md")
	securityRisks := map[string]struct{}{}
	for _, m := range securityMdRiskHeading.FindAllStringSubmatch(securityMd, -1) {
		securityRisks[m[1]] = struct{}{}
	}
	if len(securityRisks) < 10 {
		t.Fatalf("only %d AR-nn headings found in docs/security.md; the scan is broken and every "+
			"assertion below would be vacuous", len(securityRisks))
	}

	// The CR-nn namespace belongs to the register.
	registerRisks := map[string]struct{}{}
	for id := range reg.AcceptedRisks {
		if !strings.HasPrefix(id, "CR-") {
			t.Errorf("the register defines accepted risk %q. The AR-nn namespace belongs to "+
				"docs/security.md, which defines a different risk under four of those numbers; "+
				"register identifiers are CR-nn.", id)
		}
		registerRisks[id] = struct{}{}
	}
	for id := range reg.RetiredRisks {
		registerRisks[id] = struct{}{}
	}
	if len(registerRisks) == 0 {
		t.Fatal("the register declares no risk identifiers at all; the gate is vacuous")
	}

	// Nothing may be defined in both.
	for id := range securityRisks {
		if _, dup := reg.AcceptedRisks[id]; dup {
			t.Errorf("%s is defined in both docs/security.md and the register's accepted_risks. "+
				"That is the collision this gate exists for: a cross-reference to it resolves to "+
				"whichever document the reader is in.", id)
		}
	}

	// Every reference anywhere in docs/ has to resolve to exactly one of them.
	var docs []string
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".md") {
			docs = append(docs, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk docs/: %v", err)
	}
	docs = append(docs, filepath.Join(root, "SECURITY.md"), filepath.Join(root, "README.md"))

	dangling := 0
	for _, path := range docs {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		rel, _ := filepath.Rel(root, path)
		body := string(raw)

		for _, m := range arReference.FindAllStringSubmatch(body, -1) {
			if _, ok := securityRisks[m[0]]; !ok {
				dangling++
				t.Errorf("%s references %s, which docs/security.md does not define. AR-nn always "+
					"means docs/security.md; if the register's risk was meant, it is CR-%s.",
					rel, m[0], m[1])
			}
		}
		for _, m := range crReference.FindAllStringSubmatch(body, -1) {
			if _, ok := registerRisks[m[0]]; !ok {
				dangling++
				t.Errorf("%s references %s, which is neither an entry in the register's "+
					"accepted_risks nor a declared retired risk", rel, m[0])
			}
		}
	}

	t.Logf("docs/security.md defines %d AR-nn risks; the register defines %d CR-nn (including retired); %d dangling references",
		len(securityRisks), len(registerRisks), dangling)
}

// --- Gate 4: a test named in prose must exist -------------------------------

var proseTestName = regexp.MustCompile(`\bTest[A-Za-z0-9_]{4,}\b`)

// proseTestNameExceptions are the Test-shaped words in the documentation that
// are deliberately not the name of a test function, each with the reason. The
// list is short on purpose: every entry is a hole in this gate, so it has to
// earn its place.
var proseTestNameExceptions = map[string]string{
	"Testcontainers": "the library, not a test function",
	"TestComplianceRegister": "a `go test -run` prefix in the reproduction instructions, " +
		"which matches every gate in this file",
	"TestNIST63B4_2_2_3_TheAbsoluteBoundIsStillUnwired": "quoted in the corrections section as an " +
		"example of a name that never existed. Naming it is the point; if it is ever removed from " +
		"the document this entry goes with it",
}

// TestComplianceDocs_EveryTestNamedInProseExists closes the door that let
// docs/COMPLIANCE.md name TestNIST63B4_2_2_3_TheAbsoluteBoundIsStillUnwired as
// the tracker for a gap that had already closed. The register gate validates
// test names in rows. A name in prose was checked by nothing, so a reader
// following the document's own evidence found nothing there.
func TestComplianceDocs_EveryTestNamedInProseExists(t *testing.T) {
	root := repoRoot(t)

	// Test functions anywhere under tests/, plus the package tests in
	// internal/ and cmd/, because the docs cite both.
	existing := map[string]struct{}{}
	for _, sub := range []string{"tests", "internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, sub), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			// A file that does not parse is a different test's problem, so it
			// contributes no names rather than failing the walk.
			if parsed, parseErr := parser.ParseFile(fset, path, nil, 0); parseErr == nil {
				for _, decl := range parsed.Decls {
					if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
						existing[fn.Name.Name] = struct{}{}
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", sub, err)
		}
	}
	if len(existing) < 200 {
		t.Fatalf("only %d test functions found across the tree; the scan is broken", len(existing))
	}

	var files []string
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".md") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk docs/: %v", err)
	}
	files = append(files, filepath.Join(root, "README.md"), filepath.Join(root, "SECURITY.md"))
	// And the register itself. The walk above reads docs/*.md, and the register
	// is .json, so the one document that names a test in almost every row was
	// the one document this gate did not read. Two names in its notes referred
	// to tests that had been retired the day they fired --
	// TestK8sPSS_Restricted_TheExcludedWorkloadsAreStillExcluded across all ten
	// PSS rows, and TestSSDF_800_218_DependencyUpdateAutomationIsAbsent in PO.3.2
	// -- while the tests[] arrays beside them resolved 219 out of 219. Rows are
	// gated; the sentences explaining the rows were not.
	files = append(files, filepath.Join(root, "docs", "compliance-register.json"))

	named := 0
	for _, path := range files {
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		rel, _ := filepath.Rel(root, path)
		for _, name := range proseTestName.FindAllString(string(raw), -1) {
			if _, exempt := proseTestNameExceptions[name]; exempt {
				continue
			}
			named++
			if _, ok := existing[name]; !ok {
				t.Errorf("%s names %s, which does not exist anywhere under tests/, internal/ or "+
					"cmd/. A document that cites a test as its evidence and then does not have one "+
					"is worse than a document that cites nothing.", rel, name)
			}
		}
	}
	t.Logf("%d test names in prose resolved against %d test functions", named, len(existing))
}

// --- Gate 5: accepted-risk prose citations resolve --------------------------

var proseCitation = regexp.MustCompile(`\b((?:internal|cmd|charts|migrations|docs|tests|web|packages)/[A-Za-z0-9_./-]+\.(?:go|yaml|yml|sql|md|json|ts|vue)):(\d+)(-\d+)?`)

// commentAcknowledgements are the ways the prose can say "the line I am citing
// is a comment". Citing a comment is legitimate -- sometimes the comment is the
// evidence, as when a rationale reports what the code says about itself -- but
// only when the sentence says so. CR-25 cited keystore.go:297 while asserting
// that the buffer there was not zeroed. It is a comment, and the buffer is
// zeroed two functions away.
var commentAcknowledgements = []string{
	"comment", "says so", "says:", "documents itself", "documents the", "concedes", "explains",
	"states", "notes that", "argued", "records",
}

// TestComplianceRegister_AcceptedRiskCitationsResolve reads the file:line
// references in the accepted-risk prose, which is where a reader is most likely
// to follow one. Five of the six had drifted: one pointed at an SMTP sender, one
// at a struct-literal field, one at a comment about graceful shutdown, one into
// the middle of a comment, and one at a comment line the register described as a
// buffer that is not zeroed.
func TestComplianceRegister_AcceptedRiskCitationsResolve(t *testing.T) {
	reg := loadRegister(t)
	root := repoRoot(t)

	checked := 0
	for id, ar := range reg.AcceptedRisks {
		for _, field := range []struct{ name, body string }{
			{"rationale", ar.Rationale},
			{"compensating_control", ar.CompensatingControl},
			{"residual_risk", ar.ResidualRisk},
			{"cost_of_closing", ar.CostOfClosing},
		} {
			for _, m := range proseCitation.FindAllStringSubmatch(field.body, -1) {
				relPath, lineText := m[1], m[2]
				line, err := strconv.Atoi(lineText)
				if err != nil {
					continue
				}
				checked++

				raw, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(relPath)))
				if readErr != nil {
					t.Errorf("%s %s cites %s:%d, which does not exist", id, field.name, relPath, line)
					continue
				}
				lines := strings.Split(string(raw), "\n")
				if line < 1 || line > len(lines) {
					t.Errorf("%s %s cites %s:%d, but the file has %d lines",
						id, field.name, relPath, line, len(lines))
					continue
				}
				text := strings.TrimSpace(lines[line-1])
				if text == "" {
					t.Errorf("%s %s cites %s:%d, which is blank", id, field.name, relPath, line)
					continue
				}
				isRange := m[3] != ""
				if strings.HasSuffix(relPath, ".go") && strings.HasPrefix(text, "//") && !isRange {
					lower := strings.ToLower(field.body)
					acknowledged := false
					for _, word := range commentAcknowledgements {
						if strings.Contains(lower, word) {
							acknowledged = true
							break
						}
					}
					if !acknowledged {
						t.Errorf("%s %s cites %s:%d, which is a comment line (%q), and the sentence "+
							"around it does not say so. A reader following the citation lands on "+
							"prose about the code rather than on the code. CR-25 cited "+
							"keystore.go:297 this way while asserting the buffer there was not "+
							"zeroed; it is a comment, and the buffer is zeroed two functions away.",
							id, field.name, relPath, line, text)
					}
				}
			}
		}
	}

	if checked < 5 {
		t.Fatalf("only %d prose citations found across the accepted risks; the scan is broken", checked)
	}
	t.Logf("%d accepted-risk prose citations resolved", checked)
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- Gate 6: a row without a reason is a row nobody re-read -----------------

// thinNotesBaseline freezes the rows that carry no substantive reason.
//
// The register's own promise is that every requirement was "classified against
// source at a cited file:line", and the existing gates enforce that for Not
// Applicable rows only -- an N/A with no reason is indistinguishable from "not
// assessed". A *Met* row was allowed to say nothing at all, and 44 of them do.
// GDPR Art. 17, the right to erasure, was one of them: it carried an empty
// notes field while the erasure tombstone was leaving password_hash on the row.
// The empty field did not cause that, but it is why nobody looked.
//
// Writing 44 rationales in the same change that discovered the problem is how a
// register acquires errors rather than losing them, so they are frozen. The set
// is a ratchet: a new row must carry a reason, and an entry that gains one must
// be deleted from this list.
var thinNotesBaseline = map[string]struct{}{
	"GDPR|Art. 30":      {},
	"GDPR|Art. 32":      {},
	"GDPR|Art. 5(1)(c)": {},
	"GDPR|Art. 7":       {},
	"IETF RFC / OpenID Connect|OIDC Core 1.0 s3.1.3.7": {},
	"IETF RFC / OpenID Connect|RFC 7636":               {},
	"IETF RFC / OpenID Connect|RFC 8725 s3.1":          {},
	"IETF RFC / OpenID Connect|RFC 9700 s2.1.1":        {},
	"IETF RFC / OpenID Connect|RFC 9700 s4.14.2":       {},
	"IETF RFC / OpenID Connect|RFC 9700 s4.3.2":        {},
	"IETF RFC / OpenID Connect|RFC 9700 s4.5.3":        {},
	"NIST SP 800-53|AC-2":                              {},
	"NIST SP 800-53|AC-3":                              {},
	"NIST SP 800-53|AC-6":                              {},
	"NIST SP 800-53|AC-7":                              {},
	"NIST SP 800-53|AU-12":                             {},
	"NIST SP 800-53|AU-3":                              {},
	"NIST SP 800-53|AU-8":                              {},
	"NIST SP 800-53|IA-5":                              {},
	"NIST SP 800-53|SA-11":                             {},
	"NIST SP 800-53|SC-12":                             {},
	"NIST SP 800-53|SC-13":                             {},
	"NIST SP 800-53|SC-23":                             {},
	"NIST SP 800-53|SC-28":                             {},
	"NIST SP 800-53|SC-5":                              {},
	"NIST SP 800-53|SC-8":                              {},
	"NIST SP 800-53|SI-10":                             {},
	"NIST SP 800-53|SI-11":                             {},
	"NIST SP 800-53|SR-11":                             {},
	"NIST SP 800-53|SR-3":                              {},
	"NIST SP 800-53|SR-4":                              {},
	"NIST SP 800-63B-4|2.4.3":                          {},
	"NIST SP 800-63B-4|7":                              {},
	"OWASP ASVS|V10.4.6":                               {},
	"OWASP ASVS|V11.3.2":                               {},
	"OWASP ASVS|V11.4.3":                               {},
	"OWASP Top 10|A01:2025":                            {},
	"OWASP Top 10|A04:2025":                            {},
	"OWASP Top 10|A06:2025":                            {},
	"OWASP Top 10|A08:2025":                            {},
}

func TestComplianceRegister_EveryRowCarriesASubstantiveReason(t *testing.T) {
	reg := loadRegister(t)

	for _, r := range reg.Requirements {
		key := r.Standard + "|" + r.RequirementID
		thin := len(strings.Fields(r.Notes)) < 5

		if _, frozen := thinNotesBaseline[key]; frozen {
			if !thin {
				t.Errorf("%s now carries a reason and is still in thinNotesBaseline. Delete the "+
					"entry: the list may only shrink.", key)
			}
			continue
		}
		if thin {
			t.Errorf("%s is %s and says nothing about why: %q. A status without an argument is a "+
				"vote. The evidence and the test say where the control is; the notes are the only "+
				"place that says what it does and why it is enough.",
				key, r.Status, r.Notes)
		}
	}
	t.Logf("%d rows frozen without a substantive reason; the list may only shrink", len(thinNotesBaseline))
}
