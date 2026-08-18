package email

import (
	"strings"
	"testing"
	"text/template/parse"
)

// The guard's refusal arms, driven through guardTemplate wherever a template can
// reach them.
//
// These are the paths that decide a pipeline is a derivation rather than a
// verbatim substitution, and the paths that walk a rendered body looking for a
// URL a mail client would linkify. They arrived with the fix for the $-rooted
// and derived secret oracles, and an untested refusal arm is the half of a
// control that fails open when someone edits it.

// TestGuardRefusesEveryDerivedPipelineShape drives one template per shape
// pipeIsVerbatimSecret can reject, so each arm is reached by a template an
// operator could actually write rather than by a direct call.
func TestGuardRefusesEveryDerivedPipelineShape(t *testing.T) {
	cases := map[string]string{
		// cmd.Args longer than one: a function applied with an argument.
		"function with an argument": `<p>{{.Code | printf "%s"}}</p>`,
		// cmd.Args[0] is not an identifier: a field used as the pipeline stage.
		"field as a pipeline stage": `<p>{{.Code | .Upper}}</p>`,
		// An identifier outside the verbatim allowlist.
		"function outside the allowlist": `<p>{{.Code | urlquery}}</p>`,
		"html escaper":                   `<p>{{.Code | html}}</p>`,
		"js escaper":                     `<p>{{.Code | js}}</p>`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if err := guardTemplate([]byte(src)); err == nil {
				t.Errorf("guardTemplate accepted %s (%q). Anything but a verbatim substitution can "+
					"carry a secret out a piece at a time.", name, src)
			}
		})
	}
}

// TestGuardStillAcceptsTheVerbatimPipelines is the other half: the allowlist has
// to keep working, or the fix is a denial of the feature rather than of the
// attack.
func TestGuardStillAcceptsTheVerbatimPipelines(t *testing.T) {
	cases := map[string]string{
		"bare":            `<p>{{.Code}}</p>`,
		"dollar rooted":   `<p>{{$.Code}}</p>`,
		"upper":           `<p>{{.Code | upper}}</p>`,
		"lower":           `<p>{{.Code | lower}}</p>`,
		"chained folds":   `<p>{{.Code | upper | lower}}</p>`,
		"safeURL on link": `<p><a href="{{.URL | safeURL}}">go</a></p>`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if err := guardTemplate([]byte(src)); err != nil {
				t.Errorf("guardTemplate refused the verbatim substitution %s (%q): %v", name, src, err)
			}
		})
	}
}

// TestPipeIsVerbatimSecretRefusesAnEmptyPipeline covers the guard's own
// defensive head. A parsed template never yields an action with no commands, so
// this is the one arm a template cannot reach; it is called directly rather than
// excluded, because the function is one `if` away from treating "nothing" as
// "verbatim".
func TestPipeIsVerbatimSecretRefusesAnEmptyPipeline(t *testing.T) {
	if pipeIsVerbatimSecret(nil) {
		t.Error("a nil pipeline read as a verbatim secret substitution")
	}
	if pipeIsVerbatimSecret(&parse.PipeNode{}) {
		t.Error("a pipeline with no commands read as a verbatim secret substitution")
	}
}

// TestNodeIsSecretFieldRefusesOtherNodeKinds covers the fallthrough. Only a
// FieldNode and a $-rooted VariableNode name a secret; every other node kind is
// not one, and the answer has to be false rather than a panic or a true.
func TestNodeIsSecretFieldRefusesOtherNodeKinds(t *testing.T) {
	cases := map[string]parse.Node{
		"string literal":      &parse.StringNode{},
		"nested pipe":         &parse.PipeNode{},
		"a chain":             &parse.ChainNode{},
		"a non-secret field":  &parse.FieldNode{Ident: []string{"Name"}},
		"a non-root variable": &parse.VariableNode{Ident: []string{"$x", "Code"}},
	}
	for name, node := range cases {
		t.Run(name, func(t *testing.T) {
			if nodeIsSecretField(node) {
				t.Errorf("%s read as a secret field", name)
			}
		})
	}
}

// TestAutolinkScanContinuesPastANonSecretURL covers the arm that advances the
// scan. A body may carry a secret in one place and an ordinary link in another,
// and the walk has to step over the ordinary one and keep looking rather than
// stopping at the first URL-shaped run it sees.
func TestAutolinkScanContinuesPastANonSecretURL(t *testing.T) {
	// The first run is a plain configured-looking link with no secret in it; the
	// secret sits in a second run, further along.
	src := `<p>See https://example.test/help for help. Your code is {{.Code}}. ` +
		`Then visit https://evil.test/c/{{.Code}} to finish.</p>`
	err := guardTemplate([]byte(src))
	if err == nil {
		t.Fatal("the scan stopped at the first URL and missed a later one carrying the secret")
	}
	if !strings.Contains(err.Error(), "auto-linkify") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// TestAutolinkScanAcceptsABodyWhoseLinksCarryNoSecret keeps the same walk honest
// in the other direction: stepping past a run must not become refusing it.
func TestAutolinkScanAcceptsABodyWhoseLinksCarryNoSecret(t *testing.T) {
	src := `<p>See https://example.test/help and https://example.test/more. ` +
		`Your code is {{.Code}}.</p>`
	if err := guardTemplate([]byte(src)); err != nil {
		t.Errorf("a body whose links carry no secret was refused: %v", err)
	}
}

// TestAutolinkRunStopsAtTrailingPunctuation covers the trim. A sentence ending
// in a link puts a full stop inside the run, and trimming it is what decides
// where the run ends -- so a secret immediately after the punctuation is a
// different run, and a secret inside the URL is still caught.
func TestAutolinkRunStopsAtTrailingPunctuation(t *testing.T) {
	t.Run("punctuation ends the run", func(t *testing.T) {
		src := `<p>Visit https://example.test/help. Your code is {{.Code}}!</p>`
		if err := guardTemplate([]byte(src)); err != nil {
			t.Errorf("a link ending a sentence was treated as carrying the code after it: %v", err)
		}
	})
	t.Run("secret inside the url is still caught", func(t *testing.T) {
		src := `<p>Visit https://evil.test/c/{{.Code}}.</p>`
		if err := guardTemplate([]byte(src)); err == nil {
			t.Error("a secret inside a URL escaped because the run was trimmed too far")
		}
	})
}

// TestAutolinkWalkStepsPastAHarmlessRunAndKeepsLooking covers the advance.
//
// Driven on the masked text directly, because the arm needs a body where a
// URL-shaped run carries no secret and the walk has to continue past it. The
// scanner sees the masked form, so the placeholders are what a secret looks
// like by the time this runs.
func TestAutolinkWalkStepsPastAHarmlessRunAndKeepsLooking(t *testing.T) {
	t.Run("advances past a clean run to a dirty one", func(t *testing.T) {
		text := "see https://example.test/help then https://evil.test/c/" + phCode
		err := refuseSecretBearingAutolink(text)
		if err == nil {
			t.Fatal("the walk stopped at the first clean URL and never reached the one carrying the code")
		}
		if !strings.Contains(err.Error(), "auto-linkify") {
			t.Errorf("refused for the wrong reason: %v", err)
		}
	})
	t.Run("advances past every clean run and accepts", func(t *testing.T) {
		text := "see https://example.test/help then https://example.test/more and the code " + phCode
		if err := refuseSecretBearingAutolink(text); err != nil {
			t.Errorf("a body whose URL-shaped runs carry no secret was refused: %v", err)
		}
	})
	t.Run("a clean run ending the text exits the walk", func(t *testing.T) {
		// The run reaches the end of the string, so the walk leaves by its loop
		// condition rather than by running out of link starts. That is the only
		// way to the far exit, and without it the scanner would have an untested
		// way to finish.
		text := "your code is " + phCode + " then see https://example.test/help"
		if err := refuseSecretBearingAutolink(text); err != nil {
			t.Errorf("a trailing URL carrying no secret was refused: %v", err)
		}
	})
}

// TestAutolinkRunTrimsARunThatIsAllPunctuation covers the trim's exhausted arm.
//
// findAutolinkStart only reports a position that begins a scheme or www., so a
// run consisting entirely of punctuation cannot arrive through the scanner.
// extendAutolinkRun is called directly rather than excluded, because "trim the
// trailing punctuation" and "trim until nothing is left" differ by whether the
// loop has a floor, and the floor is the whole reason the caller cannot loop
// forever on a zero-length run.
func TestAutolinkRunTrimsARunThatIsAllPunctuation(t *testing.T) {
	text := "...!?"
	if got := extendAutolinkRun(text, 0); got != 0 {
		t.Errorf("extendAutolinkRun returned %d for a run of nothing but punctuation, want 0; a "+
			"non-zero end there would hand the caller a run it already rejected", got)
	}
}
