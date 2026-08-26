package spec_test

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The admin gateway opened on a phone showed a sidebar and nothing else.
//
// .sidebar is position:fixed at z-index 100, and 100% wide below 480px. The
// mobile media query set transform: translateX(0) on it -- open -- and the only
// thing that ever added the class which closed it was a click handler. Nothing
// set it at load and nothing persisted it, so every first paint on a narrow
// viewport was a full-screen panel over the content. The content underneath
// also carried the desktop 220px offset, so the page was pushed right as well
// as covered.
//
// The interesting part is not that a default was wrong. It is that the
// stylesheet and the script disagreed about which state was the default and
// nothing could see the disagreement: the CSS named the closed state, the JS
// named the same class, and neither said which one you get with no JavaScript
// at all. That is the shape this gate holds -- the two files must agree, and
// the state you get without scripting must be the one that does not cover the
// page.
//
// The admin UI has no unit tests of its own and its Playwright specs do not run
// in CI, so a file-level assertion is what is available. It is also enough: the
// defect was visible in the two files, side by side.

var (
	adminStyle = filepath.Join("internal", "adminapi", "static", "style.css")
	adminJS    = filepath.Join("internal", "adminapi", "static", "admin.js")

	// The mobile block, from its media query to the closing brace of the rule
	// that follows the sidebar declarations. Matching the whole block is
	// deliberate: the question is what .sidebar resolves to inside it.
	mobileBlock = regexp.MustCompile(`(?s)@media \(max-width: 768px\) \{(.*?)\n\}`)

	// The bare .sidebar rule inside that block, i.e. the one with no class
	// qualifier, which is what a viewport gets before any script runs.
	bareSidebarRule = regexp.MustCompile(`(?s)\n    \.sidebar \{(.*?)\}`)

	// A transform that moves the panel off-screen. Either translateX(-100%) or
	// a negative pixel value at least the panel's width qualifies; the point is
	// the sign, not the unit.
	offScreen = regexp.MustCompile(`translateX\(\s*-\s*(100%|\d+px)\s*\)`)

	// classList.toggle('...') in the sidebar initialiser.
	toggledClass = regexp.MustCompile(`sidebar\.classList\.toggle\('([a-z-]+)'\)`)
)

func TestAdminSidebarIsClosedWithoutJavaScriptOnAPhone(t *testing.T) {
	root := repoRoot(t)
	css := readFileString(t, filepath.Join(root, adminStyle))

	block := mobileBlock.FindStringSubmatch(css)
	if block == nil {
		t.Fatal("no max-width: 768px block in the admin stylesheet. If the breakpoint " +
			"moved, move this gate with it rather than deleting it: the defect it holds " +
			"was a full-screen sidebar over the content on every narrow first paint.")
	}

	rule := bareSidebarRule.FindStringSubmatch(block[1])
	if rule == nil {
		t.Fatal("the mobile block no longer sets a bare .sidebar rule, so what a phone " +
			"gets before any script runs is whatever the desktop rule said -- which is a " +
			"fixed, full-height panel at z-index 100")
	}
	if !offScreen.MatchString(rule[1]) {
		t.Errorf("the mobile .sidebar default does not move the panel off-screen:\n%s\n"+
			"It is position:fixed at z-index 100 and 100%% wide below 480px, so an "+
			"on-screen default covers the page until something removes it -- and the "+
			"only thing that ever did was a click.", strings.TrimSpace(rule[1]))
	}
}

// The stylesheet and the script have to name the same class, and it has to be
// the one that OPENS the panel. The pair this replaced disagreed: the CSS
// described a closed state and the JS toggled the class for it, so the default
// was open and only a click could fix it.
func TestAdminSidebarToggleNamesTheClassTheStylesheetOpensWith(t *testing.T) {
	root := repoRoot(t)
	css := readFileString(t, filepath.Join(root, adminStyle))
	js := readFileString(t, filepath.Join(root, adminJS))

	m := toggledClass.FindStringSubmatch(js)
	if m == nil {
		t.Fatal("admin.js no longer toggles a class on the sidebar; if the mechanism " +
			"changed, this gate has to change with it")
	}
	class := m[1]

	block := mobileBlock.FindStringSubmatch(css)
	if block == nil {
		t.Fatal("no max-width: 768px block in the admin stylesheet")
	}
	qualified := "\n    .sidebar." + class + " {"
	if !strings.Contains(block[1], qualified) {
		t.Fatalf("admin.js toggles %q and the mobile block has no .sidebar.%s rule, so "+
			"the button changes a class nothing styles and the panel never moves",
			class, class)
	}

	// And the qualified rule must be the one that brings it on-screen, which is
	// what makes the toggled class "open" rather than "closed".
	after := block[1][strings.Index(block[1], qualified):]
	end := strings.Index(after, "}")
	if end < 0 {
		t.Fatalf(".sidebar.%s rule is unterminated", class)
	}
	body := after[:end]
	if offScreen.MatchString(body) {
		t.Errorf(".sidebar.%s moves the panel OFF-screen, so the class the button adds "+
			"is the closed one and the default is open. That is the arrangement that "+
			"put a full-screen panel over the admin UI on every phone: body was\n%s",
			class, strings.TrimSpace(body))
	}
	if !strings.Contains(body, "translateX(0)") {
		t.Errorf(".sidebar.%s does not bring the panel on-screen; body was\n%s",
			class, strings.TrimSpace(body))
	}
}
