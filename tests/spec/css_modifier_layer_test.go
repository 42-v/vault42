package spec_test

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// A size modifier has to be able to beat the class it modifies.
//
// Tailwind v4 compiles every @utility into @layer utilities. A plain CSS rule
// written outside any @layer is unlayered, and unlayered CSS wins over layered
// CSS in the cascade whatever the specificity. So when the base class is a plain
// rule and its modifier is an @utility, the base overrides the modifier and the
// modifier does nothing at all.
//
// That is what happened to vault42-spinner-sm. .vault42-spinner was a plain rule
// setting w-5 h-5; vault42-spinner-sm was an @utility setting w-4 h-4. Every
// "small" spinner in the app rendered at the default size, on two call sites,
// and nothing could see it: the class was present in the markup, the rule was
// present in the stylesheet, and the build emitted both. Only the layer differed.
// vault42-spinner-lg escaped only because somebody happened to write it as a
// plain rule next to the base.
//
// This gate holds the pairing rather than the sizes: a modifier and its base
// must be declared the same way.
//
// That is a necessary condition and not a sufficient one, and the difference is
// worth stating here so nobody reads a pass as proof. Order inside @layer
// utilities is Tailwind's property-set sort, not source order, so two utilities
// declared identically can still emit in the wrong order -- measured, adding
// w-full to vault42-btn-sm moves it ahead of vault42-btn and makes it inert at
// every one of its nine call sites, and this gate passes throughout. The gate
// that settles it compiles the stylesheet and reads the emitted offsets:
// web/src/__tests__/spinnerCascade.test.ts. This one is the cheap early signal
// that runs with the Go suite.
//
// The tests are read-only. They never write to the source tree.

var (
	styleSheet = filepath.Join("web", "src", "style.css")

	// `@utility name {` -- the layered form.
	utilityDecl = regexp.MustCompile(`(?m)^@utility\s+([a-zA-Z0-9_-]+)\s*\{`)
	// `.name {` at column zero -- the unlayered form.
	plainDecl = regexp.MustCompile(`(?m)^\.([a-zA-Z0-9_-]+)\s*\{`)

	// Suffixes that mean "this class modifies another one" rather than standing
	// alone. A class ending in one of these is checked against its base.
	modifierSuffixes = []string{"-sm", "-lg", "-xs", "-xl"}
)

func TestACSSModifierIsDeclaredTheSameWayAsTheClassItModifies(t *testing.T) {
	css := readFileString(t, filepath.Join(repoRoot(t), styleSheet))

	// class name -> "utility" or "plain"
	form := map[string]string{}
	for _, m := range utilityDecl.FindAllStringSubmatch(css, -1) {
		form[m[1]] = "@utility"
	}
	for _, m := range plainDecl.FindAllStringSubmatch(css, -1) {
		form[m[1]] = "a plain rule"
	}

	if len(form) == 0 {
		t.Fatalf("no class declarations found in %s. If the stylesheet moved, move this "+
			"gate with it: what it holds is that a size modifier can actually beat the "+
			"class it modifies.", styleSheet)
	}

	var checked int
	names := make([]string, 0, len(form))
	for name := range form {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		for _, suffix := range modifierSuffixes {
			if !strings.HasSuffix(name, suffix) {
				continue
			}
			base := strings.TrimSuffix(name, suffix)
			baseForm, ok := form[base]
			if !ok {
				// Not a modifier of anything in this sheet; it just ends that way.
				continue
			}
			checked++
			if baseForm != form[name] {
				t.Errorf("%s is %s and %s is %s.\n"+
					"@utility rules land in @layer utilities and plain rules are unlayered, "+
					"and unlayered beats layered whatever the specificity -- so the plain one "+
					"wins and the other is inert no matter what it declares. Declare both the "+
					"same way and let source order decide.",
					name, form[name], base, baseForm)
			}
		}
	}

	// A gate that compares no pairs proves nothing.
	if checked == 0 {
		t.Fatalf("no modifier/base pairs found in %s, so this gate compared nothing. "+
			"If the naming convention changed, update modifierSuffixes.", styleSheet)
	}
	t.Logf("checked %d modifier/base pairs", checked)
}
