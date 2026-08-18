// What the binary does when nobody configures it, read out of the binary.
//
// The wiring gates next door ask whether the chart can reach a setting. That is
// only half of what a chart install has to be true: the other half is that
// reaching it changes nothing until the operator asks for a change. A chart that
// exposes VAULT_MFA_REQUIRED and renders it "false" has made the switch
// reachable and turned MFA off in every install that upgrades to it, which is
// worse than the gap it closed, and every one of those pods comes up healthy.
//
// So the shipped default has to be the binary's own, and that claim is only
// worth anything if it is checked against the binary rather than against a
// second copy of the number written down here. internal/config states each
// default as the second argument to envOr, envInt, envDuration or
// envBoolDefault; this file parses those call sites and hands the value to the
// gates that compare it with what `helm template` renders.
//
// Two readers are deliberately not treated as declaring a default:
//
//   - a bare os.Getenv, because applyProfileDefaults may fill the field
//     afterwards and the call site says nothing about what with. LISTEN_ADDR and
//     CACHE_BACKEND both look like "" here and are ":8443" and "redis" by the
//     time Load returns.
//   - any setting whose call sites disagree, which is how a profile-decided
//     boolean looks: VAULT_TLS_ENABLED is envBool (false) in Load and
//     setDefaultBool(true) in applyProductionDefaults. There is no single answer
//     to compare against, so this reports none rather than picking one.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// settingDefault is what internal/config gives a setting when the environment
// does not carry it, with the kind that says how to compare it: "false" and
// "0" and "" are the same answer as a string and different answers as settings.
type settingDefault struct {
	kind string
	text string
}

// The kinds. Named rather than spelled inline because the comparison in
// sameSetting switches on them and a typo there would silently pass everything.
const (
	kindBool     = "bool"
	kindDuration = "duration"
	kindInt      = "int"
	kindString   = "string"
)

// defaultReaders is every call shape in internal/config that states a default,
// as a template whose %s is the quoted environment variable name. Each pattern
// captures the default in group 1, except the two that have no argument for it
// and answer with a constant instead.
//
// setDefaultBool is here even though it lives in profiles.go: it names its
// environment variable, so a profile default that agrees with Load's is still
// one answer, and one that disagrees is caught as the ambiguity it is.
var defaultReaders = []struct {
	pattern  string
	kind     string
	constant string
}{
	{pattern: `envBool\(\s*%s\s*\)`, kind: kindBool, constant: "false"},
	{pattern: `envBoolDefault\(\s*%s\s*,\s*(true|false)\s*\)`, kind: kindBool},
	{pattern: `setDefaultBool\([^,]+,\s*(true|false)\s*,\s*%s\s*\)`, kind: kindBool},
	{pattern: `envDuration\(\s*%s\s*,\s*([^)]+)\)`, kind: kindDuration},
	{pattern: `envInt\(\s*%s\s*,\s*([^)]+)\)`, kind: kindInt},
	{pattern: `envOr\(\s*%s\s*,\s*"([^"]*)"\s*\)`, kind: kindString},
	{pattern: `envList\(\s*%s\s*\)`, kind: kindString, constant: ""},
	{pattern: `envListFold\(\s*%s\s*,`, kind: kindString, constant: ""},
}

// binaryDefault reports the default internal/config applies to env, and whether
// the package states one at all.
func binaryDefault(t *testing.T, env string) (settingDefault, bool) {
	t.Helper()

	var found []settingDefault
	for _, src := range configPackageSources(t) {
		for _, reader := range defaultReaders {
			re := regexp.MustCompile(strings.ReplaceAll(reader.pattern, "%s", regexp.QuoteMeta(strconv.Quote(env))))
			for _, m := range re.FindAllStringSubmatch(src, -1) {
				raw := reader.constant
				if len(m) > 1 {
					raw = strings.TrimSpace(m[1])
				}
				value, ok := normalizeDefault(reader.kind, raw)
				if !ok {
					// A default this file cannot evaluate is reported as no
					// answer rather than as a wrong one: the gates that use it
					// then say the claim is unchecked, which is true, instead of
					// comparing against a number nobody computed.
					return settingDefault{}, false
				}
				found = append(found, settingDefault{kind: reader.kind, text: value})
			}
		}
	}

	if len(found) == 0 {
		return settingDefault{}, false
	}
	for _, other := range found[1:] {
		if other != found[0] {
			return settingDefault{}, false
		}
	}
	return found[0], true
}

// sameSetting reports whether a rendered chart value means what the binary's
// default means. Compared per kind, because "5m" and "5m0s" are one duration
// written two ways and "0" and "" are one integer written two ways, while as
// strings each pair is a mismatch this gate would report as a defect.
func sameSetting(t *testing.T, want settingDefault, rendered string) bool {
	t.Helper()

	switch want.kind {
	case kindBool:
		return strings.EqualFold(strings.TrimSpace(rendered), want.text)
	case kindDuration:
		got, err := time.ParseDuration(strings.TrimSpace(rendered))
		if err != nil {
			return false
		}
		expect, err := time.ParseDuration(want.text)
		if err != nil {
			t.Fatalf("binaryDefault produced %q, which is not a duration", want.text)
		}
		return got == expect
	case kindInt:
		got, err := strconv.Atoi(strings.TrimSpace(rendered))
		if err != nil {
			return false
		}
		expect, err := strconv.Atoi(want.text)
		if err != nil {
			t.Fatalf("binaryDefault produced %q, which is not a whole number", want.text)
		}
		return got == expect
	default:
		return rendered == want.text
	}
}

// normalizeDefault turns the source text of a default into a comparable value.
func normalizeDefault(kind, raw string) (string, bool) {
	switch kind {
	case kindBool, kindString:
		return raw, true
	case kindDuration:
		n, unit, ok := evalConstProduct(raw)
		if !ok || unit == 0 {
			return "", false
		}
		return (time.Duration(n) * unit).String(), true
	case kindInt:
		n, unit, ok := evalConstProduct(raw)
		if !ok || unit != 0 {
			return "", false
		}
		return strconv.FormatInt(n, 10), true
	}
	return "", false
}

// durationUnits are the time constants a default in this package is written in.
var durationUnits = map[string]time.Duration{
	"time.Nanosecond":  time.Nanosecond,
	"time.Microsecond": time.Microsecond,
	"time.Millisecond": time.Millisecond,
	"time.Second":      time.Second,
	"time.Minute":      time.Minute,
	"time.Hour":        time.Hour,
}

// evalConstProduct evaluates the constant expressions the defaults in
// internal/config are written as: a product of integer literals and at most one
// time unit, such as 5*time.Minute, 720*time.Hour, 10*1024*1024 or 65536.
//
// Deliberately not a full Go expression evaluator. Anything outside this shape
// is refused, and the caller reports the default as unknown, because a gate that
// guesses at a default it could not read would compare the chart against a
// number that is not the binary's.
func evalConstProduct(expr string) (n int64, unit time.Duration, ok bool) {
	n = 1
	for _, factor := range strings.Split(expr, "*") {
		factor = strings.TrimSpace(factor)
		if u, isUnit := durationUnits[factor]; isUnit {
			if unit != 0 {
				return 0, 0, false
			}
			unit = u
			continue
		}
		v, err := strconv.ParseInt(factor, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		n *= v
	}
	return n, unit, true
}

// configPackageSources reads every non-test file of internal/config with its
// comments blanked, so a default that appears only in a sentence about the code
// cannot be mistaken for one the code applies.
func configPackageSources(t *testing.T) []string {
	t.Helper()

	dir := filepath.Join(repoRoot(t), "internal", "config")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, commentFreeSource(t, filepath.Join(dir, name)))
	}
	if len(out) == 0 {
		t.Fatal("internal/config holds no non-test Go source, so every default this file " +
			"reports would be 'unknown' and every gate built on it would pass vacuously")
	}
	return out
}

// The evaluator only has to handle the shapes internal/config actually writes,
// and it has to refuse everything else rather than return a plausible number.
func TestTheDefaultEvaluatorRefusesWhatItCannotRead(t *testing.T) {
	for _, tc := range []struct {
		expr string
		kind string
		want string
		ok   bool
	}{
		{expr: "5*time.Minute", kind: kindDuration, want: "5m0s", ok: true},
		{expr: "720*time.Hour", kind: kindDuration, want: "720h0m0s", ok: true},
		{expr: "time.Hour", kind: kindDuration, want: "1h0m0s", ok: true},
		{expr: "60 * time.Second", kind: kindDuration, want: "1m0s", ok: true},
		{expr: "1000", kind: kindInt, want: "1000", ok: true},
		{expr: "64*1024", kind: kindInt, want: "65536", ok: true},
		{expr: "10*1024*1024", kind: kindInt, want: "10485760", ok: true},
		{expr: "0", kind: kindInt, want: "0", ok: true},
		{expr: "defaultTTL", kind: kindDuration, ok: false},
		{expr: "time.Hour + time.Minute", kind: kindDuration, ok: false},
		{expr: "time.Hour*time.Hour", kind: kindDuration, ok: false},
		{expr: "5*time.Minute", kind: kindInt, ok: false},
		{expr: "1000", kind: kindDuration, ok: false},
	} {
		t.Run(tc.kind+" "+tc.expr, func(t *testing.T) {
			got, ok := normalizeDefault(tc.kind, tc.expr)
			if ok != tc.ok {
				t.Fatalf("normalizeDefault(%q, %q) ok = %v, want %v (got %q)", tc.kind, tc.expr, ok, tc.ok, got)
			}
			if ok && got != tc.want {
				t.Errorf("normalizeDefault(%q, %q) = %q, want %q", tc.kind, tc.expr, got, tc.want)
			}
		})
	}
}

// Read against the live package, so a rename of a reader helper stops this
// reporting defaults rather than reporting wrong ones.
func TestTheDefaultsAreReadOffTheConfigPackage(t *testing.T) {
	for _, tc := range []struct {
		env   string
		kind  string
		text  string
		known bool
	}{
		{env: "VAULT_MINT_TOKEN_TTL", kind: kindDuration, text: "5m0s", known: true},
		{env: "VAULT_MAX_SESSION_LIFETIME", kind: kindDuration, text: "720h0m0s", known: true},
		{env: "VAULT_MAX_SESSIONS_PER_USER", kind: kindInt, text: "10", known: true},
		{env: "VAULT_MFA_REQUIRED", kind: kindBool, text: "true", known: true},
		{env: "VAULT_DPOP_ENABLED", kind: kindBool, text: "false", known: true},
		{env: "DB_NAME", kind: kindString, text: "vault", known: true},
		{env: "VAULT_MINT_ROLES", kind: kindString, text: "", known: true},

		// A bare os.Getenv states no default, and a setting the profiles
		// disagree with Load about has no single one.
		{env: "VAULT_ORIGIN", known: false},
		{env: "VAULT_TLS_ENABLED", known: false},
		{env: "SOME_VARIABLE_NOTHING_READS", known: false},
	} {
		t.Run(tc.env, func(t *testing.T) {
			got, known := binaryDefault(t, tc.env)
			if known != tc.known {
				t.Fatalf("binaryDefault(%s) known = %v, want %v (got %+v)", tc.env, known, tc.known, got)
			}
			if known && (got.kind != tc.kind || got.text != tc.text) {
				t.Errorf("binaryDefault(%s) = %+v, want kind %q text %q", tc.env, got, tc.kind, tc.text)
			}
		})
	}
}

// The comparison has to be per kind. As strings, half of these read as drift.
func TestARenderedValueIsComparedAsTheKindItIs(t *testing.T) {
	for _, tc := range []struct {
		want     settingDefault
		rendered string
		same     bool
	}{
		{want: settingDefault{kindDuration, "5m0s"}, rendered: "5m", same: true},
		{want: settingDefault{kindDuration, "720h0m0s"}, rendered: "720h", same: true},
		{want: settingDefault{kindDuration, "5m0s"}, rendered: "10m", same: false},
		{want: settingDefault{kindDuration, "5m0s"}, rendered: "", same: false},
		{want: settingDefault{kindInt, "0"}, rendered: "0", same: true},
		{want: settingDefault{kindInt, "65536"}, rendered: "65536", same: true},
		{want: settingDefault{kindInt, "0"}, rendered: "", same: false},
		{want: settingDefault{kindBool, "false"}, rendered: "false", same: true},
		{want: settingDefault{kindBool, "true"}, rendered: "false", same: false},
		{want: settingDefault{kindString, ""}, rendered: "", same: true},
		{want: settingDefault{kindString, ""}, rendered: "member", same: false},
	} {
		t.Run(tc.want.kind+" "+tc.want.text+" vs "+tc.rendered, func(t *testing.T) {
			if got := sameSetting(t, tc.want, tc.rendered); got != tc.same {
				t.Errorf("sameSetting(%+v, %q) = %v, want %v", tc.want, tc.rendered, got, tc.same)
			}
		})
	}
}
