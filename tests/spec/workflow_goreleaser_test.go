// GoReleaser config validation gate.
//
// `.goreleaser.yaml` decides what a release ships: which binaries are built,
// what lands in the archives, the checksum file that cosign signs, and the
// SBOMs. Nothing in the tree parses that file except goreleaser itself, and the
// only run of goreleaser that produces a release lives in release.yml behind a
// `v*` tag push.
//
// CI's `goreleaser check` job is therefore the last chance to catch a malformed
// config before a tag exists. That job was gated on the `go` paths filter, and
// the `go` filter lists Go sources, the module files and the coverage scripts,
// but never `.goreleaser.yaml`. A pull request that edited only the release
// config ran no goreleaser at all: the first thing to read the file was the tag
// push, where the tag is already published, half the release jobs have already
// pushed images, and the fix costs a version number.
//
// `check` is the validation this gate demands rather than `build` or `release`,
// because the config's before-hooks run pnpm and build the whole SPA into
// internal/frontend/dist. Parsing the config has to stay cheap enough that
// every config edit can afford it.
//
// The property: for every goreleaser config in the tree, a change that touches
// only that file must reach a job running `goreleaser check`. The test decides
// that by evaluating ci.yml's own filters, outputs and job conditions, so it
// keeps holding when any of the three is rewritten.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// ciStep decodes `with` as free-form because workflow inputs mix strings with
// numbers (fetch-depth, node-version) and a typed map would fail to decode the
// file before this gate could assert anything about it.
type ciStep struct {
	ID   string         `yaml:"id"`
	Uses string         `yaml:"uses"`
	Run  string         `yaml:"run"`
	With map[string]any `yaml:"with"`
}

type ciJob struct {
	Name    string            `yaml:"name"`
	If      string            `yaml:"if"`
	Needs   yaml.Node         `yaml:"needs"`
	Outputs map[string]string `yaml:"outputs"`
	Steps   []ciStep          `yaml:"steps"`
}

type ciWorkflow struct {
	Jobs map[string]ciJob `yaml:"jobs"`
}

// TestGoReleaserConfigIsValidatedWhenItChanges is the gate.
func TestGoReleaserConfigIsValidatedWhenItChanges(t *testing.T) {
	root := repoRoot(t)
	wf := parseCIWorkflow(t, root, "ci.yml")

	configs := goreleaserConfigs(t, root)
	validators := jobsRunningGoReleaserCheck(wf)
	if len(validators) == 0 {
		t.Fatal("no job in ci.yml runs `goreleaser check`, so the release config is parsed for the " +
			"first time on a tag push, when the tag already exists and the release is half published")
	}

	for _, config := range configs {
		var reached []string
		for _, name := range validators {
			if jobRunsForChange(t, wf, name, config) {
				reached = append(reached, name)
			}
		}
		if len(reached) == 0 {
			t.Errorf("a pull request touching only %s runs no `goreleaser check` job in ci.yml "+
				"(candidates: %s), so a malformed release config merges green and surfaces on the "+
				"tag push, after the tag is published and images are already pushed. The paths "+
				"filter feeding those jobs must match %s.",
				config, strings.Join(validators, ", "), config)
		}
	}
}

// goreleaserConfigs finds the release configs at the repo root. Discovering them
// rather than naming one keeps the gate honest if the config is split or
// renamed, which is exactly when nobody remembers to update the paths filter.
func goreleaserConfigs(t *testing.T, root string) []string {
	t.Helper()

	var found []string
	for _, pattern := range []string{".goreleaser*.yaml", ".goreleaser*.yml"} {
		matches, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		for _, m := range matches {
			found = append(found, filepath.Base(m))
		}
	}
	if len(found) == 0 {
		t.Fatal("no goreleaser config at the repo root; the release artifacts are built from one, " +
			"so this gate has stopped seeing what it guards")
	}
	sort.Strings(found)
	return found
}

// jobsRunningGoReleaserCheck reports the jobs that validate the config without
// building it. A job that only runs `goreleaser build` or `goreleaser release`
// does not count: those run the before-hooks, which install pnpm dependencies
// and build the SPA, and no config edit would be able to afford them.
func jobsRunningGoReleaserCheck(wf ciWorkflow) []string {
	var names []string
	for name, job := range wf.Jobs {
		for _, step := range job.Steps {
			args := withString(step, "args")
			viaAction := strings.Contains(step.Uses, "goreleaser/goreleaser-action") &&
				hasWord(args, "check")
			viaRun := strings.Contains(step.Run, "goreleaser") && hasWord(step.Run, "check")
			if viaAction || viaRun {
				names = append(names, name)
				break
			}
		}
	}
	sort.Strings(names)
	return names
}

// jobRunsForChange evaluates the job's condition for a push or pull request
// whose only changed file is path.
func jobRunsForChange(t *testing.T, wf ciWorkflow, jobName, path string) bool {
	t.Helper()

	job := wf.Jobs[jobName]
	if strings.TrimSpace(job.If) == "" {
		return true
	}
	return evalCondition(t, job.If, conditionEnv(t, wf, job, path))
}

// conditionEnv resolves the `needs.<job>.outputs.<name>` values the job can see.
// Outputs of jobs the job does not declare in `needs` resolve to the empty
// string, which is what Actions itself does and a common way for a filter to
// silently stop gating anything.
func conditionEnv(t *testing.T, wf ciWorkflow, job ciJob, path string) map[string]string {
	t.Helper()

	env := map[string]string{}
	for _, dep := range needsList(t, job) {
		depJob, ok := wf.Jobs[dep]
		if !ok {
			t.Fatalf("job depends on %q, which ci.yml does not define", dep)
		}
		filters := pathsFilterValues(t, depJob, path)
		for out, expr := range depJob.Outputs {
			env["needs."+dep+".outputs."+out] = resolveOutput(expr, filters)
		}
	}
	return env
}

// outputRef matches the `steps.<id>.outputs.<filter>` shape a paths-filter
// result travels through on its way to a job output.
var outputRef = regexp.MustCompile(`steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)`)

// resolveOutput turns a job output expression into the value it would carry.
func resolveOutput(expr string, filters map[string]bool) string {
	m := outputRef.FindStringSubmatch(expr)
	if m == nil {
		return ""
	}
	if filters[m[2]] {
		return "true"
	}
	return "false"
}

// pathsFilterValues reports which of the job's paths-filter filters match path.
func pathsFilterValues(t *testing.T, job ciJob, path string) map[string]bool {
	t.Helper()

	values := map[string]bool{}
	for _, step := range job.Steps {
		if !strings.Contains(step.Uses, "dorny/paths-filter") {
			continue
		}
		raw := withString(step, "filters")
		if raw == "" {
			t.Fatal("a dorny/paths-filter step in ci.yml has no inline `filters`; this gate reads " +
				"them to decide what a change reaches and cannot evaluate an external filter file")
		}
		var parsed map[string][]string
		if err := yaml.Unmarshal([]byte(raw), &parsed); err != nil {
			t.Fatalf("the paths filters in ci.yml are no longer a plain name-to-patterns mapping "+
				"(%v); this gate reads them to decide what a change reaches and must be taught the "+
				"new shape rather than passing blindly", err)
		}
		for name, patterns := range parsed {
			for _, pattern := range patterns {
				if globMatch(pattern, path) {
					values[name] = true
					break
				}
			}
		}
	}
	return values
}

// globMatch answers whether a paths-filter pattern selects path.
func globMatch(pattern, path string) bool {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch {
		case strings.HasPrefix(pattern[i:], "**/"):
			b.WriteString("(?:[^/]+/)*")
			i += 2
		case strings.HasPrefix(pattern[i:], "**"):
			b.WriteString(".*")
			i++
		case pattern[i] == '*':
			b.WriteString("[^/]*")
		case pattern[i] == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(pattern[i])))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String()).MatchString(path)
}

// needsList reads `needs` in both shapes Actions accepts.
func needsList(t *testing.T, job ciJob) []string {
	t.Helper()

	var many []string
	if err := job.Needs.Decode(&many); err == nil {
		return many
	}
	var one string
	if err := job.Needs.Decode(&one); err == nil && one != "" {
		return []string{one}
	}
	return nil
}

// withString reads a step input as text.
func withString(step ciStep, key string) string {
	v, ok := step.With[key]
	if !ok {
		return ""
	}
	return fmt.Sprint(v)
}

// hasWord reports whether s contains word as a whole shell argument, so
// `check` is not read out of `--check-nothing` or a job named `precheck`.
func hasWord(s, word string) bool {
	for _, field := range strings.Fields(s) {
		if field == word {
			return true
		}
	}
	return false
}

func parseCIWorkflow(t *testing.T, root, name string) ciWorkflow {
	t.Helper()

	path := filepath.Join(root, ".github", "workflows", name)
	data, err := os.ReadFile(path) // #nosec G304 -- fixed path inside the repo
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}

	var wf ciWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	if len(wf.Jobs) == 0 {
		t.Fatalf("%s declares no jobs; this gate cannot prove anything against an empty set", name)
	}
	return wf
}

// ---------------------------------------------------------------------------
// Actions expression evaluation
//
// The gate has to answer "would this job run", not "does the condition mention
// the right filter". A condition that ANDs two filters together, or that names
// an output of a job missing from `needs`, mentions everything and still gates
// nothing.
// ---------------------------------------------------------------------------

type condParser struct {
	t    *testing.T
	toks []string
	pos  int
	env  map[string]string
}

func evalCondition(t *testing.T, expr string, env map[string]string) bool {
	t.Helper()

	p := &condParser{t: t, toks: tokenizeCondition(t, expr), env: env}
	v := p.parseOr()
	if p.pos != len(p.toks) {
		t.Fatalf("could not fully evaluate the job condition %q; this gate must be taught the new "+
			"syntax rather than guessing whether the job runs", expr)
	}
	return v
}

var condToken = regexp.MustCompile(`^(\|\||&&|==|!=|!|\(|\)|'[^']*'|[A-Za-z0-9_.\-]+)`)

func tokenizeCondition(t *testing.T, expr string) []string {
	t.Helper()

	var toks []string
	s := strings.TrimSpace(expr)
	s = strings.TrimSuffix(strings.TrimPrefix(s, "${{"), "}}")
	for {
		s = strings.TrimSpace(s)
		if s == "" {
			return toks
		}
		m := condToken.FindString(s)
		if m == "" {
			t.Fatalf("unreadable character in the job condition %q; this gate must be taught the "+
				"new syntax rather than guessing whether the job runs", expr)
		}
		toks = append(toks, m)
		s = s[len(m):]
	}
}

func (p *condParser) parseOr() bool {
	v := p.parseAnd()
	for p.peek() == "||" {
		p.pos++
		// No short circuit: the right side must still parse, otherwise a
		// condition this gate cannot read would slip through as true.
		v = p.parseAnd() || v
	}
	return v
}

func (p *condParser) parseAnd() bool {
	v := p.parseUnary()
	for p.peek() == "&&" {
		p.pos++
		v = p.parseUnary() && v
	}
	return v
}

func (p *condParser) parseUnary() bool {
	if p.peek() == "!" {
		p.pos++
		return !p.parseUnary()
	}
	return p.parsePrimary()
}

func (p *condParser) parsePrimary() bool {
	if p.peek() == "(" {
		p.pos++
		v := p.parseOr()
		if p.peek() != ")" {
			p.t.Fatal("unbalanced parentheses in a ci.yml job condition; this gate cannot decide " +
				"whether the job runs")
		}
		p.pos++
		return v
	}

	left := p.parseValue()
	switch p.peek() {
	case "==":
		p.pos++
		return left == p.parseValue()
	case "!=":
		p.pos++
		return left != p.parseValue()
	}
	// Actions casts a bare value to a boolean, and every non-empty string is
	// true, including the string "false".
	return left != ""
}

// parseValue resolves one operand to the string Actions would substitute.
func (p *condParser) parseValue() string {
	tok := p.peek()
	if tok == "" {
		p.t.Fatal("a ci.yml job condition ends mid-expression; this gate cannot decide whether the " +
			"job runs")
	}
	p.pos++

	if strings.HasPrefix(tok, "'") {
		return strings.Trim(tok, "'")
	}
	if p.peek() == "(" {
		p.pos++
		if p.peek() != ")" {
			p.t.Fatalf("the status function %s(...) in a ci.yml job condition takes arguments this "+
				"gate cannot evaluate", tok)
		}
		p.pos++
		switch tok {
		case "always", "success":
			return "true"
		case "failure", "cancelled":
			return "false"
		default:
			p.t.Fatalf("unknown function %s() in a ci.yml job condition; this gate must be taught "+
				"what it returns rather than guessing whether the job runs", tok)
		}
	}
	if strings.HasPrefix(tok, "needs.") {
		return p.env[tok]
	}
	if tok == "true" || tok == "false" {
		return tok
	}
	p.t.Fatalf("a ci.yml job condition depends on %s, which this gate cannot resolve for a "+
		"single-file change; teach it that context rather than letting the condition go unchecked", tok)
	return ""
}

func (p *condParser) peek() string {
	if p.pos >= len(p.toks) {
		return ""
	}
	return p.toks[p.pos]
}
