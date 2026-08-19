// Release version-stamp gate.
//
// A shipped binary answers "which release am I" from a build stamp: the release
// pipeline passes `-ldflags "-X main.Version=1.0.0"`, the linker writes that
// string into a package-level variable, and `--version` prints it. It is the
// only way an operator holding a downloaded binary, or a responder matching a
// CVE against a running fleet, can establish what is actually deployed. The
// archives carry no other version marker: the file name is chosen by the release
// job, not by the binary.
//
// The linker does not verify that the symbol named by -X exists. `-X
// main.Version=1.0.0` against a package main that declares no Version links
// cleanly, prints no warning, exits 0, and produces a binary with no version in
// it. A wrong stamp is not a build failure, it is a silent no-op, and the only
// symptom is a string that is absent from an artifact nobody inspects.
//
// The bridge shipped that way. Its goreleaser build passed all three stamps at
// `main.*` while cmd/bridge declared none of them, so every release archive
// contained a bridge that reported nothing, while the config read as though it
// were versioned like the other two binaries. cmd/bridge is deliberately
// stdlib-only and imports no internal package, so the stamp cannot be moved to a
// shared package either: a -X against a package the binary does not link is
// dropped just as quietly.
//
// Three properties are checked, and together they make the stamp end to end
// rather than merely present in a config:
//
//   - every -X a build passes names a variable that the built package really
//     declares, so no stamp is silently dropped;
//   - every stamp variable a built package declares is passed by its build, so
//     no binary ships reporting its compiled-in default;
//   - builds agree on what each stamp means, so two binaries out of one release
//     cannot report two different versions.
//
// The second property is what carries the bridge forward. cmd/bridge declares no
// stamp variables today, so it is shipped unversioned by design rather than by
// accident; the moment someone adds Version to it, this gate demands the ldflags
// that make it reach the binary.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// stampBuild is the part of a goreleaser build definition this gate reads.
type stampBuild struct {
	ID      string   `yaml:"id"`
	Main    string   `yaml:"main"`
	Binary  string   `yaml:"binary"`
	Ldflags []string `yaml:"ldflags"`
}

type stampConfig struct {
	Builds []stampBuild `yaml:"builds"`
}

// stampFlag is one -X target, split into the package it names, the variable in
// that package, and the value the release would write there.
type stampFlag struct {
	pkg   string
	ident string
	value string
}

// xFlag matches the left side of a -X assignment. The value is deliberately not
// captured here: goreleaser values are templates such as `{{ .Version }}` and
// contain spaces, so the end of a value is found by looking for the next -X
// rather than by tokenizing on whitespace.
var xFlag = regexp.MustCompile(`-X[ =]\s*([^\s=]+)=`)

// stampFlagsOf extracts every -X target a build passes. One ldflags entry may
// hold several flags, which is how the Dockerfiles write them, so the entries
// are scanned rather than compared.
func stampFlagsOf(b stampBuild) []stampFlag {
	flags := make([]stampFlag, 0, len(b.Ldflags))
	for _, entry := range b.Ldflags {
		matches := xFlag.FindAllStringSubmatchIndex(entry, -1)
		for i, m := range matches {
			key := entry[m[2]:m[3]]
			end := len(entry)
			if i+1 < len(matches) {
				end = matches[i+1][0]
			}
			dot := strings.LastIndex(key, ".")
			if dot <= 0 || dot == len(key)-1 {
				// A -X target with no package qualifier cannot resolve to
				// anything, so it is reported as a flag against no package and
				// fails the first property with the rest.
				flags = append(flags, stampFlag{pkg: "", ident: key, value: strings.TrimSpace(entry[m[1]:end])})
				continue
			}
			flags = append(flags, stampFlag{
				pkg:   key[:dot],
				ident: key[dot+1:],
				value: strings.TrimSpace(entry[m[1]:end]),
			})
		}
	}
	return flags
}

// stampConfigPaths finds the release configs at the repository root. They are
// discovered rather than named so a config that is split or renamed is still
// held to the properties below, which is exactly when nobody remembers a gate.
func stampConfigPaths(t *testing.T, root string) []string {
	t.Helper()

	patterns := []string{".goreleaser*.yaml", ".goreleaser*.yml"}
	found := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		found = append(found, matches...)
	}
	if len(found) == 0 {
		t.Fatal("no goreleaser config at the repo root; the release binaries are built from one, " +
			"so this gate has stopped seeing what it guards")
	}
	sort.Strings(found)
	return found
}

// stampBuilds reads the build definitions out of every goreleaser config.
func stampBuilds(t *testing.T, root string) []stampBuild {
	t.Helper()

	paths := stampConfigPaths(t, root)
	builds := make([]stampBuild, 0, len(paths))
	for _, name := range paths {
		data, err := os.ReadFile(name) // #nosec G304 -- path comes from a glob inside the repo
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var cfg stampConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		builds = append(builds, cfg.Builds...)
	}
	if len(builds) == 0 {
		t.Fatal("the goreleaser config declares no builds; the release ships the binaries listed " +
			"there, so this gate has stopped seeing what it guards")
	}
	return builds
}

// stampMainDir resolves a build's `main` to the directory holding its sources.
// goreleaser accepts a package directory, a path to the file holding main(), or
// nothing at all, which means the module root.
func stampMainDir(t *testing.T, root string, b stampBuild) string {
	t.Helper()

	main := strings.TrimSpace(b.Main)
	if main == "" {
		main = "."
	}
	if strings.HasSuffix(main, ".go") {
		main = path.Dir(main)
	}
	dir := filepath.Join(root, filepath.FromSlash(main))
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("goreleaser build %q builds %q, which is not a directory in the repository; the "+
			"release would fail to build it", stampBuildName(b), b.Main)
	}
	return dir
}

// stampBuildName is what a failure calls the build. The id is what the config
// and the archives refer to; the binary name is the fallback so a build without
// an id is still identifiable in the message.
func stampBuildName(b stampBuild) string {
	switch {
	case b.ID != "":
		return b.ID
	case b.Binary != "":
		return b.Binary
	default:
		return b.Main
	}
}

// stampDeclaredVars returns the package-level variable names declared in dir.
// Test files are skipped: a variable that exists only under `go test` is not in
// the shipped binary, so a stamp aimed at one would still be dropped.
func stampDeclaredVars(t *testing.T, dir string) map[string]bool {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	fset := token.NewFileSet()
	declared := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", filepath.Join(dir, name), err)
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, ident := range value.Names {
					declared[ident.Name] = true
				}
			}
		}
	}
	return declared
}

// TestEveryVersionStampReachesTheShippedBinary fails when a build passes a -X
// the linker cannot apply.
func TestEveryVersionStampReachesTheShippedBinary(t *testing.T) {
	root := repoRoot(t)
	builds := stampBuilds(t, root)

	var checked int
	for _, b := range builds {
		flags := stampFlagsOf(b)
		if len(flags) == 0 {
			continue
		}
		dir := stampMainDir(t, root, b)
		declared := stampDeclaredVars(t, dir)

		for _, f := range flags {
			checked++

			if f.pkg != "main" {
				t.Errorf("the %q build stamps -X %s.%s, which is not the main package it builds (%s). "+
					"A stamp lands only if the package it names is linked into that binary, and the "+
					"shipped binaries share no such package: cmd/bridge is deliberately stdlib-only and "+
					"imports nothing from internal/. A -X against a package the binary does not link is "+
					"dropped by the linker without a diagnostic, so the released binary reports no "+
					"version.",
					stampBuildName(b), f.pkg, f.ident, b.Main)
				continue
			}

			if !declared[f.ident] {
				t.Errorf("the %q build stamps -X main.%s, but package main in %s declares no such "+
					"variable. The linker accepts -X for a symbol it cannot find, drops it, and exits "+
					"0, so the release builds green and ships a %s binary with no version in it: an "+
					"operator holding the artifact cannot tell the release from a nightly, and a CVE "+
					"response cannot establish which build is deployed. Declare %s as a package-level "+
					"variable there and print it, or drop the flag.",
					stampBuildName(b), f.ident, b.Main, stampBuildName(b), f.ident)
			}
		}
	}

	if checked == 0 {
		t.Fatal("no goreleaser build stamps a version through -X, so every released binary reports " +
			"its compiled-in default and this gate has stopped seeing what it guards")
	}
}

// TestEveryDeclaredStampIsSetByItsBuild is the converse, and it is the half that
// catches the gap being closed the wrong way round: source that is ready to
// report a version while the release forgets to supply one.
//
// The vocabulary of what counts as a stamp is taken from the config rather than
// hardcoded here, so renaming Version, or adding a fourth stamp, keeps the gate
// working without anyone remembering this file.
func TestEveryDeclaredStampIsSetByItsBuild(t *testing.T) {
	root := repoRoot(t)
	builds := stampBuilds(t, root)

	vocabulary := map[string]bool{}
	for _, b := range builds {
		for _, f := range stampFlagsOf(b) {
			if f.pkg == "main" {
				vocabulary[f.ident] = true
			}
		}
	}
	if len(vocabulary) == 0 {
		t.Fatal("no goreleaser build stamps a version through -X, so there is no stamp vocabulary " +
			"left to hold the other builds to and this gate has stopped seeing what it guards")
	}

	for _, b := range builds {
		set := map[string]bool{}
		for _, f := range stampFlagsOf(b) {
			set[f.ident] = true
		}

		declared := stampDeclaredVars(t, stampMainDir(t, root, b))
		missing := make([]string, 0, len(declared))
		for name := range declared {
			if vocabulary[name] && !set[name] {
				missing = append(missing, name)
			}
		}
		if len(missing) == 0 {
			continue
		}
		sort.Strings(missing)

		t.Errorf("package main in %s declares %s, which the other shipped binaries carry the release "+
			"version in, but the %q build passes no -X for %s. The variable keeps its compiled-in "+
			"default, so the released binary answers with a placeholder while the release notes say "+
			"otherwise.",
			b.Main, strings.Join(missing, ", "), stampBuildName(b), strings.Join(missing, ", "))
	}
}

// TestShippedBinariesAgreeOnWhatEachStampMeans keeps one release from producing
// binaries that disagree about their own version.
//
// The stamps are templates, and the values they can be given are not
// interchangeable: `{{ .Version }}` is the release version, `{{ .Tag }}` carries
// the tag prefix, and `{{ .FullCommit }}` is not a version at all. Two builds
// stamping the same variable from different templates put two answers to the
// same question in one archive.
func TestShippedBinariesAgreeOnWhatEachStampMeans(t *testing.T) {
	root := repoRoot(t)
	builds := stampBuilds(t, root)

	sources := map[string]map[string][]string{}
	for _, b := range builds {
		for _, f := range stampFlagsOf(b) {
			if sources[f.ident] == nil {
				sources[f.ident] = map[string][]string{}
			}
			sources[f.ident][f.value] = append(sources[f.ident][f.value], stampBuildName(b))
		}
	}

	for _, ident := range sortedStampIdents(sources) {
		values := sources[ident]
		if len(values) < 2 {
			continue
		}
		report := make([]string, 0, len(values))
		for value, ids := range values {
			sort.Strings(ids)
			report = append(report, strings.Join(ids, ", ")+" -> "+value)
		}
		sort.Strings(report)
		t.Errorf("the shipped binaries stamp %s from different values (%s), so one release produces "+
			"binaries that answer the same question differently and no single answer can be trusted.",
			ident, strings.Join(report, "; "))
	}
}

// sortedStampIdents keeps failures in a stable order so a run reads the same
// twice and diffs cleanly in CI logs.
func sortedStampIdents(sources map[string]map[string][]string) []string {
	idents := make([]string, 0, len(sources))
	for ident := range sources {
		idents = append(idents, ident)
	}
	sort.Strings(idents)
	return idents
}
