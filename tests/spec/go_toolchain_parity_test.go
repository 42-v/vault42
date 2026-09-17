package spec_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// One Go version builds this project, and three files have to agree on which.
//
// They did not. go.mod carried `toolchain go1.26.6`, the three Dockerfiles built
// on `golang:1.27.0-alpine`, and the README badge published 1.26.6 -- so the two
// artifacts a release produces were compiled by different compilers, and the
// number on the front page described only one of them.
//
// That is not cosmetic here, because of what the Dockerfile itself is trying to
// do. Its build stage carries -trimpath and -buildvcs=false with a comment
// explaining that the published image and the published archive "hold the same
// program, and until now they did not hold the same binary". Two binaries from
// two compilers are not the same binary, so the work that comment describes was
// being undone a few lines above it by the FROM line.
//
// Nothing could see it. The badge gate counts files and lines and never reads a
// version string; the route and register gates do not look at Dockerfiles; and
// the drift is invisible at build time because Go's toolchain rule is a floor,
// not a pin. A `toolchain` line OLDER than the local toolchain is ignored
// entirely -- measured, not assumed: a module pinning go1.24.5 built with the
// local go1.26.5. So the image's newer Go silently won and go.mod's line
// described nothing.
//
// The direction matters. go.mod NEWER than the image is the dangerous one: the
// builder would fetch a toolchain over the network mid-build, which a pinned
// base image and a digest exist to prevent. That is asserted separately below,
// with its own message.

var (
	// `FROM --platform=$BUILDPLATFORM golang:1.27.0-alpine@sha256:...`
	golangBase = regexp.MustCompile(`(?m)^FROM\s+.*golang:(\d+\.\d+(?:\.\d+)?)-`)
	// `toolchain go1.27.0`
	goModToolchain = regexp.MustCompile(`(?m)^toolchain\s+go(\d+\.\d+(?:\.\d+)?)\s*$`)
	// The shields.io Go badge in the README block.
	readmeGoBadge = regexp.MustCompile(`badge/Go-(\d+\.\d+(?:\.\d+)?)-`)
)

// declaredToolchain is the version go.mod names, which is what
// actions/setup-go resolves through `go-version-file: go.mod` for the goreleaser
// build, and what scripts/readme-gen.sh publishes as the Go badge.
func declaredToolchain(t *testing.T, root string) string {
	t.Helper()
	m := goModToolchain.FindStringSubmatch(readFileString(t, filepath.Join(root, "go.mod")))
	if m == nil {
		t.Fatal("go.mod carries no `toolchain` line. readme-gen.sh publishes the Go badge from " +
			"it and release.yml resolves setup-go from it, so removing it does not simplify " +
			"anything -- it just moves the version somewhere nothing checks.")
	}
	return m[1]
}

// goBuilderImages maps each Dockerfile that compiles Go to the base it pins.
func goBuilderImages(t *testing.T, root string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read repo root: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "Dockerfile") {
			continue
		}
		if m := golangBase.FindStringSubmatch(readFileString(t, filepath.Join(root, e.Name()))); m != nil {
			out[e.Name()] = m[1]
		}
	}
	if len(out) == 0 {
		t.Fatal("no Dockerfile in the repository root builds on a golang image. If the build " +
			"moved, move this gate with it: the defect it holds is two release artifacts " +
			"compiled by two different Go versions with nothing comparing them.")
	}
	return out
}

func TestEveryGoBuilderPinsTheToolchainGoModDeclares(t *testing.T) {
	root := repoRoot(t)
	declared := declaredToolchain(t, root)
	images := goBuilderImages(t, root)

	names := make([]string, 0, len(images))
	for name := range images {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if images[name] != declared {
			t.Errorf("%s builds on golang:%s and go.mod declares toolchain go%s.\n"+
				"The image binary and the goreleaser archive binary are then compiled by "+
				"different compilers, which is exactly what the -trimpath and -buildvcs "+
				"comment in that build stage exists to prevent. Move both, or move neither.",
				name, images[name], declared)
		}
	}
}

// The two directions of the same drift are not equally bad, and the failure
// message has to say which one happened.
func TestNoGoBuilderHasToFetchAToolchainMidBuild(t *testing.T) {
	root := repoRoot(t)
	declared := declaredToolchain(t, root)

	for name, image := range goBuilderImages(t, root) {
		if compareGoVersions(declared, image) > 0 {
			t.Errorf("%s pins golang:%s but go.mod requires go%s, which is newer.\n"+
				"Go would download the required toolchain during the image build. The base "+
				"image is pinned by digest precisely so the build does not reach the network "+
				"for its compiler, and this defeats that.",
				name, image, declared)
		}
	}
}

// The published number has to be one of the two it could be, rather than a third
// thing nobody builds with. The badge is generated from go.mod, so this catches
// a README regenerated from a tree that has since moved.
func TestTheGoBadgePublishesTheToolchainThatBuilds(t *testing.T) {
	root := repoRoot(t)
	declared := declaredToolchain(t, root)

	m := readmeGoBadge.FindStringSubmatch(readFileString(t, filepath.Join(root, "README.md")))
	if m == nil {
		t.Fatal("README.md has no Go badge; scripts/readme-gen.sh writes one into the " +
			"<!-- badges --> block")
	}
	if m[1] != declared {
		t.Errorf("the README Go badge says %s and go.mod declares toolchain go%s. "+
			"Re-run scripts/readme-gen.sh. The badge's own comment in that script says it "+
			"reports what ships, so a stale one is a claim about the release rather than a "+
			"cosmetic slip.", m[1], declared)
	}
}

// compareGoVersions orders dotted versions numerically, so 1.27.0 sorts above
// 1.26.6 rather than below it the way a string comparison would. A component
// that does not parse counts as zero, which is only reachable if one of the
// regexes above matched something that is not a version.
func compareGoVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		av, bv := 0, 0
		if i < len(as) {
			av, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			bv, _ = strconv.Atoi(bs[i])
		}
		if av != bv {
			if av > bv {
				return 1
			}
			return -1
		}
	}
	return 0
}
