package compliance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// =============================================================================
// OWASP Application Security Verification Standard (ASVS) v4.0.3
// V14.2: Dependency
// https://owasp.org/www-project-application-security-verification-standard/
// =============================================================================

// --- V14.2.1: Components are up to date ---

var semverPrefix = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)`)

func semverBelow(version, floor string) bool {
	v, f := semverPrefix.FindStringSubmatch(version), semverPrefix.FindStringSubmatch(floor)
	if v == nil || f == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		a, _ := strconv.Atoi(v[i])
		b, _ := strconv.Atoi(f[i])
		if a != b {
			return a < b
		}
	}
	return false
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "pnpm-workspace.yaml")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("V14.2.1: repository root not found")
		}
		dir = parent
	}
}

func TestASVS_V14_2_1_PnpmOverrideFloors(t *testing.T) {
	root := repoRoot(t)

	raw, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		t.Fatalf("read package.json: %v", err)
	}
	var manifest struct {
		Pnpm struct {
			Overrides map[string]string `json:"overrides"`
		} `json:"pnpm"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("parse package.json: %v", err)
	}
	if len(manifest.Pnpm.Overrides) == 0 {
		t.Fatal("V14.2.1: pnpm.overrides is empty; the transitive security floors have been dropped")
	}

	lock, err := os.ReadFile(filepath.Join(root, "pnpm-lock.yaml"))
	if err != nil {
		t.Fatalf("read pnpm-lock.yaml: %v", err)
	}

	// A parent-scoped override (`eslint>ajv`) deliberately holds one consumer
	// below the root floor, so that floor does not apply to every copy.
	narrowed := map[string]bool{}
	for key := range manifest.Pnpm.Overrides {
		if i := strings.LastIndex(key, ">"); i >= 0 {
			narrowed[key[i+1:]] = true
		}
	}

	floorSpec := regexp.MustCompile(`>=\s*(\d+\.\d+\.\d+)`)
	resolved := 0
	for name, spec := range manifest.Pnpm.Overrides {
		if strings.Contains(name, ">") || narrowed[name] {
			continue
		}
		floor := floorSpec.FindStringSubmatch(spec)
		if floor == nil {
			continue
		}
		entry := regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(name) + `@(\S+?):`)
		for _, match := range entry.FindAllStringSubmatch(string(lock), -1) {
			resolved++
			if semverBelow(match[1], floor[1]) {
				t.Errorf("V14.2.1: %s@%s in pnpm-lock.yaml is below the %s floor declared in pnpm.overrides", name, match[1], floor[1])
			}
		}
	}
	if resolved == 0 {
		t.Fatal("V14.2.1: no overridden package resolved out of pnpm-lock.yaml; the lockfile parse is broken")
	}
}
