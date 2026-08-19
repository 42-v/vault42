package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// LOG_LEVEL was parsed into Config.LogLevel, given a per-profile default and
// documented as "log verbosity" while no vault42 binary read it. An operator who
// set LOG_LEVEL=error to cut log exposure got byte-for-byte the same output as
// LOG_LEVEL=debug, with no error and no hint. These three gates fail if that
// knob returns dead, if the docs start promising it again, or if setting it goes
// quiet again.
//
// The gates deliberately allow a future real implementation: each one passes the
// moment something outside internal/config actually reads the field.

// logLevelRepoRoot resolves the repository root from this package's directory,
// which the source and docs scans below need.
func logLevelRepoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "go.mod")); statErr != nil {
		t.Fatalf("no go.mod at presumed repo root %s: %v", root, statErr)
	}
	return root
}

// logLevelFieldDeclared reports whether Config still carries a LogLevel field.
func logLevelFieldDeclared() bool {
	_, ok := reflect.TypeOf(Config{}).FieldByName("LogLevel")
	return ok
}

// logLevelSkipDir excludes vendored trees and the two Go packages that must not
// count as readers: internal/config declares the field, so its own references
// are self-reference rather than consumption, and cmd/bridge has a separate
// Config type whose LogLevel comes from BRIDGE_LOG_LEVEL and is genuinely wired.
func logLevelSkipDir(rel string) bool {
	switch rel {
	case "node_modules", "web", "site", "packages", "coverage", "tmp", ".git":
		return true
	}
	return rel == filepath.Join("internal", "config") || rel == filepath.Join("cmd", "bridge")
}

// logLevelReaders lists non-test Go files that read a Config.LogLevel field.
func logLevelReaders(t *testing.T, root string) []string {
	t.Helper()
	var readers []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if d.IsDir() {
			if logLevelSkipDir(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, readErr := os.ReadFile(path) // #nosec G304 -- path comes from walking this repo, not from input
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(body), ".LogLevel") {
			readers = append(readers, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	return readers
}

func TestLogLevelIsNeverParsedAndIgnored(t *testing.T) {
	root := logLevelRepoRoot(t)
	if !logLevelFieldDeclared() {
		return
	}
	readers := logLevelReaders(t, root)
	if len(readers) == 0 {
		t.Errorf("Config declares a LogLevel field that no file outside internal/config reads.\n" +
			"A parsed-and-ignored setting makes LOG_LEVEL=error and LOG_LEVEL=debug produce identical output.\n" +
			"Either wire the field into logging the server performs, or drop the field and its docs.")
	}
}

// logLevelWordAt reports whether s contains "LogLevel" as a whole word. The
// word check is what keeps systemd's unrelated LogLevelMax= directive, which
// docs/localhost-profile.md sets on purpose, out of the results.
func logLevelWordAt(s string) bool {
	const word = "LogLevel"
	for i := 0; ; {
		j := strings.Index(s[i:], word)
		if j < 0 {
			return false
		}
		end := i + j + len(word)
		if end == len(s) || !isWordByte(s[end]) {
			return true
		}
		i = end
	}
}

func isWordByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

// Fence markers around prose that documents LOG_LEVEL as removed rather than
// offering it as a setting. Without them this gate would forbid explaining the
// removal, which would push the next reader into rediscovering the whole defect.
// Wrapping a genuine setting in the fence is possible but has to be done on
// purpose and shows up in review, which is the point.
const (
	logLevelFenceOpen  = "<!-- loglevel-gate:begin -->"
	logLevelFenceClose = "<!-- loglevel-gate:end -->"
)

// logLevelDocMentions returns "file:line: text" for every docs line that
// presents LOG_LEVEL or Config.LogLevel as a vault42 setting. BRIDGE_LOG_LEVEL
// is stripped first because the bridge's own knob is wired and documented
// correctly.
func logLevelDocMentions(t *testing.T, root string) []string {
	t.Helper()
	docs := filepath.Join(root, "docs")
	var found []string
	err := filepath.WalkDir(docs, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		body, readErr := os.ReadFile(path) // #nosec G304 -- path comes from walking docs/, not from input
		if readErr != nil {
			return readErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		fenced := false
		for i, line := range strings.Split(string(body), "\n") {
			switch {
			case strings.Contains(line, logLevelFenceOpen):
				fenced = true
				continue
			case strings.Contains(line, logLevelFenceClose):
				fenced = false
				continue
			case fenced:
				continue
			}
			scanned := strings.ReplaceAll(line, "BRIDGE_LOG_LEVEL", "")
			if strings.Contains(scanned, "LOG_LEVEL") || logLevelWordAt(scanned) {
				found = append(found, rel+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk docs: %v", err)
	}
	return found
}

func TestDocsDoNotPromiseLogLevel(t *testing.T) {
	root := logLevelRepoRoot(t)
	if logLevelFieldDeclared() && len(logLevelReaders(t, root)) > 0 {
		t.Skip("LogLevel is wired into the server, so documenting it is correct")
	}
	if mentions := logLevelDocMentions(t, root); len(mentions) > 0 {
		t.Errorf("docs present LOG_LEVEL as a vault42 setting, but the server has no log-verbosity control:\n  %s",
			strings.Join(mentions, "\n  "))
	}
}

func TestSettingLogLevelIsNotSilent(t *testing.T) {
	root := logLevelRepoRoot(t)
	if logLevelFieldDeclared() && len(logLevelReaders(t, root)) > 0 {
		t.Skip("LogLevel is wired into the server, so it is honored rather than announced")
	}

	t.Setenv("VAULT_PROFILE", "production")
	t.Setenv("LOG_LEVEL", "error")
	out := cliconfigCaptureLog(t, func() {
		if _, err := Load(); err != nil {
			t.Fatalf("Load: %v", err)
		}
	})
	if !strings.Contains(out, "LOG_LEVEL") {
		t.Errorf("Load() ignored LOG_LEVEL=error without saying so; startup log was:\n%s", out)
	}

	t.Setenv("LOG_LEVEL", "")
	quiet := cliconfigCaptureLog(t, func() {
		if _, err := Load(); err != nil {
			t.Fatalf("Load: %v", err)
		}
	})
	if strings.Contains(quiet, "LOG_LEVEL") {
		t.Errorf("Load() warned about LOG_LEVEL when it was not set; startup log was:\n%s", quiet)
	}
}
