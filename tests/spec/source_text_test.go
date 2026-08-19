package spec_test

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// =============================================================================
// A construct that appears only in a comment satisfies a substring assertion.
//
// Most of this suite works by reading a production file and asking whether some
// construct is in it. Read raw, "is it in the file" answers yes for a sentence
// describing the construct, a commented-out draft of it, and a note explaining
// why it was removed. The gate then holds up a claim the code does not make.
//
// This is not a theoretical failure mode in this repository. A comment on
// namespace() in internal/middleware/ratelimit.go argued its fallback was safe
// because "TestRateLimitersAreNamespaced asserts it", and for weeks the only
// occurrence of that name in the tree was the sentence claiming it. The same
// shape one level down is a chart gate satisfied by the line in the template
// that explains what the template no longer does.
//
// commentFreeSource is what every read in this package that is later scanned as
// text goes through. It blanks comments rather than deleting them, so byte
// offsets and line numbers still line up with the file on disk -- one gate takes
// its offsets from a go/ast parse of the same bytes, and a delete would silently
// shift every one of them.
// =============================================================================

// commentFreeSource reads a production file and returns it with every comment
// replaced by spaces.
//
// The comment syntax is chosen by extension from a closed vocabulary: a file
// type this does not know is a Fatal rather than a guess, because guessing wrong
// in the permissive direction restores exactly the defect this exists to remove.
func commentFreeSource(t *testing.T, path string) string {
	t.Helper()
	return blankComments(t, path, readFileString(t, path))
}

// blankComments is commentFreeSource split from the read, so a caller that
// already holds the bytes does not read the file twice.
func blankComments(t *testing.T, path, src string) string {
	t.Helper()

	syntax, known := commentSyntaxFor(path)
	if !known {
		t.Fatalf("commentFreeSource does not know how %s comments, so it cannot tell a construct "+
			"from a sentence describing one. Teach it that file type rather than reading the file "+
			"raw: a raw read is satisfied by a comment, which is the defect this helper exists "+
			"for.", path)
		return ""
	}

	switch syntax {
	case syntaxGo:
		return blankGoComments(t, path, src)
	case syntaxSQL:
		return blankLineComments(t, path, src, "--", anywhere)
	case syntaxYAML:
		return blankYAMLComments(src)
	case syntaxHelmYAML:
		// Helm templates that emit YAML (configmap.yaml, deployment.yaml, …)
		// carry both comment grammars: {{/* … */}} is invisible to helm
		// template and never reaches the rendered manifest, while # is a YAML
		// comment in the emitted document. Blanking only # left a Helm
		// comment containing `VAULT_DPOP_ENABLED:` able to satisfy the chart
		// wiring gate for a switch the rendered ConfigMap never set.
		return blankYAMLComments(blankHelmTemplateComments(src))
	case syntaxHelmPartial:
		// Helm partials: {{/* ... */}} is the template comment, and a # at the
		// start of a line is a YAML comment in the fragment being emitted.
		return blankLineComments(t, path, blankHelmTemplateComments(src), "#", lineStart)
	case syntaxHelmNotes:
		// NOTES.txt is a Helm template whose plain text is printed verbatim, so
		// only the template comment is a comment; a # is a character an
		// operator reads.
		return blankHelmTemplateComments(src)
	case syntaxMarkdown:
		return blankBlockComments(src, "<!--", "-->")
	case syntaxHashAtLineStart:
		// A # only opens a comment at the start of a line in a Dockerfile, and
		// mid-line in a shell script it is far more often part of a value than
		// a comment, so both are handled at line start only.
		return blankLineComments(t, path, src, "#", lineStart)
	}
	return ""
}

// The comment syntaxes this helper knows. A closed vocabulary, because the
// alternative to refusing an unknown file type is guessing, and a wrong guess in
// the permissive direction is the raw read it replaced.
const (
	syntaxGo              = "go"
	syntaxSQL             = "sql"
	syntaxYAML            = "yaml"
	syntaxHelmYAML        = "helm-yaml"
	syntaxHelmPartial     = "helm-partial"
	syntaxHelmNotes       = "helm-notes"
	syntaxMarkdown        = "markdown"
	syntaxHashAtLineStart = "hash-at-line-start"
)

// commentSyntaxFor picks the syntax by file type, and reports whether it knows
// one at all. Split out of blankComments so the refusal is assertable without
// having to observe a t.Fatal.
func commentSyntaxFor(path string) (string, bool) {
	base, ext := filepath.Base(path), filepath.Ext(path)
	slash := filepath.ToSlash(path)
	switch {
	case ext == ".go":
		return syntaxGo, true
	case ext == ".sql":
		return syntaxSQL, true
	case (ext == ".yaml" || ext == ".yml") && strings.Contains(slash, "/templates/"):
		// Under charts/*/templates a .yaml file is a Helm template that emits
		// YAML, not a plain YAML document. See syntaxHelmYAML.
		return syntaxHelmYAML, true
	case ext == ".yaml", ext == ".yml":
		return syntaxYAML, true
	case ext == ".tpl":
		return syntaxHelmPartial, true
	case ext == ".txt":
		return syntaxHelmNotes, true
	case ext == ".md":
		return syntaxMarkdown, true
	case ext == ".sh", base == "Dockerfile", strings.HasPrefix(base, "Dockerfile."):
		return syntaxHashAtLineStart, true
	}
	return "", false
}

// commentPlacement says where an opener starts a comment.
type commentPlacement int

const (
	// lineStart: only when it is the first non-space token on the line.
	lineStart commentPlacement = iota
	// anywhere: at any column.
	anywhere
)

// blankLineComments blanks from opener to end of line, preserving length.
func blankLineComments(t *testing.T, path, src, opener string, where commentPlacement) string {
	t.Helper()

	if strings.HasSuffix(path, ".sql") && strings.Contains(src, "/*") {
		// The same limit tests/spec/retention_guard_test.go states: a block
		// comment is not handled, and a gate that silently mis-parses is worse
		// than one whose limit is asserted.
		t.Fatalf("%s contains a /* block comment, which this blanker does not handle, so "+
			"commented-out SQL would be read as live. Extend it.", path)
	}

	out := []byte(src)
	for _, line := range lineSpans(src) {
		text := src[line.start:line.end]
		idx := strings.Index(text, opener)
		if idx < 0 {
			continue
		}
		if where == lineStart && strings.TrimSpace(text[:idx]) != "" {
			continue
		}
		blank(out, line.start+idx, line.end)
	}
	return string(out)
}

// blankBlockComments blanks every opener..closer region, preserving length.
// An unterminated opener blanks to end of file, which is what the parser of
// that format would do with it.
func blankBlockComments(src, opener, closer string) string {
	out := []byte(src)
	for i := 0; ; {
		start := strings.Index(src[i:], opener)
		if start < 0 {
			break
		}
		start += i
		end := strings.Index(src[start+len(opener):], closer)
		if end < 0 {
			blank(out, start, len(src))
			break
		}
		end = start + len(opener) + end + len(closer)
		blank(out, start, end)
		i = end
	}
	return string(out)
}

// blankHelmTemplateComments blanks every Helm `{{/* … */}}` comment,
// including the whitespace-control forms (`{{- /* … */ -}}`, `{{ /* … */}}`,
// `{{-/* … */}}`). A literal search for `{{/*` alone left `{{- /* ENV: */}}`
// readable to every chart wiring gate that goes through commentFreeSource.
func blankHelmTemplateComments(src string) string {
	out := []byte(src)
	for i := 0; i < len(src); {
		start, body, ok := findHelmCommentOpen(src, i)
		if !ok {
			break
		}
		closeAt := strings.Index(src[body:], "*/")
		if closeAt < 0 {
			blank(out, start, len(src))
			break
		}
		end := body + closeAt + len("*/")
		// Optional whitespace-control dash and spaces before the closing }}.
		for end < len(src) && (src[end] == ' ' || src[end] == '\t') {
			end++
		}
		if end < len(src) && src[end] == '-' {
			end++
		}
		for end < len(src) && (src[end] == ' ' || src[end] == '\t') {
			end++
		}
		if end+1 < len(src) && src[end] == '}' && src[end+1] == '}' {
			end += 2
		}
		blank(out, start, end)
		i = end
	}
	return string(out)
}

// findHelmCommentOpen locates the next Helm comment opener at or after i and
// returns the index of the opening `{{`, the index just past `/*`, and whether
// one was found.
func findHelmCommentOpen(src string, i int) (start, body int, ok bool) {
	for i < len(src) {
		j := strings.Index(src[i:], "{{")
		if j < 0 {
			return 0, 0, false
		}
		start = i + j
		p := start + 2
		if p < len(src) && src[p] == '-' {
			p++
		}
		for p < len(src) && (src[p] == ' ' || src[p] == '\t') {
			p++
		}
		if p+1 < len(src) && src[p] == '/' && src[p+1] == '*' {
			return start, p + 2, true
		}
		i = start + 2
	}
	return 0, 0, false
}

// blankYAMLComments applies YAML's actual comment rule: a # opens a comment
// when it is outside a quoted scalar and is either the first non-space on the
// line or preceded by whitespace.
//
// The rule matters rather than being pedantry. `key: "a#b"` is a value, and
// blanking from that # would delete the very text a gate is asserting on --
// turning a comment-stripping fix into a new false negative.
func blankYAMLComments(src string) string {
	out := []byte(src)
	for _, line := range lineSpans(src) {
		text := src[line.start:line.end]
		var single, double bool
		for i := 0; i < len(text); i++ {
			switch text[i] {
			case '\'':
				if !double {
					single = !single
				}
			case '"':
				if !single {
					double = !double
				}
			case '#':
				if single || double {
					continue
				}
				if i > 0 && text[i-1] != ' ' && text[i-1] != '\t' {
					continue
				}
				blank(out, line.start+i, line.end)
				i = len(text)
			}
		}
	}
	return string(out)
}

// blankGoComments blanks every comment in a Go file, taken from the parser
// rather than from a scan for "//", so a // inside a string literal survives.
func blankGoComments(t *testing.T, path, src string) string {
	t.Helper()

	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s to find its comments: %v", path, err)
	}
	out := []byte(src)
	for _, group := range parsed.Comments {
		for _, c := range group.List {
			blank(out, fset.Position(c.Pos()).Offset, fset.Position(c.End()).Offset)
		}
	}
	return string(out)
}

type span struct{ start, end int }

// lineSpans returns the byte range of every line, excluding the newline, so a
// blanker never eats the line structure a caller may be splitting on.
func lineSpans(src string) []span {
	var out []span
	start := 0
	for i := 0; i < len(src); i++ {
		if src[i] == '\n' {
			out = append(out, span{start, i})
			start = i + 1
		}
	}
	if start <= len(src) {
		out = append(out, span{start, len(src)})
	}
	return out
}

// blank overwrites a byte range with spaces, leaving newlines in place so line
// numbers and offsets are unchanged.
func blank(out []byte, start, end int) {
	if start < 0 {
		start = 0
	}
	if end > len(out) {
		end = len(out)
	}
	for i := start; i < end; i++ {
		if out[i] != '\n' {
			out[i] = ' '
		}
	}
}

// containsIdentifier reports whether src contains needle bounded by non-word
// characters on both sides.
//
// A bare strings.Contains for "VAULT_METRICS_ADDR" is satisfied by
// "X_VAULT_METRICS_ADDR", and one for "loginLimiter := middleware.RateLimit" by
// "adminLoginLimiter := middleware.RateLimit". Both are the same false negative:
// the gate stays green while the thing it names is gone and something with a
// longer name stands in its place. Anchoring is what makes the assertion about
// the value rather than about a prefix of some other value.
func containsIdentifier(src, needle string) bool {
	return regexp.MustCompile(`(^|[^0-9A-Za-z_])` + regexp.QuoteMeta(needle) + `($|[^0-9A-Za-z_])`).MatchString(src)
}

// A substring match must not be satisfied by a longer name that contains it.
func TestASubstringMatchIsAnchoredToTheWholeValue(t *testing.T) {
	for _, tc := range []struct {
		name   string
		src    string
		needle string
		want   bool
	}{
		{"exact yaml value", "        - name: VAULT_HMAC_SECRET_FILE\n", "name: VAULT_HMAC_SECRET_FILE", true},
		{"longer yaml value", "        - name: VAULT_HMAC_SECRET_FILE_OLD\n", "name: VAULT_HMAC_SECRET_FILE", false},
		{"exact configmap key", "  VAULT_METRICS_ADDR: \"0.0.0.0:9090\"\n", "VAULT_METRICS_ADDR:", true},
		{"prefixed configmap key", "  X_VAULT_METRICS_ADDR: \"x\"\n", "VAULT_METRICS_ADDR:", false},
		{"exact limiter", "\tloginLimiter := middleware.RateLimit(cfg)\n", "loginLimiter := middleware.RateLimit", true},
		{"limiter with a longer name", "\tadminLoginLimiter := middleware.RateLimit(cfg)\n", "loginLimiter := middleware.RateLimit", false},
		{"exact accessor", "\tvaultcrypto.Argon2Time()\n", "vaultcrypto.Argon2Time", true},
		{"accessor with a longer name", "\tvaultcrypto.Argon2TimeCost()\n", "vaultcrypto.Argon2Time", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsIdentifier(tc.src, tc.needle); got != tc.want {
				t.Errorf("containsIdentifier(%q, %q) = %v, want %v", tc.src, tc.needle, got, tc.want)
			}
		})
	}
}

// Every case below is a comment that would satisfy a raw substring assertion in
// this suite, and the length check is what lets one gate keep taking go/ast byte
// offsets from the same bytes it scans.
func TestCommentsCannotSatisfyASubstringAssertion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		path    string
		src     string
		gone    []string
		kept    []string
		sameLen bool
	}{
		{
			name: "go line and block comments",
			path: "server.go",
			src: "package p\n// authLimiter := middleware.RateLimit(x)\n/* fooLimiter := middleware.RateLimit(y) */\n" +
				"var live = middleware.RateLimit(z)\nvar s = \"// not a comment\"\n",
			gone:    []string{"authLimiter", "fooLimiter"},
			kept:    []string{"var live = middleware.RateLimit(z)", "// not a comment"},
			sameLen: true,
		},
		{
			name:    "yaml full-line and trailing comments",
			path:    "values.yaml",
			src:     "data:\n  # name: VAULT_HMAC_SECRET_FILE\n  KEY: value # name: VAULT_KMS_KEY\n  URL: \"http://x/#frag\"\n",
			gone:    []string{"VAULT_HMAC_SECRET_FILE", "VAULT_KMS_KEY"},
			kept:    []string{"KEY: value", "http://x/#frag"},
			sameLen: true,
		},
		{
			name: "helm yaml template comments including whitespace-control",
			path: "charts/vault/templates/configmap.yaml",
			src: "data:\n  {{- /* VAULT_DPOP_ENABLED: \"false\" */}}\n" +
				"  {{/* VAULT_MINT_ENABLED: \"true\" */ -}}\n" +
				"  # VAULT_HMAC_SECRET_FILE: x\n" +
				"  VAULT_APP_NAME: \"x\"\n",
			gone:    []string{"VAULT_DPOP_ENABLED", "VAULT_MINT_ENABLED", "VAULT_HMAC_SECRET_FILE"},
			kept:    []string{"VAULT_APP_NAME"},
			sameLen: true,
		},
		{
			name:    "yaml hash inside a single-quoted scalar",
			path:    "values.yaml",
			src:     "tag: 'v1#2'\nother: real # tag: 'v9#9'\n",
			gone:    []string{"v9#9"},
			kept:    []string{"v1#2"},
			sameLen: true,
		},
		{
			name:    "dockerfile comments only at line start",
			path:    "Dockerfile",
			src:     "# USER 101\nFROM nginx-unprivileged:1\nRUN echo 'a # b'\n",
			gone:    []string{"USER 101"},
			kept:    []string{"nginx-unprivileged", "a # b"},
			sameLen: true,
		},
		{
			name:    "sql line comments",
			path:    "018_x.sql",
			src:     "-- DELETE FROM audit.audit_log WHERE timestamp < cutoff;\nSELECT 1; -- cutoff := NOW();\nSELECT '--x';\n",
			gone:    []string{"DELETE FROM audit.audit_log", "cutoff := NOW()"},
			kept:    []string{"SELECT 1;"},
			sameLen: true,
		},
		{
			name:    "helm template comments",
			path:    "_helpers.tpl",
			src:     "{{/* dir .Values.firstBootCredential.path */}}\n{{- /* dir .Values.dashComment.path */ -}}\n{{- define \"vault.x\" -}}\n# dir .Values.other.path\n{{- end -}}\n",
			gone:    []string{"firstBootCredential.path", "dashComment.path", "other.path"},
			kept:    []string{"vault.x"},
			sameLen: true,
		},
		{
			name:    "markdown comments",
			path:    "CHANGELOG.md",
			src:     "<!-- see UPGRADING.md -->\nSee docs/OTHER.md\n",
			gone:    []string{"UPGRADING.md"},
			kept:    []string{"docs/OTHER.md"},
			sameLen: true,
		},
		{
			name:    "helm NOTES keep their hashes",
			path:    "NOTES.txt",
			src:     "{{/* UPGRADING.md */}}\n# 1. read docs/OTHER.md\n",
			gone:    []string{"UPGRADING.md"},
			kept:    []string{"# 1. read docs/OTHER.md"},
			sameLen: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := blankComments(t, tc.path, tc.src)
			if tc.sameLen && len(got) != len(tc.src) {
				t.Errorf("blanking changed the length from %d to %d, so every byte offset a "+
					"caller took from a parse of the same source is now wrong", len(tc.src), len(got))
			}
			if strings.Count(got, "\n") != strings.Count(tc.src, "\n") {
				t.Errorf("blanking changed the line count from %d to %d", strings.Count(tc.src, "\n"), strings.Count(got, "\n"))
			}
			for _, needle := range tc.gone {
				if strings.Contains(got, needle) {
					t.Errorf("%q survived in a comment, so a substring assertion for it would "+
						"still be satisfied by the comment:\n%s", needle, got)
				}
			}
			for _, needle := range tc.kept {
				if !strings.Contains(got, needle) {
					t.Errorf("%q was blanked out of live source, which would make every "+
						"assertion on it a false failure:\n%s", needle, got)
				}
			}
		})
	}
}

// A file type the blanker does not know must be refused rather than read raw,
// and every type this suite actually reads must be known.
func TestAnUnknownFileTypeIsRefusedRatherThanReadRaw(t *testing.T) {
	for _, path := range []string{"scripts/deploy.rb", "web/index.html", "package.json", "Makefile"} {
		if syntax, known := commentSyntaxFor(path); known {
			t.Errorf("commentSyntaxFor(%q) claims %q. Reading a file type raw is what lets a "+
				"comment satisfy an assertion, so an unknown type has to refuse.", path, syntax)
		}
	}
	for path, want := range map[string]string{
		"internal/server/server.go":             syntaxGo,
		"migrations/018_x.sql":                  syntaxSQL,
		"charts/vault/templates/configmap.yaml": syntaxHelmYAML,
		"charts/vault/values.yml":               syntaxYAML,
		"charts/vault/templates/_helpers.tpl":   syntaxHelmPartial,
		"charts/vault/templates/NOTES.txt":      syntaxHelmNotes,
		"CHANGELOG.md":                          syntaxMarkdown,
		"web/Dockerfile":                        syntaxHashAtLineStart,
		"scripts/version-bump.sh":               syntaxHashAtLineStart,
	} {
		syntax, known := commentSyntaxFor(path)
		if !known || syntax != want {
			t.Errorf("commentSyntaxFor(%q) = %q, %v; want %q, true", path, syntax, known, want)
		}
	}
}
