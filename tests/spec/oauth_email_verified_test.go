// Verified-email mapping gate for the OAuth providers.
//
// internal/handler/oauth.go attaches a social identity to an existing local
// account only when the provider reports a verified email and the account
// reports one too. That pair of flags is the only thing standing between a
// social login and someone else's account: once the callback binds
// (provider, provider_user_id) to the victim's user id, every later login on
// that provider mints the victim's tokens.
//
// The Facebook provider used to fill the flag with `info.Email != ""`, so
// "verified" meant "the response carried a non-empty string". Whoever could
// make the Graph API return the victim's address owned the victim's account.
// The defect was not one wrong expression. It is that a bool field with a
// truthful name accepts anything the compiler will widen into it, and the unit
// test next to it pinned the wrong answer as the expectation.
//
// So this gate asserts the property rather than the instance: every UserInfo a
// provider builds states EmailVerified explicitly, and fills it from a boolean
// the provider itself answered with, never from the shape of a string.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// oauth2PackageDir holds every Provider implementation, so discovering the
// mappings by directory keeps this gate current when a provider is added.
var oauth2PackageDir = filepath.Join("internal", "oauth2")

// minUserInfoMappings is a floor on what discovery must find. Google, GitHub,
// Facebook, the OIDC userinfo endpoint and the OIDC id_token each build one.
// A number below this means the extractor stopped matching the source, not that
// the providers stopped mapping the flag.
const minUserInfoMappings = 5

// verificationTokens name the identifiers that carry a provider's own answer to
// "has this address been verified": Google's verified_email, GitHub's
// verified+primary pair from /user/emails, the OIDC email_verified claim. A
// provider whose signal is spelled differently has to add the word here, which
// is an edit a reviewer sees rather than a silent widening.
var verificationTokens = []string{"verified", "verify", "confirmed"}

// failClosedCommentWindow is how far above the mapping a comment may sit and
// still count as its explanation, in lines.
const failClosedCommentWindow = 14

// failClosedCommentMinLen rejects a placeholder such as "// no signal" as an
// explanation. The point of the comment is the consequence, which does not fit
// in a few words.
const failClosedCommentMinLen = 120

// linkConsequence is appended to every failure because the person who reads
// this message is the one who broke the property, not the one who wrote it.
const linkConsequence = "internal/handler/oauth.go links a social identity to an " +
	"existing local account when the provider and the account both report a verified " +
	"email. A flag derived from anything other than the provider's own verification " +
	"answer hands the victim's account, and the victim's tokens on every later login, " +
	"to whoever can make that provider return the victim's address."

// userInfoMapping is one EmailVerified field inside a UserInfo literal.
type userInfoMapping struct {
	file      string
	line      int
	fn        string
	value     ast.Expr
	src       string
	explained bool // a substantial comment sits on or just above the field
}

func (m userInfoMapping) where() string {
	return fmt.Sprintf("%s:%d (%s)", m.file, m.line, m.fn)
}

// TestOAuthUserInfoDerivesEmailVerifiedFromAVerificationSignal is the gate.
func TestOAuthUserInfoDerivesEmailVerifiedFromAVerificationSignal(t *testing.T) {
	mappings, _ := collectUserInfoMappings(t)
	if len(mappings) < minUserInfoMappings {
		t.Fatalf("found %d EmailVerified mappings in %s, expected at least %d: the extractor "+
			"has stopped seeing what it guards, so this gate is passing on an empty set",
			len(mappings), oauth2PackageDir, minUserInfoMappings)
	}

	for _, m := range mappings {
		shape := &mappingShape{}
		shape.walk(m.value)

		switch {
		case len(shape.rejected) > 0:
			t.Errorf("%s sets EmailVerified to %s, which %s rather than reading a boolean the "+
				"provider sent. Presence, length and equality of a string say that an address "+
				"arrived, never that anyone proved they own it. %s",
				m.where(), m.src, strings.Join(shape.rejected, " and "), linkConsequence)

		case shape.constTrue:
			t.Errorf("%s sets EmailVerified to %s, asserting verification for every login the "+
				"provider accepts. %s", m.where(), m.src, linkConsequence)

		case shape.failClosed():
			// Constant false is the correct answer for a provider that publishes no
			// verification signal. TestFailClosedEmailVerifiedIsExplained requires it
			// to carry its reason.

		case !namesAVerificationSignal(shape.leaves):
			t.Errorf("%s sets EmailVerified from %s, and none of %v names a verification "+
				"signal (%v). Either the value is not the provider's verification answer, or "+
				"it is spelled in a way this gate cannot recognize and the vocabulary needs "+
				"the new word. %s",
				m.where(), m.src, shape.leaves, verificationTokens, linkConsequence)
		}
	}
}

// TestEveryUserInfoLiteralStatesEmailVerified rejects a provider that leaves the
// field to its zero value. Omission happens to be safe today, but it is a
// decision nobody can see in review, and the next edit to that literal makes it
// again without noticing.
func TestEveryUserInfoLiteralStatesEmailVerified(t *testing.T) {
	mappings, silent := collectUserInfoMappings(t)
	if len(mappings)+len(silent) < minUserInfoMappings {
		t.Fatalf("found %d UserInfo literals in %s, expected at least %d: the extractor has "+
			"stopped seeing what it guards", len(mappings)+len(silent), oauth2PackageDir, minUserInfoMappings)
	}
	for _, s := range silent {
		t.Errorf("%s builds a UserInfo without naming EmailVerified, so the flag is whatever "+
			"the zero value happens to be. State it, so that the account-linking decision is "+
			"visible where it is made. %s", s, linkConsequence)
	}
}

// TestFailClosedEmailVerifiedIsExplained keeps a constant false honest. A
// provider that cannot prove ownership must say so where the mapping is, or the
// next reader takes it for an oversight and restores the takeover.
func TestFailClosedEmailVerifiedIsExplained(t *testing.T) {
	mappings, _ := collectUserInfoMappings(t)
	var checked int
	for _, m := range mappings {
		shape := &mappingShape{}
		shape.walk(m.value)
		if !shape.failClosed() {
			continue
		}
		checked++
		if !m.explained {
			t.Errorf("%s sets EmailVerified to false with no comment saying why the provider "+
				"offers no verification signal and what that costs. Without the reason on the "+
				"line, restoring the presence check reads like a fix.", m.where())
		}
	}
	if checked == 0 {
		t.Log("no provider currently fails closed on EmailVerified")
	}
}

// ---------------------------------------------------------------------------
// Expression shape
// ---------------------------------------------------------------------------

// mappingShape is the result of walking the expression assigned to
// EmailVerified. Two shapes are acceptable: the constant false, or boolean
// reads joined only by !, && and ||. Go's own type checker then guarantees
// every leaf is a bool, because nothing else compiles in those positions. A
// comparison, a literal or a call means the flag is being computed out of data
// that never carried a verification answer.
type mappingShape struct {
	leaves    []string
	constTrue bool
	constant  bool
	rejected  []string
}

// failClosed reports the constant-false mapping: no verification claimed, no
// account linked by email.
func (s *mappingShape) failClosed() bool {
	return s.constant && !s.constTrue && len(s.leaves) == 0 && len(s.rejected) == 0
}

func (s *mappingShape) walk(e ast.Expr) {
	switch v := e.(type) {
	case *ast.ParenExpr:
		s.walk(v.X)
	case *ast.Ident:
		switch v.Name {
		case "true":
			s.constant, s.constTrue = true, true
		case "false":
			s.constant = true
		default:
			s.leaves = append(s.leaves, v.Name)
		}
	case *ast.SelectorExpr:
		if !isPlainRef(v.X) {
			s.rejected = append(s.rejected, "reads through a computed value")
			return
		}
		s.leaves = append(s.leaves, v.Sel.Name)
	case *ast.UnaryExpr:
		if v.Op != token.NOT {
			s.rejected = append(s.rejected, fmt.Sprintf("applies %s", v.Op))
			return
		}
		s.walk(v.X)
	case *ast.BinaryExpr:
		if v.Op != token.LAND && v.Op != token.LOR {
			s.rejected = append(s.rejected, fmt.Sprintf("compares with %s", v.Op))
			return
		}
		s.walk(v.X)
		s.walk(v.Y)
	case *ast.BasicLit:
		s.rejected = append(s.rejected, fmt.Sprintf("mentions the literal %s", v.Value))
	case *ast.CallExpr:
		s.rejected = append(s.rejected, "calls a function")
	default:
		s.rejected = append(s.rejected, fmt.Sprintf("uses %T", e))
	}
}

// isPlainRef reports whether e is a bare name or a chain of field selections,
// which is what a decoded payload field looks like.
func isPlainRef(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.Ident:
		return true
	case *ast.SelectorExpr:
		return isPlainRef(v.X)
	default:
		return false
	}
}

// namesAVerificationSignal reports whether any leaf carries a word that marks it
// as the provider's verification answer.
func namesAVerificationSignal(leaves []string) bool {
	for _, l := range leaves {
		lower := strings.ToLower(l)
		for _, tok := range verificationTokens {
			if strings.Contains(lower, tok) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

// collectUserInfoMappings parses every non-test file in the oauth2 package and
// returns each EmailVerified mapping inside a UserInfo literal, plus the
// locations of literals that name no such field.
func collectUserInfoMappings(t *testing.T) (found []userInfoMapping, silent []string) {
	t.Helper()

	dir := filepath.Join(repoRoot(t), oauth2PackageDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", oauth2PackageDir, err)
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		src := readFileString(t, path)

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok || !isUserInfoLiteral(lit) {
					return true
				}
				value := fieldValue(lit, "EmailVerified")
				if value == nil {
					silent = append(silent, fmt.Sprintf("%s:%d (%s)",
						name, fset.Position(lit.Lbrace).Line, fn.Name.Name))
					return true
				}
				line := fset.Position(value.Pos()).Line
				found = append(found, userInfoMapping{
					file:      name,
					line:      line,
					fn:        fn.Name.Name,
					value:     value,
					src:       exprText(src, fset, value),
					explained: hasExplanation(fset, file.Comments, line),
				})
				return true
			})
		}
	}
	return found, silent
}

// isUserInfoLiteral matches both UserInfo{...} and the qualified form, so the
// gate keeps working if a provider moves to its own package.
func isUserInfoLiteral(lit *ast.CompositeLit) bool {
	switch v := lit.Type.(type) {
	case *ast.Ident:
		return v.Name == "UserInfo"
	case *ast.SelectorExpr:
		return v.Sel.Name == "UserInfo"
	default:
		return false
	}
}

// fieldValue returns the expression a keyed literal assigns to field.
func fieldValue(lit *ast.CompositeLit, field string) ast.Expr {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, ok := kv.Key.(*ast.Ident); ok && key.Name == field {
			return kv.Value
		}
	}
	return nil
}

// hasExplanation reports whether a comment of substance sits on the mapping's
// line or in the lines just above it.
func hasExplanation(fset *token.FileSet, comments []*ast.CommentGroup, line int) bool {
	for _, cg := range comments {
		start := fset.Position(cg.Pos()).Line
		end := fset.Position(cg.End()).Line
		if start > line || end < line-failClosedCommentWindow {
			continue
		}
		if len(strings.TrimSpace(cg.Text())) >= failClosedCommentMinLen {
			return true
		}
	}
	return false
}

// exprText recovers the source of an expression so failures quote the code as
// written instead of a reprinted approximation of it.
func exprText(src string, fset *token.FileSet, e ast.Expr) string {
	start := fset.Position(e.Pos()).Offset
	end := fset.Position(e.End()).Offset
	if start < 0 || end > len(src) || start >= end {
		return "<unavailable>"
	}
	return src[start:end]
}
