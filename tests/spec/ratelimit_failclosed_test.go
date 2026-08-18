// Rate-limiter fail-open register.
//
// middleware.RateLimit falls back to a per-process in-memory counter when the
// shared cache is unavailable. That is a deliberate availability choice, and it
// multiplies the effective limit by the replica count: at the chart's default of
// three pods, a 10-per-minute limiter becomes 30, and up to 100 at the HPA
// maximum. FailClosed: true opts a limiter out of that and answers 503 instead.
//
// The limiters guarding credential guessing all set it, with a comment citing
// audit L4, and POST /client/token did not. That route verifies a client secret
// with Argon2, so it is exactly a guessing surface, and during a cache outage
// its budget scaled with the pod count while the pods stayed in rotation,
// because a degraded cache deliberately still reports ready.
//
// Nothing could see the omission. FailClosed is a struct field with a usable
// zero value, so a limiter that never mentions it compiles, runs, and looks
// like every other one at a glance.
//
// This gate makes the absence a decision rather than an oversight: every
// limiter either sets it or is named below with the reason it does not need to.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// failOpenByDesign lists the limiters that may fall back to per-pod counters,
// with the reason each is not a credential-guessing surface.
//
// Adding a name here is a security decision and should be argued in review. The
// question to answer is: if this limit silently multiplied by the replica count
// during a cache outage, what would an attacker gain?
var failOpenByDesign = map[string]string{
	"refreshRL":       "a refresh token is 64 random bytes, so there is nothing to guess; the limiter caps churn, and the replay detection behind it is what protects a stolen one",
	"verifyEmailRL":   "consumes a single-use token delivered to the caller's own inbox, which is not a guessable space",
	"confirmRL":       "re-entry of a password inside an already authenticated session; the credential comparison it fronts is itself limited by loginRL's key",
	"oauthExchangeRL": "exchanges a single-use random authorization code; the code is the entropy and it is spent on first use",
	"authorizeRL":     "starts a social login and carries no secret; refusing it during a cache outage would take OAuth down without protecting anything",
	"oauthCallbackRL": "finishes a social login and has nothing guessable in it: the state is HMAC-signed, the browser binding is a __Host- cookie whose hash is inside that state, and the PKCE verifier is server-side and single-use. Failing it closed would also buy nothing, because the verifier lookup behind it is itself a cache read, so an outage refuses the callback either way",
	"identityReadRL":  "behind authentication: the credential was verified before this runs, so it caps capacity rather than guessing",
	"identityWriteRL": "behind authentication, same reasoning as identityReadRL",
	"blobUploadRL":    "behind authentication; caps how much an authenticated caller may store, not how many secrets they may try",
	"blobReadRL":      "behind authentication, same reasoning as blobUploadRL",
	"svcDocWriteRL":   "behind authentication and keyed on the authenticated client id",
	"svcDocReadRL":    "behind authentication and keyed on the authenticated client id",
	"dataExportRL":    "behind authentication; it caps an expensive operation, and failing it closed would deny a subject their own data during an outage they did not cause",
}

// TestEveryCredentialLimiterFailsClosed fails when a rate limiter in server.go
// neither sets FailClosed nor is registered above as deliberately fail-open.
func TestEveryCredentialLimiterFailsClosed(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "internal", "server", "server.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing server.go: %v", err)
	}
	src := readFileString(t, path)

	var checked int
	ast.Inspect(file, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		name, ok := as.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		start := fset.Position(as.Rhs[0].Pos()).Offset
		end := fset.Position(as.Rhs[0].End()).Offset
		if start < 0 || end > len(src) || start >= end {
			return true
		}
		text := src[start:end]
		if !strings.Contains(text, "middleware.RateLimitConfig{") {
			return true
		}
		checked++

		if strings.Contains(text, "FailClosed: true") {
			return true
		}
		if _, allowed := failOpenByDesign[name.Name]; allowed {
			return true
		}
		t.Errorf("internal/server/server.go:%d builds the limiter %q without FailClosed. On a "+
			"cache outage it falls back to a per-process counter, so the limit multiplies by the "+
			"replica count while the pods stay in rotation, because a degraded cache still "+
			"reports ready. Either set FailClosed: true, or add %q to failOpenByDesign in this "+
			"test with the reason it is not a credential-guessing surface.",
			fset.Position(as.Pos()).Line, name.Name, name.Name)
		return true
	})

	if checked == 0 {
		t.Fatal("no rate limiter was found in server.go; the construction style changed and this " +
			"gate has stopped seeing what it guards")
	}
}

// TestFailOpenRegisterHasNoStaleEntries keeps the list above honest.
//
// An entry naming a limiter that no longer exists is a reason nobody has to
// justify any more, and it hides the next one: a new limiter reusing an old name
// would inherit an exemption written for something else.
func TestFailOpenRegisterHasNoStaleEntries(t *testing.T) {
	root := repoRoot(t)
	src := readFileString(t, filepath.Join(root, "internal", "server", "server.go"))

	for name := range failOpenByDesign {
		if !strings.Contains(src, name+" := middleware.RateLimit") {
			t.Errorf("failOpenByDesign names %q, which server.go no longer builds. Remove the "+
				"entry, so a future limiter reusing the name cannot inherit an exemption written "+
				"for a different route.", name)
		}
	}
}
