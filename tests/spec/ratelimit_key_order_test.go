// Middleware-ordering gate for client-keyed rate limiters.
//
// handler.ClientRateLimitKey reads the client id out of the request's JWT
// claims and falls back to the IP bucket when there are none. Claims are placed
// on the context by the Auth middleware, so a limiter configured with that key
// but mounted OUTSIDE Auth reads a nil context on every request and silently
// uses the fallback.
//
// All three client-keyed limiters were mounted that way. The configuration read
// correctly, the comment above them explained why an IP bucket would be wrong,
// and per-client limiting never happened once. Nothing failed, because a
// fallback is not an error, and the unit test for the key function exercises it
// in isolation where a context is easy to supply.
//
// This checks the property that actually matters, which is an ordering
// relationship between two wrappers rather than anything either one does alone.
// It parses the real route registrations with go/ast, the way
// route_drift_test.go does, and reads the nesting rather than trusting a
// comment.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// clientKeyedFunc is the key function whose contract depends on claims already
// being on the context.
const clientKeyedFunc = "ClientRateLimitKey"

// authIdent is the middleware that puts them there.
const authIdent = "authMw"

// TestClientKeyedLimitersSitInsideAuth fails when a limiter configured with
// ClientRateLimitKey is applied outside the Auth middleware.
//
// The check works on the source text of each mux.Handle call rather than on a
// resolved type graph, because the thing being asserted is lexical nesting: the
// limiter's identifier must appear inside authMw's argument list, not around it.
func TestClientKeyedLimitersSitInsideAuth(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "internal", "server", "server.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing server.go: %v", err)
	}

	// Collect the limiter variables built with the client-keyed function. Each is
	// `name := middleware.RateLimit(..., KeyFunc: handler.ClientRateLimitKey, ...)`.
	// Blanked rather than stripped: the offsets below come from the go/ast
	// parse of the same file, so the two views have to stay byte-aligned.
	src := commentFreeSource(t, path)
	clientKeyed := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		ident, ok := as.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		start := fset.Position(as.Rhs[0].Pos()).Offset
		end := fset.Position(as.Rhs[0].End()).Offset
		if start < 0 || end > len(src) || start >= end {
			return true
		}
		if strings.Contains(src[start:end], clientKeyedFunc) {
			clientKeyed[ident.Name] = true
		}
		return true
	})

	if len(clientKeyed) == 0 {
		t.Fatalf("found no limiter built with %s; it was renamed or removed and this "+
			"gate has stopped seeing what it guards", clientKeyedFunc)
	}

	// Every expression that wraps a handler: the mux.Handle calls, plus the local
	// helper closures the document routes are built from.
	var checked int
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		start := fset.Position(call.Pos()).Offset
		end := fset.Position(call.End()).Offset
		if start < 0 || end > len(src) || start >= end {
			return true
		}
		text := src[start:end]

		for name := range clientKeyed {
			li := strings.Index(text, name+"(")
			ai := strings.Index(text, authIdent+"(")
			if li < 0 || ai < 0 {
				continue
			}
			checked++
			// authMw must open first, so that the limiter is nested within it.
			if li < ai {
				t.Errorf("%s:%d applies the client-keyed limiter %q outside %s. "+
					"%s reads the client id from the request's claims, which %s "+
					"installs, so this silently falls back to the IP bucket the "+
					"limiter exists to avoid.",
					"internal/server/server.go", fset.Position(call.Pos()).Line,
					name, authIdent, clientKeyedFunc, authIdent)
			}
		}
		return true
	})

	if checked == 0 {
		t.Fatal("no route was found applying a client-keyed limiter alongside authMw; " +
			"the mounting style changed and this gate needs updating")
	}
}

// failClosedCredentialReleaseLimiters are IP-keyed, FailClosed limiters on
// routes that release credentials (KMS unwrap today). Unlike the client-keyed
// set above, mounting them outside authMw does not break their key function —
// it breaks their budget: an unauthenticated flood from a shared egress IP
// burns the same fail-closed bucket legitimate clients need, and the next
// authenticated unwrap is refused with 429. mintRL is client-keyed and already
// covered by TestClientKeyedLimitersSitInsideAuth.
var failClosedCredentialReleaseLimiters = map[string]bool{
	"kmsUnwrapRL": true,
}

// TestFailClosedCredentialReleaseLimitersSitInsideAuth fails when an
// IP-keyed fail-closed unwrap/mint-class limiter wraps authMw rather than
// sitting inside it. The route register still names the limiter either way;
// only the nesting decides whether anonymous traffic can exhaust it.
func TestFailClosedCredentialReleaseLimitersSitInsideAuth(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "internal", "server", "server.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing server.go: %v", err)
	}
	src := commentFreeSource(t, path)

	var checked int
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		start := fset.Position(call.Pos()).Offset
		end := fset.Position(call.End()).Offset
		if start < 0 || end > len(src) || start >= end {
			return true
		}
		text := src[start:end]

		for name := range failClosedCredentialReleaseLimiters {
			li := strings.Index(text, name+"(")
			ai := strings.Index(text, authIdent+"(")
			if li < 0 || ai < 0 {
				continue
			}
			checked++
			if li < ai {
				t.Errorf("%s:%d applies the fail-closed credential-release limiter %q outside %s. "+
					"Unauthenticated requests from a shared egress IP then burn the unwrap budget "+
					"before any legitimate client reaches the key-release path.",
					"internal/server/server.go", fset.Position(call.Pos()).Line, name, authIdent)
			}
		}
		return true
	})

	if checked == 0 {
		t.Fatal("no route was found applying a fail-closed credential-release limiter alongside " +
			"authMw; the mounting style changed and this gate needs updating")
	}
}

// readFileString reads a source file so the nesting check above can work on byte
// offsets taken from the same parse.
func readFileString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- fixed path inside the repo
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
