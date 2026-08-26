package spec_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The behavioral half of this gate lives in
// internal/server/dpop_issuance_test.go, which drives a malformed proof at every
// issuance route. That test can only check the routes someone remembered to list.
// This one checks the file, so a route added later cannot be forgotten: every
// registration on the vault mux must either run through a wrapper that applies
// dpopWrap, or be named below with a reason.
//
// POST /client/token was the one registration that had neither. It is also the
// only issuance path that can produce a token holding the kms:unwrap or
// mint:token scope, so the sender-constraint on both credential-release oracles
// was unreachable while the comparison in middleware.DPoP looked live.

// serverRouteSource is the vault mux. The admin gateway
// (internal/adminapi/router.go) is deliberately out of scope: it authenticates
// with mTLS client certificates and an admin session cookie rather than with the
// access tokens DPoP binds.
var serverRouteSource = filepath.Join("internal", "server", "server.go")

// dpopWrapperIdents are the identifiers that put the DPoP middleware into a
// chain: the wrapper itself, plus the four route-builder closures and the two
// service-document builders defined in the same function. Each of those closures
// is separately asserted to contain dpopWrap by
// TestTheRouteBuilderClosuresAllApplyDPoP, so this list cannot be satisfied by a
// wrapper that has quietly stopped applying it.
var dpopWrapperIdents = []string{
	"dpopWrap",
	"authed",
	"authedChallenge",
	"confirmed",
	"docRead",
	"docWrite",
}

// routeBuilderClosures are the local helpers whose whole job is to build a
// middleware chain for a family of routes. Each must apply dpopWrap.
var routeBuilderClosures = []string{"authed", "authedChallenge", "confirmed", "docRead", "docWrite"}

// dpopExemptRoutes are the registrations that legitimately run no DPoP
// middleware. Each needs a reason, because adding a route here is how the gate
// gets defeated, and a reason is the thing a reviewer can disagree with.
//
// The rule: a route is exempt only when it neither issues an access token nor
// authenticates one. A route that does either belongs in the chain.
var dpopExemptRoutes = map[string]string{
	"GET /metrics":                          "no token: the metrics listener authenticates with its own bearer secret or not at all",
	"GET /healthz":                          "unauthenticated liveness probe",
	"GET /readyz":                           "unauthenticated readiness probe",
	"GET /auth/capabilities":                "unauthenticated feature advertisement",
	"POST /auth/register":                   "creates an account; issues no token",
	"GET /auth/verify-email":                "consumes an emailed link; issues no token",
	"POST /auth/password/reset":             "sends an emailed link; issues no token",
	"POST /auth/password/reset/confirm":     "consumes an emailed link; issues no token",
	"GET /.well-known/jwks.json":            "unauthenticated public key set",
	"GET /.well-known/openid-configuration": "unauthenticated discovery document",
	"GET /auth/oauth2/authorize":            "browser redirect; issues no token",
	"GET /auth/oauth2/callback/{provider}":  "browser redirect from the provider; a binding cannot be demonstrated inside a top-level GET the user agent performs, so the pair minted here is structurally unbindable",
	"POST /auth/oauth2/exchange":            "replays the pair the callback already minted; there is nothing left to bind",
	"/":                                     "SPA catch-all; serves static assets",
}

// TestEveryVaultRouteIsBehindDPoPOrExempt is the gate.
func TestEveryVaultRouteIsBehindDPoPOrExempt(t *testing.T) {
	root := repoRoot(t)
	registrations := parseServerRegistrations(t, filepath.Join(root, serverRouteSource))
	if len(registrations) == 0 {
		t.Fatal("parsed zero registrations from internal/server/server.go: the extractor is broken, not the wiring")
	}

	patterns := make([]string, 0, len(registrations))
	for pattern := range registrations {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)

	for _, pattern := range patterns {
		reg := registrations[pattern]
		var wrapped bool
		for _, ident := range dpopWrapperIdents {
			if mentionsIdent(reg.handler, ident) {
				wrapped = true
				break
			}
		}
		if wrapped {
			if _, exempt := dpopExemptRoutes[pattern]; exempt {
				t.Errorf("%s (%s) applies DPoP but is still listed as exempt; drop the exemption "+
					"so the list keeps meaning what it says", pattern, reg.pos)
			}
			continue
		}
		if _, exempt := dpopExemptRoutes[pattern]; exempt {
			continue
		}
		t.Errorf("%s (%s) runs no DPoP middleware.\n"+
			"If it issues an access token, nothing it mints can carry cnf.jkt and the token is an "+
			"unbindable bearer credential. If it authenticates one, a sender-constrained token is "+
			"accepted there as an ordinary bearer token and the binding buys nothing, because a "+
			"stolen token is replayed at the unwrapped route instead.\n"+
			"Wrap it, or add it to dpopExemptRoutes with a reason.", pattern, reg.pos)
	}

	// The exempt list must not outlive the routes it names, or it becomes a
	// standing permission for a path someone re-adds later.
	for pattern := range dpopExemptRoutes {
		if _, ok := registrations[pattern]; !ok {
			t.Errorf("dpopExemptRoutes names %q, which internal/server/server.go no longer registers", pattern)
		}
	}
}

// TestTheRouteBuilderClosuresAllApplyDPoP closes the gate's own back door.
// Without it, deleting dpopWrap from the body of authed() would leave every
// route it builds passing the check above on the strength of the name alone.
func TestTheRouteBuilderClosuresAllApplyDPoP(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(root, serverRouteSource), nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", serverRouteSource, err)
	}

	bodies := map[string]ast.Expr{}
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		id, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		if _, ok := assign.Rhs[0].(*ast.FuncLit); !ok {
			return true
		}
		bodies[id.Name] = assign.Rhs[0]
		return true
	})

	for _, name := range routeBuilderClosures {
		body, ok := bodies[name]
		if !ok {
			t.Errorf("internal/server/server.go no longer defines a %s(...) route builder; "+
				"dpopWrapperIdents still credits routes for naming it", name)
			continue
		}
		if !mentionsIdent(body, "dpopWrap") {
			t.Errorf("%s(...) no longer applies dpopWrap, so every route it builds accepts a "+
				"sender-constrained token as an ordinary bearer token", name)
		}
	}
}

// registration is one mux.Handle/mux.HandleFunc call: the handler expression and
// where it was written.
type registration struct {
	handler ast.Expr
	pos     string
}

// parseServerRegistrations extracts every mux registration from the vault mux,
// keyed by its routing pattern.
func parseServerRegistrations(t *testing.T, path string) map[string]registration {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	out := map[string]registration{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") {
			return true
		}
		recv, ok := sel.X.(*ast.Ident)
		if !ok || recv.Name != "mux" || len(call.Args) < 2 {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		pattern, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		p := fset.Position(call.Lparen)
		out[pattern] = registration{
			handler: call.Args[1],
			pos:     fmt.Sprintf("%s:%d", serverRouteSource, p.Line),
		}
		return true
	})
	return out
}

// ---------------------------------------------------------------------------
// The documentation half
// ---------------------------------------------------------------------------
//
// The two gates above hold the wiring. Nothing held what the documents say
// about the wiring, and that is where it went wrong: POST /client/token was
// wrapped, refresh families gained a dpop_jkt binding that survives rotation,
// and four documents went on describing the state before all of it. docs/spec.md
// said the route "is not wrapped in the DPoP middleware" and that "refresh
// tokens are not sender-bound"; docs/security.md AR-10 told operators in as many
// words not to record VAULT_DPOP_ENABLED as a mitigation. An auditor reading
// those would have recorded the product's strongest sender-constraint as absent,
// which is a worse outcome than not having written it down.
//
// It survived because the machine-checked documentation surfaces are the
// compliance register, the route inventories and the badge figures. Ordinary
// prose is read by nobody in CI. These two do not fix that in general -- they
// hold the claims that turned out to be worth holding, and only in one
// direction: silence is fine, describing a wrap that exists is fine, and only
// the contradiction fails.

// docsThatDescribeDPoP are the documents that make wiring claims. api.md is
// included because it is the one an integrator reads.
var docsThatDescribeDPoP = []string{
	filepath.Join("docs", "spec.md"),
	filepath.Join("docs", "security.md"),
	filepath.Join("docs", "api.md"),
	filepath.Join("docs", "architecture.md"),
}

// notWrappedClaim matches a sentence asserting a route sits outside the DPoP
// middleware, capturing the route so the claim can be checked against the
// router rather than merely counted.
var notWrappedClaim = regexp.MustCompile(
	"`(?:POST|GET|PUT|DELETE|PATCH) (/[^`]*)`[^.\n]{0,120}?is not wrapped in the DPoP middleware")

func TestNoDocumentSaysARouteIsUnwrappedWhileTheRouterWrapsIt(t *testing.T) {
	root := repoRoot(t)
	regs := parseServerRegistrations(t, filepath.Join(root, serverRouteSource))
	if len(regs) == 0 {
		t.Fatal("no registrations parsed, so this gate reads nothing and would pass anything")
	}

	wrapped := map[string]bool{}
	for pattern, reg := range regs {
		for _, ident := range dpopWrapperIdents {
			if mentionsIdent(reg.handler, ident) {
				if fields := strings.Fields(pattern); len(fields) == 2 {
					wrapped[fields[1]] = true
				}
				break
			}
		}
	}
	if len(wrapped) == 0 {
		t.Fatal("no route resolves as DPoP-wrapped; the middleware was renamed or the " +
			"detection broke, and a gate that finds nothing passes everything")
	}

	for _, doc := range docsThatDescribeDPoP {
		body := readFileString(t, filepath.Join(root, doc))
		for _, m := range notWrappedClaim.FindAllStringSubmatch(body, -1) {
			route := strings.TrimSpace(m[1])
			if wrapped[route] {
				t.Errorf("%s says %s is not wrapped in the DPoP middleware, and server.go "+
					"mounts it inside dpopWrap. One of the two is wrong and it is not the "+
					"router.", doc, route)
			}
		}
	}
}

// AR-10's instruction is the sharpest sentence in the risk register, and it was
// false for as long as POST /client/token was wrapped: an operator following it
// records a working control as no control. The flag is a mitigation for a client
// that presents proofs, and is not one for the endpoint in general -- the
// difference is the whole point, so the blanket form cannot come back.
func TestAR10DoesNotForbidRecordingAControlThatExists(t *testing.T) {
	root := repoRoot(t)
	body := readFileString(t, filepath.Join(root, "docs", "security.md"))
	if !strings.Contains(body, "AR-10") {
		// Fail rather than skip. A skipped test prints the same ok as one that
		// ran, and this gate exists because a sentence in AR-10 was false for a
		// release. If the risk is genuinely retired, retiring this with it is a
		// decision somebody should have to make on purpose.
		t.Fatal("docs/security.md no longer contains AR-10. If the risk was retired, " +
			"retire this gate in the same change and say so; do not leave a control " +
			"that reports ok because it found nothing to check.")
	}

	regs := parseServerRegistrations(t, filepath.Join(root, serverRouteSource))
	reg, ok := regs["POST /client/token"]
	if !ok {
		return
	}
	var clientTokenWrapped bool
	for _, ident := range dpopWrapperIdents {
		if mentionsIdent(reg.handler, ident) {
			clientTokenWrapped = true
			break
		}
	}
	if !clientTokenWrapped {
		// Unwrapped again, so the blanket instruction is true again.
		return
	}

	flat := strings.Join(strings.Fields(body), " ")
	if strings.Contains(flat, "Do not record `VAULT_DPOP_ENABLED` as a mitigation for this risk") {
		t.Error("security.md tells operators not to record VAULT_DPOP_ENABLED as a mitigation " +
			"for AR-10, while server.go wraps POST /client/token in dpopWrap. Say what is true " +
			"of a client that presents proofs and what is true of one that does not, rather " +
			"than the blanket form, which was written when the route was unwrapped.")
	}
}
