package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Erasure has to survive the token that was valid when it ran.
//
// DELETE /user/account tombstones the row and revokes the refresh families, but
// middleware.Auth validates signature, issuer, audience and type and never reads
// the database, so an access token minted a moment before the erasure keeps
// working for the rest of VAULT_ACCESS_TOKEN_TTL. #82 closed that on
// PUT /user/profile and said what it was leaving open: "PUT /user/identity,
// POST /user/blobs and the 5-minute confirm-window MFA writes are still
// reachable the same way ... so they are filed separately rather than
// half-done here."
//
// The behavioural half of this gate is TestAnErasedSubjectIsRefusedAtEveryGuardedWrite
// in internal/server, which drives the real wired chain.
// That test can only cover the routes someone remembered to list. This one reads
// the wiring, so the route added next year cannot be forgotten: every
// create-or-update registration under /user/ or /auth/2fa/ either runs the
// erased-account guard or is named below with a reason.
//
// Only POST, PUT and PATCH are in scope. A DELETE cannot put personal data back
// onto a tombstoned account, and DELETE /user/account in particular MUST stay
// reachable on one: the erasure cascade spans nine stores with no transaction,
// every step is idempotent, and re-running an interrupted erasure is the
// documented way to finish it.

// guardedWriteIdents are the identifiers that put middleware.LiveAccount into a
// chain: the middleware itself plus the two route-builder closures defined in
// setupRoutes. Both closures are separately asserted to contain liveMw by
// TestTheWriteRouteBuildersAllApplyTheErasureGuard, so this list cannot be
// satisfied by a wrapper that has quietly stopped applying it.
var guardedWriteIdents = []string{"liveMw", "authedWrite", "confirmedWrite"}

// writeRouteBuilders are the local helpers whose whole job is to build a chain
// for a route that writes personal data. Each must apply liveMw.
var writeRouteBuilders = []string{"authedWrite", "confirmedWrite"}

// erasureGuardExemptRoutes are the create-or-update registrations that
// legitimately run no erased-account guard. Each needs a reason, because adding
// a route here is how the gate gets defeated, and a reason is the thing a
// reviewer can disagree with.
var erasureGuardExemptRoutes = map[string]string{
	"PUT /user/profile": "guarded in the handler and in the SQL instead, by #82: UpdateProfile reads the row and refuses Deleted, and UserRepo.Update carries AND deleted = FALSE and reports ErrUserNotUpdatable when it matches nothing. Adding the middleware here would read the same row a second time on a path that already has to read it.",

	"PATCH /user/devices/{id}": "renames an existing device row and creates none. The erasure cascade calls devices.DeleteAllForUser, so a tombstoned account has no device left to rename and the UPDATE matches nothing.",

	// The challenge-token family. A challenge token is minted only by a
	// successful login, and AuthService.Login refuses user.Deleted
	// (internal/service/auth.go) before it mints anything. CompleteMFALogin
	// re-reads the row and refuses Deleted again, which covers an account erased
	// inside the challenge window. So no challenge token for an erased account
	// can exist, and none of these routes is reachable with one.
	"POST /auth/2fa/totp/verify":            "challenge-token route; login refuses an erased account before a challenge token exists",
	"POST /auth/2fa/webauthn/verify/begin":  "challenge-token route; login refuses an erased account before a challenge token exists",
	"POST /auth/2fa/webauthn/verify/finish": "challenge-token route; login refuses an erased account before a challenge token exists",
	"POST /auth/2fa/backup-code/verify":     "challenge-token route; login refuses an erased account before a challenge token exists",
	"POST /auth/2fa/email-otp/verify":       "challenge-token route; login refuses an erased account before a challenge token exists",
	"POST /auth/2fa/email-otp/resend":       "challenge-token route; login refuses an erased account before a challenge token exists",
}

// inScope reports whether a routing pattern is a create-or-update on a user's
// own data, which is the set that can undo an erasure.
func inScope(pattern string) bool {
	method, path, ok := strings.Cut(pattern, " ")
	if !ok {
		return false
	}
	switch method {
	case "POST", "PUT", "PATCH":
	default:
		return false
	}
	return strings.HasPrefix(path, "/user/") || strings.HasPrefix(path, "/auth/2fa/")
}

// TestEveryPersonalDataWriteIsBehindTheErasureGuardOrExempt is the gate.
func TestEveryPersonalDataWriteIsBehindTheErasureGuardOrExempt(t *testing.T) {
	root := repoRoot(t)
	registrations := parseServerRegistrations(t, filepath.Join(root, serverRouteSource))
	if len(registrations) == 0 {
		t.Fatal("parsed zero registrations from internal/server/server.go: the extractor is broken, not the wiring")
	}

	patterns := make([]string, 0, len(registrations))
	for pattern := range registrations {
		if inScope(pattern) {
			patterns = append(patterns, pattern)
		}
	}
	sort.Strings(patterns)
	if len(patterns) == 0 {
		t.Fatal("no create-or-update route matched the scope filter: inScope is broken, not the wiring")
	}

	for _, pattern := range patterns {
		reg := registrations[pattern]
		var guarded bool
		for _, ident := range guardedWriteIdents {
			if mentionsIdent(reg.handler, ident) {
				guarded = true
				break
			}
		}
		if guarded {
			if _, exempt := erasureGuardExemptRoutes[pattern]; exempt {
				t.Errorf("%s (%s) applies the erasure guard but is still listed as exempt; drop the "+
					"exemption so the list keeps meaning what it says", pattern, reg.pos)
			}
			continue
		}
		if _, exempt := erasureGuardExemptRoutes[pattern]; exempt {
			continue
		}
		t.Errorf("%s (%s) writes a user's own data behind no erased-account guard.\n"+
			"An access token minted before DELETE /user/account keeps verifying for the rest of its "+
			"TTL, and middleware.Auth never reads the database, so the holder of that token can put "+
			"personal data back onto a tombstoned row and the Article 17 erasure does not stick.\n"+
			"Wrap it with authedWrite or confirmedWrite, or add it to erasureGuardExemptRoutes with a reason.",
			pattern, reg.pos)
	}

	// The exempt list must not outlive the routes it names, or it becomes a
	// standing permission for a path someone re-adds later.
	for pattern := range erasureGuardExemptRoutes {
		if _, ok := registrations[pattern]; !ok {
			t.Errorf("erasureGuardExemptRoutes names %q, which internal/server/server.go no longer registers", pattern)
		}
		if !inScope(pattern) {
			t.Errorf("erasureGuardExemptRoutes names %q, which is not a create-or-update route this gate "+
				"examines; the exemption is inert and reads as protection that is not there", pattern)
		}
	}
}

// TestTheWriteRouteBuildersAllApplyTheErasureGuard closes the gate's own back
// door. Without it, deleting liveMw from the body of authedWrite would leave
// every route it builds passing the check above on the strength of the name.
func TestTheWriteRouteBuildersAllApplyTheErasureGuard(t *testing.T) {
	root := repoRoot(t)
	bodies := parseServerClosures(t, filepath.Join(root, serverRouteSource))

	for _, name := range writeRouteBuilders {
		body, ok := bodies[name]
		if !ok {
			t.Errorf("internal/server/server.go no longer defines a %s(...) route builder; "+
				"guardedWriteIdents still credits routes for naming it", name)
			continue
		}
		if !mentionsIdent(body, "liveMw") {
			t.Errorf("%s(...) no longer applies liveMw, so every route it builds accepts a write "+
				"from an account that has been erased", name)
		}
	}
}

// parseServerClosures collects every `name := func(...)` route-builder closure
// defined in setupRoutes, keyed by name, so a gate can assert what a wrapper
// actually applies rather than trusting the name a registration mentions.
//
// Shared with TestTheRouteBuilderClosuresAllApplyDPoP: both gates need the same
// map, and two copies of it would be two things to keep in step.
func parseServerClosures(t *testing.T, path string) map[string]ast.Expr {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
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
	return bodies
}
