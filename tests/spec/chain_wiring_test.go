// Deployment-chain register: what the two routers actually install.
//
// Every control in this repository is a middleware, and a middleware is only a
// control on the routes it is mounted on. Nothing observed the mounting. Exactly
// three files in the tree import internal/server, so the 986 tests in
// tests/attack, tests/compliance and internal/middleware construct middleware in
// isolation and certify it there — which is how a device-fingerprint binding, an
// IP access list and a body cap all came to be certified against code the
// deployment did not run. A deployment-level mutation sweep neutered fourteen of
// the seventeen layers and guard closures the two routers install with the whole
// suite green, and the attack suite caught none of thirteen.
//
// The specific defect this file exists to make impossible is one identifier
// wide. server.go builds two authentication middleware — authMw, which accepts
// an access token, and challengeMw, which also accepts the 2fa_challenge token
// minted after the password succeeds and before the second factor. Repointing
// the authed closure from the first to the second grants twenty-one routes,
// including decrypted PII and the full GDPR export, to a caller holding the
// password alone. No handler reads TokenType, so the defense in depth that
// rescues the tree from plain authentication removal does not apply, and both
// gates that should have caught it accepted "authMw(" or "challengeMw(" as
// equivalent. A check that accepts either is not a check.
//
// So this gate names, per route, the exact set of guards that route is entitled
// to. Roles rather than identifiers: each role is resolved from what the
// deployment builds the variable from (middleware.Auth* versus
// middleware.AuthChallenge*, and so on), so renaming a variable moves the gate
// with the code, while swapping one middleware for another fails. The match is
// exact in both directions — a missing guard and an extra one are both drift.
//
// The behavioral half lives in internal/server/chain_probe_test.go, which
// drives the wired mux and the assembled Chain and asserts that a request which
// must be refused is refused. Neither half is sufficient alone: this one cannot
// see a middleware that stops enforcing, and that one cannot see a route nobody
// wrote a probe for.
//
// The tests are read-only. They never write to the source tree.
package spec_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// chainAdminSource is the admin plane's router. It is a separate binary behind
// mutual TLS on loopback, and it installs its own chain, so it needs its own
// inventory rather than a share of the vault's.
var chainAdminSource = filepath.Join("internal", "adminapi", "router.go")

// The guard roles. A role is what a middleware does, not what the variable
// holding it is called.
const (
	roleAuth        = "authentication"           // middleware.Auth / AuthDynamic — access tokens only
	roleChallenge   = "challenge-authentication" // middleware.AuthChallenge* — also accepts 2fa_challenge
	roleFingerprint = "fingerprint"              // middleware.Fingerprint — device binding
	roleConfirm     = "confirmation"             // middleware.Confirmed — recent password re-entry
	roleDPoP        = "dpop"                     // middleware.DPoP — sender constraint
)

// chainRoles maps each role to the middleware constructor the deployment must
// build it from. Resolution is by construction, so the gate survives a rename
// and fails a substitution — which is the whole point, since the substitution is
// the finding.
var chainRoles = map[string]func(string) bool{
	roleAuth:        func(n string) bool { return n == "Auth" || n == "AuthDynamic" },
	roleChallenge:   func(n string) bool { return n == "AuthChallenge" || n == "AuthChallengeDynamic" },
	roleFingerprint: func(n string) bool { return n == "Fingerprint" },
	roleConfirm:     func(n string) bool { return n == "Confirmed" },
	roleDPoP:        func(n string) bool { return n == "DPoP" },
}

// chainExpectation is one route registration: the guards it is entitled to, the
// rate limiter that fronts it, and the scope literal it requires.
//
// guards is an exact set. An extra guard is drift as much as a missing one: a
// route that quietly gained challenge-authentication is the finding, and a route
// that quietly gained a confirmation gate is a usability regression nobody
// decided on.
type chainExpectation struct {
	guards  []string
	limiter string
	scope   string
}

// chainAuthed, chainConfirmed and chainChallenge are the three guard sets the
// vault mounts, named once so a row reads as a decision rather than a list.
//
//	chainAuthed    — an access token, bound to the device, sender-constrained.
//	chainConfirmed — the same, plus a password re-entry inside the last few
//	                 minutes. The six second-factor management routes take it,
//	                 because binding a new authenticator or removing an old one
//	                 is the move an account takeover makes.
//	chainChallenge — the 2fa_challenge token, and nothing else may take it. It is
//	                 minted after the first factor and before the second, so a
//	                 route that accepts it is a route reachable with the password
//	                 alone.
var (
	chainAuthed    = []string{roleAuth, roleFingerprint, roleDPoP}
	chainConfirmed = []string{roleAuth, roleFingerprint, roleConfirm, roleDPoP}
	chainChallenge = []string{roleChallenge, roleFingerprint, roleDPoP}
	chainPublic    []string
)

// chainRouteGuards is the register: every registration setupRoutes makes, with
// the guards, limiter and scope it is entitled to.
//
// The value is a slice because one pattern is registered twice — POST
// /auth/register has a rate-limited arm and a 403 arm, chosen on
// cfg.RegistrationEnabled — and collapsing the two would let either arm inherit
// the other's evidence. Entries are matched against registrations in source
// order.
var chainRouteGuards = map[string][]chainExpectation{
	// Public surface. No guards by design; the limiter is the whole control on
	// several of these, so it is pinned here rather than left to a comment.
	"GET /healthz":                          {{guards: chainPublic}},
	"GET /readyz":                           {{guards: chainPublic}},
	"GET /auth/capabilities":                {{guards: chainPublic}},
	"POST /auth/register":                   {{guards: chainPublic, limiter: "registerRL"}, {guards: chainPublic}},
	"POST /auth/login":                      {{guards: []string{roleDPoP}, limiter: "loginRL"}},
	"POST /auth/refresh":                    {{guards: []string{roleDPoP}, limiter: "refreshRL"}},
	"GET /auth/verify-email":                {{guards: chainPublic, limiter: "verifyEmailRL"}},
	"POST /auth/password/reset":             {{guards: chainPublic, limiter: "passwordResetRL"}},
	"POST /auth/password/reset/confirm":     {{guards: chainPublic, limiter: "passwordResetRL"}},
	"POST /client/token":                    {{guards: []string{roleDPoP}, limiter: "clientTokenRL"}},
	"GET /.well-known/jwks.json":            {{guards: chainPublic}},
	"GET /.well-known/openid-configuration": {{guards: chainPublic}},
	"GET /auth/oauth2/authorize":            {{guards: chainPublic, limiter: "authorizeRL"}},
	"GET /auth/oauth2/callback/{provider}":  {{guards: chainPublic, limiter: "oauthCallbackRL"}},
	"POST /auth/oauth2/exchange":            {{guards: chainPublic, limiter: "oauthExchangeRL"}},
	"/":                                     {{guards: chainPublic}},

	// Session and profile.
	"POST /auth/logout":          {{guards: chainAuthed}},
	"POST /auth/confirm":         {{guards: chainAuthed, limiter: "confirmRL"}},
	"GET /user/profile":          {{guards: chainAuthed}},
	"PUT /user/profile":          {{guards: chainAuthed}},
	"GET /user/sessions":         {{guards: chainAuthed}},
	"DELETE /user/sessions/{id}": {{guards: chainAuthed}},
	"DELETE /user/sessions":      {{guards: chainAuthed}},
	"GET /user/devices":          {{guards: chainAuthed}},
	"PATCH /user/devices/{id}":   {{guards: chainAuthed}},
	"DELETE /user/devices/{id}":  {{guards: chainAuthed}},
	"DELETE /user/account":       {{guards: chainAuthed, limiter: "accountDeleteRL"}},
	"POST /user/password":        {{guards: chainAuthed, limiter: "confirmRL"}},

	// Second factor. The split between chainAuthed, chainConfirmed and
	// chainChallenge here is the whole of the MFA threat model: verify takes the
	// challenge token because that is the request completing the login, and
	// every route that enrolls, removes or regenerates a factor takes the
	// confirmation gate because a stolen access token must not be enough.
	"GET /auth/2fa/status":                       {{guards: chainAuthed}},
	"POST /auth/2fa/totp/setup":                  {{guards: chainConfirmed}},
	"POST /auth/2fa/totp/verify":                 {{guards: chainChallenge, limiter: "totpRL"}},
	"DELETE /auth/2fa/totp":                      {{guards: chainConfirmed}},
	"POST /auth/2fa/webauthn/register/begin":     {{guards: chainConfirmed}},
	"POST /auth/2fa/webauthn/register/finish":    {{guards: chainConfirmed}},
	"POST /auth/2fa/webauthn/verify/begin":       {{guards: chainChallenge}},
	"POST /auth/2fa/webauthn/verify/finish":      {{guards: chainChallenge}},
	"GET /auth/2fa/webauthn/credentials":         {{guards: chainAuthed}},
	"DELETE /auth/2fa/webauthn/credentials/{id}": {{guards: chainConfirmed}},
	"POST /auth/2fa/backup-codes":                {{guards: chainConfirmed}},
	"POST /auth/2fa/backup-code/verify":          {{guards: chainChallenge, limiter: "totpRL"}},
	"POST /auth/2fa/email-otp/verify":            {{guards: chainChallenge, limiter: "totpRL"}},
	"POST /auth/2fa/email-otp/resend":            {{guards: chainChallenge, limiter: "totpRL"}},

	// Personal data. Reads and writes are authenticated; the destructive routes
	// additionally confirm, because erasure has no undo.
	"GET /user/identity":               {{guards: chainAuthed, limiter: "identityReadRL"}},
	"PUT /user/identity":               {{guards: chainAuthed, limiter: "identityWriteRL"}},
	"DELETE /user/identity":            {{guards: chainConfirmed, limiter: "confirmRL"}},
	"POST /user/marketing/unsubscribe": {{guards: chainAuthed, limiter: "identityReadRL"}},
	"POST /user/blobs":                 {{guards: chainAuthed, limiter: "blobUploadRL"}},
	"GET /user/blobs":                  {{guards: chainAuthed, limiter: "blobReadRL"}},
	"GET /user/blobs/{id}":             {{guards: chainAuthed, limiter: "blobReadRL"}},
	"DELETE /user/blobs/{id}":          {{guards: chainConfirmed, limiter: "confirmRL"}},
	"PUT /user/blobs/named/{name}":     {{guards: chainAuthed, limiter: "blobUploadRL"}},
	"GET /user/blobs/named/{name}":     {{guards: chainAuthed, limiter: "blobReadRL"}},
	"DELETE /user/blobs/named/{name}":  {{guards: chainConfirmed, limiter: "confirmRL"}},
	"GET /user/data-export":            {{guards: chainAuthed, limiter: "dataExportRL"}},
	"GET /user/social":                 {{guards: chainAuthed}},
	"DELETE /user/social/{id}":         {{guards: chainAuthed, limiter: "confirmRL"}},

	// Machine surface. No fingerprint: a service client has no device. The scope
	// literal is the entire authorization on all six, so it is pinned by value.
	// Widening kms:unwrap to read opens the key-release oracle to every user
	// token, because all four user issuance sites hardcode read and write.
	"PUT /service/documents/{subject}/{key}":    {{guards: []string{roleAuth, roleDPoP}, limiter: "svcDocWriteRL", scope: `"svcdoc:write"`}},
	"GET /service/documents/{subject}/{key}":    {{guards: []string{roleAuth, roleDPoP}, limiter: "svcDocReadRL", scope: `"svcdoc:read"`}},
	"DELETE /service/documents/{subject}/{key}": {{guards: []string{roleAuth, roleDPoP}, limiter: "svcDocWriteRL", scope: `"svcdoc:write"`}},
	"GET /service/documents/{subject}":          {{guards: []string{roleAuth, roleDPoP}, limiter: "svcDocReadRL", scope: `"svcdoc:read"`}},
	"POST /kms/unwrap":                          {{guards: []string{roleAuth, roleDPoP}, limiter: "kmsUnwrapRL", scope: `"kms:unwrap"`}},
	"POST /mint":                                {{guards: []string{roleAuth, roleDPoP}, limiter: "mintRL", scope: "handler.MintScope"}},
}

// The floors. A classifier that recognizes nothing reports no violations, which
// reads the same as a correctly wired mux.
const (
	chainRouteFloor     = 60
	chainAuthedFloor    = 20
	chainConfirmedFloor = 6
	chainChallengeFloor = 6
)

// TestEveryRouteIsMountedBehindTheGuardsItIsEntitledTo is the gate.
func TestEveryRouteIsMountedBehindTheGuardsItIsEntitledTo(t *testing.T) {
	root := repoRoot(t)
	regs := chainClassifyRoutes(t, filepath.Join(root, serverSource), "setupRoutes")

	if len(regs) < chainRouteFloor {
		t.Fatalf("only %d route registrations were classified in %s, below the floor of %d; the "+
			"classifier has stopped seeing the mux and this gate would pass over an unguarded route",
			len(regs), serverSource, chainRouteFloor)
	}

	seen := map[string]int{}
	var authed, confirmed, challenged int
	for _, reg := range regs {
		want, ok := chainRouteGuards[reg.pattern]
		if !ok {
			t.Errorf("%s mounts %q, which the deployment-chain register does not name. Add a row "+
				"saying which guards it is entitled to; a route nobody named is a route nobody "+
				"decided the authentication for.", reg.pos, reg.pattern)
			continue
		}
		idx := seen[reg.pattern]
		seen[reg.pattern]++
		if idx >= len(want) {
			t.Errorf("%s registers %q for the %d%s time; the register names only %d. A second "+
				"registration of one pattern is either dead wiring or a second, differently "+
				"guarded way in.", reg.pos, reg.pattern, idx+1, chainOrdinal(idx+1), len(want))
			continue
		}
		exp := want[idx]

		if got := reg.guards; !equalStrings(chainSorted(got), chainSorted(exp.guards)) {
			t.Errorf("%s mounts %q behind %v; the register entitles it to %v.\n"+
				"Roles are resolved from the middleware each variable is built from, so this is a "+
				"substitution or a removal, not a rename. %s",
				reg.pos, reg.pattern, chainRender(got), chainRender(exp.guards),
				chainWhyItMatters(exp.guards, got))
		}
		if reg.limiter != exp.limiter {
			t.Errorf("%s mounts %q behind the limiter %s; the register names %s. The budget in "+
				"front of a route is the only thing bounding how many times a caller may try it.",
				reg.pos, reg.pattern, chainOrNone(reg.limiter), chainOrNone(exp.limiter))
		}
		if reg.scope != exp.scope {
			t.Errorf("%s mounts %q behind RequireScope(%s); the register names %s. The scope "+
				"literal is the whole authorization on this route: every user token hardcodes "+
				"read and write, so widening it to either hands the route to every logged-in user.",
				reg.pos, reg.pattern, chainOrNone(reg.scope), chainOrNone(exp.scope))
		}

		switch {
		case chainHasRole(exp.guards, roleConfirm):
			confirmed++
			authed++
		case chainHasRole(exp.guards, roleChallenge):
			challenged++
		case chainHasRole(exp.guards, roleAuth):
			authed++
		}
	}

	for pattern, want := range chainRouteGuards {
		if n := seen[pattern]; n != len(want) {
			t.Errorf("the deployment-chain register names %q %d time(s), but %s registers it %d "+
				"time(s). A row for a route that no longer exists is a standing entitlement for "+
				"whatever re-uses the path.", pattern, len(want), serverSource, n)
		}
	}

	if authed < chainAuthedFloor {
		t.Errorf("only %d routes classified as authenticated, below the floor of %d", authed, chainAuthedFloor)
	}
	if confirmed < chainConfirmedFloor {
		t.Errorf("only %d routes classified as confirmation-gated, below the floor of %d; the six "+
			"second-factor management routes are the ones that must be there", confirmed, chainConfirmedFloor)
	}
	if challenged < chainChallengeFloor {
		t.Errorf("only %d routes classified as challenge-authenticated, below the floor of %d",
			challenged, chainChallengeFloor)
	}
	t.Logf("%d registrations classified: %d authenticated, %d confirmation-gated, %d challenge-only",
		len(regs), authed, confirmed, challenged)
}

// chainWhyItMatters turns the two substitutions that are exploitable into a
// sentence, so a failure explains itself rather than reporting a set difference.
func chainWhyItMatters(want, got []string) string {
	switch {
	case chainHasRole(want, roleAuth) && chainHasRole(got, roleChallenge):
		return "This route now accepts the 2fa_challenge token, which is minted after the password " +
			"succeeds and before the second factor. No handler reads TokenType, so the route is " +
			"reachable with the victim's password alone."
	case chainHasRole(want, roleConfirm) && !chainHasRole(got, roleConfirm):
		return "This route no longer requires a recent password re-entry. A stolen access token is " +
			"now enough to enroll an authenticator or remove one, and post-change revocation only " +
			"retires refresh families, so the attacker's stateless access token outlives it."
	case chainHasRole(want, roleFingerprint) && !chainHasRole(got, roleFingerprint):
		return "This route no longer binds the token to the device that obtained it, so a stolen " +
			"token replays from any address."
	case chainHasRole(want, roleAuth) && !chainHasRole(got, roleAuth) && !chainHasRole(got, roleChallenge):
		return "This route now establishes no caller identity at the chain at all."
	}
	return "Re-derive which credential this route should take before changing the register."
}

// ---------------------------------------------------------------------------
// Chain: the layers every request passes through
// ---------------------------------------------------------------------------

// chainLayers is the middleware Server.Chain installs, in the order the source
// assembles it — which is the reverse of the order a request meets it, because
// each statement wraps the previous one.
//
// Order is pinned as well as membership. Two of these are order-dependent and
// nothing else records that: Recovery has to be outermost or a panic in any
// later layer escapes to the connection, and RequestID has to precede Logger or
// every log line carries an empty correlation id.
//
// The honeypot logger is the one conditional layer and sits inside the profile
// branch, so it is listed with the others and matched inside the branch.
var chainLayers = []struct{ call, why string }{
	{"honeypot.LoggingMiddleware", "captures the request on a honeypot deployment; the innermost layer, so it sees what the handler would have seen"},
	{"middleware.MaxBodyWithExemptions", "caps the request body at 8KB for every route that does not enforce its own"},
	{"middleware.ClientIPContext", "resolves the client address once, so the rate limiter and the per-source account lockout agree on what the client is; without it the lockout collapses to one bucket per user and five failures from anywhere lock any account whose email is known"},
	{"middleware.AppContext", "resolves the X-Vault-App tenant for white-label mail"},
	{"middleware.CORS", "sets the cross-origin response headers"},
	{"middleware.IPAccess", "the sole enforcement point for all four operator IP and geo lists"},
	{"middleware.SecurityHeaders", "sets CSP, HSTS, X-Content-Type-Options and the frame options"},
	{"middleware.Logger", "writes the access log every audit and forensic claim reads"},
	{"middleware.RequestID", "stamps the correlation id the deny logging and every downstream log line carry"},
	{"middleware.Recovery", "turns a handler panic into a JSON 500 instead of a dropped connection"},
}

// TestTheMiddlewareChainInstallsEveryLayerInOrder pins Chain.
//
// It matches on the assignment rather than on the call, because the cheapest
// way to neuter a layer is to leave the text in place and stop assigning the
// result: `_ = middleware.IPAccess()(h)` reads correctly, greps correctly, and
// installs nothing.
func TestTheMiddlewareChainInstallsEveryLayerInOrder(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(root, serverSource), nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", serverSource, err)
	}
	fn := chainMethod(file, "Chain")
	if fn == nil {
		t.Fatalf("%s no longer defines Server.Chain; the chain moved and this gate has stopped "+
			"seeing what it guards", serverSource)
	}

	var installed []string
	for _, stmt := range chainAllStmts(fn.Body) {
		as, ok := stmt.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			continue
		}
		lhs, ok := as.Lhs[0].(*ast.Ident)
		if !ok || lhs.Name != "h" {
			continue
		}
		if name := chainLayerName(as.Rhs[0]); name != "" {
			installed = append(installed, name)
		}
	}

	want := make([]string, 0, len(chainLayers))
	for _, l := range chainLayers {
		want = append(want, l.call)
	}
	if equalStrings(installed, want) {
		t.Logf("Chain installs %d layers in the pinned order", len(installed))
		return
	}

	have := map[string]bool{}
	for _, name := range installed {
		have[name] = true
	}
	for _, l := range chainLayers {
		if !have[l.call] {
			t.Errorf("Server.Chain no longer assigns the result of %s to the chain. That layer %s.\n"+
				"Note that deleting the statement and leaving it unassigned look identical to a "+
				"grep and identical to a reader; only the assignment installs it.", l.call, l.why)
		}
	}
	for _, name := range installed {
		if !chainLayerDeclared(name) {
			t.Errorf("Server.Chain installs %s, which the layer register does not name. Add it "+
				"with the sentence saying what it buys, so the next reader can weigh removing it.", name)
		}
	}
	if len(installed) == len(want) {
		t.Errorf("Server.Chain installs the right layers in the wrong order.\n got: %v\nwant: %v\n"+
			"Each statement wraps the previous one, so the source order is the reverse of the "+
			"order a request meets them. Recovery must stay last in the source and therefore "+
			"outermost, or a panic in any other layer escapes as a dropped connection; RequestID "+
			"must precede Logger, or every access-log line carries an empty correlation id.",
			installed, want)
	}
}

// TestStartServesTheChainAndNothingElse keeps Chain from becoming decorative.
//
// Every layer above can be perfectly assembled and never reach a request, if
// Start hands the mux to http.Server directly. That is a one-word change in a
// file nothing else reads.
func TestStartServesTheChainAndNothingElse(t *testing.T) {
	root := repoRoot(t)
	src := commentFreeSource(t, filepath.Join(root, serverSource))
	for _, want := range []string{"h := s.Chain(mux)", "Handler: h,"} {
		if !strings.Contains(src, want) {
			t.Errorf("internal/server/server.go no longer contains %q. Start must serve "+
				"Chain(setupRoutes()); handing the mux to http.Server directly leaves every layer "+
				"in Chain assembled and unreached.", want)
		}
	}
}

// chainStartConfig is the process-wide configuration Start installs before it
// serves. None of it is a middleware, all of it decides what the middleware
// see, and every reference to any of these outside Start is a test setting its
// own value — so nothing observed the deployed arguments at all.
//
// The pinned text is the expression, not the value: SetTrustedProxies("0.0.0.0/0")
// makes every client's X-Forwarded-For believed, which simultaneously defeats
// every per-IP limiter, the per-source lockout, both IP access lists,
// AppContext's trusted-proxy gate and the address on every audit row.
var chainStartConfig = map[string]string{
	"middleware.SetTrustedProxies":       "cfg.TrustedProxies",
	"middleware.SetRealIPHeader":         "cfg.RealIPHeader",
	"middleware.SetTLSFingerprintHeader": "cfg.TLSFingerprintHeader",
	"middleware.SetIPAccessLists":        "cfg.IPAllowlist, cfg.IPBlocklist, cfg.GeoAllowlist, cfg.GeoBlocklist, cfg.GeoIPHeader",
}

// TestStartInstallsTheProcessWideConfigurationFromConfig pins those four calls
// and their arguments.
func TestStartInstallsTheProcessWideConfigurationFromConfig(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(root, serverSource), nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", serverSource, err)
	}
	fn := chainMethod(file, "Start")
	if fn == nil {
		t.Fatalf("%s no longer defines Server.Start", serverSource)
	}

	found := map[string]string{}
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := chainCalleeName(call)
		if _, wanted := chainStartConfig[name]; !wanted {
			return true
		}
		args := make([]string, 0, len(call.Args))
		for _, a := range call.Args {
			args = append(args, nodeText(t, fset, a))
		}
		found[name] = strings.Join(args, ", ")
		return true
	})

	for name, want := range chainStartConfig {
		got, ok := found[name]
		if !ok {
			t.Errorf("Server.Start no longer calls %s. It is process-wide state with a usable "+
				"zero value, so dropping the call compiles, runs, and silently leaves the "+
				"configuration an operator set unread.", name)
			continue
		}
		if got != want {
			t.Errorf("Server.Start calls %s(%s); the deployment register pins %s(%s). The "+
				"argument is the configuration: a literal here overrides what the operator asked "+
				"for, and no test outside this one reads the deployed value.", name, got, name, want)
		}
	}
}

// chainPinnedArgs are the deployment arguments whose value is the control.
//
// Each is one token wide and each has a plausible-looking wrong value.
// Fingerprint(true) is soft mode, where a mismatch is logged and the request
// proceeds, and the text "fingerprintMw(" survives at every call site. An empty
// audience argument means "do not check the audience" — internal/jwt/validate.go
// gates the comparison on the expected audience being non-empty. d.HIBPEnabled
// replaced by false disables breach checking while five register rows stay Met.
var chainPinnedArgs = []struct {
	callee string
	args   string
	why    string
}{
	{"middleware.Fingerprint", "false", "false is enforcing mode. true is soft mode: a device mismatch is logged and the request proceeds, and every call site still reads fingerprintMw("},
	{"middleware.WithDPoPScheme", "cfg.DPoPEnabled", "the DPoP authorization scheme is accepted exactly while the operator has enabled it"},
	{"middleware.Auth", "d.Keys, cfg.Origin, cfg.Origin, dpopScheme", "the third argument is the expected audience; empty means the aud claim is not checked at all"},
	{"middleware.AuthDynamic", "d.KeyStore.KeyProvider(), cfg.Origin, cfg.Origin, dpopScheme", "the keystore branch takes the same issuer and audience as the static branch, or rotation quietly relaxes verification"},
	{"middleware.AuthChallenge", "d.Keys, cfg.Origin, cfg.Origin, dpopScheme", "same audience as the access-token middleware; the challenge token is a credential too"},
	{"middleware.AuthChallengeDynamic", "d.KeyStore.KeyProvider(), cfg.Origin, cfg.Origin, dpopScheme", "same as the static challenge branch"},
	{"middleware.MaxBodyWithExemptions", `8 * 1024, []string{"/user/blobs", "/service/documents"}`, "the exemption list is the whole of the body cap's escape hatch; widening it to / exempts everything"},
	{"handler.NewPasswordHandler", "d.Users, d.PwHistory, d.Tokens, d.EmailSender, d.AuditLog, d.Cache, cfg.Origin, cfg.AppName, d.Pepper, cfg.PasswordMinLength, d.HIBP, d.HIBPEnabled", "the last argument is breach checking; a literal false disables it while five compliance rows stay Met on evidence that never reads it"},
}

// TestDeploymentArgumentsArePinned executes the pins.
func TestDeploymentArgumentsArePinned(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(root, serverSource), nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", serverSource, err)
	}

	found := map[string][]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := chainCalleeName(call)
		if name == "" {
			return true
		}
		args := make([]string, 0, len(call.Args))
		for _, a := range call.Args {
			args = append(args, nodeText(t, fset, a))
		}
		found[name] = append(found[name], strings.Join(args, ", "))
		return true
	})

	for _, pin := range chainPinnedArgs {
		calls, ok := found[pin.callee]
		if !ok {
			t.Errorf("%s is no longer called in %s; the deployment argument register pins it as "+
				"%s(%s). %s", pin.callee, serverSource, pin.callee, pin.args, pin.why)
			continue
		}
		for _, got := range calls {
			if got != pin.args {
				t.Errorf("%s calls %s(%s); the deployment argument register pins %s(%s).\n%s",
					serverSource, pin.callee, got, pin.callee, pin.args, pin.why)
			}
		}
	}
}

// chainLimiterBudgets is every rate limiter the vault mounts, with the budget it
// is deployed with.
//
// A budget is not a struct field like FailClosed, which the fail-closed register
// already guards: it is two numbers that look equally plausible at any value.
// totpRL is the sharpest case — it caps TOTP verify, backup-code verify and both
// email-OTP routes, so it is the entire bound on guessing a six-digit code
// inside the five-minute challenge window, and raising its limit is invisible
// everywhere else in the tree.
var chainLimiterBudgets = map[string]struct{ limit, window string }{
	"loginRL":         {"5", "15 * time.Minute"},
	"registerRL":      {"3", "time.Hour"},
	"refreshRL":       {"30", "time.Minute"},
	"passwordResetRL": {"3", "time.Hour"},
	"totpRL":          {"5", "5 * time.Minute"},
	"verifyEmailRL":   {"10", "time.Hour"},
	"confirmRL":       {"5", "15 * time.Minute"},
	"clientTokenRL":   {"10", "time.Minute"},
	"accountDeleteRL": {"3", "time.Hour"},
	"oauthExchangeRL": {"10", "time.Minute"},
	"authorizeRL":     {"10", "time.Minute"},
	"oauthCallbackRL": {"10", "time.Minute"},
	"identityReadRL":  {"30", "time.Minute"},
	"identityWriteRL": {"10", "time.Minute"},
	"blobUploadRL":    {"10", "time.Minute"},
	"blobReadRL":      {"30", "time.Minute"},
	"svcDocWriteRL":   {"60", "time.Minute"},
	"svcDocReadRL":    {"300", "time.Minute"},
	"dataExportRL":    {"5", "time.Minute"},
	"kmsUnwrapRL":     {"30", "time.Minute"},
	"mintRL":          {"60", "time.Minute"},
}

// TestEveryRateLimiterBudgetIsPinned fails when a deployed budget changes
// without the register changing with it.
func TestEveryRateLimiterBudgetIsPinned(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, serverSource)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", serverSource, err)
	}
	src := readFileString(t, path)

	seen := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		name, ok := as.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		lit, ok := rateLimitConfigLiteral(as.Rhs[0], fset, src)
		if !ok {
			return true
		}
		seen[name.Name] = true

		want, declared := chainLimiterBudgets[name.Name]
		if !declared {
			t.Errorf("%s:%d builds the limiter %q, which the budget register does not name. A "+
				"limiter nobody pinned is a budget nobody chose.",
				serverSource, fset.Position(as.Pos()).Line, name.Name)
			return true
		}
		gotLimit := chainFieldText(t, fset, lit, "Limit")
		gotWindow := chainFieldText(t, fset, lit, "Window")
		if gotLimit != want.limit || gotWindow != want.window {
			t.Errorf("%s:%d deploys %q at %s per %s; the budget register pins %s per %s. A budget "+
				"is two numbers that look equally plausible at any value, so a change here has to "+
				"be argued rather than noticed.",
				serverSource, fset.Position(as.Pos()).Line, name.Name,
				gotLimit, gotWindow, want.limit, want.window)
		}
		return true
	})

	for name := range chainLimiterBudgets {
		if !seen[name] {
			t.Errorf("the budget register names %q, which %s no longer builds. Remove the entry, "+
				"so a future limiter reusing the name cannot inherit a budget written for a "+
				"different route.", name, serverSource)
		}
	}
}

// ---------------------------------------------------------------------------
// The admin plane
// ---------------------------------------------------------------------------

// chainAdminLayers is the chain NewRouter installs, in source order. Six of the
// seven can be removed with every suite green: seven test functions reference
// LocalOnly and RejectProxyHeaders, and every one of them constructs the
// middleware and wraps its own handler.
var chainAdminLayers = []struct{ call, why string }{
	{"MaxBody", "caps the admin request body; without it an admin body is unbounded"},
	{"Recovery", "turns a handler panic into a response instead of a process kill, which on a single-replica admin plane is a denial of service"},
	{"RequestID", "strips the client-supplied X-Request-ID, which is otherwise a log-injection primitive"},
	{"SecurityHeaders", "the admin UI is HTML in a browser; without this it is served with no CSP, no HSTS and no frame options"},
	{"RejectProxyHeaders", "layer 4 of the six-layer local-only enforcement"},
	{"LocalOnly", "layer 6, and the one that writes the admin:killswitch_triggered audit record"},
}

// TestTheAdminRouterInstallsEveryLayerInOrder is the admin twin of the vault
// chain gate. The two loopback layers are inside the !DevMode branch, which is
// where they belong and also where a deletion is least visible.
func TestTheAdminRouterInstallsEveryLayerInOrder(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(root, chainAdminSource), nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", chainAdminSource, err)
	}
	fn := findTopLevelFunc(file, "NewRouter")
	if fn == nil {
		t.Fatalf("%s no longer defines NewRouter", chainAdminSource)
	}

	var installed []string
	for _, stmt := range chainAllStmts(fn.Body) {
		as, ok := stmt.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			continue
		}
		lhs, ok := as.Lhs[0].(*ast.Ident)
		if !ok || lhs.Name != "handler" {
			continue
		}
		if name := chainLayerName(as.Rhs[0]); name != "" {
			installed = append(installed, name)
		}
	}

	want := make([]string, 0, len(chainAdminLayers))
	for _, l := range chainAdminLayers {
		want = append(want, l.call)
	}
	if equalStrings(installed, want) {
		return
	}
	have := map[string]bool{}
	for _, name := range installed {
		have[name] = true
	}
	for _, l := range chainAdminLayers {
		if !have[l.call] {
			t.Errorf("adminapi.NewRouter no longer assigns %s into the chain. That layer %s.",
				l.call, l.why)
		}
	}
	if len(installed) == len(want) {
		t.Errorf("adminapi.NewRouter installs the right layers in the wrong order.\n got: %v\nwant: %v",
			installed, want)
	}
}

// chainAdminRoutePerms is the admin route register: which permission each
// guarded route demands.
//
// Downgrading one entry from a super-admin permission to an operator one is
// three characters and passes every suite: the gate that exists for this asks
// only whether the viewer tier is refused, so it has no notion of the tier a
// route was meant to sit at. In the mutated state an operator reaches POST
// /admin/admins and mints a new super-admin.
//
// An empty value means the route is authenticated by session only, with no
// permission gate; those four are deliberate and named rather than absent.
var chainAdminRoutePerms = map[string]string{
	"POST /admin/auth/logout":           "",
	"GET /admin/status":                 "",
	"POST /admin/admins/me/totp/setup":  "",
	"POST /admin/admins/me/totp/verify": "",

	"GET /admin/keys":                               "rbac.KeysList",
	"POST /admin/keys/rotate":                       "rbac.KeysRotate",
	"DELETE /admin/keys/{kid}":                      "rbac.KeysRevoke",
	"GET /admin/users":                              "rbac.UsersList",
	"GET /admin/users/{id}":                         "rbac.UsersRead",
	"POST /admin/users/import":                      "rbac.UsersImport",
	"POST /admin/users/{id}/lock":                   "rbac.UsersLock",
	"POST /admin/users/{id}/unlock":                 "rbac.UsersUnlock",
	"POST /admin/users/{id}/require-password-reset": "rbac.UsersReset",
	"POST /admin/users/{id}/clear-password-reset":   "rbac.UsersReset",
	"DELETE /admin/users/{id}":                      "rbac.UsersDelete",
	"GET /admin/sessions":                           "rbac.AdminsManage",
	"POST /admin/sessions/revoke-all":               "rbac.SessionsRevoke",
	"GET /admin/audit":                              "rbac.AuditRead",
	"GET /admin/clients":                            "rbac.ClientsList",
	"GET /admin/clients/{id}":                       "rbac.ClientsRead",
	"POST /admin/clients":                           "rbac.ClientsCreate",
	"POST /admin/clients/{id}/revoke":               "rbac.ClientsRevoke",
	"POST /admin/clients/{id}/rotate":               "rbac.ClientsRotate",
	"GET /admin/roles":                              "rbac.RolesList",
	"POST /admin/roles":                             "rbac.RolesCreate",
	"DELETE /admin/roles/{name}":                    "rbac.RolesDelete",
	"GET /admin/email-branding":                     "rbac.EmailRead",
	"GET /admin/email-branding/{app}":               "rbac.EmailRead",
	"PUT /admin/email-branding/{app}":               "rbac.EmailWrite",
	"DELETE /admin/email-branding/{app}":            "rbac.EmailDelete",
	"GET /admin/email-templates":                    "rbac.EmailRead",
	"POST /admin/email-templates/preview":           "rbac.EmailWrite",
	"GET /admin/email-templates/{app}/{name}":       "rbac.EmailRead",
	"PUT /admin/email-templates/{app}/{name}":       "rbac.EmailWrite",
	"DELETE /admin/email-templates/{app}/{name}":    "rbac.EmailDelete",
	"GET /admin/config":                             "rbac.ConfigRead",
	"PUT /admin/config/{key}":                       "rbac.ConfigWrite",
	"DELETE /admin/config/{key}":                    "rbac.ConfigWrite",
	"GET /admin/metrics":                            "rbac.MetricsRead",
	"GET /admin/admins":                             "rbac.AdminsManage",
	"POST /admin/admins":                            "rbac.AdminsCreate",
	"POST /admin/admins/{id}/revoke":                "rbac.AdminsRevoke",
}

// chainAdminUnguarded are the registrations that carry no session gate: the
// login route and the HTML page shells. The pages are static and carry no
// secrets; every datum they show comes from one of the guarded routes above.
var chainAdminUnguarded = map[string]string{
	"POST /admin/auth/login":   "the login route itself, rate-limited rather than authenticated",
	"GET /admin/":              "HTML shell",
	"GET /admin/login":         "HTML shell",
	"GET /admin/ui/users":      "HTML shell",
	"GET /admin/ui/keys":       "HTML shell",
	"GET /admin/ui/sessions":   "HTML shell",
	"GET /admin/ui/audit":      "HTML shell",
	"GET /admin/ui/clients":    "HTML shell",
	"GET /admin/ui/admins":     "HTML shell",
	"GET /admin/ui/config":     "HTML shell",
	"GET /admin/ui/users/{id}": "HTML shell",
	"GET /admin/ui/totp-setup": "HTML shell",
	"GET /admin/static/":       "embedded static assets",
}

// TestEveryAdminRouteDemandsThePermissionItIsRegisteredWith is the gate.
func TestEveryAdminRouteDemandsThePermissionItIsRegisteredWith(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, chainAdminSource)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", chainAdminSource, err)
	}

	seen := map[string]bool{}
	var guarded int
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		pattern, _, ok := muxRegistration(call)
		if !ok {
			return true
		}
		seen[pattern] = true
		pos := fmt.Sprintf("%s:%d", chainAdminSource, fset.Position(call.Lparen).Line)

		perm, sessionGated := chainAdminPermission(t, fset, call.Args[1])
		if _, unguarded := chainAdminUnguarded[pattern]; unguarded {
			if sessionGated {
				t.Errorf("%s registers %q behind the session gate, but the register lists it as "+
					"unguarded. Drop the exemption so the list keeps meaning what it says.", pos, pattern)
			}
			return true
		}
		want, declared := chainAdminRoutePerms[pattern]
		if !declared {
			t.Errorf("%s registers %q, which the admin route register does not name. Add it with "+
				"the permission it demands, or to chainAdminUnguarded with the reason it needs none.",
				pos, pattern)
			return true
		}
		if !sessionGated {
			t.Errorf("%s mounts %q with no session gate at all; the register demands %s behind "+
				"authentication.", pos, pattern, want)
			return true
		}
		guarded++
		if perm != want {
			t.Errorf("%s mounts %q behind %s; the admin route register demands %s. A permission "+
				"downgrade is three characters and every suite stays green, because the gate that "+
				"exists for this asks only whether the viewer tier is refused and has no notion of "+
				"the tier a route was meant to sit at.",
				pos, pattern, chainOrNone(perm), want)
		}
		return true
	})

	for pattern := range chainAdminRoutePerms {
		if !seen[pattern] {
			t.Errorf("the admin route register names %q, which %s no longer registers", pattern, chainAdminSource)
		}
	}
	for pattern := range chainAdminUnguarded {
		if !seen[pattern] {
			t.Errorf("chainAdminUnguarded names %q, which %s no longer registers", pattern, chainAdminSource)
		}
	}
	if guarded < 40 {
		t.Fatalf("only %d admin routes were classified as permission-gated; the admin plane mounts "+
			"more than that, so the classifier has stopped seeing them", guarded)
	}
}

// TestTheAdminLoginRouteKeepsItsRateLimiter pins the one limiter on the admin
// plane. Its own doc says it is independent of account lockout, so lockout does
// not substitute: this is the control against unlimited per-IP admin password
// guessing, and against Argon2id CPU exhaustion from an unauthenticated caller.
//
// Mutating the limiter's internals fails three tests, because all three build
// their own. Removing it from the deployed route failed nothing.
func TestTheAdminLoginRouteKeepsItsRateLimiter(t *testing.T) {
	root := repoRoot(t)
	src := commentFreeSource(t, filepath.Join(root, chainAdminSource))
	for _, want := range []string{
		"loginRL := NewLoginRateLimit(10, time.Minute)",
		`mux.HandleFunc("POST /admin/auth/login", loginRL.Wrap(auth.Login))`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("%s no longer contains %q. Admin login is an Argon2id verification reachable "+
				"without credentials; unwrapping it leaves per-IP password guessing unbounded and "+
				"the CPU cost with it.", chainAdminSource, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

// chainRegistration is one classified mux registration.
type chainRegistration struct {
	pattern string
	pos     string
	guards  []string
	limiter string
	scope   string
}

// chainClassifyRoutes resolves every registration inside one method to the set
// of guard roles reaching it, the limiter fronting it and the scope it demands.
//
// Resolution walks through the local route-builder closures rather than around
// them: authed, confirmed, authedChallenge, docRead and docWrite are all
// closures over the middleware, so a route is classified by what its wrapper is
// made of and a new wrapper added tomorrow is classified the same way.
func chainClassifyRoutes(t *testing.T, path, method string) []chainRegistration {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	fn := chainMethod(file, method)
	if fn == nil {
		t.Fatalf("%s no longer defines a %s method", path, method)
	}

	// Roles resolved from construction, over the whole file: the middleware are
	// built inside the method, but reading the file keeps a future move out of
	// it from blinding the gate silently.
	roleOf := map[string]string{}
	for role, match := range chainRoles {
		for ident := range identsBuiltFrom(file, "middleware", match) {
			roleOf[ident] = role
		}
	}
	if len(roleOf) == 0 {
		t.Fatalf("no guard middleware was found in %s; the construction style changed and this "+
			"gate has stopped seeing what it guards", path)
	}
	limiters := identsBuiltFrom(file, "middleware", func(n string) bool { return n == "RateLimit" })
	closures := chainClosureBodies(fn)

	var out []chainRegistration
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		pattern, _, ok := muxRegistration(call)
		if !ok {
			return true
		}
		reg := chainRegistration{
			pattern: pattern,
			pos:     fmt.Sprintf("%s:%d", filepath.Base(filepath.Dir(path))+"/"+filepath.Base(path), fset.Position(call.Lparen).Line),
		}
		roles := map[string]bool{}
		var scopes []string
		chainWalk(t, fset, call.Args[1], roleOf, limiters, closures, map[string]bool{}, roles, &reg.limiter, &scopes)
		for role := range roles {
			reg.guards = append(reg.guards, role)
		}
		sort.Strings(reg.guards)
		if len(scopes) > 0 {
			reg.scope = scopes[0]
		}
		out = append(out, reg)
		return true
	})
	sort.SliceStable(out, func(i, j int) bool { return out[i].pos < out[j].pos })
	return out
}

// chainWalk is the resolver. It records a role for every identifier built from a
// guard middleware, the limiter for every identifier built from
// middleware.RateLimit, the argument of every middleware.RequireScope call, and
// descends into any local closure it meets.
func chainWalk(
	t *testing.T,
	fset *token.FileSet,
	node ast.Node,
	roleOf map[string]string,
	limiters map[string]struct{},
	closures map[string]*ast.FuncLit,
	visited map[string]bool,
	roles map[string]bool,
	limiter *string,
	scopes *[]string,
) {
	t.Helper()
	ast.Inspect(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if chainCalleeName(call) == "middleware.RequireScope" && len(call.Args) > 0 {
				*scopes = append(*scopes, nodeText(t, fset, call.Args[0]))
			}
		}
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		if role, hit := roleOf[id.Name]; hit {
			roles[role] = true
			return true
		}
		if _, hit := limiters[id.Name]; hit {
			if *limiter == "" {
				*limiter = id.Name
			}
			return true
		}
		if body, hit := closures[id.Name]; hit && !visited[id.Name] {
			visited[id.Name] = true
			chainWalk(t, fset, body, roleOf, limiters, closures, visited, roles, limiter, scopes)
		}
		return true
	})
}

// chainClosureBodies collects the local func literals a route registration can
// name: the route builders, and the DPoP wrapper they all compose.
func chainClosureBodies(fn *ast.FuncDecl) map[string]*ast.FuncLit {
	out := map[string]*ast.FuncLit{}
	ast.Inspect(fn, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range as.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || i >= len(as.Rhs) {
				continue
			}
			if fl, ok := as.Rhs[i].(*ast.FuncLit); ok {
				out[id.Name] = fl
			}
		}
		return true
	})
	return out
}

// chainAdminPermission reads the permission out of a withPerm(...) registration
// and reports whether the registration is behind the session gate at all.
func chainAdminPermission(t *testing.T, fset *token.FileSet, expr ast.Expr) (string, bool) {
	t.Helper()
	var perm string
	var gated bool
	ast.Inspect(expr, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == "sessionAuth" {
			gated = true
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fun, ok := call.Fun.(*ast.Ident)
		if !ok || fun.Name != "withPerm" || len(call.Args) < 2 {
			return true
		}
		perm = nodeText(t, fset, call.Args[1])
		return true
	})
	return perm, gated
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// chainMethod finds a method on *Server (or any receiver) by name.
func chainMethod(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

// chainAllStmts flattens a block, descending one level into if-statements so a
// layer installed inside a profile or dev-mode branch is still seen.
func chainAllStmts(block *ast.BlockStmt) []ast.Stmt {
	if block == nil {
		return nil
	}
	out := make([]ast.Stmt, 0, len(block.List))
	for _, stmt := range block.List {
		if ifs, ok := stmt.(*ast.IfStmt); ok {
			out = append(out, chainAllStmts(ifs.Body)...)
			continue
		}
		out = append(out, stmt)
	}
	return out
}

// chainLayerName returns the pkg.Name (or bare Name) of the middleware
// constructor an expression installs, however many call levels wrap it.
func chainLayerName(expr ast.Expr) string {
	var name string
	ast.Inspect(expr, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			if base, ok := fun.X.(*ast.Ident); ok {
				name = base.Name + "." + fun.Sel.Name
			}
		case *ast.Ident:
			if name == "" {
				name = fun.Name
			}
		}
		return true
	})
	return name
}

func chainLayerDeclared(name string) bool {
	for _, l := range chainLayers {
		if l.call == name {
			return true
		}
	}
	return false
}

// chainCalleeName renders pkg.Name for a call whose callee is a selector.
func chainCalleeName(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	base, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return base.Name + "." + sel.Sel.Name
}

// chainCompositeField returns the value of a named field in a composite
// literal, or nil when it is absent.
func chainCompositeField(lit *ast.CompositeLit, field string) ast.Expr {
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

// chainFieldText renders a named field of a composite literal, reporting an
// absent field as "absent" rather than panicking on a nil node.
func chainFieldText(t *testing.T, fset *token.FileSet, lit *ast.CompositeLit, field string) string {
	t.Helper()
	expr := chainCompositeField(lit, field)
	if expr == nil {
		return "absent"
	}
	return nodeText(t, fset, expr)
}

func chainHasRole(set []string, role string) bool {
	for _, s := range set {
		if s == role {
			return true
		}
	}
	return false
}

func chainSorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func chainRender(set []string) string {
	if len(set) == 0 {
		return "no guards"
	}
	return strings.Join(chainSorted(set), " + ")
}

func chainOrNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func chainOrdinal(n int) string {
	switch n {
	case 1:
		return "st"
	case 2:
		return "nd"
	case 3:
		return "rd"
	}
	return "th"
}
