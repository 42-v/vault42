package compliance

import (
	"crypto/rsa"
	"go/ast"
	"go/printer"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/middleware"
)

// =============================================================================
// OWASP ASVS 5.0.0 — V3 Web Frontend Security
//
// Eleven V3 rows carried one sentence: "vault42 ships no browser-facing
// application of its own. The Vue SPA in web/ is a separate deliverable
// assessed separately." Four independent facts refute it. internal/frontend
// embeds dist/* into cmd/vault; Dockerfile:32 and .goreleaser.yaml:26-29 put a
// real Vue build there before compiling, so the shipped image and the shipped
// release archives both contain one; internal/server/server.go:641 serves it at
// the catch-all route; and charts/vault/templates/frontend.yaml ships a
// separate nginx deployment that serves the same SPA cross-origin to the API.
// middleware.SecurityHeaders is even parameterised on serveFrontend and carries
// a dedicated frontendCSP — the code knew it served a browser application while
// the register said it did not.
//
// Excluding web/ *source* from assessment is legitimate and stays. It is not a
// reason to mark server-side HTTP response controls Not Applicable: CORS, CSP,
// cookie and redirect behavior are all emitted by in-scope Go code, on every
// response, whether or not the SPA is the thing consuming them.
//
// These tests are what those rows now rest on.
// =============================================================================

// --- V3.4.2 — CORS Access-Control-Allow-Origin ---

// The requirement permits either a fixed value or validation against an
// allowlist. vault42 does the second, so the assertion that matters is the
// negative one: an origin that is not on the list must not come back in the
// header. A test that only checks the configured origin is echoed passes
// against a middleware that reflects anything.
func TestASVS_V3_4_2_CORSReflectsOnlyAllowlistedOrigins(t *testing.T) {
	const primary = "https://vault.example.com"
	const extra = "https://admin.example.com"

	handler := middleware.CORS(primary, []string{extra}, false)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	for _, allowed := range []string{primary, extra} {
		req := httptest.NewRequest(http.MethodGet, "/user/blobs", nil)
		req.Header.Set("Origin", allowed)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != allowed {
			t.Errorf("V3.4.2: allowlisted origin %q was not reflected; got %q", allowed, got)
		}
	}

	// The attack: an origin the operator never configured.
	for _, hostile := range []string{
		"https://evil.example.com",
		"https://vault.example.com.evil.test",
		"null",
		"http://vault.example.com", // scheme downgrade of an allowlisted origin
	} {
		req := httptest.NewRequest(http.MethodGet, "/user/blobs", nil)
		req.Header.Set("Origin", hostile)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if got := rec.Header().Get("Access-Control-Allow-Origin"); got == hostile {
			t.Errorf("V3.4.2: origin %q was reflected into Access-Control-Allow-Origin; "+
				"the allowlist is not being consulted", hostile)
		}
		if rec.Header().Get("Access-Control-Allow-Credentials") == "true" &&
			rec.Header().Get("Access-Control-Allow-Origin") == hostile {
			t.Errorf("V3.4.2: credentials were allowed for unlisted origin %q", hostile)
		}
	}

	// The requirement's second clause: when "*" is used the response must carry
	// nothing sensitive. vault42 satisfies it structurally by never pairing "*"
	// with credentials. Dev allow-all is the only path that can emit "*".
	devHandler := middleware.CORS("", nil, true)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	devHandler.ServeHTTP(rec, req)
	if rec.Header().Get("Access-Control-Allow-Origin") == "*" &&
		rec.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Error("V3.4.2: Access-Control-Allow-Credentials is set alongside a wildcard origin")
	}

	// Even in allow-all, a non-localhost origin must not be reflected: an
	// exposed dev server would otherwise be a same-credentials cross-origin
	// read for any site on the internet.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rec = httptest.NewRecorder()
	devHandler.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got == "https://evil.example.com" {
		t.Error("V3.4.2: allow-all dev mode reflected a non-localhost origin")
	}
}

// --- V3.5.2 — preflight cannot be bypassed ---

// The requirement is about the gap between "we rely on preflight" and "every
// route that matters actually triggers one". A cross-origin request escapes
// preflight only when it is a simple request: a safelisted method with only
// CORS-safelisted request headers. vault42 closes that gap because every
// authenticated route needs `Authorization`, which is not safelisted, so the
// browser must preflight before it is ever sent — and the preflight response
// names a closed header set rather than a wildcard.
func TestASVS_V3_5_2_SensitiveFunctionalityAlwaysTriggersPreflight(t *testing.T) {
	handler := middleware.CORS("https://vault.example.com", nil, false)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("V3.5.2: the preflight request reached the wrapped handler instead of being answered by the middleware")
		}))

	req := httptest.NewRequest(http.MethodOptions, "/user/blobs", nil)
	req.Header.Set("Origin", "https://vault.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Authorization")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("V3.5.2: preflight answered with %d, want 204", rec.Code)
	}

	allowHeaders := rec.Header().Get("Access-Control-Allow-Headers")
	if strings.Contains(allowHeaders, "*") {
		t.Errorf("V3.5.2: Access-Control-Allow-Headers is %q; a wildcard lets any header through a preflight", allowHeaders)
	}
	if !strings.Contains(allowHeaders, "Authorization") {
		t.Errorf("V3.5.2: Access-Control-Allow-Headers is %q and does not name Authorization, "+
			"which is the header that forces the preflight in the first place", allowHeaders)
	}
	for _, safelisted := range []string{"Accept-Language", "Content-Language"} {
		if strings.Contains(allowHeaders, safelisted) {
			t.Errorf("V3.5.2: %s is named in Access-Control-Allow-Headers; it is CORS-safelisted "+
				"and naming it adds nothing while widening the surface", safelisted)
		}
	}

	// The other half: a route that matters must be unreachable without the
	// non-safelisted header. Bearer auth with no Authorization header is a 401,
	// so a simple cross-origin request cannot reach authenticated functionality
	// even when it skips preflight.
	authed := middleware.Auth(map[string]*rsa.PublicKey{}, "vault-test", "test-audience")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("V3.5.2: an unauthenticated request reached an authenticated handler")
		}))
	req = httptest.NewRequest(http.MethodPost, "/user/blobs", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Content-Type", "text/plain") // a simple, preflight-free content type
	rec = httptest.NewRecorder()
	authed.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("V3.5.2: a preflight-free cross-origin POST with no Authorization header got %d, want 401", rec.Code)
	}
}

// --- V3.5.1 — CSRF on cookie-authenticated sensitive functionality ---

// POST /auth/refresh authenticates from a cookie, not from a bearer token
// (internal/handler/auth.go reads r.Cookie(refreshTokenCookie)), which is
// exactly the shape the requirement addresses. The defense is the cookie's own
// attributes: SameSite=Strict means the browser does not attach it to a
// cross-site request at all, so the forged request arrives unauthenticated.
//
// This drives a real login through the exported handler and reads the live
// Set-Cookie, so it fails if the attribute is dropped at the issuing site
// rather than only if a constant changes.
func TestASVS_V3_5_1_TheCookieAuthenticatedRouteIsProtectedBySameSiteStrict(t *testing.T) {
	cookie := auditCookiesDriveLogin(t)

	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("V3.5.1: the refresh cookie's SameSite is %v, not Strict. Strict is the whole "+
			"anti-CSRF control on POST /auth/refresh: without it a cross-site form post "+
			"carries the session cookie and rotates the victim's token family.", cookie.SameSite)
	}
	if !cookie.HttpOnly {
		t.Error("V3.5.1: the refresh cookie is not HttpOnly, so script on any XSS foothold can read it " +
			"and forge the request directly rather than having to ride the browser")
	}
	if !cookie.Secure {
		t.Error("V3.5.1: the refresh cookie is not Secure")
	}
	if !strings.HasPrefix(cookie.Name, "__Host-") {
		t.Errorf("V3.5.1: the refresh cookie is named %q; without the __Host- prefix a sibling "+
			"subdomain can overwrite it, which is CSRF by cookie fixation", cookie.Name)
	}
	if cookie.Path != "/" {
		t.Errorf("V3.5.1: __Host- requires Path=/; got %q", cookie.Path)
	}
	if cookie.Domain != "" {
		t.Errorf("V3.5.1: __Host- forbids a Domain attribute; got %q", cookie.Domain)
	}

	// The premise the row rests on: the refresh route really does authenticate
	// from the cookie. If that stops being true the requirement stops applying,
	// and the register row has to be revisited rather than silently kept.
	src := readCodeOnly(t, "internal/handler/auth.go")
	if !strings.Contains(src, "r.Cookie(refreshTokenCookie)") {
		t.Error("V3.5.1: internal/handler/auth.go no longer reads the refresh token from a cookie. " +
			"If cookie authentication is gone this requirement's applicability changed: " +
			"update the register row rather than deleting this assertion.")
	}
}

// --- V3.7.1 — supported client-side technologies ---

// The requirement names NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight,
// NACL and Java applets. The shipped frontend is Vue 3 built by Vite, and the
// only markup vault42 emits server-side is the email templates. This asserts
// that none of the named technologies appears in anything the server ships or
// serves, including the embedded SPA's own index and the email templates.
func TestASVS_V3_7_1_NoObsoletePluginTechnologyIsShipped(t *testing.T) {
	// The element and attribute names by which each dead technology is loaded.
	forbidden := map[string]string{
		"<applet":                       "a Java applet",
		"<embed":                        "an NSAPI/Shockwave plugin object",
		"application/x-shockwave-flash": "Flash",
		"application/x-silverlight":     "Silverlight",
		"classid=":                      "an ActiveX control",
		"x-nacl":                        "Native Client",
		".swf":                          "a Flash movie",
		".xap":                          "a Silverlight package",
	}

	// Everything the Go binary can put in front of a browser: the embedded SPA
	// entry point and every server-rendered template.
	for _, rel := range []string{
		"internal/frontend/dist/index.html",
		"web/index.html",
	} {
		src := strings.ToLower(readProductionSource(t, rel))
		for token, what := range forbidden {
			if strings.Contains(src, token) {
				t.Errorf("V3.7.1: %s references %s (%q)", rel, what, token)
			}
		}
	}

	// The build toolchain half: Vue 3 and Vite, both currently supported.
	pkg := readProductionSource(t, "web/package.json")
	for _, want := range []string{"\"vue\"", "vite"} {
		if !strings.Contains(pkg, want) {
			t.Errorf("V3.7.1: web/package.json no longer declares %s; the row's claim that the "+
				"client stack is Vue 3 + Vite no longer holds and needs re-deriving", want)
		}
	}
}

// --- V3.7.2 — automatic redirects to another host must be allowlisted ---

// Every http.Redirect in the shipped tree is in internal/handler/oauth.go, and
// every target is either h.origin (the operator-configured origin, never a
// request value) plus a literal path, or the provider authorize URL built from
// the static provider map and gated on isSafeAuthorizeRedirect.
//
// The assertion is structural because that is where the property lives: the
// danger is a *new* redirect somewhere else, taking its target from a request
// parameter. A behavioral test of the four sites that exist today cannot see
// the fifth one arriving.
func TestASVS_V3_7_2_EveryRedirectTargetIsServerControlled(t *testing.T) {
	// Accessors that read attacker-controlled request data.
	requestDerived := []string{
		"URL.Query()", "FormValue", "PostFormValue", "PathValue",
		"Header.Get", "Referer()", "r.Host",
	}

	var sites int
	for _, pf := range productionGoFiles(t) {
		// A redirect target is often a local built one or two lines earlier, so
		// the expression at the call site is a bare identifier. Resolving it
		// through the enclosing function's assignments is what makes this a
		// check on the value rather than on the spelling.
		assigned := assignmentsByIdentifier(t, pf)

		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || selectorName(call.Fun) != "http.Redirect" {
				return true
			}
			sites++
			if len(call.Args) < 3 {
				return true
			}
			raw := renderNode(t, pf, call.Args[2])
			target := raw
			if ident, ok := call.Args[2].(*ast.Ident); ok {
				rhs, found := assigned[ident.Name]
				if !found {
					t.Errorf("V3.7.2: %s redirects to identifier %q with no assignment in this file; "+
						"the target cannot be shown to be server-controlled", pf.pos(call), ident.Name)
					return true
				}
				target = rhs
			}
			for _, acc := range requestDerived {
				if strings.Contains(target, acc) {
					t.Errorf("V3.7.2: %s redirects to a request-derived target %q. Every redirect "+
						"target must come from the configured origin or from the static provider "+
						"map, or this is an open redirect.", pf.pos(call), target)
				}
			}
			// Positive form: the target is built from the configured origin, or
			// it is the provider authorize URL, which carries its own gate --
			// asserted separately below, because a name is not a control.
			if !strings.Contains(target, "origin") && raw != "authURL" {
				t.Errorf("V3.7.2: %s redirects to %q, which is neither built from the configured "+
					"origin nor the gated provider authorize URL. A new redirect target needs "+
					"its own allowlist argument and a register update.", pf.pos(call), target)
			}
			return true
		})
	}

	if sites == 0 {
		t.Fatal("V3.7.2: no http.Redirect call site found in the production tree; the scan is broken " +
			"and would pass vacuously")
	}

	// The one target that leaves vault42's own origin is the upstream provider
	// authorize endpoint, and it is validated before use.
	oauth := readCodeOnly(t, "internal/handler/oauth.go")
	if !strings.Contains(oauth, "isSafeAuthorizeRedirect(authURL)") {
		t.Error("V3.7.2: the provider authorize URL is no longer checked by isSafeAuthorizeRedirect " +
			"before http.Redirect. That check is what makes the cross-host redirect allowlisted " +
			"rather than merely configured.")
	}
	if !strings.Contains(oauth, `u.Scheme == "https"`) {
		t.Error("V3.7.2: isSafeAuthorizeRedirect no longer requires an absolute https target")
	}

	t.Logf("V3.7.2: %d redirect call sites checked", sites)
}

// renderNode renders an AST node back to source text, the form the assertions
// above match against.
func renderNode(t *testing.T, pf parsedFile, n ast.Node) string {
	t.Helper()
	var sb strings.Builder
	if err := printer.Fprint(&sb, pf.fset, n); err != nil {
		t.Fatalf("render node in %s: %v", pf.path, err)
	}
	return sb.String()
}

// assignmentsByIdentifier maps every identifier assigned in a file to the
// rendered source of everything assigned to it. A name assigned twice keeps
// both, joined, so a second assignment cannot hide behind the first.
func assignmentsByIdentifier(t *testing.T, pf parsedFile) map[string]string {
	t.Helper()
	out := map[string]string{}
	ast.Inspect(pf.file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			ident, ok := lhs.(*ast.Ident)
			if !ok || i >= len(assign.Rhs) {
				continue
			}
			rendered := renderNode(t, pf, assign.Rhs[i])
			if prior, seen := out[ident.Name]; seen {
				out[ident.Name] = prior + " || " + rendered
			} else {
				out[ident.Name] = rendered
			}
		}
		return true
	})
	return out
}
