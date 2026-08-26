package spec_test

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The routes that persist subject-owned data have to keep their erasure guard.
//
// An access token outlives the erasure that invalidated it, so a write reaching
// storage the erasure already scrubbed puts personal data back onto a subject
// who asked for it to be gone. auth.users can refuse that itself -- UserRepo's
// UPDATE carries AND deleted = FALSE -- but the other stores cannot.
// identity.profiles is keyed by an unlinkable pseudonym with no user_id and no
// foreign key, which is what makes it pseudonymous and also what makes SQL blind
// to the connection; blobs are the same shape; and the MFA setup routes never
// load the user row at all.
//
// For those the only thing that can know is a lookup, and the only thing holding
// the lookup in place is one wrapper name at one call site. Swapping authedLive
// back to authed compiles, serves, and passes every handler test, because no
// handler test goes through the router. This gate reads the routing table so
// that edit fails the build instead.
//
// The tests are read-only. They never write to the source tree.

var serverRouting = filepath.Join("internal", "server", "server.go")

// guardedRoutes are the routes that write subject-owned data into a store the
// database cannot check. The value is the wrapper each must be mounted with.
//
// PUT /user/profile is deliberately absent: auth.users states the rule in its
// own UPDATE, and a second guard there would cost a round trip while hiding
// where the real invariant lives.
var guardedRoutes = map[string]string{
	"PUT /user/identity":           "authedLive",
	"POST /user/blobs":             "authedLive",
	"PUT /user/blobs/named/{name}": "authedLive",
	"POST /auth/2fa/totp/setup":    "confirmedLive",
	"POST /auth/2fa/backup-codes":  "confirmedLive",
}

func TestSubjectWritingRoutesRequireALiveAccount(t *testing.T) {
	src := commentFreeSource(t, filepath.Join(repoRoot(t), serverRouting))

	var checked int
	for route, wrapper := range guardedRoutes {
		// mux.Handle("<route>", ...) -- the rest of the line holds the wrappers.
		pattern := regexp.MustCompile(`mux\.Handle\("` + regexp.QuoteMeta(route) + `",([^\n]*)`)
		m := pattern.FindStringSubmatch(src)
		if m == nil {
			t.Errorf("no mux.Handle for %q in %s. If the route moved or was renamed, move "+
				"this gate with it rather than deleting the entry: what it holds is that an "+
				"erased subject cannot write personal data back.", route, serverRouting)
			continue
		}
		checked++
		if !strings.Contains(m[1], wrapper) {
			t.Errorf("%q is not mounted with %s:\n\t%s\n"+
				"Without it the handler runs for a subject whose data has already been "+
				"erased, and writes it back into a store that cannot tell.",
				route, wrapper, strings.TrimSpace(m[1]))
		}
	}

	if checked == 0 {
		t.Fatalf("this gate matched no routes at all in %s, so it proved nothing", serverRouting)
	}
}

// The wrappers have to actually contain the guard. Naming one authedLive while
// it wraps the same chain as authed would satisfy the test above and nothing else.
func TestTheLiveWrappersActuallyCarryTheGuard(t *testing.T) {
	src := commentFreeSource(t, filepath.Join(repoRoot(t), serverRouting))

	for _, name := range []string{"authedLive", "confirmedLive"} {
		decl := regexp.MustCompile(name + ` := func\(h http\.HandlerFunc\) http\.Handler \{\s*\n\s*return ([^\n]*)`)
		m := decl.FindStringSubmatch(src)
		if m == nil {
			t.Errorf("no %s wrapper declared in %s", name, serverRouting)
			continue
		}
		if !strings.Contains(m[1], "liveMw") {
			t.Errorf("%s does not apply liveMw:\n\t%s\nThe name says the account is checked; "+
				"the body has to be what checks it.", name, strings.TrimSpace(m[1]))
		}
	}

	if !strings.Contains(src, "middleware.RequireLiveAccount(") {
		t.Error("server.go no longer constructs middleware.RequireLiveAccount, so whatever " +
			"liveMw now is, it is not the erasure guard")
	}
}
