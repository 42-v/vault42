package compliance

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/rbac"
)

// =============================================================================
// OWASP Application Security Verification Standard (ASVS) v4.0.3
// V4: Access Control
// https://owasp.org/www-project-application-security-verification-standard/
// =============================================================================

func permSet(role rbac.Role) map[rbac.Permission]bool {
	set := make(map[rbac.Permission]bool)
	for _, p := range rbac.PermissionsForRole(role) {
		set[p] = true
	}
	return set
}

// --- V4.1.3: Least privilege ---

// The read-only role is defined by the verbs it may carry, not by the list of
// permissions that happen to be in viewerPerms today. Granting viewer anything
// that changes state fails here rather than at the next review.
func TestASVS_V4_1_3_ViewerHoldsNoMutatingPermission(t *testing.T) {
	readOnly := map[string]bool{"list": true, "read": true}
	granted := rbac.PermissionsForRole(rbac.RoleViewer)
	if len(granted) == 0 {
		t.Fatal("V4.1.3: viewer resolved to no permissions at all; the role model did not load")
	}
	for _, p := range granted {
		verb := string(p)
		if i := strings.LastIndex(verb, ":"); i >= 0 {
			verb = verb[i+1:]
		}
		if !readOnly[verb] {
			t.Errorf("V4.1.3: viewer holds %q, a state-changing permission", p)
		}
	}
}

func TestASVS_V4_1_3_RolesAreStrictlyHierarchical(t *testing.T) {
	viewer, operator, super := permSet(rbac.RoleViewer), permSet(rbac.RoleOperator), permSet(rbac.RoleSuperAdmin)

	for p := range viewer {
		if !operator[p] {
			t.Errorf("V4.1.3: operator is missing %q, which viewer holds", p)
		}
	}
	for p := range operator {
		if !super[p] {
			t.Errorf("V4.1.3: super_admin is missing %q, which operator holds", p)
		}
	}
	if len(operator) <= len(viewer) || len(super) <= len(operator) {
		t.Errorf("V4.1.3: roles must strictly widen, got viewer=%d operator=%d super_admin=%d",
			len(viewer), len(operator), len(super))
	}
}

// --- V4.1.5: Access control fails securely ---

func TestASVS_V4_1_5_UnrecognizedRoleGrantsNothing(t *testing.T) {
	everything := rbac.PermissionsForRole(rbac.RoleSuperAdmin)
	for _, role := range []string{"", "admin", "root", "*", "Super_Admin", "SUPER_ADMIN", " super_admin", "viewer "} {
		if rbac.IsValidRole(role) {
			t.Errorf("V4.1.5: %q must not be accepted as a role", role)
		}
		for _, p := range everything {
			if rbac.HasPermission(rbac.Role(role), p) {
				t.Errorf("V4.1.5: unrecognized role %q was granted %q", role, p)
			}
		}
	}
}

// --- V4.1.1: Access control enforced on a trusted service layer ---

// RequireScope gates the KMS unwrap oracle. The match must be exact: a token
// carrying a prefix of the required scope, or a longer scope that merely starts
// with it, confers nothing.
func TestASVS_V4_1_1_RequireScopeEnforcesExactScope(t *testing.T) {
	const required = "kms:unwrap"
	guarded := middleware.RequireScope(required)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		name   string
		claims *vaultcrypto.VaultClaims
		want   int
	}{
		{"unauthenticated", nil, http.StatusUnauthorized},
		{"no scopes", &vaultcrypto.VaultClaims{}, http.StatusForbidden},
		{"unrelated scope", &vaultcrypto.VaultClaims{Scopes: []string{"profile"}}, http.StatusForbidden},
		{"prefix of required", &vaultcrypto.VaultClaims{Scopes: []string{"kms"}}, http.StatusForbidden},
		{"required is a prefix", &vaultcrypto.VaultClaims{Scopes: []string{"kms:unwrap:readonly"}}, http.StatusForbidden},
		{"granted", &vaultcrypto.VaultClaims{Scopes: []string{"profile", required}}, http.StatusOK},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodPost, "/kms/unwrap", nil)
		if tc.claims != nil {
			req = req.WithContext(context.WithValue(req.Context(), middleware.ClaimsKey, tc.claims))
		}
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("V4.1.1: %s: got %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
}

// permIdentToValue maps an rbac constant identifier onto the permission string
// it holds: every constant is <Resource><Verb> and every value is
// "<resource>:<verb>". The mapping is checked against the real permission
// vocabulary by the caller, so a renamed constant fails loudly instead of
// quietly resolving to nothing.
func permIdentToValue(name string) string {
	for i := 1; i < len(name); i++ {
		if name[i] >= 'A' && name[i] <= 'Z' {
			return strings.ToLower(name[:i]) + ":" + strings.ToLower(name[i:])
		}
	}
	return strings.ToLower(name)
}

// adminGuardedRoutes reads the admin gateway router and returns the rbac
// constant guarding each route, keyed by "METHOD /path".
func adminGuardedRoutes(t *testing.T) map[string]string {
	t.Helper()
	path := filepath.Join(repoRoot(t), "internal", "adminapi", "router.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse router.go: %v", err)
	}

	routes := make(map[string]string)
	ast.Inspect(parsed, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Handle" {
			return true
		}
		pattern, ok := call.Args[0].(*ast.BasicLit)
		if !ok || pattern.Kind != token.STRING {
			return true
		}
		guard, ok := call.Args[1].(*ast.CallExpr)
		if !ok {
			return true
		}
		if fn, ok := guard.Fun.(*ast.Ident); !ok || fn.Name != "withPerm" || len(guard.Args) < 2 {
			return true
		}
		perm, ok := guard.Args[1].(*ast.SelectorExpr)
		if !ok {
			return true
		}
		routes[strings.Trim(pattern.Value, `"`)] = perm.Sel.Name
		return true
	})
	return routes
}

// A route wired to the wrong permission is invisible to the rbac tests: the
// permission table stays correct while the endpoint enforces the wrong entry.
// Every admin route that changes state must therefore be gated by a permission
// the read-only role does not hold.
func TestASVS_V4_1_1_MutatingAdminRoutesDenyViewer(t *testing.T) {
	routes := adminGuardedRoutes(t)
	if len(routes) < 20 {
		t.Fatalf("V4.1.1: only %d guarded admin routes parsed out of router.go; the parse is broken", len(routes))
	}

	viewer, vocabulary := permSet(rbac.RoleViewer), permSet(rbac.RoleSuperAdmin)
	mutating := map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}

	for route, ident := range routes {
		perm := rbac.Permission(permIdentToValue(ident))
		if !vocabulary[perm] {
			t.Errorf("V4.1.1: %s is guarded by rbac.%s, which is not a permission super_admin holds", route, ident)
			continue
		}
		method, _, _ := strings.Cut(route, " ")
		if mutating[method] && viewer[perm] {
			t.Errorf("V4.1.1: %s changes state but is gated by %q, which the read-only viewer role holds", route, perm)
		}
	}
}
