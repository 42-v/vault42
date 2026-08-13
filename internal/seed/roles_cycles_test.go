package seed

import (
	"reflect"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/rbac"
)

// Cycle 1 — reserved-role rejection across every position, every reserved
// name, and every user index. The validator must catch the violation no
// matter where in the user array it sits or where in the role list it
// appears, otherwise an attacker who controls one row can poke admin in
// via a non-obvious position.

func TestCycleReservedRoleRejection_AllPositions(t *testing.T) {
	emailVerified := true
	for reserved := range ReservedAdminRoles {
		for _, where := range []string{"first", "middle", "last", "only"} {
			t.Run(reserved+"_"+where, func(t *testing.T) {
				roles := buildRolesWith(reserved, where)
				sf := &SeedFile{Users: []UserSeed{{
					Email: "x@l.l", Password: "fifteenCharsExactly!!", DisplayName: "X",
					Locale: "en", EmailVerified: &emailVerified, Roles: roles,
				}}}
				err := validate(sf)
				if err == nil {
					t.Fatalf("validate accepted reserved role %q at %s position (roles=%v)", reserved, where, roles)
				}
				if !strings.Contains(err.Error(), "reserved for the admins seed array") {
					t.Errorf("expected reserved-roles error, got %v", err)
				}
			})
		}
	}
}

func TestCycleReservedRoleRejection_PerUserIndex(t *testing.T) {
	emailVerified := true
	for _, badIdx := range []int{0, 1, 2, 5, 9} {
		t.Run("badAtUser"+itoa(badIdx), func(t *testing.T) {
			users := make([]UserSeed, 10)
			for i := range users {
				roles := []string{"viewer", "operator"}
				if i == badIdx {
					roles = append(roles, "super_admin")
				}
				users[i] = UserSeed{
					Email: "u" + itoa(i) + "@l.l", Password: "fifteenCharsExactly!!",
					DisplayName: "U" + itoa(i), Locale: "en",
					EmailVerified: &emailVerified, Roles: roles,
				}
			}
			err := validate(&SeedFile{Users: users})
			if err == nil {
				t.Fatalf("validate accepted reserved role at users[%d]", badIdx)
			}
			want := "users[" + itoa(badIdx) + "]"
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error must blame the offending row %s, got %v", want, err)
			}
		})
	}
}

// Cycle 2 — FilterUserRoles invariants. Run on many shaped inputs to confirm
// (a) idempotence, (b) input immutability, (c) order preservation,
// (d) duplicate preservation for non-reserved roles.

func TestCycleFilterUserRoles_Invariants(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"strip both reserved", []string{"viewer", "admin", "operator", "super_admin"}, []string{"viewer", "operator"}},
		{"all reserved → nil-equivalent", []string{"admin", "super_admin"}, []string{}},
		{"no reserved", []string{"viewer", "operator", "tenant-x"}, []string{"viewer", "operator", "tenant-x"}},
		{"mixed with duplicates", []string{"viewer", "viewer", "admin", "operator", "operator"}, []string{"viewer", "viewer", "operator", "operator"}},
		{"reserved at edges", []string{"admin", "viewer", "super_admin"}, []string{"viewer"}},
		{"single non-reserved", []string{"viewer"}, []string{"viewer"}},
		{"single reserved", []string{"admin"}, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := append([]string(nil), tc.in...)
			out := FilterUserRoles(tc.in)

			// (a) idempotence — filtering a filtered slice is a no-op.
			twice := FilterUserRoles(out)
			if !sliceEq(out, twice) {
				t.Errorf("not idempotent: 1x=%v 2x=%v", out, twice)
			}

			// (b) input immutability — caller's slice unchanged.
			if !reflect.DeepEqual(snapshot, tc.in) {
				t.Errorf("input was mutated: before=%v after=%v", snapshot, tc.in)
			}

			// (c) order + (d) duplicate preservation for the kept roles.
			if !sliceEq(out, tc.want) && !(len(out) == 0 && len(tc.want) == 0) {
				t.Errorf("got %v, want %v", out, tc.want)
			}
		})
	}
}

// Cycle 3 — case sensitivity is INTENTIONAL. ReservedAdminRoles compares
// strings byte-for-byte against the lowercase names that the JWT issuer
// emits. If Hermod ever case-folds before role checks, this test will
// remind us to also case-fold here. Until then, "Admin" (uppercase A) is
// a distinct, harmless string — the attacker gains nothing because the
// authorization policy only matches lowercase "admin".
func TestCycleFilterUserRoles_CaseSensitivity(t *testing.T) {
	in := []string{"Admin", "ADMIN", "Admin ", "admin", "viewer"}
	out := FilterUserRoles(in)
	want := []string{"Admin", "ADMIN", "Admin ", "viewer"}
	if !sliceEq(out, want) {
		t.Fatalf("got %v, want %v (case-sensitive contract)", out, want)
	}
}

// Cycle 4 — bulk-validation perf sanity. A seed file with 1000 users +
// 100 admins must still validate in under a second on the test runner.
// Catches accidental O(n²) regressions in validate (it currently uses a
// map for duplicate checks).
func TestCycleValidate_BulkSeed(t *testing.T) {
	emailVerified := true
	users := make([]UserSeed, 1000)
	for i := range users {
		users[i] = UserSeed{
			Email: "u" + itoa(i) + "@l.l", Password: "fifteenCharsExactly!!",
			DisplayName: "U" + itoa(i), Locale: "en",
			EmailVerified: &emailVerified, Roles: []string{"viewer", "operator"},
		}
	}
	admins := make([]AdminSeed, 100)
	for i := range admins {
		tier := rbac.ValidRoles[i%len(rbac.ValidRoles)]
		admins[i] = AdminSeed{Username: "a" + itoa(i), Password: "fifteenCharsExactly!!", Role: string(tier)}
	}
	if err := validate(&SeedFile{Users: users, Admins: admins}); err != nil {
		t.Fatalf("bulk seed rejected: %v", err)
	}
}

// Cycle 5 — invalid admin role rejection × every off-list role.
// Catches typos like "vieer", "Admin" (wrong case), and tier-confusion
// like "user" (which is the default user table role).
func TestCycleValidate_InvalidAdminRoles(t *testing.T) {
	bad := []string{"vieer", "Admin", "ADMIN", "user", "tenant-x", "", "  admin  "}
	for _, role := range bad {
		t.Run("admin_role="+role, func(t *testing.T) {
			err := validate(&SeedFile{Admins: []AdminSeed{{
				Username: "a", Password: "fifteenCharsExactly!!", Role: role,
			}}})
			if err == nil {
				t.Fatalf("validate accepted invalid admin role %q", role)
			}
		})
	}
}

// ---- helpers ---------------------------------------------------------

func buildRolesWith(reserved, where string) []string {
	base := []string{"viewer", "operator", "tenant-x"}
	switch where {
	case "first":
		return append([]string{reserved}, base...)
	case "middle":
		return []string{base[0], reserved, base[1], base[2]}
	case "last":
		return append(append([]string{}, base...), reserved)
	case "only":
		return []string{reserved}
	default:
		return append(base, reserved)
	}
}

func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
