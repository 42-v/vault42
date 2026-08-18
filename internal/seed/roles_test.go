package seed

import (
	"strings"
	"testing"
)

// Validator must reject any user whose roles list contains an admin-tier
// name. Those tiers belong to the AdminUser table, never the user table.
func TestValidateRejectsAdminRolesOnUsers(t *testing.T) {
	cases := []struct {
		name string
		role string
	}{
		{"admin alone", "admin"},
		{"super_admin alone", "super_admin"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			emailVerified := true
			sf := &File{
				Users: []UserSeed{{
					Email:         "evil@example.com",
					Password:      "fifteenCharsExactly!!",
					DisplayName:   "Evil",
					Locale:        "en",
					EmailVerified: &emailVerified,
					Roles:         []string{"viewer", tc.role},
				}},
			}
			err := validate(sf)
			if err == nil {
				t.Fatalf("expected validate to reject %q in user roles, got nil", tc.role)
			}
			if !strings.Contains(err.Error(), "reserved for the admins seed array") {
				t.Errorf("error did not mention reserved-roles guard: %v", err)
			}
		})
	}
}

// Validator must accept the non-reserved roles unchanged. Hermod's RBAC
// uses these strings (viewer / operator / arbitrary tenant-defined).
func TestValidateAcceptsNonReservedUserRoles(t *testing.T) {
	emailVerified := true
	sf := &File{
		Users: []UserSeed{{
			Email:         "ok@example.com",
			Password:      "fifteenCharsExactly!!",
			DisplayName:   "OK",
			Locale:        "en",
			EmailVerified: &emailVerified,
			Roles:         []string{"viewer", "operator", "tenant-x"},
		}},
	}
	if err := validate(sf); err != nil {
		t.Fatalf("validate rejected non-reserved roles: %v", err)
	}
}

// Defense in depth: even if a user record somehow has admin/super_admin
// in its roles (direct SQL insert, migration bug, etc.), FilterUserRoles
// must strip them before JWT issuance.
func TestFilterUserRolesStripsAdminTier(t *testing.T) {
	in := []string{"viewer", "admin", "operator", "super_admin", "tenant-x"}
	out := FilterUserRoles(in)

	want := map[string]bool{"viewer": true, "operator": true, "tenant-x": true}
	if len(out) != len(want) {
		t.Fatalf("filter result has %d roles, want %d: %v", len(out), len(want), out)
	}
	for _, r := range out {
		if !want[r] {
			t.Errorf("filter kept disallowed role %q", r)
		}
	}
}

// Empty / nil input → nil out (caller falls back to ["user"] default).
func TestFilterUserRolesEmpty(t *testing.T) {
	if got := FilterUserRoles(nil); got != nil {
		t.Errorf("FilterUserRoles(nil) = %v, want nil", got)
	}
	if got := FilterUserRoles([]string{}); got != nil {
		t.Errorf("FilterUserRoles([]) = %v, want nil", got)
	}
}

// Operator must be in the admin role allowlist now (added alongside the
// per-user roles work so Hermod can cleanly distinguish operator from
// admin without conflating "admin" with the gateway tier).
func TestValidateAcceptsOperatorAdminRole(t *testing.T) {
	sf := &File{
		Admins: []AdminSeed{{
			Username: "ops",
			Password: "fifteenCharsExactly!!",
			Role:     "operator",
		}},
	}
	if err := validate(sf); err != nil {
		t.Fatalf("validate rejected operator admin role: %v", err)
	}
}
