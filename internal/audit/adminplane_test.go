package audit

import "testing"

// The classification is what GET /admin/audit withholds by, so a class it
// misses is a row a viewer-tier admin reads the admin roster out of.
func TestIsAdminPlaneEventKnowsBothNamespaces(t *testing.T) {
	for _, eventType := range []string{
		AdminLogin, AdminLoginFailure, AdminTwoFASetup, AdminAccountCreate,
		AdminAuthzDenied, AdminSessionRejected, AdminKillswitchTriggered,
		"admin:role_create", "admin:users_import", "admin:email_branding_set",
	} {
		if !IsAdminPlaneEvent(eventType) {
			t.Errorf("%q is an admin-plane event and IsAdminPlaneEvent says it is not, so a caller "+
				"without admins:manage is served it", eventType)
		}
	}
}

// The other direction. Withholding a user-plane class would take the trail away
// from the auditor the viewer tier exists for, which is the failure mode that
// makes "exclude everything that mentions an admin" the wrong rule.
func TestIsAdminPlaneEventLeavesTheUserPlaneAlone(t *testing.T) {
	for _, eventType := range []string{
		LoginSuccess, LoginFailure, PasswordChange, TwoFASetup, SessionRevoke,
		AccountErased, SvcDocGet, "", "administrator_login", "adminx_login",
	} {
		if IsAdminPlaneEvent(eventType) {
			t.Errorf("%q is not an admin-plane event and IsAdminPlaneEvent says it is; the auditor "+
				"loses a row they are meant to read", eventType)
		}
	}
}

// The prefixes leave the package as a copy. A caller parks them in a query
// filter that outlives the call, and a shared backing array would let one
// caller's edit decide what the next caller withholds.
func TestAdminPlaneEventPrefixesAreCopies(t *testing.T) {
	first := AdminPlaneEventPrefixes()
	if len(first) == 0 {
		t.Fatal("no prefixes returned; every event type would classify as user-plane")
	}
	first[0] = "nothing_starts_with_this"

	for _, prefix := range AdminPlaneEventPrefixes() {
		if prefix == "nothing_starts_with_this" {
			t.Fatal("a caller's write reached the package's own copy of the prefixes")
		}
	}
	if !IsAdminPlaneEvent(AdminLogin) {
		t.Error("the classification changed after a caller edited the slice it was handed")
	}
}
