package audit

import "strings"

// The admin plane is written in two namespaces, not one.
//
// Every event class the vocabulary block declares for the operator surface is
// spelled with an underscore -- admin_login, admin_account_create,
// admin_authz_denied -- but seven event types the admin gateway emits were
// never given a constant at all and use a colon instead: admin:role_create,
// admin:role_delete, admin:users_import and the four admin:email_* classes.
// The killswitch trip is admin:killswitch_triggered as well, declared over in
// severity.go because the gateway writes that row straight to the repository.
// Both spellings are in the store today, so a rule that knew only the
// underscore half would have withheld admin_login from a lower-tier caller and
// handed them admin:users_import in the same response.
//
// The rule is over the namespace rather than over a list of classes on purpose.
// A list is a thing the next event type escapes silently, and it escapes in a
// diff that looks like it only adds a constant; a namespace is a thing the next
// event type has to be named out of, which is a deliberate act. tests/spec
// asserts the convention in both directions -- every Admin-named constant
// resolves to a value this function accepts, and every event type the admin
// gateway emits is one this function accepts -- so a new admin-plane class
// cannot arrive under a name the rule does not recognize.
var adminPlaneEventPrefixes = [...]string{"admin_", "admin:"}

// AdminPlaneEventPrefixes returns the namespaces admin-plane event types are
// written in, as a fresh slice the caller may keep or hand to a query filter.
// It is a copy rather than the backing array so that a caller storing it in a
// [repository.AuditFilter] cannot reach back and change what the next caller
// classifies.
func AdminPlaneEventPrefixes() []string {
	out := make([]string, len(adminPlaneEventPrefixes))
	copy(out, adminPlaneEventPrefixes[:])
	return out
}

// IsAdminPlaneEvent reports whether eventType names an event about the operator
// surface itself: who administers the deployment, what they did to it, and what
// was refused to them.
//
// Those rows are the admin roster in historical form. admin_login carries the
// acting admin's id, source address, user agent, username and role;
// admin_account_create carries the created admin's username and role;
// admin_authz_denied carries the refused admin's role; admin_session_rejected
// enumerates admin ids against the paths they were refused. A caller who may
// not read GET /admin/sessions must not read these back out of the audit trail
// instead, which is what the admins:manage permission is for.
func IsAdminPlaneEvent(eventType string) bool {
	for _, prefix := range adminPlaneEventPrefixes {
		if strings.HasPrefix(eventType, prefix) {
			return true
		}
	}
	return false
}
