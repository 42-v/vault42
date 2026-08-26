// Package rbac defines the role-based access control model for the admin gateway.
// Roles and permissions are hardcoded — a SQL injection cannot escalate privileges
// by inserting a new role into the database.
//
// The model is three roles over one flat permission vocabulary. The roles form
// a strict chain, viewer ⊂ operator ⊂ super_admin, split by consequence rather
// than by job title: viewer can only observe, operator additionally holds the
// reversible containment levers used during an incident, and super_admin holds
// everything irreversible or privilege-granting. Each [Permission] constant
// names the route it guards and the tier at which it enters the chain.
//
// Enforcement lives outside this package and reads it: internal/adminapi/router.go
// binds one permission to each admin route through withPerm, and
// adminapi.RBACCheck calls [HasPermission] on the session's role. This package
// decides, it does not intercept, so a route that nobody wrapped is a route
// nobody authorizes.
package rbac

// Permission represents a specific admin operation. A permission is the unit
// every admin route is gated on: internal/adminapi/router.go wraps each handler
// in withPerm with exactly one of the constants below, and
// adminapi.RBACCheck refuses the request when [HasPermission] says the session's
// role does not hold it.
type Permission string

// The complete admin permission vocabulary. Nothing outside this list is a
// permission: [HasPermission] returns false for any value not present in one of
// the three role tables, so a typo or an invented string denies rather than
// grants.
//
// Two naming invariants hold across the whole block and are load-bearing:
// every constant is <Resource><Verb> and every value is "<resource>:<verb>".
// tests/compliance/owasp_access_control_test.go derives one from the other to
// check that each admin route is guarded by a permission the read-only role
// does not hold, so renaming a constant without renaming its value fails that
// test rather than silently unguarding a route.
//
// The tier annotations below name the lowest role that holds the permission;
// higher roles inherit it (see [Role]).
const (
	// KeysList grants read-only listing of signing key metadata: kid,
	// algorithm, status and lifecycle timestamps, never key material.
	// Route: GET /admin/keys. Tier: viewer.
	KeysList Permission = "keys:list"
	// KeysRotate grants generating a new signing key and retiring the current
	// one. Retired keys keep verifying until they expire, so a rotation does
	// not invalidate outstanding tokens.
	// Route: POST /admin/keys/rotate. Tier: operator.
	KeysRotate Permission = "keys:rotate"
	// KeysRevoke grants terminal revocation of a signing key. The key leaves
	// JWKS immediately and every token it signed stops verifying, so this is
	// the break-glass response to suspected private key compromise and is not
	// reversible.
	// Route: DELETE /admin/keys/{kid}. Tier: super_admin.
	KeysRevoke Permission = "keys:revoke"

	// AuditRead grants querying the audit log, which records authentication
	// outcomes, admin actions and the client IP behind each. It is read-only by
	// design: there is no corresponding write or delete permission, because an
	// admin who can edit the audit trail can erase their own actions.
	// Route: GET /admin/audit. Tier: viewer.
	AuditRead Permission = "audit:read"

	// UsersList grants paging over end-user accounts.
	// Route: GET /admin/users. Tier: viewer.
	UsersList Permission = "users:list"
	// UsersRead grants reading a single end-user account, including its lock
	// state, roles and enrolled MFA factors.
	// Route: GET /admin/users/{id}. Tier: viewer.
	UsersRead Permission = "users:read"
	// UsersLock grants disabling an account's ability to authenticate. It is
	// the reversible half of the pair with UsersUnlock and is the intended
	// first response to a suspected account takeover.
	// Route: POST /admin/users/{id}/lock. Tier: operator.
	UsersLock Permission = "users:lock"
	// UsersUnlock grants restoring an account locked either by an operator or
	// by the failed-login lockout.
	// Route: POST /admin/users/{id}/unlock. Tier: operator.
	UsersUnlock Permission = "users:unlock"
	// UsersReset grants imposing and lifting a forced password reset on an end
	// user account (auth.users.must_reset_password, migration 039). While the
	// state holds, the account's stored password will not sign it in and the
	// account holder is mailed a reset link instead.
	//
	// It sits at operator for the reason UsersLock does: it is reversible
	// containment. Nothing is destroyed, no privilege is granted, and the
	// account recovers by completing the reset it has already been mailed.
	//
	// One permission covers both directions rather than the two UsersLock and
	// UsersUnlock use. The pair is one lever with one blast radius, and
	// splitting it would only mean something if an admin were meant to impose
	// the state without being able to lift it, which is the opposite of what a
	// reversible control is for. Both halves of the lock pair sit at the same
	// tier anyway, so that split buys nothing this does not.
	// Routes: POST /admin/users/{id}/password-reset-required,
	// DELETE /admin/users/{id}/password-reset-required. Tier: operator.
	UsersReset Permission = "users:reset"
	// UsersDelete grants erasure of an account and the identity, blob and
	// session records that hang off it. This is the GDPR erasure path, it is
	// not reversible, and it is why the role that holds it is the highest one.
	// Route: DELETE /admin/users/{id}. Tier: super_admin.
	UsersDelete Permission = "users:delete"
	// UsersImport grants bulk creation of accounts from a migration payload,
	// including pre-hashed passwords. An import can therefore introduce
	// credentials that never passed the live registration checks, which is why
	// it sits at the top tier rather than with the other user-write verbs.
	// Route: POST /admin/users/import. Tier: super_admin.
	UsersImport Permission = "users:import"

	// SessionsList grants visibility into active refresh-token sessions.
	// Route: GET /admin/sessions. Tier: viewer.
	SessionsList Permission = "sessions:list"
	// SessionsRevoke grants mass revocation of refresh tokens, forcing
	// reauthentication. It is the containment lever for a leaked token and is
	// deliberately available one tier below the destructive permissions.
	// Route: POST /admin/sessions/revoke-all. Tier: operator.
	SessionsRevoke Permission = "sessions:revoke"

	// ClientsList grants listing registered OAuth2 clients. Client records
	// carry redirect URIs and grant configuration, so unlike the other list
	// verbs this one starts at operator rather than viewer.
	// Route: GET /admin/clients. Tier: operator.
	ClientsList Permission = "clients:list"
	// ClientsRead grants reading a single OAuth2 client's configuration.
	// Route: GET /admin/clients/{id}. Tier: operator.
	ClientsRead Permission = "clients:read"
	// ClientsCreate grants registering a new OAuth2 client and minting its
	// secret. A new client is a new way into the token endpoint, so this is
	// super_admin only.
	// Route: POST /admin/clients. Tier: super_admin.
	ClientsCreate Permission = "clients:create"
	// ClientsRevoke grants disabling an OAuth2 client, ending its ability to
	// obtain tokens.
	// Route: POST /admin/clients/{id}/revoke. Tier: super_admin.
	ClientsRevoke Permission = "clients:revoke"
	// ClientsRotate grants replacing an OAuth2 client's secret, which breaks
	// every deployment still holding the old one.
	// Route: POST /admin/clients/{id}/rotate. Tier: super_admin.
	ClientsRotate Permission = "clients:rotate"

	// ConfigRead grants reading the runtime-adjustable configuration.
	// Route: GET /admin/config. Tier: viewer.
	ConfigRead Permission = "config:read"
	// ConfigWrite grants changing and deleting runtime configuration entries.
	// Configuration reaches security behavior, so this permission is treated
	// as equivalent to changing the deployment and is super_admin only.
	// Routes: PUT /admin/config/{key}, DELETE /admin/config/{key}.
	// Tier: super_admin.
	ConfigWrite Permission = "config:write"

	// MetricsRead grants reading aggregate service metrics. It exposes counts
	// and rates, not the records behind them.
	// Route: GET /admin/metrics. Tier: viewer.
	MetricsRead Permission = "metrics:read"

	// AdminsManage grants listing the admin accounts themselves. It is a read
	// verb held only by super_admin: the roster of who can administer the
	// deployment is reconnaissance for an attacker who has taken a lower-tier
	// admin session, so it does not follow the usual "list is viewer" rule.
	// Route: GET /admin/admins. Tier: super_admin.
	AdminsManage Permission = "admins:manage"
	// AdminsCreate grants creating an admin account at any role, including
	// another super_admin. It is the privilege-escalation permission, and the
	// reason no role below super_admin may hold any admins:* verb.
	//
	// "At any role" is literal. Migration 016 refuses an admin row that
	// outranks the account named in its created_by, but nothing in Go compares
	// the two ranks: adminapi.CreateAdmin checks this permission and
	// [IsValidRole], and no more. The invariant holds today only because this
	// permission belongs to the highest tier, so the creator can never be
	// outranked. Granting admins:create to a lower tier would therefore not be
	// a widening of what that tier may create, it would be a full escalation to
	// super_admin, caught only by the database trigger.
	// Route: POST /admin/admins. Tier: super_admin.
	AdminsCreate Permission = "admins:create"
	// AdminsRevoke grants disabling an admin account, up to and including the
	// last remaining super_admin, so it can lock a deployment out of its own
	// admin plane.
	// Route: POST /admin/admins/{id}/revoke. Tier: super_admin.
	AdminsRevoke Permission = "admins:revoke"

	// The roles:* verbs govern auth.app_roles, the end-user role catalog, and
	// not auth.admin_roles. The distinction decides their blast radius, so it
	// is stated once here and assumed by the three constants below.
	// internal/adminapi/roles.go serves all three from the AppRole repository:
	// an app_roles row is a role string an end user may carry in the "roles"
	// claim of a signed access token, which AuthService.effectiveRoles
	// validates the user's stored roles against at JWT issuance. No admin route
	// writes auth.admin_roles at all, so nothing reachable over the admin API
	// can add, rename or remove an admin tier, and no app_roles row can widen
	// this package: [HasPermission] resolves only the three roles compiled in.

	// RolesList grants reading the end-user role catalog.
	// Route: GET /admin/roles. Tier: viewer.
	RolesList Permission = "roles:list"
	// RolesCreate grants adding a role to the end-user catalog, which makes
	// that string issuable in a user's JWT roles claim. Whoever holds it
	// decides what a relying party will see asserted about a user, which is why
	// it is super_admin rather than a catalog-editing tier of its own.
	// Route: POST /admin/roles. Tier: super_admin.
	RolesCreate Permission = "roles:create"
	// RolesDelete grants removing a role from the end-user catalog, which stops
	// the catalog filter from issuing it and so silently drops that claim from
	// every subsequent token. Catalog entries marked reserved refuse deletion.
	// Route: DELETE /admin/roles/{name}. Tier: super_admin.
	RolesDelete Permission = "roles:delete"
	// UsersRoles grants replacing the role set on an existing user, which is
	// the assignment the catalog permissions above only make possible. Holding
	// it means deciding what a relying party is told about a specific person,
	// so it sits beside RolesCreate at super_admin rather than with the
	// operator tier's reversible containment verbs. It is one permission
	// because the route replaces the whole set: there is no narrower grant that
	// adds a role without also being able to remove one.
	// Route: PUT /admin/users/{id}/roles. Tier: super_admin.
	UsersRoles Permission = "users:roles"

	// EmailRead grants reading email branding and the transactional email
	// templates.
	// Routes: GET /admin/email-branding, GET /admin/email-branding/{app},
	// GET /admin/email-templates, GET /admin/email-templates/{app}/{name}.
	// Tier: viewer.
	EmailRead Permission = "email:read"
	// EmailWrite grants editing branding and templates, and rendering a
	// preview. Templates are the text of password-reset and verification mail,
	// so whoever holds this can rewrite the links users are asked to trust,
	// which is a phishing primitive rather than a cosmetic change.
	// Routes: PUT /admin/email-branding/{app}, POST /admin/email-templates/preview,
	// PUT /admin/email-templates/{app}/{name}. Tier: super_admin.
	EmailWrite Permission = "email:write"
	// EmailDelete grants removing branding and template overrides, which
	// reverts the affected mail to the built-in defaults.
	// Routes: DELETE /admin/email-branding/{app},
	// DELETE /admin/email-templates/{app}/{name}. Tier: super_admin.
	EmailDelete Permission = "email:delete"
)

// Role represents an admin role. The three roles form a strict chain, each a
// proper superset of the one below it:
//
//	viewer ⊂ operator ⊂ super_admin
//
// Strict means both halves are enforced, not merely intended.
// [HasPermission] implements containment structurally, by falling through from
// the higher tier's table into the lower one, so a permission granted to viewer
// cannot fail to reach operator. Properness is enforced by
// tests/compliance/owasp_access_control_test.go, which fails when any tier does
// not hold everything the tier below holds and when any tier is not strictly
// larger than the one below it. The same file fails if viewer is ever granted a
// permission whose verb is not "list" or "read".
//
// The practical consequence for granting a role: the tiers are containment, not
// job descriptions. Promoting an admin from viewer to operator never removes an
// ability, and demoting never leaves a stray one behind. Read the tier notes on
// each [Permission] constant to see where a specific ability enters the chain.
//
// A role string that is not exactly one of these three grants nothing at all;
// see [IsValidRole] and the fail-closed note on [HasPermission].
type Role string

// The complete set of admin roles, lowest tier first. These values are the
// contract with the auth.admin_roles table and with the role column on admin
// accounts, so they are compared literally: case, spacing and spelling must
// match exactly.
//
// Two of these strings are not unique to the admin plane. Migration 005 seeds
// "viewer" and "operator" into auth.app_roles as end-user roles, so an ordinary
// user account can legitimately carry roles:["operator"] in a signed access
// token. The two planes never meet inside this service: the admin gateway
// authorizes from auth.admin_users.role reached through a session token and
// never reads a JWT roles claim, and a user JWT never reaches
// [HasPermission]. A relying party that treats the claim as this package's tier
// would be reading a user-plane string as an admin-plane one.
const (
	// RoleViewer is the read-only tier. It holds only list and read verbs and
	// no permission that changes state, which is what makes it safe to hand to
	// on-call responders and auditors who need to see the system without being
	// able to alter it.
	RoleViewer Role = "viewer"
	// RoleOperator is the day-to-day incident-response tier. On top of viewer
	// it adds the reversible containment levers: rotate a signing key, lock and
	// unlock an account, revoke sessions, and read the OAuth2 client registry.
	// It deliberately holds nothing terminal, so an operator can respond to an
	// incident without being able to destroy evidence or accounts.
	RoleOperator Role = "operator"
	// RoleSuperAdmin is the full tier. On top of operator it adds everything
	// irreversible or privilege-granting: key revocation, account erasure, user
	// import, OAuth2 client lifecycle, configuration writes, email template
	// writes, role table changes, and the admins:* verbs that can create
	// another super_admin. Granting this role grants the ability to grant it.
	RoleSuperAdmin Role = "super_admin"
)

// ValidRoles lists every recognized role, lowest tier first. It is not a
// permission source: authorization decisions go through [HasPermission].
//
// The order is lowest tier first and the package tests pin it against the
// permission sets, so it is an ordering with meaning rather than a whim. Nothing
// outside this package depends on it any more: internal/seed used to read a
// role's index here as its privilege rank, which made a reorder anywhere invert
// the rank migration 016 enforces in SQL, and it now keeps its own private map
// of the ranks auth.admin_roles actually holds.
//
// That coupling was worth removing rather than documenting. This is an exported
// slice, so an importer sorting it in place for a strongest-first role picker
// would have inverted the rank at runtime with the source order unchanged, and
// no gate reading this file could have seen it.
var ValidRoles = []Role{RoleViewer, RoleOperator, RoleSuperAdmin}

// IsValidRole reports whether r is exactly one of the three recognized admin
// roles. The comparison is literal, so "Super_Admin", "SUPER_ADMIN",
// " super_admin" and "admin" are all rejected: a role that merely looks right
// is not a role.
func IsValidRole(r string) bool {
	switch Role(r) {
	case RoleViewer, RoleOperator, RoleSuperAdmin:
		return true
	}
	return false
}

// viewerPerms are the permissions granted to the viewer role, and through the
// fallthrough chain to every role. Nothing here may change state: the entries
// are restricted to "list" and "read" verbs so that holding viewer is
// observation only.
var viewerPerms = map[Permission]bool{
	KeysList:     true,
	AuditRead:    true,
	UsersList:    true,
	UsersRead:    true,
	SessionsList: true,
	ConfigRead:   true,
	MetricsRead:  true,
	RolesList:    true,
	EmailRead:    true,
}

// operatorPerms are the permissions operator adds on top of viewer. Each is
// reversible: it can contain an incident but cannot destroy an account, a key
// or an audit record.
var operatorPerms = map[Permission]bool{
	KeysRotate:     true,
	UsersLock:      true,
	UsersUnlock:    true,
	UsersReset:     true,
	SessionsRevoke: true,
	ClientsList:    true,
	ClientsRead:    true,
}

// superAdminPerms are the permissions super_admin adds on top of operator.
// Every entry is either irreversible or privilege-granting, which is the line
// that separates this tier from operator.
var superAdminPerms = map[Permission]bool{
	KeysRevoke:    true,
	UsersDelete:   true,
	ClientsCreate: true,
	ClientsRevoke: true,
	ClientsRotate: true,
	ConfigWrite:   true,
	AdminsManage:  true,
	AdminsCreate:  true,
	AdminsRevoke:  true,
	RolesCreate:   true,
	RolesDelete:   true,
	UsersImport:   true,
	UsersRoles:    true,
	EmailWrite:    true,
	EmailDelete:   true,
}

// HasPermission reports whether role holds perm. It is the single
// authorization decision in the admin plane: every guarded route reaches it
// through adminapi.RBACCheck.
//
// The fallthrough chain is what makes viewer ⊂ operator ⊂ super_admin true by
// construction rather than by three tables that have to be kept consistent by
// hand. Each tier consults its own additions and then falls through to the tier
// below, so a permission added to viewerPerms is automatically held by all
// three roles and cannot be forgotten from the higher ones.
//
// It fails closed on both arguments. An unrecognized role matches no case and
// reaches the final return false, so a corrupted or attacker-supplied role
// string grants nothing rather than defaulting to a tier. An unrecognized
// permission is absent from every map, and a missing key in a map[Permission]bool
// yields false, so an invented permission is denied too.
func HasPermission(role Role, perm Permission) bool {
	switch role {
	case RoleSuperAdmin:
		if superAdminPerms[perm] {
			return true
		}
		fallthrough
	case RoleOperator:
		if operatorPerms[perm] {
			return true
		}
		fallthrough
	case RoleViewer:
		return viewerPerms[perm]
	}
	// Unrecognized role: deny. Reached for "", for a role that was valid in an
	// older schema, and for anything an attacker could get into the role column.
	return false
}

// PermissionsForRole returns every permission role holds, in the order of the
// vocabulary below. An unrecognized role yields nil.
//
// The result is derived from [HasPermission], never from the tier maps
// directly, so this function and the live authorization decision can never
// disagree. The literal list it iterates is the one place the vocabulary is
// enumerated: a new [Permission] constant that is not added here is invisible
// to callers that ask what a role can do, including the compliance tests that
// audit route guards against it.
func PermissionsForRole(role Role) []Permission {
	var perms []Permission
	all := []Permission{
		KeysList, KeysRotate, KeysRevoke, AuditRead,
		UsersList, UsersRead, UsersLock, UsersUnlock, UsersReset, UsersDelete, UsersImport, UsersRoles,
		SessionsList, SessionsRevoke,
		ClientsList, ClientsRead, ClientsCreate, ClientsRevoke, ClientsRotate,
		ConfigRead, ConfigWrite, MetricsRead,
		AdminsManage, AdminsCreate, AdminsRevoke,
		RolesList, RolesCreate, RolesDelete,
		EmailRead, EmailWrite, EmailDelete,
	}
	for _, p := range all {
		if HasPermission(role, p) {
			perms = append(perms, p)
		}
	}
	return perms
}
