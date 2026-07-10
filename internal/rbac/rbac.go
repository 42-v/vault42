// Package rbac defines the role-based access control model for the admin gateway.
// Roles and permissions are hardcoded — a SQL injection cannot escalate privileges
// by inserting a new role into the database.
package rbac

// Permission represents a specific admin operation.
type Permission string

const (
	KeysList       Permission = "keys:list"
	KeysRotate     Permission = "keys:rotate"
	KeysRevoke     Permission = "keys:revoke"
	AuditRead      Permission = "audit:read"
	UsersList      Permission = "users:list"
	UsersRead      Permission = "users:read"
	UsersLock      Permission = "users:lock"
	UsersUnlock    Permission = "users:unlock"
	UsersDelete    Permission = "users:delete"
	UsersImport    Permission = "users:import"
	SessionsList   Permission = "sessions:list"
	SessionsRevoke Permission = "sessions:revoke"
	ClientsList    Permission = "clients:list"
	ClientsRead    Permission = "clients:read"
	ClientsCreate  Permission = "clients:create"
	ClientsRevoke  Permission = "clients:revoke"
	ClientsRotate  Permission = "clients:rotate"
	ConfigRead     Permission = "config:read"
	ConfigWrite    Permission = "config:write"
	MetricsRead    Permission = "metrics:read"
	AdminsManage   Permission = "admins:manage"
	AdminsCreate   Permission = "admins:create"
	AdminsRevoke   Permission = "admins:revoke"
	RolesList      Permission = "roles:list"
	RolesCreate    Permission = "roles:create"
	RolesDelete    Permission = "roles:delete"
	EmailRead      Permission = "email:read"
	EmailWrite     Permission = "email:write"
	EmailDelete    Permission = "email:delete"
)

// Role represents an admin role. Roles are strictly hierarchical:
// super_admin > operator > viewer.
type Role string

const (
	RoleViewer     Role = "viewer"
	RoleOperator   Role = "operator"
	RoleSuperAdmin Role = "super_admin"
)

// ValidRoles lists all valid role values for validation.
var ValidRoles = []Role{RoleViewer, RoleOperator, RoleSuperAdmin}

// IsValidRole checks whether a role string is a recognized admin role.
func IsValidRole(r string) bool {
	switch Role(r) {
	case RoleViewer, RoleOperator, RoleSuperAdmin:
		return true
	}
	return false
}

// viewerPerms are permissions granted to the viewer role.
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

// operatorPerms are additional permissions granted to the operator role (on top of viewer).
var operatorPerms = map[Permission]bool{
	KeysRotate:     true,
	UsersLock:      true,
	UsersUnlock:    true,
	SessionsRevoke: true,
	ClientsList:    true,
	ClientsRead:    true,
}

// superAdminPerms are additional permissions granted to super_admin (on top of operator).
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
	EmailWrite:    true,
	EmailDelete:   true,
}

// HasPermission checks whether the given role has the specified permission.
// Roles are hierarchical: super_admin includes operator, operator includes viewer.
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
	return false
}

// PermissionsForRole returns all permissions granted to the given role.
func PermissionsForRole(role Role) []Permission {
	var perms []Permission
	all := []Permission{
		KeysList, KeysRotate, KeysRevoke, AuditRead,
		UsersList, UsersRead, UsersLock, UsersUnlock, UsersDelete, UsersImport,
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
