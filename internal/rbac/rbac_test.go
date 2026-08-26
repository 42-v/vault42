package rbac

import "testing"

func TestHasPermission_ViewerBasics(t *testing.T) {
	allowed := []Permission{KeysList, AuditRead, UsersList, UsersRead, SessionsList, ConfigRead, MetricsRead}
	for _, p := range allowed {
		if !HasPermission(RoleViewer, p) {
			t.Errorf("viewer should have permission %s", p)
		}
	}

	denied := []Permission{
		KeysRotate, KeysRevoke, UsersLock, UsersUnlock, UsersReset, UsersDelete,
		SessionsRevoke, ClientsList, ClientsRead, ClientsCreate, ClientsRevoke, ClientsRotate,
		ConfigWrite, AdminsManage, AdminsCreate, AdminsRevoke,
	}
	for _, p := range denied {
		if HasPermission(RoleViewer, p) {
			t.Errorf("viewer should NOT have permission %s", p)
		}
	}
}

func TestHasPermission_OperatorInheritsViewer(t *testing.T) {
	// Operator should have all viewer permissions
	for _, p := range []Permission{KeysList, AuditRead, UsersList, UsersRead, SessionsList, ConfigRead, MetricsRead} {
		if !HasPermission(RoleOperator, p) {
			t.Errorf("operator should inherit viewer permission %s", p)
		}
	}

	// Operator-specific permissions
	for _, p := range []Permission{KeysRotate, UsersLock, UsersUnlock, UsersReset, SessionsRevoke, ClientsList, ClientsRead} {
		if !HasPermission(RoleOperator, p) {
			t.Errorf("operator should have permission %s", p)
		}
	}

	// Super-admin only
	for _, p := range []Permission{KeysRevoke, UsersDelete, ClientsCreate, ClientsRevoke, ClientsRotate, ConfigWrite, AdminsManage, AdminsCreate, AdminsRevoke} {
		if HasPermission(RoleOperator, p) {
			t.Errorf("operator should NOT have super_admin permission %s", p)
		}
	}
}

func TestHasPermission_SuperAdminHasAll(t *testing.T) {
	all := []Permission{
		KeysList, KeysRotate, KeysRevoke, AuditRead,
		UsersList, UsersRead, UsersLock, UsersUnlock, UsersReset, UsersDelete,
		SessionsList, SessionsRevoke,
		ClientsList, ClientsRead, ClientsCreate, ClientsRevoke, ClientsRotate,
		ConfigRead, ConfigWrite, MetricsRead,
		AdminsManage, AdminsCreate, AdminsRevoke,
	}
	for _, p := range all {
		if !HasPermission(RoleSuperAdmin, p) {
			t.Errorf("super_admin should have permission %s", p)
		}
	}
}

func TestHasPermission_InvalidRole(t *testing.T) {
	if HasPermission(Role("hacker"), KeysList) {
		t.Error("invalid role should have no permissions")
	}
}

func TestIsValidRole(t *testing.T) {
	for _, r := range []string{"viewer", "operator", "super_admin"} {
		if !IsValidRole(r) {
			t.Errorf("%s should be a valid role", r)
		}
	}
	for _, r := range []string{"admin", "root", "hacker", ""} {
		if IsValidRole(r) {
			t.Errorf("%s should NOT be a valid role", r)
		}
	}
}

func TestPermissionsForRole_Counts(t *testing.T) {
	viewerPerms := PermissionsForRole(RoleViewer)
	operatorPerms := PermissionsForRole(RoleOperator)
	superAdminPerms := PermissionsForRole(RoleSuperAdmin)

	if len(viewerPerms) != 9 {
		t.Errorf("viewer should have 9 permissions, got %d", len(viewerPerms))
	}
	if len(operatorPerms) != 16 {
		t.Errorf("operator should have 16 permissions, got %d", len(operatorPerms))
	}
	if len(superAdminPerms) != 31 {
		t.Errorf("super_admin should have 31 permissions, got %d", len(superAdminPerms))
	}

	// Hierarchy: each higher role has strictly more permissions
	if len(operatorPerms) <= len(viewerPerms) {
		t.Error("operator should have more permissions than viewer")
	}
	if len(superAdminPerms) <= len(operatorPerms) {
		t.Error("super_admin should have more permissions than operator")
	}
}
