package rbac

import "testing"

func TestAuditLogRetentionPermissionsAreHumanAdminOnly(t *testing.T) {
	for _, role := range []string{RoleMember, RoleOperator, RoleAgent} {
		if Can(role, PermAuditLogRetentionView) {
			t.Fatalf("%s must not hold audit-log retention visibility", role)
		}
		if Can(role, PermAuditLogRetentionManage) {
			t.Fatalf("%s must not hold audit-log retention management", role)
		}
	}
	for _, role := range []string{RoleOwner, RoleAdmin} {
		if !Can(role, PermAuditLogRetentionView) {
			t.Fatalf("%s must hold audit-log retention visibility", role)
		}
		if !Can(role, PermAuditLogRetentionManage) {
			t.Fatalf("%s must hold audit-log retention management", role)
		}
	}
	if !IsMutating(PermAuditLogRetentionManage) {
		t.Fatal("audit-log retention management must require a verified mutating principal")
	}
	if IsMutating(PermAuditLogRetentionView) {
		t.Fatal("audit-log retention visibility must remain available to unverified admins")
	}
}
