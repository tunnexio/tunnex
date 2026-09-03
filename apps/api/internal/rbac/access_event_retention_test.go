package rbac

import "testing"

func TestAccessEventRetentionManageIsHumanAdminOnly(t *testing.T) {
	for _, role := range []string{RoleMember, RoleOperator, RoleAgent} {
		if Can(role, PermAccessEventRetentionManage) {
			t.Fatalf("%s must not hold access-event retention management", role)
		}
	}
	for _, role := range []string{RoleOwner, RoleAdmin} {
		if !Can(role, PermAccessEventRetentionManage) {
			t.Fatalf("%s must hold access-event retention management", role)
		}
	}
	if !IsMutating(PermAccessEventRetentionManage) {
		t.Fatal("access-event retention management must require a verified mutating principal")
	}
}
