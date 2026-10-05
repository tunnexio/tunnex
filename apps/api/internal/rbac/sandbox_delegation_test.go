package rbac

import "testing"

func TestSandboxDelegationAdministrationHumanOnly(t *testing.T) {
	for _, role := range []string{RoleOwner, RoleAdmin} {
		if !Can(role, PermSandboxDelegateManage) {
			t.Fatal("human administrator missing grant authority")
		}
	}
	for _, role := range []string{RoleMember, RoleAIView, RoleAIAdmin, RoleOperator, RoleAgent} {
		if Can(role, PermSandboxDelegateManage) {
			t.Fatalf("%s can delegate", role)
		}
	}
	if !IsMutating(PermSandboxDelegateManage) {
		t.Fatal("unverified delegation mutation")
	}
	for _, role := range []string{RoleOperator, RoleAgent} {
		for _, perm := range []Permission{PermSandboxCreate, PermSandboxView, PermSandboxManage} {
			if Can(role, perm) {
				t.Fatalf("unscoped %s authority for %s", perm, role)
			}
		}
	}
}
