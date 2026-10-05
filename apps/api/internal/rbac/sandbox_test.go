package rbac

import "testing"

func TestSandboxCapabilities(t *testing.T) {
	for _, role := range []string{RoleMember, RoleAdmin, RoleOwner} {
		for _, p := range []Permission{PermSandboxView, PermSandboxCreate, PermSandboxManage} {
			if !Can(role, p) {
				t.Fatalf("%s missing %s", role, p)
			}
		}
	}
	for _, role := range []string{RoleOperator, RoleAgent, RoleAIAdmin, RoleAIView} {
		for _, p := range []Permission{PermSandboxView, PermSandboxCreate, PermSandboxManage, PermSandboxAdmin, PermSandboxTemplateManage} {
			if Can(role, p) {
				t.Fatalf("%s inherited %s", role, p)
			}
		}
	}
	if Can(RoleMember, PermSandboxAdmin) || Can(RoleMember, PermSandboxTemplateManage) || IsMutating(PermSandboxView) || !IsMutating(PermSandboxCreate) || !IsMutating(PermSandboxManage) {
		t.Fatal("sandbox capability boundaries wrong")
	}
}
