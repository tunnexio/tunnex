package rbac

import "testing"

func TestAgentTemplatePermissionIsNarrowAndMutating(t *testing.T) {
	if !Can(RoleOwner, PermAgentTemplateManage) || !Can(RoleAdmin, PermAgentTemplateManage) {
		t.Fatal("owner/admin must manage F09 agent groups and templates")
	}
	for _, role := range []string{RoleMember, RoleOperator, RoleAgent} {
		if Can(role, PermAgentTemplateManage) {
			t.Fatalf("%s unexpectedly received agent_template:manage", role)
		}
	}
	if !IsMutating(PermAgentTemplateManage) {
		t.Fatal("agent_template:manage must require verified email")
	}
	if Can(RoleOperator, PermAgentTemplateManage) || !Can(RoleOperator, PermAgentGrantAccess) {
		t.Fatal("operator keeps grant authority but never template administration")
	}
}
