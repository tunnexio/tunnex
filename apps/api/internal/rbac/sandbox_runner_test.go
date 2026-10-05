package rbac

import "testing"

func TestSandboxRunnerManagementRequiresOrganizationAdministration(t *testing.T) {
	for _, role := range []string{RoleOwner, RoleAdmin} {
		if !Can(role, PermSandboxRunnerManage) {
			t.Fatalf("%s must manage scoped runner enrollment", role)
		}
	}
	for _, role := range []string{RoleMember, RoleOperator, RoleAgent, RoleAIAdmin, RoleAIView} {
		if Can(role, PermSandboxRunnerManage) {
			t.Fatalf("%s must not enroll a runner", role)
		}
	}
}
