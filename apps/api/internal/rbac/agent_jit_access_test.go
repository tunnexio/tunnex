package rbac

import "testing"

func TestAgentJITAccessPermissionsAreHumanAndMutating(t *testing.T) {
	for _, role := range []string{RoleOwner, RoleAdmin} {
		if !Can(role, PermAgentAccessRequest) || !Can(role, PermAgentAccessApprove) {
			t.Fatalf("%s must request and approve agent JIT access", role)
		}
	}
	for _, role := range []string{RoleMember, RoleOperator, RoleAgent} {
		if Can(role, PermAgentAccessRequest) || Can(role, PermAgentAccessApprove) {
			t.Fatalf("%s unexpectedly received organization-wide F10 authority", role)
		}
	}
	if !IsMutating(PermAgentAccessRequest) || !IsMutating(PermAgentAccessApprove) {
		t.Fatal("F10 request and approval permissions must require verified email")
	}
}
