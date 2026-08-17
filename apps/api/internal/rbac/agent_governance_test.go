package rbac

import "testing"

func TestAgentGovernanceRoleMatrix(t *testing.T) {
	all := []Permission{
		PermAgentEnroll,
		PermAgentViewPrivileged,
		PermAgentManage,
		PermAgentGrantAccess,
		PermAgentRevoke,
	}
	for _, role := range []string{RoleOwner, RoleAdmin} {
		for _, permission := range all {
			if !Can(role, permission) {
				t.Fatalf("%s must hold %s", role, permission)
			}
		}
	}
	for _, permission := range all {
		if Can(RoleMember, permission) {
			t.Fatalf("unrelated member must not hold organization-wide %s", permission)
		}
		if Can(RoleAgent, permission) {
			t.Fatalf("agent principal must not hold %s", permission)
		}
	}
	if !Can(RoleOperator, PermAgentGrantAccess) {
		t.Fatal("operator needs the additional agent-source policy gate")
	}
	for _, permission := range []Permission{PermAgentEnroll, PermAgentViewPrivileged, PermAgentManage, PermAgentRevoke} {
		if Can(RoleOperator, permission) {
			t.Fatalf("operator must not hold %s", permission)
		}
	}
	if IsMutating(PermAgentViewPrivileged) {
		t.Fatal("privileged view is read-only")
	}
}
