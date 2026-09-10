package rbac

import "testing"

func TestHumanRoleSets(t *testing.T) {
	for _, roles := range [][]string{nil, {}, {"operator"}, {"agent"}, {"member", "agent"}, {"unknown"}, {"member", "member"}} {
		if _, err := NormalizeHumanRoles(roles); err == nil {
			t.Errorf("accepted invalid human roles %v", roles)
		}
	}
	roles, err := NormalizeHumanRoles([]string{"member", "ai-admin"})
	if err != nil || len(roles) != 2 || roles[0] != "ai-admin" {
		t.Fatalf("canonical role set: %v, %v", roles, err)
	}
	if !CanAny(roles, PermAIProviderManage) || !CanAny(roles, PermMemberList) {
		t.Fatal("role union lost a permission")
	}
	for _, denied := range []Permission{PermMemberManage, PermPolicyManage, PermOrgUpdate, PermMachineManage} {
		if CanAny(roles, denied) {
			t.Errorf("AI administrator gained %s", denied)
		}
	}
	if CanAny([]string{"member"}, PermAIProviderManage) {
		t.Fatal("removing AI administrator did not remove its permission")
	}
	if !CanAny([]string{"ai-view"}, PermAIProviderView) || CanAny([]string{"ai-view"}, PermAIProviderManage) || CanAny([]string{"ai-view"}, PermAIGatewayManage) {
		t.Fatal("AI viewer must be read-only")
	}
}
