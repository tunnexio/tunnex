package rbac

import "testing"

// mcp:manage is its own permission: it is not agent_template:manage under another name, and no machine
// or agent principal holds it.
func TestMCPManagePermissionIsNarrowAndMutating(t *testing.T) {
	if !Can(RoleOwner, PermMCPManage) || !Can(RoleAdmin, PermMCPManage) {
		t.Fatal("owner and admin must manage MCP")
	}
	for _, role := range []string{RoleMember, RoleAIAdmin, RoleAIView, RoleOperator, RoleAgent} {
		if Can(role, PermMCPManage) {
			t.Fatalf("%s unexpectedly received mcp:manage", role)
		}
	}
	if !IsMutating(PermMCPManage) {
		t.Fatal("mcp:manage must require a verified email")
	}
	if PermMCPManage == PermAgentTemplateManage || string(PermMCPManage) != "mcp:manage" {
		t.Fatal("mcp:manage must be a permission of its own")
	}
}
