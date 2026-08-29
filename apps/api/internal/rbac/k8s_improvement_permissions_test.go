package rbac

import "testing"

func TestK8sImprovementPermissionsStaySeparated(t *testing.T) {
	for _, role := range []string{RoleOwner, RoleAdmin} {
		for _, permission := range []Permission{PermK8sHAView, PermK8sHAManage, PermK8sScopeView, PermK8sScopeManage, PermK8sScopeApprove} {
			if !Can(role, permission) {
				t.Fatalf("%s must hold %s", role, permission)
			}
		}
	}
	if !Can(RoleOperator, PermK8sHAView) {
		t.Fatal("operator must be able to observe HA convergence")
	}
	for _, permission := range []Permission{PermK8sHAManage, PermK8sScopeView, PermK8sScopeManage, PermK8sScopeApprove} {
		if Can(RoleOperator, permission) {
			t.Fatalf("operator must not hold %s", permission)
		}
	}
	for _, role := range []string{RoleMember, RoleAgent} {
		for _, permission := range []Permission{PermK8sHAView, PermK8sHAManage, PermK8sScopeView, PermK8sScopeManage, PermK8sScopeApprove} {
			if Can(role, permission) {
				t.Fatalf("%s must not hold %s", role, permission)
			}
		}
	}
	if IsMutating(PermK8sHAView) || IsMutating(PermK8sScopeView) {
		t.Fatal("view permissions must not require mutation identity")
	}
	for _, permission := range []Permission{PermK8sHAManage, PermK8sScopeManage, PermK8sScopeApprove} {
		if !IsMutating(permission) {
			t.Fatalf("%s must retain the verified-human mutation gate", permission)
		}
	}
}
