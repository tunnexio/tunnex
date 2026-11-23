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

// K8N-3: turning a cluster's Kubernetes API access on is its own capability. It is not k8s:manage, the
// machine operator does not hold it (no GitOps resource may switch it on), and it keeps the verified-human
// gate every mutating permission has.
func TestK8sAPIManageIsItsOwnHumanPermission(t *testing.T) {
	if PermK8sAPIManage == PermK8sManage || string(PermK8sAPIManage) != "k8s_api:manage" {
		t.Fatalf("k8s_api:manage must be a distinct permission, got %q", PermK8sAPIManage)
	}
	for _, role := range []string{RoleOwner, RoleAdmin} {
		if !Can(role, PermK8sAPIManage) {
			t.Fatalf("%s must hold k8s_api:manage", role)
		}
	}
	for _, role := range []string{RoleOperator, RoleMember, RoleAgent} {
		if Can(role, PermK8sAPIManage) {
			t.Fatalf("%s must not hold k8s_api:manage", role)
		}
	}
	if !Can(RoleOperator, PermK8sManage) {
		t.Fatal("the operator keeps k8s:manage; the two permissions are separate")
	}
	if !IsMutating(PermK8sAPIManage) {
		t.Fatal("k8s_api:manage must keep the verified-email mutation gate")
	}
}
