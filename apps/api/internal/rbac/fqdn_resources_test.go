package rbac

import "testing"

func TestFQDNResourcePermissionsAreExplicitAndNarrow(t *testing.T) {
	for _, role := range []string{RoleOwner, RoleAdmin} {
		if !Can(role, PermFQDNResourceView) || !Can(role, PermFQDNResourceManage) {
			t.Fatalf("%s must hold the explicit FQDN resource grants", role)
		}
	}
	for _, role := range []string{RoleMember, RoleOperator, RoleAgent} {
		if Can(role, PermFQDNResourceView) || Can(role, PermFQDNResourceManage) {
			t.Fatalf("%s must not gain FQDN resource access through an unrelated role", role)
		}
	}
	if IsMutating(PermFQDNResourceView) {
		t.Fatal("fqdn_resource:view must remain a read permission")
	}
	if !IsMutating(PermFQDNResourceManage) {
		t.Fatal("fqdn_resource:manage must remain verified-email gated")
	}
}
