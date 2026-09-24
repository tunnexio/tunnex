package rbac

import "testing"

func TestIPsecManageRoleBoundary(t *testing.T) {
	permission := Permission("ipsec:manage")
	for role := range Policy() {
		t.Run(role, func(t *testing.T) {
			want := role == RoleOwner || role == RoleAdmin
			if got := Can(role, permission); got != want {
				t.Fatalf("Can(%q, %q) = %v, want %v", role, permission, got, want)
			}
		})
	}
	for _, role := range []string{"", "unknown"} {
		if Can(role, permission) {
			t.Fatalf("unknown role %q must not manage IPsec", role)
		}
	}
	if !IsMutating(permission) {
		t.Fatal("IPsec management must retain verified-principal mutation enforcement")
	}
}

func TestIPsecManageRoleSetUnion(t *testing.T) {
	permission := Permission("ipsec:manage")
	for _, tc := range []struct {
		name  string
		roles []string
		want  bool
	}{
		{"empty", nil, false},
		{"readers and AI administrator", []string{RoleMember, RoleAIView, RoleAIAdmin}, false},
		{"machine roles", []string{RoleAgent, RoleOperator}, false},
		{"unknown mixed with member", []string{"unknown", RoleMember}, false},
		{"administrator after reader", []string{RoleMember, RoleAdmin}, true},
		{"owner after AI administrator", []string{RoleAIAdmin, RoleOwner}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CanAny(tc.roles, permission); got != tc.want {
				t.Fatalf("CanAny(%v, %q) = %v, want %v", tc.roles, permission, got, tc.want)
			}
		})
	}
}
