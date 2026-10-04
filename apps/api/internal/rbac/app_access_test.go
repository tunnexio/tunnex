package rbac

import "testing"

func TestAppAccessAuthoritySeparation(t *testing.T) {
	administrative := []Permission{PermAppAccessView, PermAppAccessManage, PermAppAccessGrant, PermAppAccessSessionManage, PermAppAccessEventView}
	for _, role := range []string{RoleOwner, RoleAdmin} {
		for _, perm := range administrative {
			if !Can(role, perm) {
				t.Fatalf("%s lacks %s", role, perm)
			}
		}
		if !Can(role, PermAppAccessUse) {
			t.Fatal("admin cannot explicitly granted app")
		}
	}
	if !Can(RoleMember, PermAppAccessUse) {
		t.Fatal("member requires use capability")
	}
	for _, perm := range administrative {
		if Can(RoleMember, perm) {
			t.Fatalf("member gained %s", perm)
		}
	}
	for _, role := range []string{RoleOperator, RoleAgent, RoleAIAdmin, RoleAIView} {
		for _, perm := range append(administrative, PermAppAccessUse) {
			if Can(role, perm) {
				t.Fatalf("%s gained %s", role, perm)
			}
		}
	}
	for _, perm := range []Permission{PermAppAccessView, PermAppAccessUse, PermAppAccessEventView} {
		if IsMutating(perm) {
			t.Fatalf("read %s mutating", perm)
		}
	}
	for _, perm := range []Permission{PermAppAccessManage, PermAppAccessGrant, PermAppAccessSessionManage} {
		if !IsMutating(perm) {
			t.Fatalf("write %s bypasses email gate", perm)
		}
	}
	if !CanAny([]string{RoleAIView, RoleMember}, PermAppAccessUse) || CanAny([]string{RoleAIView, RoleMember}, PermAppAccessManage) {
		t.Fatal("role union authority wrong")
	}
}
