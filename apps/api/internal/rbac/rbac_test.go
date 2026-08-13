package rbac

import "testing"

func TestCanPermissionMatrix(t *testing.T) {
	cases := []struct {
		role string
		perm Permission
		want bool
	}{
		{RoleMember, PermOrgView, true},
		{RoleMember, PermMemberList, true},
		{RoleMember, PermOrgUpdate, false},
		{RoleMember, PermOrgDelete, false},
		{RoleMember, PermMemberInvite, false},
		{RoleMember, PermMemberManage, false},

		{RoleAdmin, PermOrgView, true},
		{RoleAdmin, PermOrgUpdate, true},
		{RoleAdmin, PermMemberInvite, true},
		{RoleAdmin, PermMemberManage, true},
		{RoleAdmin, PermOrgDelete, false}, // only owners delete the org

		{RoleOwner, PermOrgDelete, true},
		{RoleOwner, PermMemberManage, true},

		{"nonsense", PermOrgView, false},
	}
	for _, c := range cases {
		if got := Can(c.role, c.perm); got != c.want {
			t.Errorf("Can(%q,%q)=%v want %v", c.role, c.perm, got, c.want)
		}
	}
}

// TestCanManageMembershipMatrix is the executable privilege-escalation spec:
// for every (actor, target, newRole) it pins allow/deny.
func TestCanManageMembershipMatrix(t *testing.T) {
	cases := []struct {
		name                   string
		actor, target, newRole string
		want                   bool
	}{
		{"member cannot manage anyone", RoleMember, RoleMember, RoleAdmin, false},
		{"admin promotes member to admin", RoleAdmin, RoleMember, RoleAdmin, true},
		{"admin CANNOT promote to owner", RoleAdmin, RoleMember, RoleOwner, false},
		{"admin CANNOT modify an owner", RoleAdmin, RoleOwner, RoleMember, false},
		{"admin removes a member", RoleAdmin, RoleMember, "", true},
		{"admin CANNOT remove an owner", RoleAdmin, RoleOwner, "", false},
		{"owner promotes to owner", RoleOwner, RoleMember, RoleOwner, true},
		{"owner demotes another owner", RoleOwner, RoleOwner, RoleAdmin, true},
		{"owner removes an owner", RoleOwner, RoleOwner, "", true},
	}
	for _, c := range cases {
		if got := CanManageMembership(c.actor, c.target, c.newRole); got != c.want {
			t.Errorf("%s: CanManageMembership(%q,%q,%q)=%v want %v",
				c.name, c.actor, c.target, c.newRole, got, c.want)
		}
	}
}

// TestSiteManagePermGrants is the S8.1 site:manage deliberate-red: a non-holder (member) is refused
// by construction (the grant table), owner+admin hold it, and it is mutating (email-gated at the
// handler). The handler 403 rides authorize(..., PermSiteManage) — this pins the grants that back it.
func TestSiteManagePermGrants(t *testing.T) {
	if Can(RoleMember, PermSiteManage) {
		t.Fatal("a member must NOT hold site:manage (register/bind/advertise/approve are admin powers)")
	}
	if !Can(RoleAdmin, PermSiteManage) || !Can(RoleOwner, PermSiteManage) {
		t.Fatal("owner and admin must hold site:manage")
	}
	if !IsMutating(PermSiteManage) {
		t.Fatal("site:manage is mutating (must be email-verified gated)")
	}
}

// TestSiteReadVsManageSplit is the S8.3 D5 deliberate-red: a MEMBER reads the site topology (org:view —
// the read-only Sites page) but CANNOT mutate it (site:manage). The handlers back this — ListSites /
// ListSiteSubnets gate org:view; register/advertise/approve/bind/unbind/delete + getSiteReferences gate
// site:manage — so a member sees the topology their traffic traverses yet every mutation still 403s.
func TestSiteReadVsManageSplit(t *testing.T) {
	if !Can(RoleMember, PermOrgView) {
		t.Fatal("a member must read the topology (org:view backs ListSites/ListSiteSubnets)")
	}
	if Can(RoleMember, PermSiteManage) {
		t.Fatal("a member must NOT mutate sites (site:manage gates every mutation + the deletion preview)")
	}
}

// TestOperatorRoleScope — S10.2 D3: the machine 'operator' role is scoped to EXACTLY the operator's verbs
// (register cluster, expose Service, create grant, read org) and NOTHING else — never member/org
// administration, never machine:manage (a machine can't mint more machines), never org:delete.
func TestOperatorRoleScope(t *testing.T) {
	// member:list is READ-ONLY, added for user-subject resolution (WF-OP-1) — resolving a TunnexGrant's
	// user subject email->id. It must NOT bring any membership-MUTATION perm (member:invite / member:manage).
	has := []Permission{PermOrgView, PermK8sManage, PermPolicyManage, PermPolicyView, PermMemberList}
	for _, p := range has {
		if !Can(RoleOperator, p) {
			t.Fatalf("operator must hold %q", p)
		}
	}
	hasNot := []Permission{PermMachineManage, PermMemberManage, PermMemberInvite, PermOrgUpdate, PermOrgDelete, PermMfaManage, PermSiteManage, PermDeviceApprove}
	for _, p := range hasNot {
		if Can(RoleOperator, p) {
			t.Fatalf("operator must NOT hold %q (scope creep)", p)
		}
	}
	// machine:manage is owner-only — never admin, never member, never operator.
	if Can(RoleAdmin, PermMachineManage) || Can(RoleMember, PermMachineManage) || Can(RoleOperator, PermMachineManage) {
		t.Fatal("machine:manage must be OWNER-ONLY")
	}
	if !Can(RoleOwner, PermMachineManage) {
		t.Fatal("owner must hold machine:manage")
	}
}
