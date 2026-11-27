package rbac

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
)

// RBAC-1 (docs/RBAC-1-roles.md): four human roles between Member and Admin. Each role's grant list is pinned
// EXACTLY, so a permission can neither be added to nor dropped from a new role without this test naming it.
var rbac1Grants = map[string][]Permission{
	RoleAuditor: {
		PermAIGatewayView, PermAIModelAccessView, PermAIProviderView, PermAIWorkloadView,
		PermAgentViewPrivileged, PermAppAccessEventView, PermAppAccessView, PermAuditLogRetentionView,
		PermAuditViewAll, PermBeamAuditView, PermDeviceView, PermFQDNResourceView, PermK8sHAView,
		PermK8sScopeView, PermMemberList, PermOrgView, PermPolicyView, PermSandboxView,
	},
	RoleAgentsAdmin: {
		PermAgentAccessApprove, PermAgentAccessRequest, PermAgentCredentialRotate, PermAgentEnroll,
		PermAgentGrantAccess, PermAgentMCPToolApprovalApprove, PermAgentMCPToolPolicyManage, PermAgentManage,
		PermAgentRevoke, PermAgentRuntimeManage, PermAgentTemplateManage, PermAgentViewPrivileged,
		PermMCPManage, PermMemberList, PermOrgView, PermPolicyView,
	},
	RoleNetworkAdmin: {
		PermConnectivityManage, PermDeviceApprovalManage, PermDeviceApprove,
		PermDeviceHealthManage, PermDeviceRestore, PermDeviceTransfer, PermDeviceView, PermFQDNResourceManage,
		PermFQDNResourceView, PermGatewayManage, PermIPsecManage, PermK8sAPIManage, PermK8sHAManage,
		PermK8sHAView, PermK8sManage, PermK8sScopeApprove, PermK8sScopeManage, PermK8sScopeView, PermMemberList,
		PermOrgView, PermPolicyRuleManage, PermPolicyView, PermResourceManage, PermSiteManage,
	},
	RoleHelpdesk: {
		PermDeviceApprove, PermDeviceRestore, PermDeviceView, PermMemberList, PermMfaReset, PermOrgView,
	},
}

func TestRBAC1NewRoleGrantsAreExact(t *testing.T) {
	policy := Policy()
	for role, want := range rbac1Grants {
		if !ValidRole(role) {
			t.Fatalf("%s is not a role", role)
		}
		w := make([]string, len(want))
		for i, p := range want {
			w[i] = string(p)
		}
		sort.Strings(w)
		if got := policy[role]; strings.Join(got, ",") != strings.Join(w, ",") {
			t.Errorf("%s grants:\n got  %v\n want %v", role, got, w)
		}
	}
}

// No new role assigns roles or touches the organization itself, the licence or machine credentials.
func TestRBAC1NewRolesNeverAdministerPeopleOrTheOrg(t *testing.T) {
	forbidden := []Permission{PermMemberInvite, PermMemberManage, PermOrgUpdate, PermOrgDelete, PermLicenseManage, PermMachineManage}
	for role := range rbac1Grants {
		for _, p := range forbidden {
			if Can(role, p) {
				t.Errorf("%s must not hold %s", role, p)
			}
		}
		for _, target := range []string{RoleMember, RoleOwner, RoleAdmin, role} {
			for _, newRole := range []string{"", RoleMember, RoleAdmin, role} {
				if CanManageMembership(role, target, newRole) {
					t.Errorf("CanManageMembership(%s,%s,%q) must be false", role, target, newRole)
				}
			}
		}
	}
}

// The auditor holds every read the admin holds, minus the ones that expose secrets or private content.
// Derived mechanically: every admin permission named *:view, *_view or *:list is a read.
func TestRBAC1AuditorIsAdminReadsMinusSecrets(t *testing.T) {
	excluded := map[Permission]string{
		// Gates no server route today; holding it only offers a terminal page the auditor cannot use.
		PermServerAccessView: "no route; terminal page only",
	}
	for _, p := range Policy()[RoleAdmin] {
		perm := Permission(p)
		read := strings.HasSuffix(p, ":view") || strings.Contains(p, "_view") || strings.HasSuffix(p, ":list") || strings.Contains(p, ":view_")
		if !read {
			continue
		}
		if _, skip := excluded[perm]; skip {
			if Can(RoleAuditor, perm) {
				t.Errorf("auditor must not hold %s (%s)", perm, excluded[perm])
			}
			continue
		}
		if !Can(RoleAuditor, perm) {
			t.Errorf("auditor is missing the admin read %s", perm)
		}
	}
	for _, p := range Policy()[RoleAuditor] {
		if IsMutating(Permission(p)) && Permission(p) != PermAIWorkloadView {
			t.Errorf("auditor holds %s, which is not a read", p)
		}
	}
	for _, secret := range []Permission{PermServerAccessReplay, PermVaultUse, PermVaultAssign, PermAgentMCPToolApprovalApprove, PermAgentEnroll} {
		if Can(RoleAuditor, secret) {
			t.Errorf("auditor must not hold %s (secrets or private content)", secret)
		}
	}
}

func TestRBAC1AuditViewAllHolders(t *testing.T) {
	for role := range rolePermissions {
		want := role == RoleOwner || role == RoleAdmin || role == RoleAuditor
		if Can(role, PermAuditViewAll) != want {
			t.Errorf("audit:view_all held by %s = %v, want %v", role, !want, want)
		}
	}
}

// Every split permission is held by owner and admin, so splitting changed nothing for them.
func TestRBAC1SplitPermissionsKeepOwnerAndAdmin(t *testing.T) {
	for _, p := range []Permission{PermAuditViewAll, PermGatewayManage, PermDeviceView, PermMfaReset, PermDeviceApprovalManage, PermResourceManage} {
		if !Can(RoleOwner, p) || !Can(RoleAdmin, p) {
			t.Errorf("owner and admin must hold %s", p)
		}
		if Can(RoleOperator, p) || Can(RoleAgent, p) || Can(RoleMember, p) {
			t.Errorf("%s must not reach member, operator or agent", p)
		}
	}
	for _, read := range []Permission{PermAuditViewAll, PermDeviceView} {
		if IsMutating(read) {
			t.Errorf("%s is a read", read)
		}
	}
}

func TestRBAC1HumanRoleOrderAndMachineRoles(t *testing.T) {
	all := []string{RoleMember, RoleHelpdesk, RoleAIView, RoleAuditor, RoleAIAdmin, RoleAgentsAdmin, RoleNetworkAdmin, RoleAdmin, RoleOwner}
	got, err := NormalizeHumanRoles(all)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{RoleOwner, RoleAdmin, RoleNetworkAdmin, RoleAgentsAdmin, RoleAuditor, RoleHelpdesk, RoleAIAdmin, RoleAIView, RoleMember}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("order %v, want %v", got, want)
	}
	for _, r := range []string{RoleAuditor, RoleAgentsAdmin, RoleNetworkAdmin, RoleHelpdesk} {
		if p, err := NormalizeHumanRoles([]string{r, RoleMember}); err != nil || p[0] != r {
			t.Errorf("%s + member: %v %v", r, p, err)
		}
	}
	for _, machine := range []string{RoleOperator, RoleAgent} {
		if _, err := NormalizeHumanRoles([]string{RoleHelpdesk, machine}); err == nil {
			t.Errorf("%s must stay non-assignable", machine)
		}
	}
}

func TestRBAC1AdminGradeAndHelpdeskCeiling(t *testing.T) {
	for _, r := range []string{RoleOwner, RoleAdmin, RoleNetworkAdmin, RoleAgentsAdmin, RoleAuditor, RoleAIAdmin} {
		if !IsAdminGrade([]string{RoleMember, r}) {
			t.Errorf("%s is admin-grade", r)
		}
	}
	for _, r := range []string{RoleMember, RoleHelpdesk, RoleAIView} {
		if IsAdminGrade([]string{r}) {
			t.Errorf("%s is not admin-grade", r)
		}
	}
	cases := []struct {
		actor []string
		perm  Permission
		want  bool
	}{
		{[]string{RoleHelpdesk}, PermMfaReset, true},
		{[]string{RoleHelpdesk, RoleMember}, PermMfaReset, true},
		{[]string{RoleHelpdesk, RoleAdmin}, PermMfaReset, false},
		{[]string{RoleHelpdesk, RoleNetworkAdmin}, PermDeviceApprove, false},
		{[]string{RoleHelpdesk, RoleNetworkAdmin}, PermMfaReset, true},
		{[]string{RoleAdmin}, PermMfaReset, false},
		{[]string{RoleMember}, PermMfaReset, false},
	}
	for _, c := range cases {
		if got := HelpdeskCeilingApplies(c.actor, c.perm); got != c.want {
			t.Errorf("HelpdeskCeilingApplies(%v,%s)=%v want %v", c.actor, c.perm, got, c.want)
		}
	}
}

func TestRBAC1PrivateAlertDestinationStaysOwnerOnly(t *testing.T) {
	for role := range rolePermissions {
		if Can(role, PermAlertingPrivateDestination) != (role == RoleOwner) {
			t.Errorf("alerting:private_destination held by %s", role)
		}
	}
}

// The shared fixture is also read by apps/web/test/rbac1roles.test.ts against the hand-mirrored
// canManageMembership, so the two implementations are checked against one table.
func TestRBAC1CanManageMembershipSharedFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/can_manage_membership.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Actor   string `json:"actor"`
			Target  string `json:"target"`
			NewRole string `json:"new_role"`
			Allowed bool   `json:"allowed"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) < 9*9 {
		t.Fatalf("fixture has only %d cases", len(fixture.Cases))
	}
	for _, c := range fixture.Cases {
		if got := CanManageMembership(c.Actor, c.Target, c.NewRole); got != c.Allowed {
			t.Errorf("CanManageMembership(%q,%q,%q)=%v, fixture says %v", c.Actor, c.Target, c.NewRole, got, c.Allowed)
		}
	}
}
