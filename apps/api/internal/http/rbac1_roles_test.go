package http

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/password"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// RBAC-1 targeted tests (docs/RBAC-1-roles.md, Validation). The route matrix proves every uncovered mutation
// answers 403; these prove the relational rules a grant table cannot express.

// rbac1Person adds a person to org A of the RBAC-0 fixture holding roles.
func (f *rbac0Fixture) rbac1Person(t *testing.T, name string, roles ...string) sqlc.User {
	t.Helper()
	u, err := f.q.CreateUser(f.ctx, sqlc.CreateUserParams{Email: name + "-" + uuid.NewString()[:8] + "@rbac1.test", Name: name})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := password.Hash(rbac0Password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE users SET email_verified_at=now(), password_hash=$2 WHERE id=$1`, u.ID, hash); err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `INSERT INTO memberships(org_id,user_id,role,roles) VALUES($1,$2,$3,$4)`, f.orgA, u.ID, roles[0], roles); err != nil {
		t.Fatal(err)
	}
	if u, err = f.q.GetUserByID(f.ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	return u
}

// Helpdesk resets MFA for ordinary people, never for anyone holding an admin-grade role. A Helpdesk person who
// also holds a role granting mfa:reset is not limited by the ceiling.
func TestRBAC1HelpdeskCannotResetAdminGradeMFA(t *testing.T) {
	f := newRBAC0Fixture(t, true)
	helpdesk := f.rbac1Person(t, "helpdesk", rbac.RoleHelpdesk, rbac.RoleMember)
	plain := f.rbac1Person(t, "plain", rbac.RoleMember)
	aiViewer := f.rbac1Person(t, "ai-viewer", rbac.RoleAIView, rbac.RoleMember)
	for _, grade := range []string{rbac.RoleAdmin, rbac.RoleNetworkAdmin, rbac.RoleAgentsAdmin, rbac.RoleAuditor, rbac.RoleAIAdmin} {
		target := f.rbac1Person(t, "target-"+grade, rbac.RoleMember, grade)
		_, err := f.server.AdminResetMfa(f.as(t, helpdesk), api.AdminResetMfaRequestObject{OrgId: f.orgA, UserId: target.ID})
		if !hasCode(err, 403, "forbidden") {
			t.Fatalf("helpdesk reset MFA of %s: want 403 forbidden, got %v", grade, err)
		}
		if !strings.Contains(err.Error(), "administrator role") {
			t.Fatalf("helpdesk refusal for %s is not the plain message: %v", grade, err)
		}
	}
	if _, err := f.server.AdminResetMfa(f.as(t, helpdesk), api.AdminResetMfaRequestObject{OrgId: f.orgA, UserId: f.ownerA.ID}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("helpdesk reset MFA of the owner: %v", err)
	}
	// Ordinary people pass the ceiling and reach the RBAC-0 step-up (the reset itself is not the point here).
	for _, target := range []sqlc.User{plain, aiViewer} {
		_, err := f.server.AdminResetMfa(f.as(t, helpdesk), api.AdminResetMfaRequestObject{OrgId: f.orgA, UserId: target.ID})
		if mfaHandlerErrorCode(err) != "current_password_required" {
			t.Fatalf("helpdesk reset MFA of %s: want the step-up, got %v", target.Name, err)
		}
	}
	// Admin + Helpdesk: admin grants mfa:reset too, so the ceiling does not apply.
	both := f.rbac1Person(t, "admin-helpdesk", rbac.RoleAdmin, rbac.RoleHelpdesk)
	netAdmin := f.rbac1Person(t, "net", rbac.RoleNetworkAdmin)
	if _, err := f.server.AdminResetMfa(f.as(t, both), api.AdminResetMfaRequestObject{OrgId: f.orgA, UserId: netAdmin.ID}); mfaHandlerErrorCode(err) != "current_password_required" {
		t.Fatalf("admin+helpdesk reset MFA of a network admin: want the step-up, got %v", err)
	}
	// Network admin holds no MFA reset at all.
	if _, err := f.server.AdminResetMfa(f.as(t, netAdmin), api.AdminResetMfaRequestObject{OrgId: f.orgA, UserId: plain.ID}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("network admin reset MFA: %v", err)
	}
}

// Helpdesk approves, rejects and restores devices of ordinary people only.
func TestRBAC1HelpdeskDeviceActionsStopAtAdminGrade(t *testing.T) {
	f := newRBAC0Fixture(t, true)
	helpdesk := f.rbac1Person(t, "helpdesk", rbac.RoleHelpdesk)
	plain := f.rbac1Person(t, "plain", rbac.RoleMember)
	net := f.rbac1Person(t, "net", rbac.RoleNetworkAdmin, rbac.RoleMember)
	node, plainNode := uuid.New(), uuid.New()
	for i, id := range []uuid.UUID{node, plainNode} {
		key := make([]byte, 32)
		key[0] = byte(i + 1)
		if _, err := f.pool.Exec(f.ctx, `INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint,status) VALUES ($1,$2,$3,$4,$5,'gw.example:51820','active')`,
			id, f.orgA, "rbac1-gw-"+id.String()[:8], "rbac1-"+id.String(), base64.StdEncoding.EncodeToString(key)); err != nil {
			t.Fatal(err)
		}
	}
	device := func(owner uuid.UUID, nodeID uuid.UUID, n byte) uuid.UUID {
		id := uuid.New()
		key := make([]byte, 32)
		key[0] = n
		if _, err := f.pool.Exec(f.ctx, `INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES($1,$2,$3,$4,'rbac1',$5,$6,'active','human')`,
			id, f.orgA, owner, nodeID, base64.StdEncoding.EncodeToString(key), fmt.Sprintf("10.98.0.%d", n)); err != nil {
			t.Fatal(err)
		}
		return id
	}
	adminDevice := device(net.ID, node, 2)
	plainDevice := device(plain.ID, plainNode, 3)
	ctx := f.as(t, helpdesk)
	for name, call := range map[string]func() error{
		"approve": func() error {
			_, e := f.server.ApproveDevice(ctx, api.ApproveDeviceRequestObject{OrgId: f.orgA, DeviceId: adminDevice})
			return e
		},
		"reject": func() error {
			_, e := f.server.RejectDevice(ctx, api.RejectDeviceRequestObject{OrgId: f.orgA, DeviceId: adminDevice})
			return e
		},
		"restore": func() error {
			_, e := f.server.RestoreNodeDevices(ctx, api.RestoreNodeDevicesRequestObject{OrgId: f.orgA, NodeId: node, Body: &api.RestoreNodeDevicesJSONRequestBody{TargetNodeId: plainNode}})
			return e
		},
	} {
		err := call()
		if !hasCode(err, 403, "forbidden") || !strings.Contains(err.Error(), "administrator role") {
			t.Fatalf("helpdesk %s on a network admin's device: want the helpdesk refusal, got %v", name, err)
		}
	}
	if err := f.server.requireHelpdeskDeviceCeiling(ctx, f.orgA, plainDevice, rbac.PermDeviceApprove); err != nil {
		t.Fatalf("helpdesk on an ordinary person's device: %v", err)
	}
	if err := f.server.requireHelpdeskNodeCeiling(ctx, f.orgA, plainNode, rbac.PermDeviceRestore); err != nil {
		t.Fatalf("helpdesk restore on a gateway of ordinary people: %v", err)
	}
	// Network admin approves anybody's device: the ceiling is Helpdesk's only.
	if err := f.server.requireHelpdeskDeviceCeiling(f.as(t, net), f.orgA, adminDevice, rbac.PermDeviceApprove); err != nil {
		t.Fatalf("network admin is not under the helpdesk ceiling: %v", err)
	}
	// Helpdesk does not transfer devices, and cannot switch device approval off for the organization.
	if _, err := f.server.TransferNodeDevices(ctx, api.TransferNodeDevicesRequestObject{OrgId: f.orgA, NodeId: plainNode, Body: &api.TransferNodeDevicesJSONRequestBody{TargetNodeId: node}}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("helpdesk transfer: %v", err)
	}
	if _, err := f.server.SetDeviceApproval(ctx, api.SetDeviceApprovalRequestObject{OrgId: f.orgA, Body: &api.SetDeviceApprovalJSONRequestBody{Mode: "off"}}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("helpdesk switched device approval: %v", err)
	}
}

func rbac1Principal(org uuid.UUID, roles ...string) context.Context {
	return authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: uuid.New(), EmailVerified: true,
		Roles: map[uuid.UUID]string{org: roles[0]}, RoleSets: map[uuid.UUID][]string{org: roles}})
}

// AI Agents admin authors rules whose source is an agent and nothing else: not a person, a user group, a site
// or a CIDR. The permission gate decides before any service is touched.
func TestRBAC1AgentsAdminRuleSources(t *testing.T) {
	org := uuid.New()
	ctx := rbac1Principal(org, rbac.RoleAgentsAdmin)
	kind := func(k string) *api.CreatePolicyRuleRequestSrcKind {
		v := api.CreatePolicyRuleRequestSrcKind(k)
		return &v
	}
	id := uuid.New()
	cidr := "10.0.0.0/24"
	for name, body := range map[string]*api.CreatePolicyRuleJSONRequestBody{
		"user":           {SrcKind: kind("user"), SrcUserId: &id, DstKind: "resource", DstResourceId: &id},
		"group":          {SrcKind: kind("group"), SrcGroupId: &id, DstKind: "resource", DstResourceId: &id},
		"implicit group": {SrcGroupId: &id, DstKind: "resource", DstResourceId: &id},
		"site":           {SrcKind: kind("site"), SrcSiteId: &id, DstKind: "resource", DstResourceId: &id},
		"cidr":           {SrcKind: kind("cidr"), SrcCidr: &cidr, DstKind: "resource", DstResourceId: &id},
	} {
		if _, err := (apiServer{}).CreatePolicyRule(ctx, api.CreatePolicyRuleRequestObject{OrgId: org, Body: body}); !hasCode(err, 403, "forbidden") {
			t.Errorf("agents admin created a %s rule: %v", name, err)
		}
	}
	// An agent source passes the permission gate (and then needs the policy service, absent here).
	agentBody := &api.CreatePolicyRuleJSONRequestBody{SrcKind: kind("agent"), SrcDeviceId: &id, DstKind: "resource", DstResourceId: &id}
	if _, err := (apiServer{}).CreatePolicyRule(ctx, api.CreatePolicyRuleRequestObject{OrgId: org, Body: agentBody}); hasCode(err, 403, "forbidden") {
		t.Fatalf("agents admin refused an agent rule: %v", err)
	}
	if _, err := (apiServer{}).DeletePolicyRule(ctx, api.DeletePolicyRuleRequestObject{OrgId: org, RuleId: id}); hasCode(err, 403, "forbidden") {
		t.Fatalf("agents admin refused before the rule's source was known: %v", err)
	}
	// Network admin authors people rules but not agent rules; the operator keeps authoring both (RBAC-0 D4).
	net := rbac1Principal(org, rbac.RoleNetworkAdmin)
	if _, err := (apiServer{}).CreatePolicyRule(net, api.CreatePolicyRuleRequestObject{OrgId: org, Body: agentBody}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("network admin created an agent rule: %v", err)
	}
	for _, src := range []string{"", "user", "group", "site", "cidr"} {
		if got := rulePermissionForSource(src); got != rbac.PermPolicyRuleManage {
			t.Errorf("source %q needs %s, want policy_rule:manage", src, got)
		}
	}
	for _, src := range []string{"agent", "agent_group"} {
		if got := rulePermissionForSource(src); got != rbac.PermAgentGrantAccess {
			t.Errorf("source %q needs %s, want agent:grant_access", src, got)
		}
	}
	if !rbac.CanAny([]string{rbac.RoleOperator}, rbac.PermAgentGrantAccess) || !rbac.CanAny([]string{rbac.RoleOperator}, rbac.PermPolicyRuleManage) {
		t.Fatal("the GitOps operator must keep both rule permissions")
	}
}

// Network admin runs the network and still cannot switch Zero Trust, edit user groups or reconfigure
// directory sync (policy:manage stays owner and admin).
func TestRBAC1NetworkAdminCannotAdministerPolicy(t *testing.T) {
	org := uuid.New()
	ctx := rbac1Principal(org, rbac.RoleNetworkAdmin)
	s := apiServer{}
	for name, call := range map[string]func() error{
		"zero trust mode": func() error {
			_, e := s.SetZeroTrustMode(ctx, api.SetZeroTrustModeRequestObject{OrgId: org, Body: &api.SetZeroTrustModeJSONRequestBody{Mode: "open"}})
			return e
		},
		"create group": func() error {
			_, e := s.CreateGroup(ctx, api.CreateGroupRequestObject{OrgId: org, Body: &api.CreateGroupJSONRequestBody{Name: "x"}})
			return e
		},
		"add group member": func() error {
			_, e := s.AddGroupMember(ctx, api.AddGroupMemberRequestObject{OrgId: org, GroupId: uuid.New(), Body: &api.AddGroupMemberJSONRequestBody{UserId: uuid.New()}})
			return e
		},
		"directory sync": func() error {
			_, e := s.PutIdpSyncConfig(ctx, api.PutIdpSyncConfigRequestObject{OrgId: org, Body: &api.PutIdpSyncConfigJSONRequestBody{ClientId: "x", ClientSecret: "y"}})
			return e
		},
		"map directory group": func() error {
			_, e := s.MapIdpGroup(ctx, api.MapIdpGroupRequestObject{OrgId: org, Provider: "google", Body: &api.MapIdpGroupJSONRequestBody{IdpGroupId: "g"}})
			return e
		},
		"enforce MFA": func() error {
			_, e := s.SetMfaEnforce(ctx, api.SetMfaEnforceRequestObject{OrgId: org, Body: &api.SetMfaEnforceJSONRequestBody{Enforce: false}})
			return e
		},
		"rename organization": func() error {
			_, e := s.UpdateOrganization(ctx, api.UpdateOrganizationRequestObject{OrgId: org, Body: &api.UpdateOrganizationJSONRequestBody{Name: "x"}})
			return e
		},
	} {
		if err := call(); !hasCode(err, 403, "forbidden") {
			t.Errorf("network admin %s: want 403 forbidden, got %v", name, err)
		}
	}
}

// The auditor reads the organization-wide audit log (everyone else without audit:view_all reads only their
// own actions); the route matrix separately proves every write answers 403.
func TestRBAC1AuditorReadsTheOrganizationAuditLog(t *testing.T) {
	org := uuid.New()
	for _, tc := range []struct {
		roles   []string
		orgWide bool
	}{
		{[]string{rbac.RoleAuditor}, true},
		{[]string{rbac.RoleOwner}, true},
		{[]string{rbac.RoleAdmin}, true},
		{[]string{rbac.RoleMember, rbac.RoleAuditor}, true},
		{[]string{rbac.RoleMember}, false},
		{[]string{rbac.RoleAIAdmin}, false},
		{[]string{rbac.RoleNetworkAdmin}, false},
		{[]string{rbac.RoleAgentsAdmin}, false},
		{[]string{rbac.RoleHelpdesk}, false},
	} {
		p := &authctx.Principal{UserID: uuid.New(), Roles: map[uuid.UUID]string{org: tc.roles[0]}, RoleSets: map[uuid.UUID][]string{org: tc.roles}}
		scope := auditActorScope(p, org)
		if (scope == nil) != tc.orgWide {
			t.Errorf("%v: org-wide audit = %v, want %v", tc.roles, scope == nil, tc.orgWide)
		}
		if scope != nil && *scope != p.UserID {
			t.Errorf("%v: scoped audit must be the person's own actions", tc.roles)
		}
	}
}
