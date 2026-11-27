package http

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/nodepush"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/release"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// agentFeaturesFixture is one organization with an owner, an active gateway and one agent.
type agentFeaturesFixture struct {
	ctx                      context.Context
	pool                     *pgxpool.Pool
	org, owner, node, device uuid.UUID
}

func newAgentFeaturesFixture(t *testing.T) agentFeaturesFixture {
	t.Helper()
	ctx, pool := testpostgres.New(t)
	f := agentFeaturesFixture{ctx: ctx, pool: pool, org: uuid.New(), owner: uuid.New(), node: uuid.New(), device: uuid.New()}
	f.exec(t, `INSERT INTO organizations (id,name,slug,pool_cidr,max_devices_per_user) VALUES ($1,'AI-UX-1',$2,'10.96.0.0/24',0)`, f.org, "aiux1-"+f.org.String())
	f.exec(t, `INSERT INTO users (id,email,name,status) VALUES ($1,$2,'owner','active')`, f.owner, f.owner.String()+"@aiux1.test")
	f.exec(t, `INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')`, f.org, f.owner)
	key := make([]byte, 32)
	copy(key, f.node[:])
	f.exec(t, `INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint,status) VALUES ($1,$2,'aiux1-gateway',$3,$4,'gw.example:51820','active')`, f.node, f.org, "aiux1-"+f.node.String(), base64.StdEncoding.EncodeToString(key))
	f.exec(t, `INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'aiux1-agent',$5,'10.96.0.2','active','agent')`, f.device, f.org, f.owner, f.node, "aiux1-key-"+f.device.String())
	return f
}

func (f agentFeaturesFixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, query, args...); err != nil {
		t.Fatal(err)
	}
}

func (f agentFeaturesFixture) as(role string) context.Context {
	return authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: f.owner, EmailVerified: true, Roles: map[uuid.UUID]string{f.org: role}})
}

func (f agentFeaturesFixture) server(tier string) apiServer {
	mgr := licence.NewTestManager(tier, time.Now().Add(time.Hour))
	return apiServer{
		system: sqlc.New(f.pool), licence: mgr, orgs: tenancy.NewService(f.pool).WithLicence(mgr),
		agentTemplates: NewAgentTemplatePort(f.pool, nil), devices: devices.NewService(f.pool, nodepush.New(), nil),
	}
}

func (f agentFeaturesFixture) auditCount(t *testing.T, action string) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action=$2 AND actor_user_id=$3`, f.org, action, f.owner).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// MCP has its own switch: with agent groups and policy templates off and MCP on, groups, members and MCP
// work, template endpoints still need templates, and MCP cannot be turned off while a server is assigned.
func TestMCPSwitchIsIndependentOfAgentPolicyTemplates(t *testing.T) {
	f := newAgentFeaturesFixture(t)
	s := f.server("community")
	owner := f.as(rbac.RoleOwner)
	mcpEnabled := func() bool {
		t.Helper()
		resp, err := s.GetOrganizationMCPSetting(f.as(rbac.RoleMember), api.GetOrganizationMCPSettingRequestObject{OrgId: f.org})
		if err != nil {
			t.Fatal(err)
		}
		return resp.(api.GetOrganizationMCPSetting200JSONResponse).Body.Enabled
	}
	setMCP := func(enabled bool) error {
		_, err := s.SetOrganizationMCPEnabled(owner, api.SetOrganizationMCPEnabledRequestObject{OrgId: f.org, Body: &api.MCPSetting{Enabled: enabled}})
		return err
	}

	// Nothing on: unchanged behaviour, and the setting reads off without a row.
	if mcpEnabled() {
		t.Fatal("MCP must read off for an organization that never set it")
	}
	if _, err := s.ListAgentGroups(owner, api.ListAgentGroupsRequestObject{OrgId: f.org}); !hasCode(err, 403, "opt_in_required") {
		t.Fatalf("groups with both switches off: %v", err)
	}
	if _, err := s.ListAgentMCPProfiles(owner, api.ListAgentMCPProfilesRequestObject{OrgId: f.org}); !hasCode(err, 403, "opt_in_required") {
		t.Fatalf("MCP profiles with both switches off: %v", err)
	}
	if _, err := s.SetOrganizationMCPEnabled(f.as(rbac.RoleMember), api.SetOrganizationMCPEnabledRequestObject{OrgId: f.org, Body: &api.MCPSetting{Enabled: true}}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member MCP switch: %v", err)
	}
	if _, err := s.SetOrganizationMCPEnabled(owner, api.SetOrganizationMCPEnabledRequestObject{OrgId: f.org}); !hasCode(err, 400, "invalid_request") {
		t.Fatalf("MCP switch without a body: %v", err)
	}

	if err := setMCP(true); err != nil {
		t.Fatalf("turn MCP on: %v", err)
	}
	if !mcpEnabled() || f.auditCount(t, "org.mcp_enabled") != 1 {
		t.Fatalf("MCP on: enabled=%v audit=%d", mcpEnabled(), f.auditCount(t, "org.mcp_enabled"))
	}
	var templatesOn bool
	if err := f.pool.QueryRow(f.ctx, `SELECT agent_policy_templates_enabled FROM organizations WHERE id=$1`, f.org).Scan(&templatesOn); err != nil || templatesOn {
		t.Fatalf("turning MCP on must not turn templates on: %v %v", templatesOn, err)
	}

	// Groups, members and MCP work with templates off.
	created, err := s.CreateAgentGroup(owner, api.CreateAgentGroupRequestObject{OrgId: f.org, Body: &api.CreateAgentGroupRequest{Name: "mcp-only"}})
	if err != nil {
		t.Fatalf("create group with MCP on: %v", err)
	}
	group := created.(api.CreateAgentGroup201JSONResponse).Body.Id
	if _, err := s.ListAgentGroups(owner, api.ListAgentGroupsRequestObject{OrgId: f.org}); err != nil {
		t.Fatalf("list groups with MCP on: %v", err)
	}
	if _, err := s.AddAgentGroupMember(owner, api.AddAgentGroupMemberRequestObject{OrgId: f.org, GroupId: group, Body: &api.AddAgentGroupMemberRequest{DeviceId: f.device}}); err != nil {
		t.Fatalf("add member with MCP on: %v", err)
	}
	if _, err := s.ListAgentGroupMembers(owner, api.ListAgentGroupMembersRequestObject{OrgId: f.org, GroupId: group}); err != nil {
		t.Fatalf("list members with MCP on: %v", err)
	}
	profileResp, err := s.CreateAgentMCPProfile(owner, api.CreateAgentMCPProfileRequestObject{OrgId: f.org, Body: &api.CreateAgentMCPProfileRequest{Name: "tools", Endpoint: "https://mcp.example.test"}})
	if err != nil {
		t.Fatalf("create MCP profile with MCP on: %v", err)
	}
	profile := profileResp.(api.CreateAgentMCPProfile201JSONResponse).Body.Id
	if _, err := s.ReplaceAgentGroupMCPProfile(owner, api.ReplaceAgentGroupMCPProfileRequestObject{OrgId: f.org, GroupId: group, Body: &api.SetAgentGroupMCPProfileRequest{ProfileId: profile}}); err != nil {
		t.Fatalf("assign MCP profile with MCP on: %v", err)
	}
	if _, err := s.ListAgentMCPAssignments(owner, api.ListAgentMCPAssignmentsRequestObject{OrgId: f.org}); err != nil {
		t.Fatalf("list MCP assignments with MCP on: %v", err)
	}

	// Template endpoints still need the templates switch.
	if _, err := s.ListAgentPolicyTemplates(owner, api.ListAgentPolicyTemplatesRequestObject{OrgId: f.org}); !hasCode(err, 403, "opt_in_required") {
		t.Fatalf("list templates with only MCP on: %v", err)
	}
	if _, err := s.CreateAgentPolicyTemplate(owner, api.CreateAgentPolicyTemplateRequestObject{OrgId: f.org, Body: &api.CreateAgentPolicyTemplateRequest{Name: "baseline"}}); !hasCode(err, 403, "opt_in_required") {
		t.Fatalf("create template with only MCP on: %v", err)
	}
	if _, err := s.ListAgentPolicyTemplateAssignments(owner, api.ListAgentPolicyTemplateAssignmentsRequestObject{OrgId: f.org}); !hasCode(err, 403, "opt_in_required") {
		t.Fatalf("list template assignments with only MCP on: %v", err)
	}

	// Turning MCP off is refused while a server is assigned, and nothing changes.
	if err := setMCP(false); !hasCode(err, 409, "mcp_in_use") {
		t.Fatalf("turn MCP off with an assignment: %v", err)
	}
	if !mcpEnabled() || f.auditCount(t, "org.mcp_disabled") != 0 {
		t.Fatalf("refused disable changed state: enabled=%v audit=%d", mcpEnabled(), f.auditCount(t, "org.mcp_disabled"))
	}
	if _, err := s.UnassignAgentGroupMCPProfile(owner, api.UnassignAgentGroupMCPProfileRequestObject{OrgId: f.org, GroupId: group}); err != nil {
		t.Fatalf("unassign: %v", err)
	}
	if err := setMCP(false); err != nil {
		t.Fatalf("turn MCP off: %v", err)
	}
	if mcpEnabled() || f.auditCount(t, "org.mcp_disabled") != 1 || f.auditCount(t, "org.mcp_enabled") != 1 {
		t.Fatalf("MCP off: enabled=%v", mcpEnabled())
	}
	if _, err := s.ListAgentGroups(owner, api.ListAgentGroupsRequestObject{OrgId: f.org}); !hasCode(err, 403, "opt_in_required") {
		t.Fatalf("groups after MCP off: %v", err)
	}
	if _, err := s.CreateAgentGroup(owner, api.CreateAgentGroupRequestObject{OrgId: f.org, Body: &api.CreateAgentGroupRequest{Name: "late"}}); !hasCode(err, 403, "opt_in_required") {
		t.Fatalf("create group after MCP off: %v", err)
	}

	// Templates alone still open groups and MCP, exactly as before this change.
	if _, err := s.SetOrganizationAgentPolicyTemplatesEnabled(owner, api.SetOrganizationAgentPolicyTemplatesEnabledRequestObject{OrgId: f.org, Body: &api.AgentPolicyTemplateSetting{Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListAgentGroups(owner, api.ListAgentGroupsRequestObject{OrgId: f.org}); err != nil {
		t.Fatalf("groups with only templates on: %v", err)
	}
	if _, err := s.ListAgentMCPProfiles(owner, api.ListAgentMCPProfilesRequestObject{OrgId: f.org}); err != nil {
		t.Fatalf("MCP profiles with only templates on: %v", err)
	}
	if _, err := s.ListAgentPolicyTemplates(owner, api.ListAgentPolicyTemplatesRequestObject{OrgId: f.org}); err != nil {
		t.Fatalf("templates with templates on: %v", err)
	}

	// Another organization's switch is not reachable.
	if _, err := s.SetOrganizationMCPEnabled(principalWithRole(uuid.New(), rbac.RoleOwner), api.SetOrganizationMCPEnabledRequestObject{OrgId: f.org, Body: &api.MCPSetting{Enabled: true}}); !hasCode(err, 404, "org_not_found") {
		t.Fatalf("other organization MCP switch: %v", err)
	}
}

// Honest licensing: Community cannot save the runtime switch, the feature list says so with the plan
// name, and a plan that includes it saves and audits.
func TestAgentFeaturesAndRuntimeSwitchFollowThePlan(t *testing.T) {
	f := newAgentFeaturesFixture(t)
	owner := f.as(rbac.RoleOwner)
	features := func(s apiServer) map[api.AgentFeatureKey]api.AgentFeature {
		t.Helper()
		resp, err := s.ListAgentFeatures(f.as(rbac.RoleMember), api.ListAgentFeaturesRequestObject{OrgId: f.org})
		if err != nil {
			t.Fatal(err)
		}
		out := map[api.AgentFeatureKey]api.AgentFeature{}
		for _, item := range resp.(api.ListAgentFeatures200JSONResponse).Body.Items {
			out[item.Key] = item
		}
		if len(out) != 4 {
			t.Fatalf("features = %+v", out)
		}
		return out
	}
	runtimeOn := func() bool {
		t.Helper()
		var on bool
		if err := f.pool.QueryRow(f.ctx, `SELECT managed_agent_runtime_enabled FROM organizations WHERE id=$1`, f.org).Scan(&on); err != nil {
			t.Fatal(err)
		}
		return on
	}
	put := func(s apiServer, enabled bool) error {
		_, err := s.SetOrganizationAgentRuntimeEnabled(owner, api.SetOrganizationAgentRuntimeEnabledRequestObject{OrgId: f.org, Body: &api.AgentRuntimeSetting{Enabled: enabled}})
		return err
	}

	community, starter := f.server("community"), f.server("starter")
	got := features(community)
	if rt := got[api.AgentFeatureRuntimeSync]; rt.Available || rt.Enabled || rt.RequiredPlan == nil || *rt.RequiredPlan != "starter" {
		t.Fatalf("community runtime sync = %+v", rt)
	}
	if jit := got[api.AgentFeatureAgentJIT]; jit.Available || jit.RequiredPlan == nil || *jit.RequiredPlan != "scale" {
		t.Fatalf("community agent JIT = %+v", jit)
	}
	if mcp := got[api.AgentFeatureMCP]; !mcp.Available || mcp.Enabled || mcp.RequiredPlan != nil {
		t.Fatalf("community MCP = %+v", mcp)
	}
	if err := put(community, true); !hasCode(err, 403, "feature_required") {
		t.Fatalf("community runtime enable: %v", err)
	}
	if runtimeOn() || f.auditCount(t, "org.agent_runtime_enabled") != 0 {
		t.Fatal("a refused enable was saved or audited")
	}

	if rt := features(starter)[api.AgentFeatureRuntimeSync]; !rt.Available || rt.RequiredPlan != nil {
		t.Fatalf("starter runtime sync = %+v", rt)
	}
	if err := put(starter, true); err != nil {
		t.Fatalf("starter runtime enable: %v", err)
	}
	if !runtimeOn() || f.auditCount(t, "org.agent_runtime_enabled") != 1 {
		t.Fatal("starter enable was not saved and audited")
	}
	if _, err := starter.SetOrganizationMCPEnabled(owner, api.SetOrganizationMCPEnabledRequestObject{OrgId: f.org, Body: &api.MCPSetting{Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	got = features(starter)
	if !got[api.AgentFeatureRuntimeSync].Enabled || !got[api.AgentFeatureMCP].Enabled || got[api.AgentFeatureAgentGroups].Enabled || got[api.AgentFeatureAgentJIT].Enabled {
		t.Fatalf("saved switches = %+v", got)
	}

	// The plan lapsed with the switch on: it reads on but unavailable, and it can still be turned off.
	if rt := features(community)[api.AgentFeatureRuntimeSync]; !rt.Enabled || rt.Available {
		t.Fatalf("lapsed runtime sync = %+v", rt)
	}
	if err := put(community, false); err != nil {
		t.Fatalf("turning runtime synchronization off must always work: %v", err)
	}
	if runtimeOn() || f.auditCount(t, "org.agent_runtime_disabled") != 1 {
		t.Fatal("disable was not saved and audited")
	}
}

// The install step's status: every token state, the enrolled agent's tunnel facts, and no answer for a
// token of another organization.
func TestAgentBootstrapTokenStatusStatesAndIsolation(t *testing.T) {
	f := newAgentFeaturesFixture(t)
	s := f.server("starter")
	s.releaseBootstrap = &release.BootstrapRelease{}
	s.releaseBootstrapVerifier = func(context.Context, release.BootstrapRelease) (*release.BootstrapVerifierAssets, error) {
		return nil, nil
	}
	owner := f.as(rbac.RoleOwner)
	issue := func(name string) (uuid.UUID, string) {
		t.Helper()
		resp, err := s.IssueAgentBootstrapToken(owner, api.IssueAgentBootstrapTokenRequestObject{OrgId: f.org, Body: &api.IssueAgentBootstrapTokenJSONRequestBody{GatewayId: f.node, Name: name}})
		if err != nil {
			t.Fatal(err)
		}
		body := resp.(api.IssueAgentBootstrapToken201JSONResponse).Body
		if body.TokenId == nil {
			t.Fatal("issued token has no token_id")
		}
		var stored uuid.UUID
		if err := f.pool.QueryRow(f.ctx, `SELECT id FROM agent_bootstrap_tokens WHERE org_id=$1 AND agent_name=$2`, f.org, name).Scan(&stored); err != nil || stored != *body.TokenId {
			t.Fatalf("token_id = %s, stored %s (%v)", body.TokenId, stored, err)
		}
		return *body.TokenId, body.BootstrapToken
	}
	status := func(id uuid.UUID) api.AgentBootstrapTokenStatus {
		t.Helper()
		resp, err := s.GetAgentBootstrapTokenStatus(owner, api.GetAgentBootstrapTokenStatusRequestObject{OrgId: f.org, TokenId: id})
		if err != nil {
			t.Fatal(err)
		}
		return resp.(api.GetAgentBootstrapTokenStatus200JSONResponse).Body
	}

	pending, raw := issue("pending-agent")
	got := status(pending)
	if got.State != api.AgentBootstrapTokenPending || got.Id != pending || got.AgentName != "pending-agent" || got.EnrolledAt != nil || got.DeviceId != nil || got.Tunnel != nil {
		t.Fatalf("pending = %+v", got)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), raw) || strings.Contains(string(encoded), strings.TrimPrefix(raw, "tnx_agent_")) || strings.Contains(string(encoded), "hash") {
		t.Fatal("status carries token material")
	}

	// Refusals.
	req := api.GetAgentBootstrapTokenStatusRequestObject{OrgId: f.org, TokenId: pending}
	if _, err := s.GetAgentBootstrapTokenStatus(context.Background(), req); !hasCode(err, 401, "unauthenticated") {
		t.Fatalf("unauthenticated status: %v", err)
	}
	if _, err := s.GetAgentBootstrapTokenStatus(f.as(rbac.RoleMember), req); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member status: %v", err)
	}
	if _, err := s.GetAgentBootstrapTokenStatus(owner, api.GetAgentBootstrapTokenStatusRequestObject{OrgId: f.org, TokenId: uuid.New()}); !hasCode(err, 404, "bootstrap_token_not_found") {
		t.Fatalf("unknown token: %v", err)
	}
	// A real token id asked for through another organization the caller owns.
	other := uuid.New()
	f.exec(t, `INSERT INTO organizations (id,name,slug,pool_cidr,max_devices_per_user) VALUES ($1,'AI-UX-1 other',$2,'10.97.0.0/24',0)`, other, "aiux1-other-"+other.String())
	otherOwner := authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: f.owner, EmailVerified: true, Roles: map[uuid.UUID]string{other: rbac.RoleOwner}})
	if _, err := s.GetAgentBootstrapTokenStatus(otherOwner, api.GetAgentBootstrapTokenStatusRequestObject{OrgId: other, TokenId: pending}); !hasCode(err, 404, "bootstrap_token_not_found") {
		t.Fatalf("token of another organization: %v", err)
	}
	if _, err := s.GetAgentBootstrapTokenStatus(otherOwner, req); !hasCode(err, 404, "org_not_found") {
		t.Fatalf("status in an organization the caller is not in: %v", err)
	}

	revoked, _ := issue("revoked-agent")
	if _, err := s.RevokeAgentBootstrapToken(owner, api.RevokeAgentBootstrapTokenRequestObject{OrgId: f.org, TokenId: revoked}); err != nil {
		t.Fatal(err)
	}
	if got := status(revoked); got.State != api.AgentBootstrapTokenRevoked || got.Tunnel != nil || got.DeviceId != nil {
		t.Fatalf("revoked = %+v", got)
	}

	expired, _ := issue("expired-agent")
	f.exec(t, `UPDATE agent_bootstrap_tokens SET created_at=now()-interval '2 hours', expires_at=now()-interval '1 hour' WHERE id=$1`, expired)
	if got := status(expired); got.State != api.AgentBootstrapTokenExpired || got.Tunnel != nil {
		t.Fatalf("expired = %+v", got)
	}

	// Enrolled: the gateway is reporting and has seen no handshake yet.
	enrolled, _ := issue("enrolled-agent")
	f.exec(t, `UPDATE agent_bootstrap_tokens SET consumed_at=now(), consumed_device_id=$2 WHERE id=$1`, enrolled, f.device)
	f.exec(t, `UPDATE nodes SET last_seen_at=now() WHERE id=$1`, f.node)
	got = status(enrolled)
	if got.State != api.AgentBootstrapTokenEnrolled || got.EnrolledAt == nil || got.DeviceId == nil || *got.DeviceId != f.device {
		t.Fatalf("enrolled = %+v", got)
	}
	if got.Tunnel == nil || got.Tunnel.Connected || !got.Tunnel.GatewayReporting || got.Tunnel.LastHandshakeAt != nil {
		t.Fatalf("enrolled tunnel = %+v", got.Tunnel)
	}

	// Tunnel connected, from the gateway's status push.
	f.exec(t, `INSERT INTO device_status (device_id,last_handshake_at) VALUES ($1,now())`, f.device)
	got = status(enrolled)
	if got.Tunnel == nil || !got.Tunnel.Connected || !got.Tunnel.GatewayReporting || got.Tunnel.LastHandshakeAt == nil {
		t.Fatalf("connected tunnel = %+v", got.Tunnel)
	}

	// The same facts as the agents list for the same agent.
	var listedHandshake time.Time
	if err := f.pool.QueryRow(f.ctx, `SELECT last_handshake_at FROM device_status WHERE device_id=$1`, f.device).Scan(&listedHandshake); err != nil {
		t.Fatal(err)
	}
	if !got.Tunnel.LastHandshakeAt.Equal(listedHandshake) || got.Tunnel.Connected != deviceOnline(&listedHandshake) {
		t.Fatalf("tunnel = %+v, device status handshake %s", got.Tunnel, listedHandshake)
	}

	// The agent was removed: still enrolled, nothing to point at.
	f.exec(t, `UPDATE devices SET deleted_at=now(), status='revoked' WHERE id=$1`, f.device)
	got = status(enrolled)
	if got.State != api.AgentBootstrapTokenEnrolled || got.DeviceId != nil || got.Tunnel != nil {
		t.Fatalf("removed agent = %+v", got)
	}
}
