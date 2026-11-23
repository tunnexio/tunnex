package http

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	k8ssvc "github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	policyservice "github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// K8N-3 stage 1: API access handlers and "Test access" for a cluster's Kubernetes API.

func k8sAPIFacts(mutate func(*deviceAccessFacts)) deviceAccessFacts {
	f := deviceAccessBaseline()
	f.destination = "kubernetes.default.svc.prod.k8s.acme.com"
	f.reach.LocalSubnets = append(f.reach.LocalSubnets, "100.66.0.0/24")
	f.k8sAPI = &deviceAccessK8sAPI{cluster: "prod", name: "kubernetes.default.svc.prod.k8s.acme.com", enabled: true, address: "100.66.0.3",
		gatewayAssigned: true, gatewayName: "cluster-gw", gatewayFresh: true, endpointState: nodes.K8sAPIEndpointReady}
	if mutate != nil {
		mutate(&f)
	}
	return f
}

func checkByCode(b accessCheckBuilder, code string) *api.AgentAccessCheck {
	for i := range b.checks {
		if b.checks[i].Code == code {
			return &b.checks[i]
		}
	}
	return nil
}

func TestDeviceAccessChecksForAClusterAPI(t *testing.T) {
	base := []string{"device_active", "posture_not_blocking", "gateway_reporting"}
	cases := []struct {
		name    string
		mutate  func(*deviceAccessFacts)
		codes   []string
		overall api.AgentAccessDiagnosticOverall
		blocker string
		reason  string
	}{
		{name: "allowed", codes: append(append([]string{}, base...), "k8s_api_destination", "route_configured", "matching_grant", "applied_policy_current", "k8s_api_endpoint_ready"),
			overall: api.AgentAccessDiagnosticOverallAllowed},
		{name: "API access off", mutate: func(f *deviceAccessFacts) {
			f.k8sAPI.enabled, f.k8sAPI.address = false, ""
			f.policy.Allowed, f.policy.RuleID = false, ""
		}, codes: append(append([]string{}, base...), "k8s_api_not_enabled", "route_destination_unresolved", "applied_policy_current"),
			overall: api.AgentAccessDiagnosticOverallDenied, blocker: "k8s_api_not_enabled"},
		{name: "no rule", mutate: func(f *deviceAccessFacts) { f.policy.Allowed, f.policy.RuleID = false, "" },
			codes:   append(append([]string{}, base...), "k8s_api_destination", "route_configured", "no_matching_grant", "applied_policy_current", "k8s_api_endpoint_ready"),
			overall: api.AgentAccessDiagnosticOverallDenied, blocker: "no_matching_grant"},
		{name: "gateway on the control-plane node", mutate: func(f *deviceAccessFacts) { f.k8sAPI.endpointState = nodes.K8sAPIEndpointOnGatewayNode },
			codes:   append(append([]string{}, base...), "k8s_api_destination", "route_configured", "matching_grant", "applied_policy_current", "k8s_api_endpoint_unavailable"),
			overall: api.AgentAccessDiagnosticOverallDenied, blocker: "k8s_api_endpoint_unavailable", reason: "endpoints_on_gateway_node"},
		{name: "no ready API endpoints", mutate: func(f *deviceAccessFacts) { f.k8sAPI.endpointState = "no_ready_endpoints" },
			codes:   append(append([]string{}, base...), "k8s_api_destination", "route_configured", "matching_grant", "applied_policy_current", "k8s_api_endpoint_unavailable"),
			overall: api.AgentAccessDiagnosticOverallDenied, blocker: "k8s_api_endpoint_unavailable", reason: "no_ready_endpoints"},
		{name: "cluster has no gateway", mutate: func(f *deviceAccessFacts) { f.k8sAPI.gatewayAssigned, f.k8sAPI.gatewayName = false, "" },
			codes:   append(append([]string{}, base...), "k8s_api_destination", "route_configured", "matching_grant", "applied_policy_current", "k8s_api_endpoint_unavailable"),
			overall: api.AgentAccessDiagnosticOverallDenied, blocker: "k8s_api_endpoint_unavailable", reason: "no_gateway"},
		{name: "gateway has not said", mutate: func(f *deviceAccessFacts) { f.k8sAPI.endpointState = "" },
			codes:   append(append([]string{}, base...), "k8s_api_destination", "route_configured", "matching_grant", "applied_policy_current", "k8s_api_endpoint_not_observed"),
			overall: api.AgentAccessDiagnosticOverallInconclusive, blocker: "k8s_api_endpoint_not_observed"},
		{name: "cluster gateway stale", mutate: func(f *deviceAccessFacts) { f.k8sAPI.gatewayFresh = false },
			codes:   append(append([]string{}, base...), "k8s_api_destination", "route_configured", "matching_grant", "applied_policy_current", "k8s_api_endpoint_not_observed"),
			overall: api.AgentAccessDiagnosticOverallInconclusive, blocker: "k8s_api_endpoint_not_observed"},
		{name: "by address", mutate: func(f *deviceAccessFacts) { f.destination = "100.66.0.3" },
			codes:   append(append([]string{}, base...), "k8s_api_destination", "route_configured", "matching_grant", "applied_policy_current", "k8s_api_endpoint_ready"),
			overall: api.AgentAccessDiagnosticOverallAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := deviceAccessChecks(k8sAPIFacts(tc.mutate))
			if got := strings.Join(deviceAccessCodes(b), ","); got != strings.Join(tc.codes, ",") {
				t.Fatalf("codes = %s\nwant    %s", got, strings.Join(tc.codes, ","))
			}
			if b.overall() != tc.overall {
				t.Fatalf("overall = %s, want %s", b.overall(), tc.overall)
			}
			if (tc.blocker == "") != (b.firstBlocker == nil) || (b.firstBlocker != nil && *b.firstBlocker != tc.blocker) {
				t.Fatalf("first blocker = %v, want %q", b.firstBlocker, tc.blocker)
			}
			if tc.reason != "" {
				check := checkByCode(b, "k8s_api_endpoint_unavailable")
				if check == nil || check.Facts == nil || (*check.Facts)["reason"] != tc.reason {
					t.Fatalf("the endpoint check must carry the gateway's reason %q, got %+v", tc.reason, check)
				}
			}
			if len(b.checks) > 8 {
				t.Fatalf("the contract allows at most 8 checks, got %d", len(b.checks))
			}
			for _, check := range b.checks {
				if len(check.Message) > 256 || len(check.Code) > 64 {
					t.Fatalf("check exceeds the contract limits: %+v", check)
				}
			}
		})
	}

	// The messages name the cluster, in the words the paper gives.
	noRule := deviceAccessChecks(k8sAPIFacts(func(f *deviceAccessFacts) { f.policy.Allowed = false }))
	if check := checkByCode(noRule, "no_matching_grant"); check == nil || check.Message != "No rule lets this device reach the Kubernetes API of prod." {
		t.Fatalf("no-rule message = %+v", check)
	}
	onNode := deviceAccessChecks(k8sAPIFacts(func(f *deviceAccessFacts) { f.k8sAPI.endpointState = nodes.K8sAPIEndpointOnGatewayNode }))
	if check := checkByCode(onNode, "k8s_api_endpoint_unavailable"); check == nil || !strings.Contains(check.Message, "control-plane node") {
		t.Fatalf("the control-plane case must not read as a generic failure: %+v", check)
	}
	// An ordinary destination is exactly as before: no endpoint check, no API wording.
	plain := deviceAccessChecks(deviceAccessBaseline())
	if checkByCode(plain, "k8s_api_endpoint_ready") != nil || len(plain.checks) != 7 {
		t.Fatalf("an ordinary destination must keep its seven checks: %v", deviceAccessCodes(plain))
	}
	if !strings.Contains(k8sAPIAllowedNote, "a 401 or 403 from kubectl is the cluster's answer, not Tunnex's") || len(k8sAPIAllowedNote) > 256 {
		t.Fatalf("the fixed sentence changed: %q", k8sAPIAllowedNote)
	}
}

// Turning API access on needs k8s_api:manage and a human. k8s:manage alone does not do it.
func TestSetK8sClusterApiAccessPermissionBoundary(t *testing.T) {
	orgID, clusterID := uuid.New(), uuid.New()
	enable := true
	request := api.SetK8sClusterApiAccessRequestObject{OrgId: orgID, ClusterId: clusterID, Body: &api.SetK8sClusterApiAccessJSONRequestBody{Enabled: enable}}
	server := apiServer{k8s: k8ssvc.NewService(nil)} // every refusal below happens before the database is read

	operator := authctx.WithPrincipal(context.Background(), authctx.NewMachinePrincipal(uuid.New(), uuid.New(), orgID, "gitops", rbac.RoleOperator, "test"))
	if !rbac.Can(rbac.RoleOperator, rbac.PermK8sManage) {
		t.Fatal("fixture: the operator holds k8s:manage")
	}
	if _, err := server.SetK8sClusterApiAccess(operator, request); !hasCode(err, 403, "forbidden") {
		t.Fatalf("k8s:manage without k8s_api:manage must be 403 forbidden, got %v", err)
	}
	if _, err := server.SetK8sClusterApiAccess(principalWithRole(orgID, rbac.RoleMember), request); !hasCode(err, 403, "forbidden") {
		t.Fatalf("a member must be 403 forbidden, got %v", err)
	}
	unverified := authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: uuid.New(), Roles: map[uuid.UUID]string{orgID: rbac.RoleOwner}})
	if _, err := server.SetK8sClusterApiAccess(unverified, request); err == nil || hasCode(err, 404, "cluster_not_found") {
		t.Fatalf("an unverified owner must be refused before any lookup, got %v", err)
	}
	// A machine credential that somehow carries the admin role still is not a person.
	machineAdmin := authctx.WithPrincipal(context.Background(), authctx.NewMachinePrincipal(uuid.New(), uuid.New(), orgID, "overprivileged", rbac.RoleAdmin, "test"))
	if _, err := server.SetK8sClusterApiAccess(machineAdmin, request); !hasCode(err, 403, "human_actor_required") {
		t.Fatalf("a machine with the permission must be 403 human_actor_required, got %v", err)
	}
	// Another organization's administrator has no role here at all.
	if _, err := server.SetK8sClusterApiAccess(principalWithRole(uuid.New(), rbac.RoleOwner), request); err == nil || hasCode(err, 404, "cluster_not_found") {
		t.Fatalf("an outsider must be refused by authorization, got %v", err)
	}
	if _, err := server.SetK8sClusterApiAccess(principalWithRole(orgID, rbac.RoleOwner), api.SetK8sClusterApiAccessRequestObject{OrgId: orgID, ClusterId: clusterID}); !hasCode(err, 400, "invalid_request") {
		t.Fatalf("a missing body must be 400, got %v", err)
	}
}

// The response is a path description only. Tunnex never generates a kubeconfig that contains a
// credential (founder ruling 2026-11-23), so the contract has nowhere to put one.
func TestK8sApiAccessResponseCarriesNoCredential(t *testing.T) {
	vipOn := toAPIK8sApiAccess(k8ssvc.APIAccess{ClusterID: uuid.New(), ClusterName: "prod", Enabled: true, VIP: "100.66.0.3",
		FQDN: "kubernetes.default.svc.prod.k8s.acme.com", Port: 443, RuleCount: 2})
	raw, err := json.Marshal(vipOn)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"cluster_id": true, "enabled": true, "enabled_at": true, "fqdn": true, "ordinary_exposure": true, "port": true, "rule_count": true, "vip": true}
	for name := range fields {
		if !allowed[name] {
			t.Fatalf("unexpected field %q in the API access response: %s", name, raw)
		}
	}
	for _, forbidden := range []string{"token", "certificate", "client-key", "kubeconfig", "insecure", "password", "secret"} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Fatalf("the API access response mentions %q: %s", forbidden, raw)
		}
	}
	if off := toAPIK8sApiAccess(k8ssvc.APIAccess{ClusterID: uuid.New(), FQDN: "kubernetes.default.svc.prod.k8s.acme.com", Port: 443}); off.Enabled || off.Vip != nil || off.Fqdn == "" {
		t.Fatalf("off must carry the name and no address: %+v", off)
	}
}

func TestK8sAPIAccessPostgresContract(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for the K8N-3 integration proof")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	q := sqlc.New(pool)
	org, otherOrg := uuid.New(), uuid.New()
	admin, person, otherAdmin := uuid.New(), uuid.New(), uuid.New()
	homeGW, clusterGW, otherGW := uuid.New(), uuid.New(), uuid.New()
	site, otherSite, cluster, otherCluster, device := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(stmt string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, stmt, args...); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	exec(`INSERT INTO organizations (id,name,slug,pool_cidr,zero_trust_mode) VALUES ($1,'K8N3',$2,'10.96.0.0/24','enforcing')`, org, "k8n3-"+org.String()[:8])
	exec(`INSERT INTO organizations (id,name,slug,pool_cidr,zero_trust_mode) VALUES ($1,'K8N3 other',$2,'10.95.0.0/24','enforcing')`, otherOrg, "k8n3-"+otherOrg.String()[:8])
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id = ANY($1)`, []uuid.UUID{org, otherOrg})
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = ANY($1)`, []uuid.UUID{admin, person, otherAdmin})
	})
	for user, home := range map[uuid.UUID]uuid.UUID{admin: org, person: org, otherAdmin: otherOrg} {
		exec(`INSERT INTO users (id,email,status) VALUES ($1,$2,'active')`, user, user.String()+"@k8n3.example")
		exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')`, home, user)
	}
	exec(`INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'k8n3 site')`, site, org)
	exec(`INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'k8n3 other site')`, otherSite, otherOrg)
	// The device's home gateway is an edge gateway of the cluster's site; the in-cluster gateway is a
	// second node of that site. That is the ordinary shape: device -> edge gateway -> cluster gateway.
	exec(`INSERT INTO nodes (id,org_id,site_id,name,status,cert_serial,wg_public_key,endpoint,last_seen_at) VALUES ($1,$2,$3,'k8n3-home','active',$4,'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','home.example:51820',now())`, homeGW, org, site, "k8n3-home-"+homeGW.String())
	exec(`INSERT INTO nodes (id,org_id,site_id,name,status,cert_serial,wg_public_key,endpoint,last_seen_at) VALUES ($1,$2,$3,'k8n3-cluster-gw','active',$4,'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=','cluster.example:51820',now())`, clusterGW, org, site, "k8n3-cluster-"+clusterGW.String())
	exec(`INSERT INTO nodes (id,org_id,site_id,name,status,cert_serial,wg_public_key,endpoint,last_seen_at) VALUES ($1,$2,$3,'k8n3-other-gw','active',$4,'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=','other.example:51820',now())`, otherGW, otherOrg, otherSite, "k8n3-other-"+otherGW.String())
	exec(`INSERT INTO k8s_clusters (id,org_id,site_id,name,vip_range,dns_zone,dns_vip,connector_node_id) VALUES ($1,$2,$3,'prod','100.66.0.0/24','k8s.acme.com','100.66.0.2',$4)`, cluster, org, site, clusterGW)
	exec(`INSERT INTO k8s_clusters (id,org_id,site_id,name,vip_range,dns_zone,dns_vip,connector_node_id) VALUES ($1,$2,$3,'prod','100.67.0.0/24','k8s.other.com','100.67.0.2',$4)`, otherCluster, otherOrg, otherSite, otherGW)
	exec(`INSERT INTO devices (id,org_id,user_id,node_id,name,platform,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'k8n3-laptop','macos',$5,'10.96.0.7','active','human')`, device, org, person, homeGW, wgTestKey(device))

	policy := policyservice.NewService(pool)
	nodeService := nodes.NewService(pool, nil, nil)
	nodeService.SetPolicyProvider(policy)
	k8s := k8ssvc.NewService(pool)
	s := apiServer{nodes: nodeService, devices: devices.NewService(pool, nil, nil), policy: policy, k8s: k8s}
	as := func(user uuid.UUID, role string) context.Context {
		return authctx.WithPrincipal(ctx, &authctx.Principal{UserID: user, EmailVerified: true, AuthMethod: authctx.AuthSSO, Roles: map[uuid.UUID]string{org: role}})
	}
	audits := func(action string) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action=$2`, org, action).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	diagnose := func(destination string) api.DeviceAccessDiagnostic {
		t.Helper()
		response, err := s.TestDeviceAccess(as(admin, rbac.RoleAdmin), api.TestDeviceAccessRequestObject{OrgId: org, DeviceId: device, Params: api.TestDeviceAccessParams{
			Destination: destination, Protocol: api.TestDeviceAccessParamsProtocol("tcp"), Port: 443}})
		if err != nil {
			t.Fatal(err)
		}
		return response.(api.TestDeviceAccess200JSONResponse).Body
	}
	codes := func(body api.DeviceAccessDiagnostic) string {
		out := make([]string, 0, len(body.Checks))
		for _, check := range body.Checks {
			out = append(out, check.Code)
		}
		return strings.Join(out, ",")
	}
	blocker := func(body api.DeviceAccessDiagnostic) string {
		if body.FirstBlocker == nil {
			return ""
		}
		return *body.FirstBlocker
	}
	report := func(node uuid.UUID, extra map[string]any) {
		t.Helper()
		row, err := q.GetOrgNode(ctx, sqlc.GetOrgNodeParams{ID: homeGW, OrgID: org})
		if err != nil {
			t.Fatal(err)
		}
		evaluation, _, err := nodeService.EvaluateDeviceAccess(ctx, org, device, row, "10.96.0.7", "10.96.0.9", "tcp", 443)
		if err != nil {
			t.Fatal(err)
		}
		caps := map[string]any{"policy_version": evaluation.PolicyVersion, "policy_hash": evaluation.PolicyHash}
		for key, value := range extra {
			caps[key] = value
		}
		raw, _ := json.Marshal(caps)
		exec(`UPDATE nodes SET capabilities=$2, policy_reported_at=now() WHERE id=$1`, node, raw)
	}
	const apiName = "kubernetes.default.svc.prod.k8s.acme.com"

	// Read: off by default, and a member may read it (org:view), as they may read the cluster.
	got, err := s.GetK8sClusterApiAccess(as(person, rbac.RoleMember), api.GetK8sClusterApiAccessRequestObject{OrgId: org, ClusterId: cluster})
	if err != nil {
		t.Fatal(err)
	}
	if state := got.(api.GetK8sClusterApiAccess200JSONResponse).Body; state.Enabled || state.Vip != nil || state.Fqdn != apiName || state.Port != 443 || state.RuleCount != 0 {
		t.Fatalf("default state = %+v", state)
	}
	// Another organization's cluster is 404, to read and to change, even for an administrator.
	if _, err := s.GetK8sClusterApiAccess(as(admin, rbac.RoleAdmin), api.GetK8sClusterApiAccessRequestObject{OrgId: org, ClusterId: otherCluster}); !hasCode(err, 404, "cluster_not_found") {
		t.Fatalf("another organization's cluster must be 404, got %v", err)
	}
	on := &api.SetK8sClusterApiAccessJSONRequestBody{Enabled: true}
	if _, err := s.SetK8sClusterApiAccess(as(admin, rbac.RoleAdmin), api.SetK8sClusterApiAccessRequestObject{OrgId: org, ClusterId: otherCluster, Body: on}); !hasCode(err, 404, "cluster_not_found") {
		t.Fatalf("another organization's cluster must be 404, got %v", err)
	}
	// A member cannot change it.
	if _, err := s.SetK8sClusterApiAccess(as(person, rbac.RoleMember), api.SetK8sClusterApiAccessRequestObject{OrgId: org, ClusterId: cluster, Body: on}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("a member must be 403, got %v", err)
	}
	if audits("k8s.api_access_enabled") != 0 {
		t.Fatal("a refused request wrote an audit entry")
	}

	// "Test access" before enabling: the name is recognised and the answer is "off".
	report(homeGW, nil)
	off := diagnose(apiName)
	if off.Overall != api.DeviceAccessDiagnosticOverallDenied || blocker(off) != "k8s_api_not_enabled" || off.Note != nil ||
		codes(off) != "device_active,posture_not_blocking,gateway_reporting,k8s_api_not_enabled,route_destination_unresolved,applied_policy_current" {
		t.Fatalf("off diagnostic: %s / %+v", codes(off), off)
	}
	// A rule cannot be written while it is off.
	clusterRef := cluster
	userKind := api.CreatePolicyRuleRequestSrcKind("user")
	ruleBody := &api.CreatePolicyRuleJSONRequestBody{SrcKind: &userKind, SrcUserId: &person, DstKind: api.CreatePolicyRuleRequestDstKind("k8s_api"), DstK8sApiClusterId: &clusterRef}
	if _, err := s.CreatePolicyRule(as(admin, rbac.RoleAdmin), api.CreatePolicyRuleRequestObject{OrgId: org, Body: ruleBody}); !hasCode(err, 400, "k8s_api_not_enabled") {
		t.Fatalf("a rule for an API that is off must be 400 k8s_api_not_enabled, got %v", err)
	}

	// Enable, as an administrator.
	set, err := s.SetK8sClusterApiAccess(as(admin, rbac.RoleAdmin), api.SetK8sClusterApiAccessRequestObject{OrgId: org, ClusterId: cluster, Body: on})
	if err != nil {
		t.Fatal(err)
	}
	state := set.(api.SetK8sClusterApiAccess200JSONResponse).Body
	if !state.Enabled || state.Vip == nil || *state.Vip == "100.66.0.2" || !strings.HasPrefix(*state.Vip, "100.66.0.") || audits("k8s.api_access_enabled") != 1 {
		t.Fatalf("enabled state = %+v audits=%d", state, audits("k8s.api_access_enabled"))
	}
	vip := *state.Vip

	// Enabled, no rule: default deny, said in terms of the cluster. The gateway has not reported yet.
	report(homeGW, nil)
	noRule := diagnose(apiName)
	if noRule.Overall != api.DeviceAccessDiagnosticOverallDenied || blocker(noRule) != "no_matching_grant" || noRule.Note != nil ||
		codes(noRule) != "device_active,posture_not_blocking,gateway_reporting,k8s_api_destination,route_configured,no_matching_grant,applied_policy_current,k8s_api_endpoint_not_observed" {
		t.Fatalf("no-rule diagnostic: %s / %+v", codes(noRule), noRule)
	}
	if message := noRule.Checks[5].Message; message != "No rule lets this device reach the Kubernetes API of prod." {
		t.Fatalf("no-rule message = %q", message)
	}

	// The rule: refused for a site source, accepted for the person.
	siteKind := api.CreatePolicyRuleRequestSrcKind("site")
	if _, err := s.CreatePolicyRule(as(admin, rbac.RoleAdmin), api.CreatePolicyRuleRequestObject{OrgId: org, Body: &api.CreatePolicyRuleJSONRequestBody{
		SrcKind: &siteKind, SrcSiteId: &site, DstKind: api.CreatePolicyRuleRequestDstKind("k8s_api"), DstK8sApiClusterId: &clusterRef}}); !hasCode(err, 400, "k8s_api_source_not_allowed") {
		t.Fatalf("a site source must be 400 k8s_api_source_not_allowed, got %v", err)
	}
	created, err := s.CreatePolicyRule(as(admin, rbac.RoleAdmin), api.CreatePolicyRuleRequestObject{OrgId: org, Body: ruleBody})
	if err != nil {
		t.Fatal(err)
	}
	rule := created.(api.CreatePolicyRule201JSONResponse).Body
	if rule.DstKind != api.PolicyRuleDstKindK8sApi || rule.DstK8sApiClusterId == nil || *rule.DstK8sApiClusterId != cluster ||
		rule.DstK8sApiAccessOff == nil || *rule.DstK8sApiAccessOff || rule.DstK8sServiceId != nil || rule.DstK8sClusterId != nil || rule.DstK8sServiceVanished {
		t.Fatalf("created rule = %+v", rule)
	}

	// Allowed, with the gateway reporting it forwards to the API: the fixed sentence is returned.
	report(homeGW, nil)
	report(clusterGW, map[string]any{"k8s_api_endpoint": "ready"})
	for _, destination := range []string{apiName, vip} {
		allowed := diagnose(destination)
		if allowed.Overall != api.DeviceAccessDiagnosticOverallAllowed || allowed.FirstBlocker != nil ||
			codes(allowed) != "device_active,posture_not_blocking,gateway_reporting,k8s_api_destination,route_configured,matching_grant,applied_policy_current,k8s_api_endpoint_ready" {
			t.Fatalf("%s: allowed diagnostic: %s / %+v", destination, codes(allowed), allowed)
		}
		if allowed.Note == nil || *allowed.Note != "Tunnex allows the connection. The cluster still decides what you may do: a 401 or 403 from kubectl is the cluster's answer, not Tunnex's." {
			t.Fatalf("%s: the fixed sentence is missing: %+v", destination, allowed.Note)
		}
		if grant := allowed.Checks[5]; grant.Facts == nil || (*grant.Facts)["rule_id"] != rule.Id.String() {
			t.Fatalf("%s: the rule check must name the rule: %+v", destination, grant)
		}
	}
	// An ordinary destination never carries the sentence.
	if plain := diagnose("10.96.0.9"); plain.Note != nil {
		t.Fatalf("an ordinary destination must not carry the Kubernetes sentence: %+v", plain.Note)
	}

	// The gateway is on the cluster's only control-plane node: the endpoint check says so.
	report(clusterGW, map[string]any{"k8s_api_endpoint": "endpoints_on_gateway_node"})
	onNode := diagnose(apiName)
	if onNode.Overall != api.DeviceAccessDiagnosticOverallDenied || blocker(onNode) != "k8s_api_endpoint_unavailable" || onNode.Note != nil {
		t.Fatalf("control-plane diagnostic: %s / %+v", codes(onNode), onNode)
	}
	if last := onNode.Checks[len(onNode.Checks)-1]; last.Facts == nil || (*last.Facts)["reason"] != "endpoints_on_gateway_node" || (*last.Facts)["gateway"] != "k8n3-cluster-gw" {
		t.Fatalf("the endpoint check must carry the gateway's reason: %+v", last)
	}

	// The rule list labels it, and says so when API access goes off.
	offBody := &api.SetK8sClusterApiAccessJSONRequestBody{Enabled: false}
	if _, err := s.SetK8sClusterApiAccess(as(admin, rbac.RoleAdmin), api.SetK8sClusterApiAccessRequestObject{OrgId: org, ClusterId: cluster, Body: offBody}); err != nil {
		t.Fatal(err)
	}
	if audits("k8s.api_access_disabled") != 1 {
		t.Fatalf("disable audit entries = %d", audits("k8s.api_access_disabled"))
	}
	listed, err := s.ListPolicyRules(as(admin, rbac.RoleAdmin), api.ListPolicyRulesRequestObject{OrgId: org})
	if err != nil {
		t.Fatal(err)
	}
	rules := listed.(api.ListPolicyRules200JSONResponse).Body
	if len(rules) != 1 || rules[0].DstK8sApiClusterId == nil || *rules[0].DstK8sApiClusterId != cluster || rules[0].DstK8sApiAccessOff == nil || !*rules[0].DstK8sApiAccessOff {
		t.Fatalf("listed rules after disabling = %+v", rules)
	}
	report(homeGW, nil)
	if again := diagnose(apiName); blocker(again) != "k8s_api_not_enabled" {
		t.Fatalf("after disabling: %s", codes(again))
	}
	// The other organization never resolves this cluster's name to anything of ours.
	otherDiag, err := s.TestDeviceAccess(authctx.WithPrincipal(ctx, &authctx.Principal{UserID: otherAdmin, EmailVerified: true, Roles: map[uuid.UUID]string{otherOrg: rbac.RoleAdmin}}),
		api.TestDeviceAccessRequestObject{OrgId: otherOrg, DeviceId: device, Params: api.TestDeviceAccessParams{Destination: apiName, Protocol: api.TestDeviceAccessParamsProtocol("tcp"), Port: 443}})
	if !hasCode(err, 404, "device_not_found") {
		t.Fatalf("another organization must not diagnose this device: %v / %+v", err, otherDiag)
	}
}
