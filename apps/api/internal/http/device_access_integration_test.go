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
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	policyservice "github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func TestDeviceAccessDiagnosticPostgresContract(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for the UIX-1 integration proof")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	// Registered first so it runs last: the fixture cleanup below needs the pool.
	t.Cleanup(pool.Close)
	q := sqlc.New(pool)
	org, otherOrg := uuid.New(), uuid.New()
	admin, person, otherUser := uuid.New(), uuid.New(), uuid.New()
	node, otherNode := uuid.New(), uuid.New()
	device, agent, otherDevice := uuid.New(), uuid.New(), uuid.New()
	resource, rule := uuid.New(), uuid.New()
	exec := func(stmt string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, stmt, args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	exec(`INSERT INTO organizations (id,name,slug,pool_cidr,zero_trust_mode) VALUES ($1,'UIX1',$2,'10.98.0.0/24','enforcing')`, org, "uix1-"+org.String()[:8])
	exec(`INSERT INTO organizations (id,name,slug,pool_cidr,zero_trust_mode) VALUES ($1,'UIX1 other',$2,'10.97.0.0/24','enforcing')`, otherOrg, "uix1-"+otherOrg.String()[:8])
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id = ANY($1)`, []uuid.UUID{org, otherOrg})
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = ANY($1)`, []uuid.UUID{admin, person, otherUser})
	})
	for user, home := range map[uuid.UUID]uuid.UUID{admin: org, person: org, otherUser: otherOrg} {
		exec(`INSERT INTO users (id,email,status) VALUES ($1,$2,'active')`, user, user.String()+"@uix1.example")
		exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')`, home, user)
	}
	exec(`INSERT INTO nodes (id,org_id,name,status,cert_serial,wg_public_key,endpoint,last_seen_at) VALUES ($1,$2,'uix1-gw','active',$3,'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','gw.example:51820',now())`, node, org, "uix1-cert-"+node.String())
	exec(`INSERT INTO nodes (id,org_id,name,status,cert_serial,wg_public_key,endpoint,last_seen_at) VALUES ($1,$2,'uix1-other-gw','active',$3,'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=','other.example:51820',now())`, otherNode, otherOrg, "uix1-cert-"+otherNode.String())
	exec(`INSERT INTO devices (id,org_id,user_id,node_id,name,platform,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'uix1-laptop','macos',$5,'10.98.0.7','active','human')`, device, org, person, node, wgTestKey(device))
	exec(`INSERT INTO devices (id,org_id,user_id,node_id,name,platform,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'uix1-agent','linux',$5,'10.98.0.9','active','agent')`, agent, org, admin, node, wgTestKey(agent))
	exec(`INSERT INTO devices (id,org_id,user_id,node_id,name,platform,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'uix1-other-laptop','macos',$5,'10.97.0.7','active','human')`, otherDevice, otherOrg, otherUser, otherNode, wgTestKey(otherDevice))
	exec(`INSERT INTO resources (id,org_id,name,cidr,protocol,port_low,port_high) VALUES ($1,$2,'uix1-orders','10.98.0.8/32','tcp',443,443)`, resource, org)
	exec(`INSERT INTO policy_rules (id,org_id,src_kind,src_user_id,dst_kind,dst_resource_id) VALUES ($1,$2,'user',$3,'resource',$4)`, rule, org, person, resource)

	policy := policyservice.NewService(pool)
	nodeService := nodes.NewService(pool, nil, nil)
	nodeService.SetPolicyProvider(policy)
	nodeRow, err := q.GetOrgNode(ctx, sqlc.GetOrgNodeParams{ID: node, OrgID: org})
	if err != nil {
		t.Fatal(err)
	}
	evaluation, reach, err := nodeService.EvaluateDeviceAccess(ctx, org, device, nodeRow, "10.98.0.7", "10.98.0.8", "tcp", 443)
	if err != nil || !evaluation.Allowed || evaluation.RuleID != rule.String() || reach.PoolCIDR != "10.98.0.0/24" {
		t.Fatalf("compiled setup evaluation: %+v reach=%+v err=%v", evaluation, reach, err)
	}
	caps, _ := json.Marshal(map[string]any{"policy_version": evaluation.PolicyVersion, "policy_hash": evaluation.PolicyHash})
	exec(`UPDATE nodes SET capabilities=$2, policy_reported_at=now() WHERE id=$1`, node, caps)

	s := apiServer{nodes: nodeService, devices: devices.NewService(pool, nil, nil), policy: policy}
	as := func(user uuid.UUID, role string) context.Context {
		return authctx.WithPrincipal(ctx, &authctx.Principal{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: role}})
	}
	request := func(deviceID uuid.UUID, destination string) api.TestDeviceAccessRequestObject {
		return api.TestDeviceAccessRequestObject{OrgId: org, DeviceId: deviceID, Params: api.TestDeviceAccessParams{
			Destination: destination, Protocol: api.TestDeviceAccessParamsProtocol("tcp"), Port: 443,
		}}
	}
	diagnose := func(destination string) api.DeviceAccessDiagnostic {
		t.Helper()
		response, err := s.TestDeviceAccess(as(admin, rbac.RoleAdmin), request(device, destination))
		if err != nil {
			t.Fatal(err)
		}
		body, ok := response.(api.TestDeviceAccess200JSONResponse)
		if !ok {
			t.Fatalf("diagnostic response: %#v", response)
		}
		return body.Body
	}
	codes := func(body api.DeviceAccessDiagnostic) string {
		out := make([]string, 0, len(body.Checks))
		for _, check := range body.Checks {
			out = append(out, check.Code)
		}
		return strings.Join(out, ",")
	}
	assertBlocker := func(body api.DeviceAccessDiagnostic, code string) {
		t.Helper()
		if body.FirstBlocker == nil || *body.FirstBlocker != code {
			t.Fatalf("expected blocker %q, got %s / %#v", code, codes(body), body)
		}
	}

	allowed := diagnose("10.98.0.8")
	if allowed.Overall != api.DeviceAccessDiagnosticOverallAllowed || allowed.FirstBlocker != nil ||
		codes(allowed) != "device_active,posture_not_blocking,gateway_reporting,destination_ip,route_configured,matching_grant,applied_policy_current" {
		t.Fatalf("allowed diagnostic: %s / %#v", codes(allowed), allowed)
	}
	if grant := allowed.Checks[5]; grant.Facts == nil || (*grant.Facts)["rule_id"] != rule.String() || (*grant.Facts)["policy_hash"] != evaluation.PolicyHash {
		t.Fatalf("allowed diagnostic omitted the compiled rule: %#v", grant)
	}
	if route := allowed.Checks[4]; !strings.Contains(route.Message, "home gateway") {
		t.Fatalf("route check must state the home-gateway limit: %#v", route)
	}

	denied := diagnose("10.98.0.20")
	if denied.Overall != api.DeviceAccessDiagnosticOverallDenied {
		t.Fatalf("deny diagnostic: %s / %#v", codes(denied), denied)
	}
	assertBlocker(denied, "no_matching_grant")
	wrongPort := request(device, "10.98.0.8")
	wrongPort.Params.Port = 22
	if response, err := s.TestDeviceAccess(as(admin, rbac.RoleAdmin), wrongPort); err != nil {
		t.Fatal(err)
	} else {
		assertBlocker(response.(api.TestDeviceAccess200JSONResponse).Body, "no_matching_grant")
	}

	hostname := diagnose("orders.internal.example")
	if hostname.Overall != api.DeviceAccessDiagnosticOverallInconclusive ||
		codes(hostname) != "device_active,posture_not_blocking,gateway_reporting,device_dns_not_observed,route_destination_unresolved,applied_policy_current" {
		t.Fatalf("hostname diagnostic: %s / %#v", codes(hostname), hostname)
	}
	assertBlocker(diagnose("192.0.2.10"), "route_not_configured")

	exec(`UPDATE devices SET health_blocked=true WHERE id=$1`, device)
	assertBlocker(diagnose("10.98.0.8"), "posture_blocked")
	exec(`UPDATE devices SET health_blocked=false WHERE id=$1`, device)
	exec(`UPDATE nodes SET last_seen_at=now()-interval '10 minutes' WHERE id=$1`, node)
	assertBlocker(diagnose("10.98.0.8"), "gateway_not_reporting")
	exec(`UPDATE nodes SET last_seen_at=now() WHERE id=$1`, node)
	exec(`UPDATE policy_rules SET expires_at=now()-interval '1 minute' WHERE id=$1`, rule)
	assertBlocker(diagnose("10.98.0.8"), "no_matching_grant")
	exec(`UPDATE policy_rules SET expires_at=NULL WHERE id=$1`, rule)
	if again := diagnose("10.98.0.8"); again.Overall != api.DeviceAccessDiagnosticOverallAllowed {
		t.Fatalf("restored fixture must be allowed again: %s", codes(again))
	}

	if _, err := s.TestDeviceAccess(as(admin, rbac.RoleAdmin), request(otherDevice, "10.98.0.8")); !hasCode(err, 404, "device_not_found") {
		t.Fatalf("another organization's device must be 404 device_not_found, got %v", err)
	}
	if _, err := s.TestDeviceAccess(as(admin, rbac.RoleAdmin), request(agent, "10.98.0.8")); !hasCode(err, 404, "device_not_found") {
		t.Fatalf("an agent id must be 404 device_not_found, got %v", err)
	}
	if _, err := s.TestDeviceAccess(as(admin, rbac.RoleAdmin), request(uuid.New(), "10.98.0.8")); !hasCode(err, 404, "device_not_found") {
		t.Fatalf("an unknown id must be 404 device_not_found, got %v", err)
	}
	// A member lacks policy:view, even for a device they own, and learns nothing about ids.
	_, ownErr := s.TestDeviceAccess(as(person, rbac.RoleMember), request(device, "10.98.0.8"))
	_, missingErr := s.TestDeviceAccess(as(person, rbac.RoleMember), request(uuid.New(), "10.98.0.8"))
	if !hasCode(ownErr, 403, "forbidden") || !hasCode(missingErr, 403, "forbidden") {
		t.Fatalf("caller without policy:view must be 403: own=%v missing=%v", ownErr, missingErr)
	}
	badTuple := request(device, "10.98.0.8")
	badTuple.Params.Port = 0
	if _, err := s.TestDeviceAccess(as(admin, rbac.RoleAdmin), badTuple); !hasCode(err, 400, "invalid_device_access_tuple") {
		t.Fatalf("invalid tuple must be 400, got %v", err)
	}
}

// wgTestKey derives a distinct, well-formed 44-character key per fixture row.
func wgTestKey(id uuid.UUID) string {
	return strings.ToUpper(strings.ReplaceAll(id.String(), "-", ""))[:32] + "AAAAAAAAAAA="
}
