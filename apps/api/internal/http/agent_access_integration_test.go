package http

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	policyservice "github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func TestAgentAccessDiagnosticPostgresContract(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for F08 integration proof")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	// Register the pool close before the fixture cleanup below. Cleanup callbacks
	// run LIFO, so the organization (and its cascaded device_status row) is
	// deleted while the pool is still usable instead of silently leaking into
	// later package-level integration tests.
	t.Cleanup(pool.Close)
	q := sqlc.New(pool)
	org, owner, outsider, node, device, resource, rule := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(stmt string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, stmt, args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	exec(`INSERT INTO organizations (id,name,slug,pool_cidr,managed_agent_runtime_enabled,zero_trust_mode) VALUES ($1,'F08',$2,'10.99.0.0/24',true,'enforcing')`, org, "f08-"+org.String()[:8])
	for _, user := range []uuid.UUID{owner, outsider} {
		exec(`INSERT INTO users (id,email,status) VALUES ($1,$2,'active')`, user, user.String()+"@f08.example")
		exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')`, org, user)
	}
	exec(`INSERT INTO nodes (id,org_id,name,status,cert_serial,wg_public_key,endpoint,last_seen_at) VALUES ($1,$2,'f08-gw','active',$3,'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','gw.example:51820',now())`, node, org, "f08-cert-"+node.String())
	exec(`INSERT INTO devices (id,org_id,user_id,node_id,name,platform,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'f08-agent','linux','BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=','10.99.0.7','active','agent')`, device, org, owner, node)
	exec(`INSERT INTO agent_profiles (device_id) VALUES ($1)`, device)
	exec(`INSERT INTO agent_runtime_state (device_id,desired_revision,applied_revision,last_attempted_revision,client_version,last_seen_at) VALUES ($1,1,1,1,'f08-live',now())`, device)
	exec(`INSERT INTO device_status (device_id,last_handshake_at,rx_bytes,tx_bytes,updated_at) VALUES ($1,now(),10,20,now())`, device)
	exec(`INSERT INTO resources (id,org_id,name,cidr,protocol,port_low,port_high) VALUES ($1,$2,'f08-target','10.99.0.8/32','tcp',443,443)`, resource, org)
	exec(`INSERT INTO policy_rules (id,org_id,src_kind,src_device_id,dst_kind,dst_resource_id) VALUES ($1,$2,'agent',$3,'resource',$4)`, rule, org, device, resource)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	policy := policyservice.NewService(pool)
	nodeService := nodes.NewService(pool, nil, nil)
	nodeService.SetPolicyProvider(policy)
	nodeRow, err := q.GetOrgNode(ctx, sqlc.GetOrgNodeParams{ID: node, OrgID: org})
	if err != nil {
		t.Fatal(err)
	}
	evaluation, _, err := nodeService.EvaluateAgentAccess(ctx, org, device, nodeRow, "10.99.0.7", "10.99.0.8", "tcp", 443)
	if err != nil || !evaluation.Allowed || evaluation.RuleID != rule.String() {
		t.Fatalf("compiled setup evaluation: %+v / %v", evaluation, err)
	}
	caps, _ := json.Marshal(map[string]any{"policy_version": evaluation.PolicyVersion, "policy_hash": evaluation.PolicyHash})
	exec(`UPDATE nodes SET capabilities=$2, policy_reported_at=now() WHERE id=$1`, node, caps)

	s := apiServer{nodes: nodeService, devices: devices.NewService(pool, nil, nil), policy: policy,
		agentRuntime: agentruntime.New(pool, agentruntime.OrganizationOptIn(q, func() bool { return true }))}
	memberCtx := func(user uuid.UUID, role string) context.Context {
		return authctx.WithPrincipal(ctx, &authctx.Principal{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: role}})
	}
	request := func(destination string) api.TestAgentAccessRequestObject {
		return api.TestAgentAccessRequestObject{OrgId: org, DeviceId: device, Params: api.TestAgentAccessParams{
			Destination: destination, Protocol: api.TestAgentAccessParamsProtocol("tcp"), Port: 443,
		}}
	}
	diagnose := func(destination string) api.AgentAccessDiagnostic {
		t.Helper()
		response, err := s.TestAgentAccess(memberCtx(owner, rbac.RoleMember), request(destination))
		if err != nil {
			t.Fatal(err)
		}
		body, ok := response.(api.TestAgentAccess200JSONResponse)
		if !ok {
			t.Fatalf("diagnostic response: %#v", response)
		}
		return body.Body
	}
	assertBlocker := func(body api.AgentAccessDiagnostic, code string) {
		t.Helper()
		if body.FirstBlocker == nil || *body.FirstBlocker != code {
			t.Fatalf("expected blocker %q, got %#v", code, body)
		}
	}
	var beforeDevice, beforeRuntime, beforeNode time.Time
	var beforeRule string
	if err := pool.QueryRow(ctx, `SELECT d.updated_at,s.updated_at,n.updated_at,md5(row_to_json(r)::text) FROM devices d JOIN agent_runtime_state s ON s.device_id=d.id JOIN nodes n ON n.id=d.node_id JOIN policy_rules r ON r.id=$2 WHERE d.id=$1`, device, rule).Scan(&beforeDevice, &beforeRuntime, &beforeNode, &beforeRule); err != nil {
		t.Fatal(err)
	}
	allowed := diagnose("10.99.0.8")
	if allowed.Overall != api.AgentAccessDiagnosticOverallAllowed || len(allowed.Checks) != 7 || allowed.Checks[5].Code != "matching_grant" {
		t.Fatalf("allowed diagnostic: %#v", allowed)
	}
	assertDiagnosticOrder(t, allowed, "route_configured", "matching_grant")
	if allowed.Checks[5].Facts == nil || (*allowed.Checks[5].Facts)["rule_id"] != rule.String() || (*allowed.Checks[5].Facts)["policy_hash"] != evaluation.PolicyHash {
		t.Fatalf("allowed diagnostic omitted exact compiled facts: %#v", allowed.Checks[5])
	}

	hostname := diagnose("db.internal.example")
	if hostname.Overall != api.AgentAccessDiagnosticOverallInconclusive {
		t.Fatalf("hostname without agent DNS must be inconclusive: %#v", hostname)
	}
	assertBlocker(hostname, "agent_dns_not_observed")
	assertDiagnosticOrder(t, hostname, "agent_dns_not_observed", "route_destination_unresolved")
	assertBlocker(diagnose("192.0.2.10"), "route_not_configured")

	exec(`UPDATE policy_rules SET expires_at=now()-interval '1 minute' WHERE id=$1`, rule)
	assertBlocker(diagnose("10.99.0.8"), "no_matching_grant")
	exec(`UPDATE policy_rules SET expires_at=NULL WHERE id=$1`, rule)
	exec(`UPDATE agent_runtime_state SET last_seen_at=now()-interval '4 minutes' WHERE device_id=$1`, device)
	assertBlocker(diagnose("10.99.0.8"), "runtime_not_ready")
	exec(`UPDATE agent_runtime_state SET last_seen_at=now() WHERE device_id=$1`, device)
	exec(`DELETE FROM device_status WHERE device_id=$1`, device)
	exec(`UPDATE nodes SET last_seen_at=now()-interval '4 minutes' WHERE id=$1`, node)
	assertBlocker(diagnose("10.99.0.8"), "gateway_not_reporting")
	exec(`INSERT INTO device_status (device_id,last_handshake_at,rx_bytes,tx_bytes,updated_at) VALUES ($1,now(),10,20,now())`, device)
	exec(`UPDATE nodes SET last_seen_at=now() WHERE id=$1`, node)
	exec(`UPDATE devices SET status='suspended' WHERE id=$1`, device)
	assertBlocker(diagnose("10.99.0.8"), "agent_not_active")
	exec(`UPDATE devices SET status='active' WHERE id=$1`, device)
	exec(`UPDATE organizations SET managed_agent_runtime_enabled=false WHERE id=$1`, org)
	assertBlocker(diagnose("10.99.0.8"), "runtime_not_enabled")
	exec(`UPDATE organizations SET managed_agent_runtime_enabled=true WHERE id=$1`, org)
	exec(`UPDATE nodes SET capabilities=jsonb_set(capabilities,'{policy_hash}','"wrong"'), policy_reported_at=now() WHERE id=$1`, node)
	assertBlocker(diagnose("10.99.0.8"), "applied_policy_mismatch")
	exec(`UPDATE nodes SET capabilities=$2, policy_reported_at=now() WHERE id=$1`, node, caps)

	denied := diagnose("10.99.0.9")
	if denied.Overall != api.AgentAccessDiagnosticOverallDenied {
		t.Fatalf("deny diagnostic: %#v", denied)
	}
	assertBlocker(denied, "no_matching_grant")

	// Establish a fresh post-fixture baseline, then prove repeated evaluations
	// themselves do not touch any canonical policy/runtime/gateway row.
	if err := pool.QueryRow(ctx, `SELECT d.updated_at,s.updated_at,n.updated_at,md5(row_to_json(r)::text) FROM devices d JOIN agent_runtime_state s ON s.device_id=d.id JOIN nodes n ON n.id=d.node_id JOIN policy_rules r ON r.id=$2 WHERE d.id=$1`, device, rule).Scan(&beforeDevice, &beforeRuntime, &beforeNode, &beforeRule); err != nil {
		t.Fatal(err)
	}
	_ = diagnose("10.99.0.8")
	_ = diagnose("10.99.0.8")
	var afterDevice, afterRuntime, afterNode time.Time
	var afterRule string
	if err := pool.QueryRow(ctx, `SELECT d.updated_at,s.updated_at,n.updated_at,md5(row_to_json(r)::text) FROM devices d JOIN agent_runtime_state s ON s.device_id=d.id JOIN nodes n ON n.id=d.node_id JOIN policy_rules r ON r.id=$2 WHERE d.id=$1`, device, rule).Scan(&afterDevice, &afterRuntime, &afterNode, &afterRule); err != nil {
		t.Fatal(err)
	}
	if !beforeDevice.Equal(afterDevice) || !beforeRuntime.Equal(afterRuntime) || !beforeNode.Equal(afterNode) || beforeRule != afterRule {
		t.Fatalf("read-only diagnostic changed canonical rows: before=%v/%v/%v/%v after=%v/%v/%v/%v", beforeDevice, beforeRuntime, beforeNode, beforeRule, afterDevice, afterRuntime, afterNode, afterRule)
	}

	_, knownErr := s.TestAgentAccess(memberCtx(outsider, rbac.RoleMember), request("10.99.0.8"))
	missingReq := request("10.99.0.8")
	missingReq.DeviceId = uuid.New()
	_, missingErr := s.TestAgentAccess(memberCtx(outsider, rbac.RoleMember), missingReq)
	if !hasCode(knownErr, 403, "forbidden") || !hasCode(missingErr, 403, "forbidden") || knownErr.Error() != missingErr.Error() {
		t.Fatalf("known/missing member no-oracle mismatch: known=%v missing=%v", knownErr, missingErr)
	}
}

func assertDiagnosticOrder(t *testing.T, diagnostic api.AgentAccessDiagnostic, before, after string) {
	t.Helper()
	beforeAt, afterAt := -1, -1
	for i, check := range diagnostic.Checks {
		if check.Code == before {
			beforeAt = i
		}
		if check.Code == after {
			afterAt = i
		}
	}
	if beforeAt < 0 || afterAt < 0 || beforeAt >= afterAt {
		t.Fatalf("expected %q before %q, checks=%#v", before, after, diagnostic.Checks)
	}
}
