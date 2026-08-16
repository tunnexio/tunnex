//go:build enterprise

package http

import (
	"context"
	"net/url"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func TestAgentJITAccessRoutesAuthorizationRefetchAndRuleOwnership(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for F10 route proof")
	}
	ctx := context.Background()
	adminPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer adminPool.Close()
	base, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	databaseName := "tnx_f10_route_" + uuid.NewString()[:8]
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+databaseName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+databaseName+" WITH (FORCE)")
	})
	fresh := *base
	fresh.Path = "/" + databaseName
	if err := db.MigrateTo(fresh.String(), 98); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, fresh.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	org, orgOwner, agentOwner, unrelated, node, agent, resource := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(stmt string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, stmt, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations (id,name,slug,pool_cidr,zero_trust_mode) VALUES ($1,'F10 route',$2,'10.122.0.0/24','enforcing')`, org, "f10-route-"+org.String()[:8])
	for _, row := range []struct {
		id   uuid.UUID
		role string
	}{{orgOwner, rbac.RoleOwner}, {agentOwner, rbac.RoleMember}, {unrelated, rbac.RoleMember}} {
		exec(`INSERT INTO users (id,email,name,status) VALUES ($1,$2,'F10','active')`, row.id, row.id.String()+"@f10.test")
		exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,$3)`, org, row.id, row.role)
	}
	exec(`INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,'f10-gw',$3)`, node, org, "f10-route-"+node.String())
	exec(`INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'f10-agent',$5,'10.122.0.2','active','agent')`, agent, org, agentOwner, node, "f10-agent-"+agent.String())
	exec(`INSERT INTO agent_profiles (device_id,labels) VALUES ($1,'{}')`, agent)
	exec(`INSERT INTO resources (id,org_id,name,cidr,protocol,port_low,port_high) VALUES ($1,$2,'production-db','10.80.0.0/24','tcp',5432,5432)`, resource, org)

	with := func(user uuid.UUID, role string) context.Context {
		return authctx.WithPrincipal(ctx, &authctx.Principal{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: role}})
	}
	s := apiServer{
		system: sqlc.New(pool), devices: devices.NewService(pool, nil, nil),
		agentAccess: agentaccess.New(pool, nil), policy: policy.NewService(pool),
	}
	ownerCtx, requesterCtx, unrelatedCtx := with(orgOwner, rbac.RoleOwner), with(agentOwner, rbac.RoleMember), with(unrelated, rbac.RoleMember)
	createBody := &api.CreateAgentAccessRequest{
		DeviceId: agent, DestinationKind: "resource", DestinationId: resource,
		Reason: "deploy database migration", DurationSeconds: 3600, IdempotencyKey: "route-create-1",
	}
	if _, err := s.CreateAgentAccessRequest(requesterCtx, api.CreateAgentAccessRequestRequestObject{OrgId: org, Body: createBody}); !hasCode(err, 403, "opt_in_required") {
		t.Fatalf("default-off request: %v", err)
	}
	if _, err := s.SetOrganizationAgentJITAccessEnabled(unrelatedCtx, api.SetOrganizationAgentJITAccessEnabledRequestObject{OrgId: org, Body: &api.SetAgentJITAccessSettingRequest{Enabled: true}}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member opt-in: %v", err)
	}
	if _, err := s.SetOrganizationAgentJITAccessEnabled(ownerCtx, api.SetOrganizationAgentJITAccessEnabledRequestObject{OrgId: org, Body: &api.SetAgentJITAccessSettingRequest{Enabled: true}}); err != nil {
		t.Fatalf("owner opt-in: %v", err)
	}
	created, err := s.CreateAgentAccessRequest(requesterCtx, api.CreateAgentAccessRequestRequestObject{OrgId: org, Body: createBody})
	if err != nil {
		t.Fatal(err)
	}
	createdBody, ok := created.(api.CreateAgentAccessRequest201JSONResponse)
	if !ok || createdBody.Body.State != "pending" || createdBody.Body.AgentName != "f10-agent" || createdBody.Body.DestinationName != "production-db" {
		t.Fatalf("create response: %#v", created)
	}
	replayed, err := s.CreateAgentAccessRequest(requesterCtx, api.CreateAgentAccessRequestRequestObject{OrgId: org, Body: createBody})
	if err != nil {
		t.Fatal(err)
	}
	if replayBody, ok := replayed.(api.CreateAgentAccessRequest200JSONResponse); !ok || replayBody.Body.Id != createdBody.Body.Id {
		t.Fatalf("create idempotent refetch: %#v", replayed)
	}
	if _, err := s.CreateAgentAccessRequest(unrelatedCtx, api.CreateAgentAccessRequestRequestObject{OrgId: org, Body: createBody}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("unrelated create: %v", err)
	}
	if _, err := s.ListAgentAccessRequests(unrelatedCtx, api.ListAgentAccessRequestsRequestObject{OrgId: org}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("unrelated list: %v", err)
	}
	listed, err := s.ListAgentAccessRequests(requesterCtx, api.ListAgentAccessRequestsRequestObject{OrgId: org})
	if err != nil {
		t.Fatal(err)
	}
	if body := listed.(api.ListAgentAccessRequests200JSONResponse).Body; len(body.Items) != 1 || body.Items[0].Id != createdBody.Body.Id {
		t.Fatalf("scoped request list: %#v", body)
	}
	approved, err := s.ApproveAgentAccessRequest(ownerCtx, api.ApproveAgentAccessRequestRequestObject{OrgId: org, RequestId: createdBody.Body.Id, Body: &api.AgentAccessIdempotencyRequest{IdempotencyKey: "route-approve-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if approved.(api.ApproveAgentAccessRequest200JSONResponse).Body.State != "approved" {
		t.Fatalf("approve response: %#v", approved)
	}
	detail, err := s.GetAgentAccessRequest(requesterCtx, api.GetAgentAccessRequestRequestObject{OrgId: org, RequestId: createdBody.Body.Id})
	if err != nil {
		t.Fatal(err)
	}
	if body := detail.(api.GetAgentAccessRequest200JSONResponse).Body; len(body.Events) != 2 || body.Request.State != "approved" {
		t.Fatalf("detail refetch: %#v", body)
	}
	rules, err := s.ListPolicyRules(ownerCtx, api.ListPolicyRulesRequestObject{OrgId: org})
	if err != nil {
		t.Fatal(err)
	}
	ruleBody := rules.(api.ListPolicyRules200JSONResponse).Body
	if len(ruleBody) != 1 || !ruleBody[0].ManagedByAgentAccess || ruleBody[0].AgentAccessRequestId == nil || *ruleBody[0].AgentAccessRequestId != createdBody.Body.Id {
		t.Fatalf("JIT managed rule surface: %#v", ruleBody)
	}
	if _, err := s.SetOrganizationAgentJITAccessEnabled(ownerCtx, api.SetOrganizationAgentJITAccessEnabledRequestObject{OrgId: org, Body: &api.SetAgentJITAccessSettingRequest{Enabled: false}}); !hasCode(err, 409, "agent_access_request_conflict") {
		t.Fatalf("disable with live request: %v", err)
	}
	if _, err := s.RevokeAgentAccessRequest(ownerCtx, api.RevokeAgentAccessRequestRequestObject{OrgId: org, RequestId: createdBody.Body.Id, Body: &api.AgentAccessIdempotencyRequest{IdempotencyKey: "route-revoke-1"}}); err != nil {
		t.Fatal(err)
	}
	setting, err := s.SetOrganizationAgentJITAccessEnabled(ownerCtx, api.SetOrganizationAgentJITAccessEnabledRequestObject{OrgId: org, Body: &api.SetAgentJITAccessSettingRequest{Enabled: false}})
	if err != nil || setting.(api.SetOrganizationAgentJITAccessEnabled200JSONResponse).Body.Enabled {
		t.Fatalf("disable after revoke: response=%#v err=%v", setting, err)
	}
}
