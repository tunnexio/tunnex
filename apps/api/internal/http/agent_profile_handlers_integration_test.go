package http

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func TestAgentProfileHandlersAuthorizationAndAtomicity(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for handler integration proof")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var migrated bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('agent_profiles') IS NOT NULL`).Scan(&migrated); err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Skip("migration 0088 is not applied")
	}

	org, owner, outsider, node, device := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	_, err = pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,max_devices_per_user) VALUES ($1,'F01',$2,10)`, org, "f01-"+org.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org) })
	for _, u := range []uuid.UUID{owner, outsider} {
		if _, err = pool.Exec(ctx, `INSERT INTO users (id,email,name,status) VALUES ($1,$2,'F01','active')`, u, u.String()+"@example.test"); err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, `INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')`, org, u); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = pool.Exec(ctx, `INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint) VALUES ($1,$2,'gw',$3,'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','gw.example:51820')`, node, org, "serial-"+node.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO devices (id,org_id,user_id,node_id,name,platform,public_key,assigned_ip,status,transport,kind) VALUES ($1,$2,$3,$4,'agent','agent','BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=','10.99.0.10','active','wireguard','agent')`, device, org, owner, node); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO agent_profiles (device_id) VALUES ($1)`, device); err != nil {
		t.Fatal(err)
	}

	s := apiServer{devices: devices.NewService(pool, nil, nil), nodes: nodes.NewService(pool, nil, nil), policy: NewPolicyPort(pool, nil)}
	memberCtx := func(user uuid.UUID, role string) context.Context {
		return authctx.WithPrincipal(ctx, &authctx.Principal{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: role}})
	}
	listReq := api.ListAgentsRequestObject{OrgId: org}
	ownerList, err := s.ListAgents(memberCtx(owner, rbac.RoleMember), listReq)
	if err != nil {
		t.Fatalf("owner agent list: %v", err)
	}
	ownerListBody, ok := ownerList.(api.ListAgents200JSONResponse)
	if !ok || len(ownerListBody.Body) != 1 || ownerListBody.Body[0].OwnerEmail == nil || *ownerListBody.Body[0].OwnerEmail != owner.String()+"@example.test" {
		t.Fatalf("owner list omitted own owner email: %#v", ownerList)
	}
	outsiderList, err := s.ListAgents(memberCtx(outsider, rbac.RoleMember), listReq)
	if err != nil {
		t.Fatalf("member agent list: %v", err)
	}
	outsiderBody, ok := outsiderList.(api.ListAgents200JSONResponse)
	if !ok || len(outsiderBody.Body) != 1 || outsiderBody.Body[0].OwnerEmail != nil {
		t.Fatalf("plain member list leaked owner email: %#v", outsiderList)
	}
	adminList, err := s.ListAgents(memberCtx(owner, rbac.RoleOwner), listReq)
	if err != nil {
		t.Fatalf("admin/owner agent list: %v", err)
	}
	adminBody, ok := adminList.(api.ListAgents200JSONResponse)
	if !ok || len(adminBody.Body) != 1 || adminBody.Body[0].OwnerEmail == nil {
		t.Fatalf("management list omitted owner email: %#v", adminList)
	}
	if _, err := s.GetAgentProfile(memberCtx(outsider, rbac.RoleMember), api.GetAgentProfileRequestObject{OrgId: org, DeviceId: device}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("unrelated member profile read: %v", err)
	}

	env, runtime := "staging", "python"
	labels := map[string]string{"team": "sec"}
	ownerBody := &api.UpdateAgentProfileRequest{Environment: &env, Runtime: &runtime, Labels: &labels}
	if _, err := s.UpdateAgentProfile(memberCtx(owner, rbac.RoleMember), api.UpdateAgentProfileRequestObject{OrgId: org, DeviceId: device, Body: ownerBody}); err != nil {
		t.Fatalf("owner metadata update: %v", err)
	}
	refetched, err := s.GetAgentProfile(memberCtx(owner, rbac.RoleMember), api.GetAgentProfileRequestObject{OrgId: org, DeviceId: device})
	if err != nil {
		t.Fatalf("owner metadata refetch: %v", err)
	}
	profile, ok := refetched.(api.GetAgentProfile200JSONResponse)
	if !ok || profile.Body.Environment != env || profile.Body.Runtime != runtime || profile.Body.Labels["team"] != "sec" {
		t.Fatalf("metadata was not persisted in server refetch: %#v", refetched)
	}
	status := api.UpdateAgentProfileRequestStatus("suspended")
	if _, err := s.UpdateAgentProfile(memberCtx(owner, rbac.RoleMember), api.UpdateAgentProfileRequestObject{OrgId: org, DeviceId: device, Body: &api.UpdateAgentProfileRequest{Status: &status}}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("owner lifecycle update: %v", err)
	}

	adminCtx := memberCtx(owner, rbac.RoleOwner)
	active := api.UpdateAgentProfileRequestStatus("active")
	if _, err := s.UpdateAgentProfile(adminCtx, api.UpdateAgentProfileRequestObject{OrgId: org, DeviceId: device, Body: &api.UpdateAgentProfileRequest{Status: &status}}); err != nil {
		t.Fatalf("admin suspend: %v", err)
	}
	if _, err := s.UpdateAgentProfile(memberCtx(owner, rbac.RoleMember), api.UpdateAgentProfileRequestObject{OrgId: org, DeviceId: device, Body: &api.UpdateAgentProfileRequest{Status: &active}}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("owner lifecycle resume: %v", err)
	}
	if _, err := s.UpdateAgentProfile(adminCtx, api.UpdateAgentProfileRequestObject{OrgId: org, DeviceId: device, Body: &api.UpdateAgentProfileRequest{Status: &active}}); err != nil {
		t.Fatalf("admin resume: %v", err)
	}

	for _, terminal := range []string{"pending", "revoked"} {
		if _, err := pool.Exec(ctx, `UPDATE devices SET status=$2 WHERE id=$1`, device, terminal); err != nil {
			t.Fatal(err)
		}
		badEnv := "must-not-commit"
		if _, err := s.UpdateAgentProfile(adminCtx, api.UpdateAgentProfileRequestObject{OrgId: org, DeviceId: device, Body: &api.UpdateAgentProfileRequest{Environment: &badEnv, Status: &status}}); !hasCode(err, 409, "invalid_agent_transition") {
			t.Fatalf("%s lifecycle bypass: %v", terminal, err)
		}
		var got string
		if err := pool.QueryRow(ctx, `SELECT environment FROM agent_profiles WHERE device_id=$1`, device).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != env {
			t.Fatalf("%s failure partially committed metadata: got %q want %q", terminal, got, env)
		}
	}
}
