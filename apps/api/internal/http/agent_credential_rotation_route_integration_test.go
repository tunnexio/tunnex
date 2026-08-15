//go:build enterprise

package http

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func TestAgentCredentialRotationEnterpriseRoutePostgres(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for F05 route proof")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	org, owner, member, node, device := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'F05 route',$2,'10.112.0.0/24')`, org, "f05-route-"+org.String()[:8])
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })
	for id, role := range map[uuid.UUID]string{owner: rbac.RoleOwner, member: rbac.RoleMember} {
		exec(`INSERT INTO users (id,email) VALUES ($1,$2)`, id, id.String()+"@example.com")
		exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,$3)`, org, id, role)
	}
	exec(`INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,'gw',$3)`, node, org, "f05-route-"+node.String())
	exec(`INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES ($1,$2,$3,$4,'agent','f05-route-key','10.112.0.2','active','agent')`, device, org, owner, node)
	hash := sha256.Sum256([]byte("tnx_runtime_route_" + device.String()))
	exec(`INSERT INTO agent_runtime_credentials (org_id,device_id,token_hash) VALUES ($1,$2,$3)`, org, device, hash[:])

	s := apiServer{devices: devices.NewService(pool, nil, nil), policy: NewPolicyPort(pool, nil)}
	principal := func(user uuid.UUID, role string) context.Context {
		return authctx.WithPrincipal(ctx, &authctx.Principal{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: role}})
	}
	getReq := api.GetAgentCredentialRotationRequestObject{OrgId: org, DeviceId: device}
	if _, err := s.GetAgentCredentialRotation(principal(member, rbac.RoleMember), getReq); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member status = %v, want 403", err)
	}
	post, err := s.RequestAgentCredentialRotation(principal(owner, rbac.RoleOwner), api.RequestAgentCredentialRotationRequestObject{OrgId: org, DeviceId: device})
	if err != nil {
		t.Fatal(err)
	}
	postBody, ok := post.(api.RequestAgentCredentialRotation200JSONResponse)
	if !ok || postBody.Body.State != "requested" || postBody.Body.RequestedRevision == nil || *postBody.Body.RequestedRevision != 2 {
		t.Fatalf("rotation response = %#v", post)
	}
	got, err := s.GetAgentCredentialRotation(principal(owner, rbac.RoleOwner), getReq)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(strings.ToLower(string(encoded)), "token_hash") || strings.Contains(string(encoded), "tnx_runtime_") || strings.Contains(string(encoded), string(hash[:])) {
		t.Fatalf("rotation projection leaked secret/hash: %s", encoded)
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='agent.credential_rotation_requested'`, org).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("rotation audit count=%d err=%v", audits, err)
	}
}
