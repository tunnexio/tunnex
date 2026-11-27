package http

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/nodepush"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// AI-SEC-1 item 6 at the HTTP boundary: listing and revoking pending bootstrap
// tokens take the same permission as issuing one, revoking is a gated
// mutation, and no response carries a token value.
func TestPendingAgentBootstrapTokensCanBeListedAndRevoked(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	org, owner, admin, node := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO organizations (id,name,slug,pool_cidr,max_devices_per_user) VALUES ($1,'AI-SEC-1 HTTP',$2,'10.95.0.0/24',0)`, org, "aisec1-http-"+org.String())
	for id, role := range map[uuid.UUID]string{owner: "owner", admin: "admin"} {
		exec(`INSERT INTO users (id,email,name,status) VALUES ($1,$2,$3,'active')`, id, role+"@aisec1-http.test", role)
		exec(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,$3)`, org, id, role)
	}
	key := make([]byte, 32)
	copy(key, node[:])
	exec(`INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint,status) VALUES ($1,$2,'http-gateway',$3,$4,'gw.example:51820','active')`, node, org, "aisec1-http-"+node.String(), base64.StdEncoding.EncodeToString(key))

	svc := devices.NewService(pool, nodepush.New(), nil)
	s := apiServer{devices: svc}
	as := func(user uuid.UUID, role string, verified bool) context.Context {
		return authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: user, EmailVerified: verified, Roles: map[uuid.UUID]string{org: role}})
	}
	ownerCtx, adminCtx := as(owner, rbac.RoleOwner, true), as(admin, rbac.RoleAdmin, true)

	raw, err := svc.IssueAgentBootstrapToken(ctx, owner, org, node, "http-agent")
	if err != nil {
		t.Fatal(err)
	}
	listReq := api.ListAgentBootstrapTokensRequestObject{OrgId: org}

	// Refusals: the same gate as issuing a token.
	if _, err := s.ListAgentBootstrapTokens(context.Background(), listReq); !hasCode(err, 401, "unauthenticated") {
		t.Fatalf("unauthenticated list: %v", err)
	}
	if _, err := s.ListAgentBootstrapTokens(as(uuid.New(), rbac.RoleMember, true), listReq); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member list: want forbidden, got %v", err)
	}
	if _, err := s.ListAgentBootstrapTokens(principalWithRole(uuid.New(), rbac.RoleOwner), listReq); !hasCode(err, 404, "org_not_found") {
		t.Fatalf("other-organization list: want org_not_found, got %v", err)
	}

	resp, err := s.ListAgentBootstrapTokens(adminCtx, listReq)
	if err != nil {
		t.Fatal(err)
	}
	page, ok := resp.(api.ListAgentBootstrapTokens200JSONResponse)
	if !ok || len(page.Body.Items) != 1 {
		t.Fatalf("list response = %#v", resp)
	}
	item := page.Body.Items[0]
	if item.AgentName != "http-agent" || item.GatewayId != node || item.GatewayName != "http-gateway" {
		t.Fatalf("listed token = %+v", item)
	}
	if item.IssuedBy == nil || *item.IssuedBy != owner || item.IssuedByEmail == nil || *item.IssuedByEmail != "owner@aisec1-http.test" {
		t.Fatalf("listed issuer = %v / %v", item.IssuedBy, item.IssuedByEmail)
	}
	if !item.ExpiresAt.After(item.IssuedAt) {
		t.Fatalf("listed times: issued=%s expires=%s", item.IssuedAt, item.ExpiresAt)
	}
	encoded, err := json.Marshal(page.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), raw) || strings.Contains(string(encoded), strings.TrimPrefix(raw, "tnx_agent_")) || strings.Contains(string(encoded), "hash") {
		t.Fatal("listing carries token material")
	}

	revokeReq := api.RevokeAgentBootstrapTokenRequestObject{OrgId: org, TokenId: item.Id}
	if _, err := s.RevokeAgentBootstrapToken(context.Background(), revokeReq); !hasCode(err, 401, "unauthenticated") {
		t.Fatalf("unauthenticated revoke: %v", err)
	}
	if _, err := s.RevokeAgentBootstrapToken(as(uuid.New(), rbac.RoleMember, true), revokeReq); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member revoke: want forbidden, got %v", err)
	}
	if _, err := s.RevokeAgentBootstrapToken(as(owner, rbac.RoleOwner, false), revokeReq); !hasCode(err, 403, "email_not_verified") {
		t.Fatalf("unverified revoke: want email_not_verified, got %v", err)
	}
	if _, err := s.RevokeAgentBootstrapToken(principalWithRole(uuid.New(), rbac.RoleOwner), revokeReq); !hasCode(err, 404, "org_not_found") {
		t.Fatalf("other-organization revoke: want org_not_found, got %v", err)
	}
	if _, err := s.RevokeAgentBootstrapToken(ownerCtx, api.RevokeAgentBootstrapTokenRequestObject{OrgId: org, TokenId: uuid.New()}); !hasCode(err, 404, "bootstrap_token_not_found") {
		t.Fatalf("unknown token revoke: want bootstrap_token_not_found, got %v", err)
	}
	var live int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_bootstrap_tokens WHERE id=$1 AND revoked_at IS NULL`, item.Id).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Fatal("a refused revoke changed the token")
	}

	// Any member who can enroll agents can revoke, not only the issuer.
	revoked, err := s.RevokeAgentBootstrapToken(adminCtx, revokeReq)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := revoked.(api.RevokeAgentBootstrapToken204Response); !ok {
		t.Fatalf("revoke response = %#v", revoked)
	}
	var auditActor uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT actor_user_id FROM audit_logs WHERE org_id=$1 AND action='agent.bootstrap_token_revoked' AND target_id=$2`, org, item.Id.String()).Scan(&auditActor); err != nil {
		t.Fatalf("revoke audit row: %v", err)
	}
	if auditActor != admin {
		t.Fatalf("revoke audit actor = %s, want the revoking admin %s", auditActor, admin)
	}
	resp, err = s.ListAgentBootstrapTokens(ownerCtx, listReq)
	if err != nil {
		t.Fatal(err)
	}
	if page := resp.(api.ListAgentBootstrapTokens200JSONResponse); len(page.Body.Items) != 0 {
		t.Fatalf("revoked token is still listed: %+v", page.Body.Items)
	}
	if _, err := s.RevokeAgentBootstrapToken(ownerCtx, revokeReq); !hasCode(err, 404, "bootstrap_token_not_found") {
		t.Fatalf("second revoke: want bootstrap_token_not_found, got %v", err)
	}

	// The public redemption endpoint refuses it with the uniform answer.
	redeem := func(token string) error {
		_, err := s.BootstrapAgent(context.Background(), api.BootstrapAgentRequestObject{Body: &api.AgentBootstrapRequest{BootstrapToken: token, PublicKey: base64.StdEncoding.EncodeToString(key)}})
		return err
	}
	revokedErr, unknownErr := redeem(raw), redeem("tnx_agent_never-issued")
	if !hasCode(revokedErr, 401, "invalid_bootstrap_token") || unknownErr == nil || revokedErr.Error() != unknownErr.Error() {
		t.Fatalf("revoked token redemption: revoked=%v unknown=%v", revokedErr, unknownErr)
	}
}

// The issuer's email follows the agents list rule: visible to members who can
// manage people and to the issuer, hidden from anyone else.
func TestPendingAgentBootstrapTokenIssuerEmailVisibility(t *testing.T) {
	email := "issuer@aisec1-http.test"
	issuer, other := uuid.New(), uuid.New()
	token := devices.PendingAgentBootstrapToken{ID: uuid.New(), IssuedBy: &issuer, IssuedByEmail: &email}
	if got := toAPIPendingBootstrapToken(token, other, true); got.IssuedByEmail == nil || *got.IssuedByEmail != email {
		t.Fatal("a caller who can manage members must see the issuer")
	}
	if got := toAPIPendingBootstrapToken(token, issuer, false); got.IssuedByEmail == nil || *got.IssuedByEmail != email {
		t.Fatal("the issuer must see their own email")
	}
	if got := toAPIPendingBootstrapToken(token, other, false); got.IssuedByEmail != nil {
		t.Fatal("the issuer's email must be hidden from other callers")
	}
}
