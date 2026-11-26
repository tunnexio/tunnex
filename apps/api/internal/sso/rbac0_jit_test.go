package sso

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// RBAC-0 D1 (extra): an SSO login must never rewrite the role of a member whose access is revoked.
func TestRBAC0SSOJoinNeverRewritesARevokedMembersRole(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	org, user := uuid.New(), uuid.New()
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'RBAC0 SSO',$2)`, []any{org, "rbac0-sso-" + org.String()}},
		{`INSERT INTO users(id,email,name) VALUES($1,$2,'Owner')`, []any{user, user.String() + "@rbac0.test"}},
		{`INSERT INTO memberships(org_id,user_id,role,access_revoked_at) VALUES($1,$2,'owner',now())`, []any{org, user}},
	} {
		if _, err := pool.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	s := &Service{}
	if err := s.ensureMembership(ctx, sqlc.New(pool), org, user, "sso_login", Identity{Email: user.String() + "@rbac0.test", Provider: "oidc", Subject: "s"}); err != nil {
		t.Fatal(err)
	}
	var role string
	var revoked bool
	if err := pool.QueryRow(ctx, `SELECT role, access_revoked_at IS NOT NULL FROM memberships WHERE org_id=$1 AND user_id=$2`, org, user).Scan(&role, &revoked); err != nil {
		t.Fatal(err)
	}
	if role != "owner" || !revoked {
		t.Fatalf("SSO join rewrote a revoked membership: role=%q revoked=%v", role, revoked)
	}
}
