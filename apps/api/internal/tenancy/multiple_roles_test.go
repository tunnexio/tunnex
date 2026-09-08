package tenancy

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

func TestMultipleRoleManagement(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	org, owner, user := uuid.New(), uuid.New(), uuid.New()
	if _, err := tx.Exec(ctx, "INSERT INTO organizations(id,name,slug) VALUES($1,'roles',$2)", org, org.String()); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uuid.UUID{owner, user} {
		if _, err := tx.Exec(ctx, "INSERT INTO users(id,email,name) VALUES($1,$2,'roles')", id, id.String()+"@test.local"); err != nil {
			t.Fatal(err)
		}
		role := "member"
		if id == owner {
			role = "owner"
		}
		if _, err := tx.Exec(ctx, "INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,$3)", org, id, role); err != nil {
			t.Fatal(err)
		}
	}
	s := &MembershipService{q: sqlc.New(tx)}
	set := func(target uuid.UUID, actorRole string, roles []string) (sqlc.Membership, error) {
		return s.ChangeMemberRoles(ctx, &owner, actorRole, org, target, roles)
	}
	got, err := set(user, "owner", []string{"member", "ai-admin"})
	if err != nil || !reflect.DeepEqual(got.Roles, []string{"ai-admin", "member"}) || got.Role != "ai-admin" {
		t.Fatalf("add: %v %v", got, err)
	}
	got, err = s.ChangeMemberRole(ctx, &owner, "owner", org, user, "ai-view")
	if err != nil || !reflect.DeepEqual(got.Roles, []string{"ai-view", "member"}) {
		t.Fatalf("legacy edit lost other roles: %v %v", got, err)
	}
	got, err = set(user, "owner", []string{"member"})
	if err != nil || !reflect.DeepEqual(got.Roles, []string{"member"}) {
		t.Fatalf("remove AI role: %v %v", got, err)
	}
	for _, roles := range [][]string{nil, {"member", "member"}, {"member", "operator"}, {"agent"}} {
		if _, err := set(user, "owner", roles); !isCode(err, "invalid_role") {
			t.Fatalf("invalid %v: %v", roles, err)
		}
	}
	if _, err := set(user, "ai-admin", []string{"admin"}); !isCode(err, "forbidden") {
		t.Fatalf("AI role escalation: %v", err)
	}
	if _, err := set(user, "admin", []string{"owner", "member"}); !isCode(err, "forbidden") {
		t.Fatalf("admin owner escalation: %v", err)
	}
	if _, err := set(owner, "owner", []string{"ai-admin", "member"}); !isCode(err, "last_owner") {
		t.Fatalf("last owner: %v", err)
	}
	got, err = set(owner, "owner", []string{"ai-admin", "owner"})
	if err != nil || got.Role != "owner" {
		t.Fatalf("adding role to owner: %v", err)
	}
	var audited int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='member.role_changed'", org).Scan(&audited); err != nil || audited != 4 {
		t.Fatalf("audit: %d %v", audited, err)
	}
}
