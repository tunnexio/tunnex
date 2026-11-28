package tenancy

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// RBAC-1 migration 0256 widens the membership and invitation role checks and the role-set trigger to the
// four new roles. Existing rows keep their roles; the new roles rank below admin; the down migration refuses
// while any membership or invitation uses a new role, and succeeds once none does.
func TestRBAC1MigrationWidensRolesAndRefusesLossyRollback(t *testing.T) {
	ctx, pool := testpostgres.NewAtVersion(t, 255)
	org, existing, staff, invited := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) error {
		_, err := pool.Exec(ctx, sql, args...)
		return err
	}
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'M',$2)`, []any{org, "rbac1-mig-" + org.String()}},
		{`INSERT INTO users(id,email,name) VALUES($1,$2,'E')`, []any{existing, existing.String() + "@m.test"}},
		{`INSERT INTO users(id,email,name) VALUES($1,$2,'S')`, []any{staff, staff.String() + "@m.test"}},
		{`INSERT INTO memberships(org_id,user_id,role,roles) VALUES($1,$2,'ai-admin',ARRAY['member','ai-admin'])`, []any{org, existing}},
	} {
		if err := exec(stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	// Before 0256 the new roles are refused.
	if err := exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'helpdesk')`, org, staff); err == nil {
		t.Fatal("helpdesk accepted before migration 0256")
	}
	u, err := url.Parse(os.Getenv("TUNNEX_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal("fixture endpoint")
	}
	u.Path = "/" + pool.Config().ConnConfig.Database
	if err = db.MigrateTo(u.String(), 256); err != nil {
		t.Fatal(err)
	}
	var role string
	var roles []string
	if err := pool.QueryRow(ctx, `SELECT role, roles FROM memberships WHERE org_id=$1 AND user_id=$2`, org, existing).Scan(&role, &roles); err != nil {
		t.Fatal(err)
	}
	if role != "ai-admin" || strings.Join(roles, ",") != "ai-admin,member" {
		t.Fatalf("existing membership changed: %s %v", role, roles)
	}
	// Every role together; the trigger orders them and takes the first as the primary role.
	all := []string{"member", "helpdesk", "ai-view", "auditor", "ai-admin", "agents-admin", "network-admin"}
	if err := exec(`INSERT INTO memberships(org_id,user_id,role,roles) VALUES($1,$2,'member',$3)`, org, staff, all); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT role, roles FROM memberships WHERE org_id=$1 AND user_id=$2`, org, staff).Scan(&role, &roles); err != nil {
		t.Fatal(err)
	}
	if want := "network-admin,agents-admin,auditor,helpdesk,ai-admin,ai-view,member"; role != "network-admin" || strings.Join(roles, ",") != want {
		t.Fatalf("role set = %s %v, want network-admin %s", role, roles, want)
	}
	if err := exec(`UPDATE memberships SET roles=ARRAY['admin','auditor'] WHERE org_id=$1 AND user_id=$2`, org, staff); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT role FROM memberships WHERE org_id=$1 AND user_id=$2`, org, staff).Scan(&role); err != nil || role != "admin" {
		t.Fatalf("admin must rank above auditor: %s %v", role, err)
	}
	for _, bad := range [][]string{{"operator"}, {"agent"}, {"auditor", "unknown"}} {
		if err := exec(`UPDATE memberships SET roles=$3 WHERE org_id=$1 AND user_id=$2`, org, staff, bad); err == nil {
			t.Errorf("role set %v accepted", bad)
		}
	}
	if err := exec(`INSERT INTO invitations(id,org_id,email,role,token_hash,expires_at,invited_by_user_id) VALUES($1,$2,'i@m.test','network-admin',$3,now()+interval '1 day',$4)`,
		invited, org, []byte(invited.String()), existing); err != nil {
		t.Fatal(err)
	}

	down, err := db.MigrationsFS.ReadFile("migrations/0256_rbac1_roles.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	// Refused while a membership holds a new role in its set (not only as primary) …
	if err := exec(`UPDATE memberships SET roles=ARRAY['admin','auditor'] WHERE org_id=$1 AND user_id=$2`, org, staff); err != nil {
		t.Fatal(err)
	}
	if err := exec(string(down)); err == nil || !strings.Contains(err.Error(), "cannot roll back RBAC-1 roles") {
		t.Fatalf("down migration with a membership in a new role: %v", err)
	}
	// … and while an invitation does.
	if err := exec(`UPDATE memberships SET roles=ARRAY['admin'] WHERE org_id=$1 AND user_id=$2`, org, staff); err != nil {
		t.Fatal(err)
	}
	if err := exec(string(down)); err == nil || !strings.Contains(err.Error(), "cannot roll back RBAC-1 roles") {
		t.Fatalf("down migration with an invitation in a new role: %v", err)
	}
	if err := exec(`DELETE FROM invitations WHERE id=$1`, invited); err != nil {
		t.Fatal(err)
	}
	if err := exec(string(down)); err != nil {
		t.Fatalf("down migration with no new roles: %v", err)
	}
	if err := exec(`UPDATE memberships SET roles=ARRAY['admin','auditor'] WHERE org_id=$1 AND user_id=$2`, org, staff); err == nil {
		t.Fatal("auditor accepted after rollback")
	}
}
