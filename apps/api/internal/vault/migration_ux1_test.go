package vault

import (
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// VAULT-UX-1: 0245 adds the details revision and the membership purge trigger; both reverse cleanly.
func TestVaultExperienceMigrationRoundTrip(t *testing.T) {
	ctx, pool := testpostgres.NewAtVersion(t, 244)
	dsn := pool.Config().ConnString()
	org, user, entry := uuid.New(), uuid.New(), uuid.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'Migration fixture',$2)`, org, org.String())
	exec(`INSERT INTO users(id,email,email_verified_at) VALUES($1,$2,now())`, user, user.String()+"@migration.test")
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, org, user)
	exec(`INSERT INTO vault_entries(id,org_id,title,kind,visibility,owner_user_id,current_version,service_name)
 VALUES($1,$2,'Existing','password','personal',$3,1,'Private')`, entry, org, user)
	state := func(want bool) {
		t.Helper()
		var column, trigger bool
		if e := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='vault_entries' AND column_name='revision'),
 EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='vault_purge_personal_on_membership_delete')`).Scan(&column, &trigger); e != nil {
			t.Fatal(e)
		}
		if column != want || trigger != want {
			t.Fatalf("revision=%t trigger=%t want %t", column, trigger, want)
		}
		var kept bool
		if e := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vault_entries WHERE id=$1)`, entry).Scan(&kept); e != nil || !kept {
			t.Fatal("migration lost an existing entry")
		}
	}
	state(false)
	if e := db.MigrateTo(dsn, 245); e != nil {
		t.Fatal(e)
	}
	state(true)
	var revision int
	if e := pool.QueryRow(ctx, `SELECT revision FROM vault_entries WHERE id=$1`, entry).Scan(&revision); e != nil || revision != 1 {
		t.Fatalf("existing entries start at revision 1: %d %v", revision, e)
	}
	if e := db.MigrateTo(dsn, 244); e != nil {
		t.Fatal(e)
	}
	state(false)
	if e := db.MigrateTo(dsn, 245); e != nil {
		t.Fatal(e)
	}
	state(true)
}
