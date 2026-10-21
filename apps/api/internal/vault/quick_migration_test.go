package vault

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestVaultQuickMigrationPreservesCredentialsAndGuardsRollback(t *testing.T) {
	ctx, pool := testpostgres.NewAtVersion(t, 230)
	dsn := pool.Config().ConnString()
	org, user, existing := uuid.New(), uuid.New(), uuid.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'Migration fixture',$2)`, org, org.String())
	exec(`INSERT INTO users(id,email,email_verified_at) VALUES($1,$2,now())`, user, user.String()+"@migration.test")
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, org, user)
	exec(`INSERT INTO vault_entries(id,org_id,title,kind,visibility,owner_user_id,current_version,service_name,username)
 VALUES($1,$2,'Existing key','api_key','personal',$3,1,'Existing service','existing-account')`, existing, org, user)
	sealer, e := crypto.NewSealer(bytes.Repeat([]byte{37}, 32))
	if e != nil {
		t.Fatal(e)
	}
	s := New(pool, sealer)
	sealed, e := s.seal(org, existing, 1, "pre-upgrade-fixture-key", "existing-account")
	if e != nil {
		t.Fatal(e)
	}
	exec(`INSERT INTO vault_versions(org_id,entry_id,version,sealed_payload,changed_by) VALUES($1,$2,1,$3,$4)`, org, existing, sealed, user)
	if e = db.MigrateTo(dsn, 231); e != nil {
		t.Fatal(e)
	}
	index, e := s.List(ctx, org, user, 50, 0, "")
	if e != nil || index.Total != 1 || !index.Entries[0].Configured || index.Entries[0].Kind != "api_key" {
		t.Fatal("migration did not preserve existing configured credentials")
	}
	draft, e := s.QuickCreate(ctx, org, user, api.VaultQuickCreateInput{RequestId: uuid.New(), Secret: ptr("unconfigured-migration-fixture")})
	if e != nil {
		t.Fatal(e)
	}
	if e = db.MigrateTo(dsn, 230); e == nil {
		t.Fatal("rollback silently discarded or fabricated metadata for an unconfigured secret")
	}
	value, e := s.Reveal(ctx, org, user, draft.Id, 1)
	if e != nil || value.Value != "unconfigured-migration-fixture" {
		t.Fatal("refused rollback damaged the unconfigured secret")
	}
	// A failed golang-migrate step marks its version dirty before executing SQL.
	// Repair only this disposable fixture's bookkeeping after proving the guard;
	// no application database is used by this test.
	exec(`UPDATE schema_migrations SET version=231,dirty=false`)
	if e = s.Delete(ctx, org, user, draft.Id, 1); e != nil {
		t.Fatal(e)
	}
	if e = db.MigrateTo(dsn, 230); e != nil {
		t.Fatal(e)
	}
	var preserved string
	if e = pool.QueryRow(ctx, `SELECT sealed_payload FROM vault_versions WHERE org_id=$1 AND entry_id=$2 AND version=1`, org, existing).Scan(&preserved); e != nil || preserved != sealed {
		t.Fatal("rollback changed an existing encrypted version")
	}
	if e = db.MigrateTo(dsn, 231); e != nil {
		t.Fatal(e)
	}
	value, e = s.Reveal(ctx, org, user, existing, 1)
	if e != nil || value.Value != "pre-upgrade-fixture-key" || value.Username != "existing-account" {
		t.Fatal("upgrade/down/upgrade lost an existing credential")
	}
	var present bool
	if e = pool.QueryRow(ctx, `SELECT to_regclass('public.vault_quick_requests') IS NOT NULL`).Scan(&present); e != nil || !present {
		t.Fatal("re-upgrade did not restore quick request schema")
	}
}
