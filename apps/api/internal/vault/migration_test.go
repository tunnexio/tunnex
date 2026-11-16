package vault

import (
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestVaultMigrationRoundTrip(t *testing.T) {
	ctx, pool := testpostgres.NewAtVersion(t, 229)
	dsn := pool.Config().ConnString() // testpostgres guarantees this is the owned child database.
	org := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Preserved fixture',$2)`, org, org.String()); err != nil {
		t.Fatal(err)
	}
	assertState := func(version uint, present bool) {
		t.Helper()
		v, dirty, ok, err := db.Version(dsn)
		if err != nil || !ok || dirty || v != version {
			t.Fatalf("migration version state: version=%d dirty=%t ok=%t error=%v", v, dirty, ok, err)
		}
		var services, entries, versions, trigger bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass('public.vault_services') IS NOT NULL
 , to_regclass('public.vault_entries') IS NOT NULL, to_regclass('public.vault_versions') IS NOT NULL,
 to_regprocedure('public.vault_version_prevent_update()') IS NOT NULL`).Scan(&services, &entries, &versions, &trigger); err != nil {
			t.Fatal(err)
		}
		if services != present || entries != present || versions != present || trigger != present {
			t.Fatalf("Vault migration objects: services=%t entries=%t versions=%t trigger=%t want=%t", services, entries, versions, trigger, present)
		}
		var preserved bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1)`, org).Scan(&preserved); err != nil || !preserved {
			t.Fatal("unrelated organization was not preserved")
		}
	}
	assertState(229, false)
	if err := db.MigrateTo(dsn, 230); err != nil {
		t.Fatal(err)
	}
	assertState(230, true)
	if err := db.MigrateTo(dsn, 229); err != nil {
		t.Fatal(err)
	}
	assertState(229, false)
	if err := db.MigrateTo(dsn, 230); err != nil {
		t.Fatal(err)
	}
	assertState(230, true)
}
