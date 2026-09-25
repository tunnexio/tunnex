package db_test

import (
	"github.com/tunnexio/tunnex/apps/api/db"
	"testing"
)

func TestIPsecRotationUpdatedAtConvention(t *testing.T) {
	ctx, p, dsn := providerSchemaFixture(t)
	if err := db.MigrateTo(dsn, 162); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := p.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name IN('ipsec_connections','ipsec_org_settings') AND column_name='updated_at'`).Scan(&count); err != nil || count != 2 {
		t.Fatal("migration tables absent", err)
	}
	t.Setenv("TUNNEX_TEST_DATABASE_URL", dsn)
	t.Run("TestUpdatedAtTablesHaveTrigger", TestUpdatedAtTablesHaveTrigger)
}
