package db_test

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"testing"
)

func TestIPsecRuntimeMigrationPreservesLegacy(t *testing.T) {
	ctx, p, dsn := providerSchemaFixture(t)
	o := providerSeed(t, ctx, p)
	id := uuid.New()
	tx, e := p.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = insertProvider(ctx, tx, o, id); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	var before string
	if e = p.QueryRow(ctx, `SELECT row_to_json(c)::text FROM ipsec_connections c WHERE id=$1`, id).Scan(&before); e != nil {
		t.Fatal(e)
	}
	if e = db.MigrateTo(dsn, 160); e != nil {
		t.Fatal(e)
	}
	var n int
	if e = p.QueryRow(ctx, `SELECT count(*) FROM ipsec_runtime_deliveries`).Scan(&n); e != nil || n != 0 {
		t.Fatalf("invented delivery: %d %v", n, e)
	}
	if e = db.MigrateTo(dsn, 159); e != nil {
		t.Fatal(e)
	}
	var after string
	if e = p.QueryRow(ctx, `SELECT row_to_json(c)::text FROM ipsec_connections c WHERE id=$1`, id).Scan(&after); e != nil || after != before {
		t.Fatalf("legacy mutated: %v", e)
	}
	if e = db.MigrateTo(dsn, 160); e != nil {
		t.Fatal(e)
	}
	providerReject(t, ctx, p, `UPDATE ipsec_connections SET desired_intent='enabled',desired_revision=2 WHERE id=$1`, id)
	providerReject(t, ctx, p, `UPDATE ipsec_connections SET desired_intent='deleted',deleted_at=now(),finalized_at=now(),site_id=NULL,gateway_node_id=NULL,desired_revision=2 WHERE id=$1`, id)
}

func TestIPsecRuntimeStateCannotBeInventedOrErased(t *testing.T) {
	ctx, p, dsn := providerSchemaFixture(t)
	if e := db.MigrateTo(dsn, 160); e != nil {
		t.Fatal(e)
	}
	o := providerSeed(t, ctx, p)
	id := uuid.New()
	tx, e := p.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = insertProvider(ctx, tx, o, id); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	providerReject(t, ctx, p, `INSERT INTO ipsec_runtime_state(connection_id,org_id,node_id,site_id,last_potentially_delivered_revision) VALUES($1,$2,$3,$4,1)`, id, o.org, o.node, o.site)
	providerReject(t, ctx, p, `TRUNCATE ipsec_runtime_deliveries CASCADE`)
}
