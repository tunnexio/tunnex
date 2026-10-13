package ipsec_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
)

func TestPendingCleanupCannotBeSupersededBeforeExactAcknowledgementPostgres(t *testing.T) {
	ctx, pool, org, actor, sealer, req := providerFixture(t)
	if e := db.MigrateTo(pool.Config().ConnString(), 221); e != nil {
		t.Fatal(e)
	}
	store := ipsec.NewConnectionStore(pool)
	store.ConfigureRuntimePolicy(runtimeCompiler)
	c, e := store.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if e != nil {
		t.Fatal(e)
	}
	c, e = store.SetIntent(ctx, org, actor, c.ID, 1, "enabled")
	if e != nil {
		t.Fatal(e)
	}
	var serial string
	if e = pool.QueryRow(ctx, `SELECT cert_serial FROM nodes WHERE id=$1`, req.GatewayID).Scan(&serial); e != nil {
		t.Fatal(e)
	}
	p := ipsec.RuntimePrincipal{OrgID: org, NodeID: req.GatewayID, CertificateSerial: serial}
	m, e := store.Material(ctx, p, c.ID, 2, sealer)
	if e != nil {
		t.Fatal(e)
	}
	c, e = store.SetIntent(ctx, org, actor, c.ID, 2, "disabled")
	if e != nil {
		t.Fatal(e)
	}
	a, e := store.Cleanup(ctx, p, c.ID, 3)
	if e != nil {
		t.Fatal(e)
	}
	var before string
	q := `SELECT md5(jsonb_build_object('connection',(SELECT to_jsonb(c) FROM ipsec_connections c WHERE id=$1),'state',(SELECT to_jsonb(r) FROM ipsec_runtime_state r WHERE connection_id=$1),'deliveries',(SELECT jsonb_agg(to_jsonb(d)ORDER BY d.id) FROM ipsec_runtime_deliveries d WHERE connection_id=$1),'ack',(SELECT jsonb_agg(to_jsonb(a)ORDER BY a.delivery_id)FROM ipsec_runtime_acknowledgements a WHERE connection_id=$1),'guards',(SELECT jsonb_agg(to_jsonb(g)ORDER BY g.cleanup_delivery_id)FROM ipsec_retained_guards g WHERE connection_id=$1))::text)`
	if e = pool.QueryRow(ctx, q, c.ID).Scan(&before); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if _, e = store.Delete(ctx, org, actor, c.ID, 3); !errors.Is(e, ipsec.ErrCleanupInProgress) {
			t.Fatal("pending cleanup superseded", e)
		}
	}
	if _, e = store.SetIntent(ctx, org, actor, c.ID, 3, "enabled"); !errors.Is(e, ipsec.ErrConnectionIneligible) {
		t.Fatal("pending cleanup enabled", e)
	}
	// Reverting this additive migration removes only the new guard; restoring
	// it reinstates the same refusal without changing any cleanup history.
	if e = db.MigrateTo(pool.Config().ConnString(), 220); e != nil {
		t.Fatal(e)
	}
	rollbackTx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = rollbackTx.Exec(ctx, `UPDATE ipsec_connections SET desired_intent='deleted',desired_revision=4,deleted_at=now() WHERE id=$1`, c.ID)
	_ = rollbackTx.Rollback(ctx)
	if e != nil {
		t.Fatal("down migration did not restore prior SQL admission", e)
	}
	if e = db.MigrateTo(pool.Config().ConnString(), 221); e != nil {
		t.Fatal(e)
	}
	// Direct SQL must not bypass the same rule while replacing the current
	// cleanup at a later revision in the same transaction.
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = tx.Exec(ctx, `UPDATE ipsec_connections SET desired_intent='deleted',desired_revision=4,deleted_at=now() WHERE id=$1`, c.ID)
	_ = tx.Rollback(ctx)
	var pe *pgconn.PgError
	if !errors.As(e, &pe) || pe.Code != "23514" || pe.ConstraintName != "ipsec_runtime_cleanup_pending" {
		t.Fatal("SQL supersession not refused precisely", e)
	}
	var after string
	if e = pool.QueryRow(ctx, q, c.ID).Scan(&after); e != nil || after != before {
		t.Fatal("refused request changed cleanup authority", e)
	}
	page, e := store.Pending(ctx, p, nil, 100)
	if e != nil || len(page.Items) != 1 || page.Items[0].DesiredRevision != 3 || page.Items[0].Kind != "cleanup" {
		t.Fatal("original cleanup no longer pending", e, page)
	}
	again, e := store.Cleanup(ctx, p, c.ID, 3)
	if e != nil || again.ID != a.ID || again.OwnershipDigest != a.OwnershipDigest {
		t.Fatal("original cleanup retry identity changed", e)
	}
	ack := ipsec.RuntimeAcknowledgement{DeliveryID: a.ID, DesiredRevision: 3, Kind: "cleanup", Result: "cleaned", OwnershipDigest: a.OwnershipDigest, GuardRetained: true}
	for i := 0; i < 2; i++ {
		if e = store.Acknowledge(ctx, p, c.ID, ack); e != nil {
			t.Fatal("exact original ACK retry refused", e)
		}
	}
	c, e = store.Delete(ctx, org, actor, c.ID, 3)
	if e != nil || c.DesiredRevision != 4 || c.FinalizedAt == nil || c.CleanupState != "retained_guard" {
		t.Fatal("delete after original ACK did not finalize", e, c)
	}
	var delivery, cleanups, guards int
	if e = pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM ipsec_runtime_deliveries WHERE connection_id=$1),(SELECT count(*) FROM ipsec_runtime_deliveries WHERE connection_id=$1 AND kind='cleanup'),(SELECT count(*) FROM ipsec_retained_guards WHERE connection_id=$1)`, c.ID).Scan(&delivery, &cleanups, &guards); e != nil || delivery != 2 || cleanups != 1 || guards != 1 {
		t.Fatal("cleanup history rewritten", e, delivery, cleanups, guards)
	}
	var original uuid.UUID
	if e = pool.QueryRow(ctx, `SELECT cleanup_delivery_id FROM ipsec_retained_guards WHERE connection_id=$1`, c.ID).Scan(&original); e != nil || original != a.ID {
		t.Fatal("original retained cleanup lost", e)
	}
	if m.ID == a.ID {
		t.Fatal("fixture apply equals cleanup")
	}
}

func TestPendingCleanupGuardPreservesNeverDeliveredDeleteAndOtherConnectionsPostgres(t *testing.T) {
	ctx, pool, org, actor, sealer, req := providerFixture(t)
	if e := db.MigrateTo(pool.Config().ConnString(), 221); e != nil {
		t.Fatal(e)
	}
	store := ipsec.NewConnectionStore(pool)
	store.ConfigureRuntimePolicy(runtimeCompiler)
	never, e := store.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if e != nil {
		t.Fatal(e)
	}
	never, e = store.Delete(ctx, org, actor, never.ID, 1)
	if e != nil || never.FinalizedAt == nil || never.DesiredRevision != 2 {
		t.Fatal("never-delivered deletion changed", e)
	}
	// A second ordinary connection stays independently enabled/pending and its
	// desired state is never made dependent on another owner's cleanup marker.
	req.ID = uuid.New()
	req.TunnelIDs = [2]uuid.UUID{uuid.New(), uuid.New()}
	other, e := store.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if e != nil {
		t.Fatal(e)
	}
	other, e = store.SetIntent(ctx, org, actor, other.ID, 1, "enabled")
	if e != nil {
		t.Fatal(e)
	}
	var before string
	if e = pool.QueryRow(ctx, `SELECT md5(to_jsonb(c)::text)FROM ipsec_connections c WHERE id=$1`, other.ID).Scan(&before); e != nil {
		t.Fatal(e)
	}
	// Same-value Enable and stale Delete remain ordinary conflicts; they do not
	// report pending-cleanup errors when this connection has none.
	if _, e = store.SetIntent(ctx, org, actor, other.ID, 2, "enabled"); !errors.Is(e, ipsec.ErrConnectionConflict) {
		t.Fatal(e)
	}
	if _, e = store.Delete(ctx, org, actor, other.ID, 1); !errors.Is(e, ipsec.ErrConnectionConflict) {
		t.Fatal(e)
	}
	var after string
	if e = pool.QueryRow(ctx, `SELECT md5(to_jsonb(c)::text)FROM ipsec_connections c WHERE id=$1`, other.ID).Scan(&after); e != nil || before != after {
		t.Fatal("foreign connection changed", e)
	}
}
