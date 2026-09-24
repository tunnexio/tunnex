package ipsec_test

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"strings"
	"testing"
)

func runtimeCompiler(_ context.Context, _ *sqlc.Queries, in ipsec.RuntimePolicyInput) (ipsec.RuntimePolicy, error) {
	return ipsec.RuntimePolicy{Hash: strings.Repeat("a", 64), Grants: []ipsec.RuntimeGrant{{Source: in.Config.LocalPrefixes[0], Destination: in.Config.RemotePrefixes[0], Protocol: "any", RuleID: "fixture"}}}, nil
}
func TestRuntimeDeliveryRetainedDelete(t *testing.T) {
	ctx, p, org, actor, sealer, identity := createFixture(t)
	if _, e := p.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, uuid.New(), identity.SiteID); e != nil {
		t.Fatal(e)
	}
	store := ipsec.NewConnectionStore(p)
	store.ConfigureRuntimePolicy(runtimeCompiler)
	c, e := store.CreateProviderDisabled(ctx, org, actor, sealer, providerRequest(identity))
	if e != nil {
		t.Fatal(e)
	}
	c, e = store.SetIntent(ctx, org, actor, c.ID, 1, "enabled")
	if e != nil || c.DesiredRevision != 2 || c.ApplicationState != "pending" {
		t.Fatalf("enable %+v %v", c, e)
	}
	var serial string
	if e = p.QueryRow(ctx, `SELECT cert_serial FROM nodes WHERE id=$1`, identity.GatewayID).Scan(&serial); e != nil {
		t.Fatal(e)
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: identity.GatewayID, CertificateSerial: serial}
	m, e := store.Material(ctx, principal, c.ID, 2, sealer)
	if e != nil || m.ID == uuid.Nil || m.Secrets[0].PSK == "" {
		t.Fatalf("material %v", e)
	}
	again, e := store.Material(ctx, principal, c.ID, 2, sealer)
	if e != nil || again.ID != m.ID {
		t.Fatal("delivery not idempotent")
	}
	var delivered int64
	if e = p.QueryRow(ctx, `SELECT last_potentially_delivered_revision FROM ipsec_runtime_state WHERE connection_id=$1`, c.ID).Scan(&delivered); e != nil || delivered != 2 {
		t.Fatal("checkpoint absent before return")
	}
	for _, nonce := range []string{strings.Repeat("a", 32), strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("a", 128)} {
		if _, err := store.PermitLease(ctx, principal, c.ID, ipsec.RuntimeLeaseRequest{DeliveryID: m.ID, DesiredRevision: 2, PolicyHash: m.Policy.Hash, Nonce: nonce}); !errors.Is(err, ipsec.ErrConnectionInvalid) {
			t.Errorf("noncanonical nonce accepted: %v", err)
		}
	}
	for _, lineage := range [][]ipsec.RuntimeDelivery{{m.RuntimeDelivery, m.RuntimeDelivery}, {func() ipsec.RuntimeDelivery { d := m.RuntimeDelivery; d.ID = uuid.New(); return d }()}} {
		tx, err := p.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `UPDATE ipsec_connections SET desired_intent='disabled',desired_revision=3 WHERE id=$1`, c.ID); err != nil {
			tx.Rollback(ctx)
			t.Fatal(err)
		}
		raw, _ := json.Marshal(lineage)
		manifest, _ := json.Marshal(m.Manifest)
		_, err = tx.Exec(ctx, `INSERT INTO ipsec_runtime_deliveries(id,connection_id,org_id,node_id,site_id,desired_revision,kind,configuration_revision,ownership_digest,manifest,lineage,covers_delivery_revision) VALUES($1,$2,$3,$4,$5,3,'cleanup',1,$6,$7,$8,2)`, uuid.New(), c.ID, org, principal.NodeID, identity.SiteID, strings.Repeat("b", 64), manifest, raw)
		tx.Rollback(ctx)
		if err == nil {
			t.Error("forged cleanup lineage accepted")
		}
	}
	c, e = store.Delete(ctx, org, actor, c.ID, 2)
	if e != nil || c.FinalizedAt != nil || c.CleanupState != "pending" {
		t.Fatalf("pending delete %+v %v", c, e)
	}
	if _, e = store.Material(ctx, principal, c.ID, 2, sealer); !errors.Is(e, ipsec.ErrConnectionConflict) {
		t.Fatalf("stale material %v", e)
	}
	cleanup, e := store.Cleanup(ctx, principal, c.ID, 3)
	if e != nil || cleanup.CoversDeliveryRevision != 2 || !cleanup.RetainGuard {
		t.Fatalf("cleanup %v", e)
	}
	ack := ipsec.RuntimeAcknowledgement{DeliveryID: cleanup.ID, DesiredRevision: 3, Kind: "cleanup", Result: "cleaned", OwnershipDigest: cleanup.OwnershipDigest, GuardRetained: true}
	if e = store.Acknowledge(ctx, principal, c.ID, ack); e != nil {
		t.Fatal(e)
	}
	if e = store.Acknowledge(ctx, principal, c.ID, ack); e != nil {
		t.Fatalf("duplicate ack %v", e)
	}
	c, e = store.Read(ctx, org, c.ID)
	if e != nil || c.FinalizedAt == nil || c.CleanupState != "retained_guard" || c.SiteID != nil {
		t.Fatalf("finalized %+v %v", c, e)
	}
	var n int
	if e = p.QueryRow(ctx, `SELECT count(*) FROM ipsec_tunnel_secrets WHERE connection_id=$1`, c.ID).Scan(&n); e != nil || n != 0 {
		t.Fatal("secret retained after cleanup")
	}
	for _, q := range []string{`DELETE FROM sites WHERE id=$1`, `DELETE FROM nodes WHERE site_id=$1`, `UPDATE site_subnets SET status='pending' WHERE site_id=$1`} {
		if _, e = p.Exec(ctx, q, identity.SiteID); e == nil {
			t.Fatal("retained resource released")
		}
	}
	req := providerRequest(identity)
	req.ID = uuid.New()
	req.TunnelIDs = [2]uuid.UUID{uuid.New(), uuid.New()}
	if _, e = store.CreateProviderDisabled(ctx, org, actor, sealer, req); !errors.Is(e, ipsec.ErrConnectionConflict) {
		t.Fatalf("retained range reused %v", e)
	}
	if _, e = ipsec.NewSettingsStore(p).Configure(ctx, org, actor, false, 1); !errors.Is(e, ipsec.ErrSettingsConflict) {
		t.Fatalf("retained optout %v", e)
	}
}

func TestRuntimeDeliveryRollbackAndExactAcknowledgement(t *testing.T) {
	ctx, p, org, actor, sealer, identity := createFixture(t)
	if _, e := p.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, uuid.New(), identity.SiteID); e != nil {
		t.Fatal(e)
	}
	store := ipsec.NewConnectionStore(p)
	store.ConfigureRuntimePolicy(runtimeCompiler)
	c, e := store.CreateProviderDisabled(ctx, org, actor, sealer, providerRequest(identity))
	if e != nil {
		t.Fatal(e)
	}
	c, e = store.SetIntent(ctx, org, actor, c.ID, 1, "enabled")
	if e != nil {
		t.Fatal(e)
	}
	var serial string
	if e = p.QueryRow(ctx, `SELECT cert_serial FROM nodes WHERE id=$1`, identity.GatewayID).Scan(&serial); e != nil {
		t.Fatal(e)
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: identity.GatewayID, CertificateSerial: serial}
	if _, e = p.Exec(ctx, `CREATE FUNCTION reject_runtime_audit() RETURNS trigger AS $$ BEGIN IF NEW.action IN ('ipsec.material_checkpoint','ipsec.runtime_acknowledged') THEN RAISE EXCEPTION 'synthetic failure'; END IF; RETURN NEW; END $$ LANGUAGE plpgsql; CREATE TRIGGER reject_runtime_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_runtime_audit()`); e != nil {
		t.Fatal(e)
	}
	m, e := store.Material(ctx, principal, c.ID, 2, sealer)
	if !errors.Is(e, ipsec.ErrConnectionUnavailable) || m.ID != uuid.Nil || m.Secrets[0].PSK != "" {
		t.Fatal("failed audit returned material", e)
	}
	var n int
	if e = p.QueryRow(ctx, `SELECT count(*) FROM ipsec_runtime_deliveries`).Scan(&n); e != nil || n != 0 {
		t.Fatal("delivery escaped rollback", e)
	}
	var checkpoint *int64
	if e = p.QueryRow(ctx, `SELECT last_potentially_delivered_revision FROM ipsec_runtime_state WHERE connection_id=$1`, c.ID).Scan(&checkpoint); e != nil || checkpoint != nil {
		t.Fatal("checkpoint escaped rollback", e)
	}
	if _, e = p.Exec(ctx, `DROP TRIGGER reject_runtime_audit ON audit_logs`); e != nil {
		t.Fatal(e)
	}
	m, e = store.Material(ctx, principal, c.ID, 2, sealer)
	if e != nil {
		t.Fatal(e)
	}
	applied := ipsec.RuntimeAcknowledgement{DeliveryID: m.ID, DesiredRevision: 2, Kind: "apply", Result: "applied", OwnershipDigest: m.OwnershipDigest}
	wrong := applied
	wrong.OwnershipDigest = strings.Repeat("b", 64)
	if e = store.Acknowledge(ctx, principal, c.ID, wrong); !errors.Is(e, ipsec.ErrConnectionConflict) {
		t.Fatal("wrong digest accepted", e)
	}
	old := principal
	old.CertificateSerial = "obsolete"
	if e = store.Acknowledge(ctx, old, c.ID, applied); !errors.Is(e, ipsec.ErrRuntimeUnauthorized) {
		t.Fatal("obsolete certificate accepted", e)
	}
	if e = store.Acknowledge(ctx, principal, c.ID, applied); e != nil {
		t.Fatal(e)
	}
	if e = store.Acknowledge(ctx, principal, c.ID, applied); e != nil {
		t.Fatal(e)
	}
	c, e = store.Read(ctx, org, c.ID)
	if e != nil || c.DesiredRevision != 2 || c.ApplicationState != "applied" {
		t.Fatal("applied acknowledgement changed intent", e)
	}
	c, e = store.SetIntent(ctx, org, actor, c.ID, 2, "disabled")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = store.SetIntent(ctx, org, actor, c.ID, 3, "enabled"); !errors.Is(e, ipsec.ErrConnectionIneligible) {
		t.Fatal("reenabled before cleanup", e)
	}
	cleanup, e := store.Cleanup(ctx, principal, c.ID, 3)
	if e != nil {
		t.Fatal(e)
	}
	ack := ipsec.RuntimeAcknowledgement{DeliveryID: cleanup.ID, DesiredRevision: 3, Kind: "cleanup", Result: "cleaned", OwnershipDigest: cleanup.OwnershipDigest, GuardRetained: true}
	if e = store.Acknowledge(ctx, principal, c.ID, ack); e != nil {
		t.Fatal(e)
	}
	c, e = store.SetIntent(ctx, org, actor, c.ID, 3, "enabled")
	if e != nil || c.DesiredRevision != 4 {
		t.Fatal("same owner reenable", e)
	}
	m2, e := store.Material(ctx, principal, c.ID, 4, sealer)
	if e != nil || m2.ID == m.ID {
		t.Fatal("new revision delivery", e)
	}
	c, e = store.Delete(ctx, org, actor, c.ID, 4)
	if e != nil {
		t.Fatal(e)
	}
	cleanup, e = store.Cleanup(ctx, principal, c.ID, 5)
	if e != nil || len(cleanup.Lineage) != 2 || cleanup.CoversDeliveryRevision != 4 {
		t.Fatal("incomplete multi-delivery cleanup", e)
	}
	ack = ipsec.RuntimeAcknowledgement{DeliveryID: cleanup.ID, DesiredRevision: 5, Kind: "cleanup", Result: "cleaned", OwnershipDigest: cleanup.OwnershipDigest, GuardRetained: true}
	if _, e = p.Exec(ctx, `CREATE TRIGGER reject_runtime_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_runtime_audit()`); e != nil {
		t.Fatal(e)
	}
	if e = store.Acknowledge(ctx, principal, c.ID, ack); !errors.Is(e, ipsec.ErrConnectionUnavailable) {
		t.Fatal("ack audit did not fail", e)
	}
	if e = p.QueryRow(ctx, `SELECT count(*) FROM ipsec_tunnel_secrets WHERE connection_id=$1`, c.ID).Scan(&n); e != nil || n != 2 {
		t.Fatal("secrets deleted despite rollback", e)
	}
	c, e = store.Read(ctx, org, c.ID)
	if e != nil || c.FinalizedAt != nil || c.CleanupState != "pending" {
		t.Fatal("finalization escaped rollback", e)
	}
	if e = p.QueryRow(ctx, `SELECT count(*) FROM ipsec_runtime_acknowledgements WHERE delivery_id=$1`, ack.DeliveryID).Scan(&n); e != nil || n != 0 {
		t.Fatal("ack escaped rollback", e)
	}
	if _, e = p.Exec(ctx, `DROP TRIGGER reject_runtime_audit ON audit_logs`); e != nil {
		t.Fatal(e)
	}
	if e = store.Acknowledge(ctx, principal, c.ID, ack); e != nil {
		t.Fatal(e)
	}
}

func TestRuntimeCapacityNeverStrandsCleanup(t *testing.T) {
	ctx, p, org, actor, sealer, identity := createFixture(t)
	if _, e := p.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, uuid.New(), identity.SiteID); e != nil {
		t.Fatal(e)
	}
	store := ipsec.NewConnectionStore(p)
	store.ConfigureRuntimePolicy(runtimeCompiler)
	c, e := store.CreateProviderDisabled(ctx, org, actor, sealer, providerRequest(identity))
	if e != nil {
		t.Fatal(e)
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: identity.GatewayID, CertificateSerial: identity.GatewayID.String()}
	pending, e := store.Pending(ctx, principal, nil, 100)
	if e != nil || pending.OrgID != org || pending.NodeID != principal.NodeID {
		t.Fatal("pending identity missing", e)
	}
	for i := 0; i < 64; i++ {
		c, e = store.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled")
		if e != nil {
			t.Fatalf("enable %d: %v", i, e)
		}
		if _, e = store.Material(ctx, principal, c.ID, c.DesiredRevision, sealer); e != nil {
			t.Fatalf("material %d: %v", i, e)
		}
		c, e = store.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "disabled")
		if e != nil {
			t.Fatalf("disable %d: %v", i, e)
		}
		cleanup, e := store.Cleanup(ctx, principal, c.ID, c.DesiredRevision)
		if e != nil || len(cleanup.Lineage) != i+1 {
			t.Fatalf("lineage %d: %v", i, e)
		}
		e = store.Acknowledge(ctx, principal, c.ID, ipsec.RuntimeAcknowledgement{DeliveryID: cleanup.ID, DesiredRevision: c.DesiredRevision, Kind: "cleanup", Result: "cleaned", OwnershipDigest: cleanup.OwnershipDigest, GuardRetained: true})
		if e != nil {
			t.Fatalf("ack %d: %v", i, e)
		}
	}
	if _, e = store.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled"); !errors.Is(e, ipsec.ErrConnectionIneligible) {
		t.Fatal("capacity admission not refused", e)
	}
	c, e = store.Delete(ctx, org, actor, c.ID, c.DesiredRevision)
	if e != nil || c.FinalizedAt == nil || c.CleanupState != "retained_guard" {
		t.Fatal("capacity stranded deletion", e)
	}
}
