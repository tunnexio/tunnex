package ipsec_test

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
)

func TestStaticRecreationFinalizedExactDomainAndImmutableAuthority(t *testing.T) {
	ctx, p, org, actor, sealer, req := providerFixture(t)
	if err := db.MigrateTo(p.Config().ConnString(), 220); err != nil {
		t.Fatal(err)
	}
	if _, e := p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities || '{"ipsec_retained_guard_version":1}'::jsonb WHERE id=$1`, req.GatewayID); e != nil {
		t.Fatal(e)
	}
	store := ipsec.NewConnectionStore(p)
	store.ConfigureRuntimePolicy(runtimeCompiler)
	var serial string
	if err := p.QueryRow(ctx, `SELECT cert_serial FROM nodes WHERE id=$1`, req.GatewayID).Scan(&serial); err != nil {
		t.Fatal(err)
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: req.GatewayID, CertificateSerial: serial}
	fresh := func() ipsec.CreateProviderRequest {
		r := req
		r.ID = uuid.New()
		r.TunnelIDs = [2]uuid.UUID{uuid.New(), uuid.New()}
		return r
	}
	create := func(r ipsec.CreateProviderRequest) ipsec.Connection {
		t.Helper()
		c, e := store.CreateProviderDisabled(ctx, org, actor, sealer, r)
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	enable := func(c ipsec.Connection) ipsec.Connection {
		t.Helper()
		c, e := store.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled")
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	material := func(c ipsec.Connection) ipsec.RuntimeMaterial {
		t.Helper()
		m, e := store.Material(ctx, principal, c.ID, c.DesiredRevision, sealer)
		if e != nil {
			t.Fatal(e)
		}
		return m
	}
	cleanup := func(c ipsec.Connection) ipsec.RuntimeCleanup {
		t.Helper()
		d, e := store.Cleanup(ctx, principal, c.ID, c.DesiredRevision)
		if e != nil {
			t.Fatal(e)
		}
		if e = store.Acknowledge(ctx, principal, c.ID, ipsec.RuntimeAcknowledgement{DeliveryID: d.ID, DesiredRevision: d.DesiredRevision, Kind: "cleanup", Result: "cleaned", OwnershipDigest: d.OwnershipDigest, GuardRetained: true}); e != nil {
			t.Fatal(e)
		}
		return d
	}
	c := enable(create(req))
	m := material(c)
	if len(m.Manifest.RetainedGuardPredecessors) != 0 {
		t.Fatal("legacy manifest gained predecessor authority")
	}
	c, e := store.Delete(ctx, org, actor, c.ID, c.DesiredRevision)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = store.CreateProviderDisabled(ctx, org, actor, sealer, fresh()); !errors.Is(e, ipsec.ErrConnectionConflict) {
		t.Fatalf("unfinalized recreation %v", e)
	}
	oldCleanup := cleanup(c)
	// Every guard keeps protecting unrelated namespace, route and prefix admission.
	for _, prefix := range []string{"10.20.0.0/17", "10.20.0.0/15"} {
		r := fresh()
		r.Config.RemotePrefixes = []string{prefix}
		if _, e = store.CreateProviderDisabled(ctx, org, actor, sealer, r); !errors.Is(e, ipsec.ErrConnectionConflict) {
			t.Fatalf("partial overlap %s %v", prefix, e)
		}
	}
	if _, e = p.Exec(ctx, `INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.11.0.0/16','approved')`, uuid.New(), req.SiteID); e != nil {
		t.Fatal(e)
	}
	r := fresh()
	r.Config.LocalPrefixes = []string{"10.11.0.0/16"}
	if _, e = store.CreateProviderDisabled(ctx, org, actor, sealer, r); !errors.Is(e, ipsec.ErrConnectionConflict) {
		t.Fatalf("different local domain %v", e)
	}
	otherGateway := uuid.New()
	if _, e = p.Exec(ctx, `INSERT INTO nodes(id,org_id,name,cert_serial,site_id,capabilities,policy_reported_at) VALUES($1,$2,'foreign gateway',$3,$4,'{"ipsec_config_version":1}',clock_timestamp())`, otherGateway, org, otherGateway.String(), req.SiteID); e != nil {
		t.Fatal(e)
	}
	r = fresh()
	r.GatewayID = otherGateway
	if _, e = store.CreateProviderDisabled(ctx, org, actor, sealer, r); !errors.Is(e, ipsec.ErrConnectionConflict) {
		t.Fatalf("different gateway %v", e)
	}
	if _, e = p.Exec(ctx, `SELECT ipsec_provider_check_range($1,'10.20.0.0/16','route')`, org); e == nil {
		t.Fatal("shared route gained retained-prefix exemption")
	}
	successor := create(fresh())
	if successor.DesiredIntent != "disabled" || successor.DesiredRevision != 1 {
		t.Fatal("recreation did not stay disabled")
	}
	var bindings int
	if e = p.QueryRow(ctx, `SELECT count(*) FROM ipsec_static_recreations WHERE connection_id=$1`, successor.ID).Scan(&bindings); e != nil || bindings != 1 {
		t.Fatalf("binding count %d %v", bindings, e)
	}
	for _, q := range []string{`DELETE FROM ipsec_static_recreations WHERE connection_id=$1`, `UPDATE ipsec_static_recreations SET cleanup_delivery_id=gen_random_uuid() WHERE connection_id=$1`} {
		if _, e = p.Exec(ctx, q, successor.ID); e == nil {
			t.Fatal("immutable successor authority erased")
		}
	}
	successor = enable(successor)
	// Direct SQL writers cannot drop or substitute authenticated predecessor refs.
	forged := m.Manifest
	forged.ConnectionID = successor.ID
	forged.DesiredRevision = successor.DesiredRevision
	forged.RetainedGuardPredecessors = nil
	for _, refs := range [][]ipsec.RuntimeRetainedGuardPredecessor{nil, {{ConnectionID: c.ID, DeliveryID: m.ID, CleanupDeliveryID: uuid.New(), OwnershipDigest: m.OwnershipDigest}}, {{ConnectionID: uuid.New(), DeliveryID: m.ID, CleanupDeliveryID: oldCleanup.ID, OwnershipDigest: m.OwnershipDigest}}, {{ConnectionID: c.ID, DeliveryID: m.ID, CleanupDeliveryID: oldCleanup.ID, OwnershipDigest: strings.Repeat("f", 64)}}} {
		forged.RetainedGuardPredecessors = refs
		raw, _ := json.Marshal(forged)
		if _, e = p.Exec(ctx, `INSERT INTO ipsec_runtime_deliveries(id,connection_id,org_id,node_id,site_id,desired_revision,kind,configuration_revision,ownership_digest,manifest,certificate_serial) VALUES($1,$2,$3,$4,$5,$6,'apply',1,$7,$8,$9)`, uuid.New(), successor.ID, org, req.GatewayID, req.SiteID, successor.DesiredRevision, strings.Repeat("a", 64), raw, serial); e == nil {
			t.Fatal("forged predecessor delivery admitted")
		}
	}
	nextMaterial := material(successor)
	want := ipsec.RuntimeRetainedGuardPredecessor{ConnectionID: c.ID, DeliveryID: m.ID, CleanupDeliveryID: oldCleanup.ID, OwnershipDigest: m.OwnershipDigest}
	if len(nextMaterial.Manifest.RetainedGuardPredecessors) != 1 || nextMaterial.Manifest.RetainedGuardPredecessors[0] != want {
		t.Fatalf("manifest predecessor %+v", nextMaterial.Manifest.RetainedGuardPredecessors)
	}
	again, e := store.Material(ctx, principal, successor.ID, successor.DesiredRevision, sealer)
	if e != nil || again.ID != nextMaterial.ID || again.OwnershipDigest != nextMaterial.OwnershipDigest {
		t.Fatal("recreation manifest not immutable/idempotent", e)
	}
	successor, e = store.Delete(ctx, org, actor, successor.ID, successor.DesiredRevision)
	if e != nil {
		t.Fatal(e)
	}
	nextCleanup := cleanup(successor)
	third := enable(create(fresh()))
	thirdMaterial := material(third)
	if path := os.Getenv("TUNNEX_WRITE_RECREATION_WIRE"); path != "" {
		raw, e := json.Marshal(struct {
			Manifest ipsec.RuntimeManifest `json:"manifest"`
			Digest   string                `json:"ownership_digest"`
		}{thirdMaterial.Manifest, thirdMaterial.OwnershipDigest})
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	refs := thirdMaterial.Manifest.RetainedGuardPredecessors
	if len(refs) != 2 {
		t.Fatalf("cumulative predecessor count %d", len(refs))
	}
	found := map[uuid.UUID]ipsec.RuntimeRetainedGuardPredecessor{}
	for i, x := range refs {
		found[x.DeliveryID] = x
		if i > 0 && refs[i-1].DeliveryID.String() >= x.DeliveryID.String() {
			t.Fatal("predecessor order is not canonical")
		}
	}
	if found[m.ID] != want || found[nextMaterial.ID] != (ipsec.RuntimeRetainedGuardPredecessor{ConnectionID: successor.ID, DeliveryID: nextMaterial.ID, CleanupDeliveryID: nextCleanup.ID, OwnershipDigest: nextMaterial.OwnershipDigest}) {
		t.Fatal("cumulative cleanup lineage lost")
	}
	var retained int
	if e = p.QueryRow(ctx, `SELECT count(*) FROM ipsec_retained_guards WHERE org_id=$1`, org).Scan(&retained); e != nil || retained != 2 {
		t.Fatalf("old guard history mutated %d %v", retained, e)
	}
}

func TestStaticRecreationRejectsStaleAndForeignBindingsPostgres(t *testing.T) {
	ctx, p, org, actor, sealer, req := providerFixture(t)
	if e := db.MigrateTo(p.Config().ConnString(), 220); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities || '{"ipsec_retained_guard_version":1}'::jsonb WHERE id=$1`, req.GatewayID); e != nil {
		t.Fatal(e)
	}
	store := ipsec.NewConnectionStore(p)
	store.ConfigureRuntimePolicy(runtimeCompiler)
	var serial string
	if e := p.QueryRow(ctx, `SELECT cert_serial FROM nodes WHERE id=$1`, req.GatewayID).Scan(&serial); e != nil {
		t.Fatal(e)
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: req.GatewayID, CertificateSerial: serial}
	c, e := store.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if e != nil {
		t.Fatal(e)
	}
	c, e = store.SetIntent(ctx, org, actor, c.ID, 1, "enabled")
	if e != nil {
		t.Fatal(e)
	}
	firstMaterial, e := store.Material(ctx, principal, c.ID, c.DesiredRevision, sealer)
	if e != nil {
		t.Fatal(e)
	}
	c, e = store.SetIntent(ctx, org, actor, c.ID, 2, "disabled")
	if e != nil {
		t.Fatal(e)
	}
	clean := func(c ipsec.Connection) ipsec.RuntimeCleanup {
		t.Helper()
		d, e := store.Cleanup(ctx, principal, c.ID, c.DesiredRevision)
		if e != nil {
			t.Fatal(e)
		}
		if e = store.Acknowledge(ctx, principal, c.ID, ipsec.RuntimeAcknowledgement{DeliveryID: d.ID, DesiredRevision: d.DesiredRevision, Kind: "cleanup", Result: "cleaned", OwnershipDigest: d.OwnershipDigest, GuardRetained: true}); e != nil {
			t.Fatal(e)
		}
		return d
	}
	stale := clean(c)
	c, e = store.SetIntent(ctx, org, actor, c.ID, 3, "enabled")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = store.Material(ctx, principal, c.ID, c.DesiredRevision, sealer); e != nil {
		t.Fatal(e)
	}
	c, e = store.Delete(ctx, org, actor, c.ID, 4)
	if e != nil {
		t.Fatal(e)
	}
	latest := clean(c)
	for _, tc := range []struct {
		name                        string
		owner, predecessor, cleanup uuid.UUID
	}{
		{"stale cleanup", org, c.ID, stale.ID}, {"wrong predecessor", org, uuid.New(), latest.ID}, {"wrong tenant", uuid.New(), c.ID, latest.ID}, {"missing cleanup", org, c.ID, uuid.New()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, e := p.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback(ctx)
			id := uuid.New()
			if _, e = tx.Exec(ctx, `INSERT INTO ipsec_connections(id,org_id,name,site_id,gateway_node_id,historical_site_id,historical_gateway_node_id,provider_profile) VALUES($1,$2,'candidate',$3,$4,$3,$4,'aws-static-ipv4-v1')`, id, org, req.SiteID, req.GatewayID); e != nil {
				t.Fatal(e)
			}
			if _, e = tx.Exec(ctx, `INSERT INTO ipsec_static_recreations(connection_id,org_id,predecessor_connection_id,cleanup_delivery_id) VALUES($1,$2,$3,$4)`, id, tc.owner, tc.predecessor, tc.cleanup); e == nil {
				t.Fatal("forged/stale binding accepted")
			}
		})
	}
	// Latest cleanup names every immutable apply lineage of this predecessor.
	req.ID = uuid.New()
	req.TunnelIDs = [2]uuid.UUID{uuid.New(), uuid.New()}
	next, e := store.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if e != nil {
		t.Fatal(e)
	}
	next, e = store.SetIntent(ctx, org, actor, next.ID, 1, "enabled")
	if e != nil {
		t.Fatal(e)
	}
	m, e := store.Material(ctx, principal, next.ID, 2, sealer)
	if e != nil {
		t.Fatal(e)
	}
	if len(m.Manifest.RetainedGuardPredecessors) != 2 {
		t.Fatal("latest cleanup omitted earlier apply lineage")
	}
	for _, ref := range m.Manifest.RetainedGuardPredecessors {
		expectedCleanup := latest.ID
		if ref.DeliveryID == firstMaterial.ID {
			expectedCleanup = stale.ID
		}
		if ref.ConnectionID != c.ID || ref.CleanupDeliveryID != expectedCleanup {
			t.Fatal("first retained cleanup identity lost in manifest")
		}
	}
}

// Same customer connection: apply/disable twice, then a third apply/delete.
// Native immutable entries retain three different CleanupIDs even though the
// latest finalized cleanup is the complete binding proof for all three.
func TestStaticRecreationThreeApplyLineagesKeepFirstRetainedCleanupPostgres(t *testing.T) {
	ctx, p, org, actor, sealer, req := providerFixture(t)
	if err := db.MigrateTo(p.Config().ConnString(), 220); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities || '{"ipsec_retained_guard_version":1}'::jsonb WHERE id=$1`, req.GatewayID); err != nil {
		t.Fatal(err)
	}
	store := ipsec.NewConnectionStore(p)
	store.ConfigureRuntimePolicy(runtimeCompiler)
	var serial string
	if err := p.QueryRow(ctx, `SELECT cert_serial FROM nodes WHERE id=$1`, req.GatewayID).Scan(&serial); err != nil {
		t.Fatal(err)
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: req.GatewayID, CertificateSerial: serial}
	c, err := store.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if err != nil {
		t.Fatal(err)
	}
	var applies []ipsec.RuntimeMaterial
	var cleanups []ipsec.RuntimeCleanup
	for i := 0; i < 3; i++ {
		c, err = store.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled")
		if err != nil {
			t.Fatal(err)
		}
		apply, e := store.Material(ctx, principal, c.ID, c.DesiredRevision, sealer)
		if e != nil {
			t.Fatal(e)
		}
		applies = append(applies, apply)
		if i < 2 {
			c, err = store.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "disabled")
		} else {
			c, err = store.Delete(ctx, org, actor, c.ID, c.DesiredRevision)
		}
		if err != nil {
			t.Fatal(err)
		}
		cleanup, e := store.Cleanup(ctx, principal, c.ID, c.DesiredRevision)
		if e != nil {
			t.Fatal(e)
		}
		if e = store.Acknowledge(ctx, principal, c.ID, ipsec.RuntimeAcknowledgement{DeliveryID: cleanup.ID, DesiredRevision: cleanup.DesiredRevision, Kind: "cleanup", Result: "cleaned", OwnershipDigest: cleanup.OwnershipDigest, GuardRetained: true}); e != nil {
			t.Fatal(e)
		}
		cleanups = append(cleanups, cleanup)
	}
	if c.DesiredRevision != 7 {
		t.Fatal("did not reproduce the customer's revision7 delete")
	}
	var oldGuardHash string
	if err = p.QueryRow(ctx, `SELECT md5(jsonb_agg(to_jsonb(g) ORDER BY cleanup_delivery_id)::text) FROM ipsec_retained_guards g WHERE connection_id=$1`, c.ID).Scan(&oldGuardHash); err != nil {
		t.Fatal(err)
	}
	req.ID = uuid.New()
	req.TunnelIDs = [2]uuid.UUID{uuid.New(), uuid.New()}
	successor, e := store.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if e != nil {
		t.Fatal(e)
	}
	var bindingCleanup uuid.UUID
	if e = p.QueryRow(ctx, `SELECT cleanup_delivery_id FROM ipsec_static_recreations WHERE connection_id=$1 AND predecessor_connection_id=$2`, successor.ID, c.ID).Scan(&bindingCleanup); e != nil || bindingCleanup != cleanups[2].ID {
		t.Fatal("latest finalized binding weakened", e)
	}
	successor, e = store.SetIntent(ctx, org, actor, successor.ID, successor.DesiredRevision, "enabled")
	if e != nil {
		t.Fatal(e)
	}
	// Latest-cleanup-for-all was the causal defect. The database rejects it before
	// inserting any apply delivery, with the dedicated manifest constraint.
	forged := applies[2].Manifest
	forged.ConnectionID = successor.ID
	forged.DesiredRevision = successor.DesiredRevision
	for _, apply := range applies {
		forged.RetainedGuardPredecessors = append(forged.RetainedGuardPredecessors, ipsec.RuntimeRetainedGuardPredecessor{ConnectionID: c.ID, DeliveryID: apply.ID, CleanupDeliveryID: cleanups[2].ID, OwnershipDigest: apply.OwnershipDigest})
	}
	sort.Slice(forged.RetainedGuardPredecessors, func(i, j int) bool {
		return forged.RetainedGuardPredecessors[i].DeliveryID.String() < forged.RetainedGuardPredecessors[j].DeliveryID.String()
	})
	raw, _ := json.Marshal(forged)
	_, e = p.Exec(ctx, `INSERT INTO ipsec_runtime_deliveries(id,connection_id,org_id,node_id,site_id,desired_revision,kind,configuration_revision,ownership_digest,manifest,certificate_serial) VALUES($1,$2,$3,$4,$5,$6,'apply',1,$7,$8,$9)`, uuid.New(), successor.ID, org, req.GatewayID, req.SiteID, successor.DesiredRevision, strings.Repeat("a", 64), raw, serial)
	var pgErr *pgconn.PgError
	if !errors.As(e, &pgErr) || pgErr.Message != "IPsec static recreation manifest invalid" {
		t.Fatalf("wrong-cleanup mapping refusal was not causal: %v", e)
	}
	got, e := store.Material(ctx, principal, successor.ID, successor.DesiredRevision, sealer)
	if e != nil {
		t.Fatal(e)
	}
	refs := got.Manifest.RetainedGuardPredecessors
	if len(refs) != 3 {
		t.Fatalf("three-lineage history omitted: %d", len(refs))
	}
	byDelivery := map[uuid.UUID]ipsec.RuntimeRetainedGuardPredecessor{}
	for i, ref := range refs {
		byDelivery[ref.DeliveryID] = ref
		if i > 0 && refs[i-1].DeliveryID.String() >= ref.DeliveryID.String() {
			t.Fatal("unsorted refs")
		}
	}
	for i, apply := range applies {
		want := ipsec.RuntimeRetainedGuardPredecessor{ConnectionID: c.ID, DeliveryID: apply.ID, CleanupDeliveryID: cleanups[i].ID, OwnershipDigest: apply.OwnershipDigest}
		if byDelivery[apply.ID] != want {
			t.Fatalf("immutable first cleanup identity mismatch: %+v != %+v", byDelivery[apply.ID], want)
		}
	}
	var retainedCount int
	var afterGuardHash string
	if e = p.QueryRow(ctx, `SELECT count(*),md5(jsonb_agg(to_jsonb(g) ORDER BY cleanup_delivery_id)::text) FROM ipsec_retained_guards g WHERE connection_id=$1`, c.ID).Scan(&retainedCount, &afterGuardHash); e != nil || retainedCount != 3 || afterGuardHash != oldGuardHash {
		t.Fatal("old retained history rewritten", e)
	}
	if path := os.Getenv("TUNNEX_WRITE_THREE_LINEAGE_RECREATION_WIRE"); path != "" {
		wire, e := json.Marshal(struct {
			Manifest ipsec.RuntimeManifest `json:"manifest"`
			Digest   string                `json:"ownership_digest"`
		}{got.Manifest, got.OwnershipDigest})
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, wire, 0600); e != nil {
			t.Fatal(e)
		}
	}
}

func TestStaticRecreationWaitsForOriginalCleanupAcknowledgementPostgres(t *testing.T) {
	ctx, p, org, actor, sealer, req := providerFixture(t)
	if e := db.MigrateTo(p.Config().ConnString(), 221); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Exec(ctx, `UPDATE nodes SET capabilities=capabilities || '{"ipsec_retained_guard_version":1}'::jsonb WHERE id=$1`, req.GatewayID); e != nil {
		t.Fatal(e)
	}
	store := ipsec.NewConnectionStore(p)
	store.ConfigureRuntimePolicy(runtimeCompiler)
	var serial string
	if e := p.QueryRow(ctx, `SELECT cert_serial FROM nodes WHERE id=$1`, req.GatewayID).Scan(&serial); e != nil {
		t.Fatal(e)
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: req.GatewayID, CertificateSerial: serial}
	c, e := store.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if e != nil {
		t.Fatal(e)
	}
	c, e = store.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled")
	if e != nil {
		t.Fatal(e)
	}
	apply, e := store.Material(ctx, principal, c.ID, c.DesiredRevision, sealer)
	if e != nil {
		t.Fatal(e)
	}
	c, e = store.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "disabled")
	if e != nil {
		t.Fatal(e)
	}
	queued, e := store.Cleanup(ctx, principal, c.ID, c.DesiredRevision)
	if e != nil {
		t.Fatal(e)
	}
	// An unacknowledged cleanup might already be retained natively. Preserve its
	// exact delivery/revision so a lost ACK can be retried without a new identity.
	if _, e = store.Delete(ctx, org, actor, c.ID, c.DesiredRevision); !errors.Is(e, ipsec.ErrCleanupInProgress) {
		t.Fatal("pending cleanup was superseded", e)
	}
	cleaned := queued
	if e = store.Acknowledge(ctx, principal, c.ID, ipsec.RuntimeAcknowledgement{DeliveryID: cleaned.ID, DesiredRevision: cleaned.DesiredRevision, Kind: "cleanup", Result: "cleaned", OwnershipDigest: cleaned.OwnershipDigest, GuardRetained: true}); e != nil {
		t.Fatal(e)
	}
	c, e = store.Delete(ctx, org, actor, c.ID, c.DesiredRevision)
	if e != nil || c.FinalizedAt == nil {
		t.Fatal("delete after original cleanup ACK did not finalize", e)
	}
	req.ID = uuid.New()
	req.TunnelIDs = [2]uuid.UUID{uuid.New(), uuid.New()}
	next, e := store.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if e != nil {
		t.Fatal(e)
	}
	next, e = store.SetIntent(ctx, org, actor, next.ID, next.DesiredRevision, "enabled")
	if e != nil {
		t.Fatal(e)
	}
	material, e := store.Material(ctx, principal, next.ID, next.DesiredRevision, sealer)
	if e != nil {
		t.Fatal(e)
	}
	refs := material.Manifest.RetainedGuardPredecessors
	want := ipsec.RuntimeRetainedGuardPredecessor{ConnectionID: c.ID, DeliveryID: apply.ID, CleanupDeliveryID: cleaned.ID, OwnershipDigest: apply.OwnershipDigest}
	if len(refs) != 1 || refs[0] != want || refs[0].CleanupDeliveryID != queued.ID {
		t.Fatal("original acknowledged cleanup identity changed", refs)
	}
	var retained int
	if e = p.QueryRow(ctx, `SELECT count(*) FROM ipsec_retained_guards WHERE connection_id=$1`, c.ID).Scan(&retained); e != nil || retained != 1 {
		t.Fatal("unexpected cleanup lineage entered retained history", e)
	}
}
