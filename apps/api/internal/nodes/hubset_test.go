package nodes

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

func idAt(n byte) uuid.UUID { return uuid.UUID{0: n} }

func gw(n byte, endpoint, wgKey string, pri *int32, seen *time.Time) sqlc.ListSiteGatewaysForOrgRow {
	r := sqlc.ListSiteGatewaysForOrgRow{ID: idAt(n), Endpoint: endpoint, WgPublicKey: wgKey, HubPriority: pri}
	if seen != nil {
		r.LastSeenAt = pgtype.Timestamptz{Time: *seen, Valid: true}
	}
	return r
}

func ids(set []sqlc.ListSiteGatewaysForOrgRow) []byte {
	out := make([]byte, len(set))
	for i := range set {
		out[i] = set[i].ID[0]
	}
	return out
}

func pri(v int32) *int32 { return &v }

// electSiteHubSet two-tier membership reds (S8.6 (3)) — PURE, no DB.
func TestElectSiteHubSetOrdering(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fresh := now.Add(-10 * time.Second) // within hubStaleWindow
	stale := now.Add(-10 * time.Minute) // well past it

	// CAPABILITY GATE: no endpoint (NAT'd) OR no wg key → not a candidate.
	t.Run("capability gate excludes NAT'd and keyless", func(t *testing.T) {
		topo := siteTopology{gws: []sqlc.ListSiteGatewaysForOrgRow{
			gw(1, "", "K1", nil, &fresh),              // NAT'd → out
			gw(2, "1.2.3.4:51820", "", nil, &fresh),   // no key → out
			gw(3, "1.2.3.5:51820", "K3", nil, &fresh), // capable → the single hub
		}}
		if got := ids(electSiteHubSet(topo, now)); len(got) != 1 || got[0] != 3 {
			t.Fatalf("only the capable gateway is the hub, got %v", got)
		}
	})

	// NO PINS → a SINGLE auto-elected hub (set of one) — today's zero-config behavior, no standbys.
	t.Run("no pins → single-hub set of one (lowest id)", func(t *testing.T) {
		topo := siteTopology{gws: []sqlc.ListSiteGatewaysForOrgRow{
			gw(5, "h:1", "knsbfv3HVkciN84sZHAIBOD3BIMZfbvIc/h65xPcCqI=", nil, &fresh), gw(2, "h:1", "dUBWjkMrPlrb9U4mxyF+UEluQ/XwI7FGiA9Ybk9CROw=", nil, &fresh), gw(9, "h:1", "K9", nil, &fresh),
		}}
		if got := ids(electSiteHubSet(topo, now)); string(got) != string([]byte{2}) {
			t.Fatalf("no pins → set of ONE (lowest-id hub), got %v", got)
		}
	})

	// PINS present → the set is the PINNED gateways ONLY (HA opt-in); unpinned leaves EXCLUDED, ordered.
	t.Run("pins → pinned set only, unpinned leaf excluded", func(t *testing.T) {
		topo := siteTopology{gws: []sqlc.ListSiteGatewaysForOrgRow{
			gw(7, "h:1", "K7", nil, &fresh),                                              // unpinned leaf (fresh) — EXCLUDED (the walk's azure-gw)
			gw(3, "h:1", "K3", pri(2), &stale),                                           // pinned #2
			gw(5, "h:1", "knsbfv3HVkciN84sZHAIBOD3BIMZfbvIc/h65xPcCqI=", pri(1), &fresh), // pinned #1 → primary
		}}
		if got := ids(electSiteHubSet(topo, now)); string(got) != string([]byte{5, 3}) {
			t.Fatalf("pinned set ordered by priority (5=#1, 3=#2), unpinned 7 excluded, got %v", got)
		}
	})

	// A PIN priority outranks health among the pinned (operator outranks magic).
	t.Run("pin priority outranks health", func(t *testing.T) {
		topo := siteTopology{gws: []sqlc.ListSiteGatewaysForOrgRow{
			gw(3, "h:1", "K3", pri(1), &stale), // pinned #1 but STALE
			gw(7, "h:1", "K7", pri(2), &fresh), // pinned #2 but FRESH
		}}
		if got := ids(electSiteHubSet(topo, now)); got[0] != 3 {
			t.Fatalf("the lower-priority pin is primary regardless of health, got %v", got)
		}
	})

	// PINNED-BUT-INCAPABLE → excluded; the set falls back to the capable pin (capability still gates).
	t.Run("pinned but incapable is excluded", func(t *testing.T) {
		topo := siteTopology{gws: []sqlc.ListSiteGatewaysForOrgRow{
			gw(2, "", "dUBWjkMrPlrb9U4mxyF+UEluQ/XwI7FGiA9Ybk9CROw=", pri(1), &fresh), // pinned #1 but NAT'd → INELIGIBLE
			gw(4, "h:1", "K4", pri(2), &fresh),                                        // pinned #2, capable → the actual primary
		}}
		if got := ids(electSiteHubSet(topo, now)); string(got) != string([]byte{4}) {
			t.Fatalf("a pinned-but-NAT'd gateway is excluded; set falls back to the capable pin, got %v", got)
		}
	})

	// A PINNED cross-site gateway enters — membership = intent + capability, NOT geography (Slice 2 red
	// reinterpreted).
	t.Run("a pinned cross-site gateway enters", func(t *testing.T) {
		siteA, siteB := pgtype.UUID{Bytes: idAt(0xA), Valid: true}, pgtype.UUID{Bytes: idAt(0xB), Valid: true}
		g1 := gw(4, "h:1", "K4", pri(1), &fresh)
		g1.SiteID = siteA
		g2 := gw(6, "h:1", "K6", pri(2), &fresh)
		g2.SiteID = siteB
		topo := siteTopology{gws: []sqlc.ListSiteGatewaysForOrgRow{g1, g2}}
		if got := ids(electSiteHubSet(topo, now)); string(got) != string([]byte{4, 6}) {
			t.Fatalf("both pinned gateways (any site) enter in priority order, got %v", got)
		}
	})
}

// TestReconcileHubSetGeneration (S8.6 D5) — the persisted set + the fencing generation: bumps ONLY on a
// membership/order change (idempotent reconcile never bumps), survives a "restart" (a fresh Service over
// the same DB reads the same generation, never reset).
func TestReconcileHubSetGeneration(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	org := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,'O',$2)", org, "hs-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	actor := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO users (id,email,name) VALUES ($1,$2,'U')", actor, actor.String()+"@t"); e != nil {
		t.Fatalf("seed actor: %v", e)
	}
	site := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'s')", site, org); e != nil {
		t.Fatalf("seed site: %v", e)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM nodes WHERE org_id=$1", org)
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id=$1", org)
		_, _ = pool.Exec(context.Background(), "DELETE FROM users WHERE id=$1", actor)
	})
	// RANDOM ids (no cross-run collision); mkGw returns the id so assertions use captured values.
	mkGw := func(key string) uuid.UUID {
		id := uuid.New()
		if _, e := pool.Exec(ctx, "INSERT INTO nodes (id,org_id,name,cert_serial,site_id,wg_public_key,endpoint) VALUES ($1,$2,$3,$4,$5,$6,'h:1')",
			id, org, "gw-"+id.String()[:8], "cs-"+id.String()[:8], site, key); e != nil {
			t.Fatalf("seed gw: %v", e)
		}
		return id
	}

	svc := NewService(pool, nil, nil)

	// No gateways yet → empty set, generation starts at 1 on the first reconcile.
	hs, err := svc.ReconcileHubSet(ctx, org)
	if err != nil {
		t.Fatalf("reconcile 0: %v", err)
	}
	gen0 := hs.Generation

	// Two capable gateways, gA < gB by id (no pins yet → single-hub set = [gA]).
	gA, gB := mkGw("dUBWjkMrPlrb9U4mxyF+UEluQ/XwI7FGiA9Ybk9CROw="), mkGw("knsbfv3HVkciN84sZHAIBOD3BIMZfbvIc/h65xPcCqI=")
	if gB.String() < gA.String() {
		gA, gB = gB, gA
	}

	// The single hub (gA) → members [gA], bump from empty.
	hs, _ = svc.ReconcileHubSet(ctx, org)
	if hs.Generation <= gen0 {
		t.Fatalf("electing the single hub must BUMP: %d -> %d", gen0, hs.Generation)
	}
	if len(hs.Configured) != 1 || hs.Configured[0] != gA {
		t.Fatalf("no pins → members = [lowest-id hub gA], got %v", hs.Configured)
	}
	genAfterAdd := hs.Generation

	// IDEMPOTENT: N reconciles with the SAME set → the SAME generation (no idle bump — the fence holds).
	for i := 0; i < 3; i++ {
		hs, _ = svc.ReconcileHubSet(ctx, org)
	}
	if hs.Generation != genAfterAdd {
		t.Fatalf("a stable set must NOT bump across reconciles: %d -> %d", genAfterAdd, hs.Generation)
	}

	// "RESTART": a fresh Service over the same DB reads the SAME generation — CP-persisted, never reset.
	svc2 := NewService(pool, nil, nil)
	got, err := svc2.GetHubSet(ctx, org)
	if err != nil {
		t.Fatalf("get after restart: %v", err)
	}
	if got.Generation != genAfterAdd {
		t.Fatalf("the generation must SURVIVE a restart (D5 fencing), got %d want %d", got.Generation, genAfterAdd)
	}

	// gB is already present (higher id, UNPINNED) — the single-hub set is still [gA], so a reconcile does NOT
	// bump: an endpoint-bearing LEAF joining does not change the hub set (two-tier: no intent, no membership).
	hs, _ = svc.ReconcileHubSet(ctx, org)
	if hs.Generation != genAfterAdd || len(hs.Configured) != 1 || hs.Configured[0] != gA {
		t.Fatalf("an unpinned leaf must NOT change the single-hub set (no bump), got members=%v gen %d->%d", hs.Configured, genAfterAdd, hs.Generation)
	}

	// PIN gB → the set becomes the PINNED set [gB] (opt-in HA) → membership changes [gA]->[gB] → BUMP, and
	// the pin takes effect end-to-end (members[0] = gB).
	beforePin := hs.Generation
	if err := svc.SetHubPriority(ctx, actor, org, gB, pri(1)); err != nil {
		t.Fatalf("set pin: %v", err)
	}
	pinned, _ := svc.GetHubSet(ctx, org)
	if len(pinned.Configured) != 1 || pinned.Configured[0] != gB {
		t.Fatalf("pinning gB → the set is the pinned [gB], got %v", pinned.Configured)
	}
	if pinned.Generation <= beforePin {
		t.Fatalf("a pin that changes membership must bump: %d -> %d", beforePin, pinned.Generation)
	}
}

// peerByKey finds a compiled peer by its wg pubkey (nil if absent).
func peerByKey(peers []Peer, key string) *Peer {
	for i := range peers {
		if peers[i].PublicKey == key {
			return &peers[i]
		}
	}
	return nil
}

// TestSiteLinkGraphHA (S8.6 Slice 3) — the corrected (3) topology on the three-gateway WALK shape: two
// PINNED AWS hubs (primary + standby, same site) + an UNPINNED endpoint-bearing azure LEAF. Immortalizes
// the duplicate-subnet trace that caught the membership bug, + the single-AllowedIPs invariant, + hub
// symmetry, + same-site exclusion.
func TestSiteLinkGraphHA(t *testing.T) {
	fresh := time.Now()
	awsSite := idAt(0xA)
	azureSite := idAt(0xB)
	awsGw := gw(1, "aws:51820", "WJexHKl8fSOeqTI5Kb0ubME/F7jK9Zz8PFQ+dSFnIx0=", pri(1), &fresh) // primary (pin 1)
	awsGw.SiteID = pgtype.UUID{Bytes: awsSite, Valid: true}
	awsStandby := gw(2, "aws2:51820", "vdjc3/Z+eIcf/Yx3xCkD6Q0v8tK163PVqbEnbfnRIPM=", pri(2), &fresh) // standby (pin 2, SAME AWS site)
	awsStandby.SiteID = pgtype.UUID{Bytes: awsSite, Valid: true}
	azureGw := gw(3, "azure:51820", "n35dScrlS43upSjeakGVSQ/rjbN1YOix++yJxWLK3wo=", nil, &fresh) // UNPINNED leaf (endpoint-bearing — the trap)
	azureGw.SiteID = pgtype.UUID{Bytes: azureSite, Valid: true}
	topo := siteTopology{
		gws:     []sqlc.ListSiteGatewaysForOrgRow{awsGw, awsStandby, azureGw},
		subnets: map[uuid.UUID][]string{awsSite: {"172.31.0.0/16"}, azureSite: {"10.0.0.0/16"}},
	}
	nodeOf := func(g sqlc.ListSiteGatewaysForOrgRow) sqlc.Node { return sqlc.Node{ID: g.ID, SiteID: g.SiteID} }
	countWith := func(peers []Peer, cidr string) int {
		n := 0
		for i := range peers {
			for _, a := range peers[i].AllowedIPs {
				if a == cidr {
					n++
				}
			}
		}
		return n
	}

	// (1) The LEAF (azure, unpinned) compiles as a SPOKE — the primary carries the AWS subnets, the standby
	// is keepalive-only (empty), and 172.31.0.0/16 appears in EXACTLY ONE peer's AllowedIPs (the bug's death).
	azurePeers, _ := siteLinkGraphFrom(topo, nodeOf(azureGw))
	if p := peerByKey(azurePeers, "WJexHKl8fSOeqTI5Kb0ubME/F7jK9Zz8PFQ+dSFnIx0="); p == nil || len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "172.31.0.0/16" {
		t.Fatalf("azure's PRIMARY peer must carry the AWS subnets, got %+v", p)
	}
	if p := peerByKey(azurePeers, "vdjc3/Z+eIcf/Yx3xCkD6Q0v8tK163PVqbEnbfnRIPM="); p == nil || len(p.AllowedIPs) != 0 {
		t.Fatalf("azure's STANDBY peer must be keepalive-only (empty AllowedIPs), got %+v", p)
	}
	if n := countWith(azurePeers, "172.31.0.0/16"); n != 1 {
		t.Fatalf("the single-AllowedIPs invariant: 172.31.0.0/16 must be in EXACTLY ONE peer, got %d (the duplicate bug)", n)
	}

	// (2) The PRIMARY hub (aws-gw) peers with the azure leaf (azure subnets); NOT with the standby (same
	// AWS site — same-site exclusion kills the spurious same-L2 link).
	primaryPeers, primaryRoutes := siteLinkGraphFrom(topo, nodeOf(awsGw))
	if p := peerByKey(primaryPeers, "n35dScrlS43upSjeakGVSQ/rjbN1YOix++yJxWLK3wo="); p == nil || len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "10.0.0.0/16" {
		t.Fatalf("primary must peer with azure carrying azure subnets, got %+v", p)
	}
	if peerByKey(primaryPeers, "vdjc3/Z+eIcf/Yx3xCkD6Q0v8tK163PVqbEnbfnRIPM=") != nil {
		t.Fatal("primary must NOT peer with its same-site standby (same-site exclusion)")
	}

	// (3) The STANDBY hub (aws-instance-2) carries the SAME transit posture — peers with azure (azure
	// subnets, ready to forward), NOT with the same-site primary. Hub-symmetry: identical routes to the
	// primary → promotion changes nothing hub-side.
	standbyPeers, standbyRoutes := siteLinkGraphFrom(topo, nodeOf(awsStandby))
	if p := peerByKey(standbyPeers, "n35dScrlS43upSjeakGVSQ/rjbN1YOix++yJxWLK3wo="); p == nil || len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "10.0.0.0/16" {
		t.Fatalf("standby must carry the full transit posture (peer azure w/ subnets), got %+v", p)
	}
	if peerByKey(standbyPeers, "WJexHKl8fSOeqTI5Kb0ubME/F7jK9Zz8PFQ+dSFnIx0=") != nil {
		t.Fatal("standby must NOT peer with its same-site primary (same-site exclusion)")
	}
	if len(primaryRoutes) != len(standbyRoutes) || (len(primaryRoutes) > 0 && primaryRoutes[0].DstCIDR != standbyRoutes[0].DstCIDR) {
		t.Fatalf("hub-symmetry: primary + standby must carry identical routes, got %v vs %v", primaryRoutes, standbyRoutes)
	}

	// (4) ZERO-CONFIG GOLDEN: with NO pins, the same topology compiles single-hub (byte-identical to pre-HA)
	// — the leaf peers with ONLY the single elected hub (lowest id = aws-gw), NO standby peer at all.
	noPins := topo
	noPins.gws = []sqlc.ListSiteGatewaysForOrgRow{
		{ID: awsGw.ID, SiteID: awsGw.SiteID, WgPublicKey: "WJexHKl8fSOeqTI5Kb0ubME/F7jK9Zz8PFQ+dSFnIx0=", Endpoint: "aws:51820"},
		{ID: awsStandby.ID, SiteID: awsStandby.SiteID, WgPublicKey: "vdjc3/Z+eIcf/Yx3xCkD6Q0v8tK163PVqbEnbfnRIPM=", Endpoint: "aws2:51820"},
		{ID: azureGw.ID, SiteID: azureGw.SiteID, WgPublicKey: "n35dScrlS43upSjeakGVSQ/rjbN1YOix++yJxWLK3wo=", Endpoint: "azure:51820"},
	}
	azureNoPin, azureNoPinRoutes := siteLinkGraphFrom(noPins, nodeOf(azureGw))
	if len(azureNoPin) != 1 || azureNoPin[0].PublicKey != "WJexHKl8fSOeqTI5Kb0ubME/F7jK9Zz8PFQ+dSFnIx0=" {
		t.Fatalf("no-pins zero-config: the leaf peers with ONLY the single hub (aws-gw), got %d peers %+v", len(azureNoPin), azureNoPin)
	}

	// (5) VERSION/HASH — no bump: the standby peers add NO routes (the OS routes are the remote subnets,
	// peer-count-independent), so the leaf's ROUTES are IDENTICAL with pins (warm standby) and without. The
	// CanonicalHash is over routes+policy, so a standby peer never changes it → no RequiredVersion bump.
	_, azurePinnedRoutes := siteLinkGraphFrom(topo, nodeOf(azureGw))
	if len(azurePinnedRoutes) != len(azureNoPinRoutes) ||
		(len(azurePinnedRoutes) > 0 && azurePinnedRoutes[0].DstCIDR != azureNoPinRoutes[0].DstCIDR) {
		t.Fatalf("standby peers must add NO routes (hash-invariant): pinned %v vs no-pins %v", azurePinnedRoutes, azureNoPinRoutes)
	}
}

// TestGetHubSetView (S8.6 Slice 6) — the served hub set: ordered members with role (primary=members[0]),
// generation, and per-member L1 metrics from node_peer_status. The render-floor distinction: a member
// with a node_peer_status row has METRICS (even idle rx/tx=0); a NOT-reporting member has NIL metrics
// (absent ≠ zeroes-as-data).
func TestGetHubSetView(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	org := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'O',$2,'10.99.0.0/24')", org, "hv-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM nodes WHERE org_id=$1", org)
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id=$1", org)
	})
	site := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'s')", site, org); e != nil {
		t.Fatalf("seed site: %v", e)
	}
	pr, sb := uuid.New(), uuid.New()
	mk := func(id uuid.UUID, name, key string, prio int) {
		if _, e := pool.Exec(ctx, "INSERT INTO nodes (id,org_id,name,cert_serial,site_id,wg_public_key,endpoint,hub_priority) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
			id, org, name, "cs-"+id.String()[:8], site, key, "e:51820", prio); e != nil {
			t.Fatalf("seed %s: %v", name, e)
		}
	}
	mk(pr, "primary", "Astbc7xfIzi5K3VnumZWxLcEzVnAp4Qgm8FBJkE5pr4=", 1)
	mk(sb, "standby", "bEvGneTYHdxxP8w9Ugn5/A2WMq5F3D4zmt+ztfeCmGE=", 2)

	svc := NewService(pool, nil, nil)
	if _, e := svc.ReconcileHubSet(ctx, org); e != nil {
		t.Fatalf("reconcile: %v", e)
	}
	// The PRIMARY is IDLE-but-reporting: a node_peer_status row with rx/tx = 0 (a real link, no traffic yet).
	// The STANDBY is NOT reporting: NO row.
	now := time.Now()
	if _, e := pool.Exec(ctx, "INSERT INTO node_peer_status (node_id,public_key,last_handshake_at,rx_bytes,tx_bytes) VALUES ($1,'Astbc7xfIzi5K3VnumZWxLcEzVnAp4Qgm8FBJkE5pr4=',$2,0,0)", sb, now); e != nil {
		t.Fatalf("seed primary metrics: %v", e)
	}

	view, err := svc.GetHubSetView(ctx, org)
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if len(view.Members) != 2 || view.Members[0].NodeID != pr || view.Members[0].Role != "primary" || view.Members[1].Role != "standby" {
		t.Fatalf("ordered members with role (primary=members[0]), got %+v", view.Members)
	}
	// IDLE-but-reporting primary → metrics PRESENT with zeroes (an honest idle link).
	if view.Members[0].Metrics == nil || view.Members[0].Metrics.RxBytes != 0 {
		t.Fatalf("an idle-but-reporting member must have metrics (rx/tx=0 is honest), got %+v", view.Members[0].Metrics)
	}
	// NOT-reporting standby → metrics NIL (absent ≠ zeroes — a not-reporting link is a different truth).
	if view.Members[1].Metrics != nil {
		t.Fatalf("a NOT-reporting member must have ABSENT metrics (nil), never zeroes-as-data, got %+v", view.Members[1].Metrics)
	}
	if view.Generation <= 0 {
		t.Fatalf("the generation (version tag) must be served, got %d", view.Generation)
	}
}

// TestReconcileHubSetMembershipAudit — S8.6 REDUCE #4 (membership as its own event, condition 1b): a
// CONFIGURED change (a gateway leaving the pinned set — the unbind/delete membership event) bumps the
// generation AND audits hub_set.membership, DISTINCT from a promotion/failback. An unchanged reconcile
// neither bumps nor re-audits (no idle tick eroding the fence).
func TestReconcileHubSetMembershipAudit(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	org := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,'O',$2)", org, "ma-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM nodes WHERE org_id=$1", org)
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id=$1", org)
	})
	site := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'s')", site, org); e != nil {
		t.Fatalf("seed site: %v", e)
	}
	g1, g2 := uuid.New(), uuid.New()
	mk := func(id uuid.UUID, name, key string, prio int) {
		if _, e := pool.Exec(ctx, "INSERT INTO nodes (id,org_id,name,cert_serial,site_id,wg_public_key,endpoint,hub_priority) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
			id, org, name, "cs-"+id.String()[:8], site, key, "e:51820", prio); e != nil {
			t.Fatalf("seed %s: %v", name, e)
		}
	}
	mk(g1, "g1", "PwbD2C7DxRQtXmpFkZ2Dlb0sDx0sOlc6xoZSkw3D16s=", 1)
	mk(g2, "g2", "5Di08LsTWbS8MfB626cjFTO56X9FTOJbjJX4mcHaAZk=", 2)

	svc := NewService(pool, nil, nil)
	hs1, e := svc.ReconcileHubSet(ctx, org) // configured=[g1,g2] — the first membership event
	if e != nil {
		t.Fatalf("reconcile 1: %v", e)
	}
	if len(hs1.Configured) != 2 || hs1.Configured[0] != g1 {
		t.Fatalf("configured must be [g1,g2], got %v", hs1.Configured)
	}
	membershipAudits := func() int {
		var n int
		_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM audit_logs WHERE org_id=$1 AND action='hub_set.membership'", org).Scan(&n)
		return n
	}
	if membershipAudits() != 1 {
		t.Fatalf("the first configured write must audit hub_set.membership once, got %d", membershipAudits())
	}

	// UNCHANGED reconcile → NO bump, NO new audit (the fence + audit both quiet).
	hs1b, _ := svc.ReconcileHubSet(ctx, org)
	if hs1b.Generation != hs1.Generation || membershipAudits() != 1 {
		t.Fatalf("an unchanged reconcile must not bump/re-audit, gen %d->%d audits=%d", hs1.Generation, hs1b.Generation, membershipAudits())
	}

	// MEMBERSHIP EVENT: g1 leaves the site (the unbind/delete effect on configured). Reconcile drops it.
	if _, e := pool.Exec(ctx, "UPDATE nodes SET site_id=NULL WHERE id=$1", g1); e != nil {
		t.Fatalf("unbind g1: %v", e)
	}
	hs2, e := svc.ReconcileHubSet(ctx, org)
	if e != nil {
		t.Fatalf("reconcile 2: %v", e)
	}
	if len(hs2.Configured) != 1 || hs2.Configured[0] != g2 {
		t.Fatalf("after g1 leaves, configured must be [g2], got %v", hs2.Configured)
	}
	if hs2.Generation <= hs1.Generation {
		t.Fatalf("a membership change must bump the generation: %d -> %d", hs1.Generation, hs2.Generation)
	}
	if membershipAudits() != 2 {
		t.Fatalf("the membership change must audit hub_set.membership again (2 total), got %d", membershipAudits())
	}
	// The compiler + view AGREE with the new configured set — the derived active order is [g2].
	view, _ := svc.GetHubSetView(ctx, org)
	if len(view.Members) != 1 || view.Members[0].NodeID != g2 || view.Members[0].Role != "primary" {
		t.Fatalf("view must agree with the reconciled set: [g2 primary], got %+v", view.Members)
	}
}

// TestRevokedGatewayLeavesHubSet — S8.6 #4 (revoke-path): a REVOKED gateway drops from the hub-set candidate
// pool (the status='active' filter on ListSiteGatewaysForOrg) and RevokeNode's ReconcileHubSet trigger makes
// the drop durable. Revoking the PRIMARY (the loudest case — the org's active transit hub itself) removes it
// from configured, promotes the standby to the active head via the ORDINARY derivation (no blackhole), bumps
// the generation, and audits hub_set.membership. "Revoked but still electable as the org's transit hub" —
// the promise-contradiction at the topology tier — is closed.
func TestRevokedGatewayLeavesHubSet(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	org := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,'O',$2)", org, "rv-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM nodes WHERE org_id=$1", org)
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id=$1", org)
	})
	site := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'s')", site, org); e != nil {
		t.Fatalf("seed site: %v", e)
	}
	primary, standby := uuid.New(), uuid.New()
	mk := func(id uuid.UUID, name, key string, prio int) {
		if _, e := pool.Exec(ctx, "INSERT INTO nodes (id,org_id,name,cert_serial,site_id,wg_public_key,endpoint,hub_priority) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
			id, org, name, "cs-"+id.String()[:8], site, key, "e:51820", prio); e != nil {
			t.Fatalf("seed %s: %v", name, e)
		}
	}
	mk(primary, "primary", "v7uiptQLneLIoUp7JTnk9TFlyfwloQfSQB/Iey6Vt6k=", 1)
	mk(standby, "standby", "DyDCCz0F5Q7z9eZr3HPOXPV2dnNw6JKELtc6Adu4IEo=", 2)

	svc := NewService(pool, nil, nil)
	hs1, e := svc.ReconcileHubSet(ctx, org) // configured=[primary, standby]
	if e != nil {
		t.Fatalf("reconcile 1: %v", e)
	}
	if len(hs1.Configured) != 2 || hs1.Active()[0] != primary {
		t.Fatalf("configured must be [primary, standby], got %v", hs1.Configured)
	}
	membershipAudits := func() int {
		var n int
		_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM audit_logs WHERE org_id=$1 AND action='hub_set.membership'", org).Scan(&n)
		return n
	}

	// REVOKE THE PRIMARY (the active transit hub). It drops from ListSiteGatewaysForOrg (status='active') —
	// this is what RevokeNode's trigger reconciles against.
	if _, e := pool.Exec(ctx, "UPDATE nodes SET status='revoked' WHERE id=$1", primary); e != nil {
		t.Fatalf("revoke primary: %v", e)
	}
	hs2, e := svc.ReconcileHubSet(ctx, org) // the RevokeNode trigger's effect
	if e != nil {
		t.Fatalf("reconcile 2: %v", e)
	}
	if len(hs2.Configured) != 1 || hs2.Configured[0] != standby {
		t.Fatalf("a revoked primary must leave configured; the standby becomes the set, got %v", hs2.Configured)
	}
	if hs2.Active()[0] != standby {
		t.Fatalf("the standby must be the NEW active primary (promotion-shaped, no blackhole), got %v", hs2.Active())
	}
	if hs2.Generation <= hs1.Generation {
		t.Fatalf("a revoked-gateway membership change must bump the generation: %d -> %d", hs1.Generation, hs2.Generation)
	}
	if membershipAudits() != 2 {
		t.Fatalf("the revoke membership change must audit hub_set.membership (2 total), got %d", membershipAudits())
	}
	// The view agrees — the revoked primary is GONE, the standby is primary (no ghost hub candidate).
	view, _ := svc.GetHubSetView(ctx, org)
	if len(view.Members) != 1 || view.Members[0].NodeID != standby {
		t.Fatalf("the view must show only the live standby as primary, got %+v", view.Members)
	}
}

// hubTestOrg seeds an org + site + N pinned active gateways and returns the pool, svc, org, and node ids.
func hubTestOrg(t *testing.T, prefix string, keys ...string) (*pgxpool.Pool, *Service, uuid.UUID, []uuid.UUID) {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	org := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,'O',$2)", org, prefix+"-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM nodes WHERE org_id=$1", org)
		_, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id=$1", org)
	})
	site := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'s')", site, org); e != nil {
		t.Fatalf("seed site: %v", e)
	}
	ids := make([]uuid.UUID, len(keys))
	for i, key := range keys {
		id := uuid.New()
		ids[i] = id
		if _, e := pool.Exec(ctx, "INSERT INTO nodes (id,org_id,name,cert_serial,site_id,wg_public_key,endpoint,hub_priority) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
			id, org, "gw"+key, "cs-"+id.String()[:8], site, key, "e:51820", i+1); e != nil {
			t.Fatalf("seed %s: %v", key, e)
		}
	}
	return pool, NewService(pool, nil, nil), org, ids
}

func hubMembershipAuditCount(t *testing.T, pool *pgxpool.Pool, org uuid.UUID) int {
	t.Helper()
	var n int
	_ = pool.QueryRow(context.Background(), "SELECT COUNT(*) FROM audit_logs WHERE org_id=$1 AND action='hub_set.membership'", org).Scan(&n)
	return n
}

// TestFailoverCorrectorHealsConfigured — S8.6 #4/#5 REDUCE red: a gateway leaving the site (the DeleteSite/
// unbind membership event) is healed by the failover tick's CONFIGURED CORRECTOR within ONE tick, even with
// NO reconcile trigger fired — configured shrinks, the generation bumps, a hub_set.membership audit lands.
func TestFailoverCorrectorHealsConfigured(t *testing.T) {
	ctx := context.Background()
	pool, svc, org, ids := hubTestOrg(t, "corr", "H120EdakQ4xkGL5TYkYnFY7DZcGhIHZd1pvgSeesz78=", "xsmeCo1KZBjyFjpQ+kXWZrUttF5rwWYWRTUhQPHVIsA=")
	a, b := ids[0], ids[1]
	if _, e := svc.ReconcileHubSet(ctx, org); e != nil { // configured=[a,b]
		t.Fatalf("reconcile: %v", e)
	}
	before := hubMembershipAuditCount(t, pool, org)

	// A leaves the site (DeleteSite cascade / unbind effect) — NO reconcile trigger fired here.
	if _, e := pool.Exec(ctx, "UPDATE nodes SET site_id=NULL WHERE id=$1", a); e != nil {
		t.Fatalf("unbind a: %v", e)
	}
	hs0, _ := svc.GetHubSet(ctx, org)
	// ONE failover tick — the corrector re-derives configured from the live election.
	if e := svc.failoverOrg(ctx, org, time.Now()); e != nil {
		t.Fatalf("tick: %v", e)
	}
	hs1, _ := svc.GetHubSet(ctx, org)
	if len(hs1.Configured) != 1 || hs1.Configured[0] != b {
		t.Fatalf("the corrector must heal configured to [b] within one tick, got %v", hs1.Configured)
	}
	if hs1.Generation <= hs0.Generation {
		t.Fatalf("the heal must bump the generation: %d -> %d", hs0.Generation, hs1.Generation)
	}
	if hubMembershipAuditCount(t, pool, org) != before+1 {
		t.Fatalf("the corrector must audit hub_set.membership once, got %d (was %d)", hubMembershipAuditCount(t, pool, org), before)
	}
}

// TestGetHubSetViewFiltersPhantom — S8.6 #3 red: GetHubSetView derive-then-filters against LIVE gateways, so
// a configured member no longer a live gateway (revoked, before any corrector tick) is NOT shown — never as
// the primary the data plane has failed away from. The store still names it; the VIEW filters it.
func TestGetHubSetViewFiltersPhantom(t *testing.T) {
	ctx := context.Background()
	pool, svc, org, ids := hubTestOrg(t, "phan", "H120EdakQ4xkGL5TYkYnFY7DZcGhIHZd1pvgSeesz78=", "xsmeCo1KZBjyFjpQ+kXWZrUttF5rwWYWRTUhQPHVIsA=")
	a, b := ids[0], ids[1]
	if _, e := svc.ReconcileHubSet(ctx, org); e != nil { // configured=[a,b], a is primary
		t.Fatalf("reconcile: %v", e)
	}
	// Revoke A (drops from ListSiteGatewaysForOrg) WITHOUT reconciling — the swallowed-trigger window.
	if _, e := pool.Exec(ctx, "UPDATE nodes SET status='revoked' WHERE id=$1", a); e != nil {
		t.Fatalf("revoke a: %v", e)
	}
	hs, _ := svc.GetHubSet(ctx, org)
	if len(hs.Configured) != 2 { // the STORE still names the phantom (not reconciled)
		t.Fatalf("precondition: configured must still be [a,b] in the store, got %v", hs.Configured)
	}
	view, err := svc.GetHubSetView(ctx, org)
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if len(view.Members) != 1 || view.Members[0].NodeID != b || view.Members[0].Role != "primary" {
		t.Fatalf("the view must FILTER the revoked phantom a and show only live b as primary, got %+v", view.Members)
	}
	_ = a
}

// TestFailoverCorrectorIdempotent — S8.6 condition (d): a stable world (configured correct, nothing to
// demote) changes neither field, so repeated ticks write NOTHING — no generation churn under the new writer.
func TestFailoverCorrectorIdempotent(t *testing.T) {
	ctx := context.Background()
	pool, svc, org, ids := hubTestOrg(t, "idem", "H120EdakQ4xkGL5TYkYnFY7DZcGhIHZd1pvgSeesz78=", "xsmeCo1KZBjyFjpQ+kXWZrUttF5rwWYWRTUhQPHVIsA=")
	if _, e := svc.ReconcileHubSet(ctx, org); e != nil {
		t.Fatalf("reconcile: %v", e)
	}
	// Both gateways fresh (recent handshake) → nothing to demote, configured already correct.
	now := time.Now()
	for _, key := range []string{"H120EdakQ4xkGL5TYkYnFY7DZcGhIHZd1pvgSeesz78=", "xsmeCo1KZBjyFjpQ+kXWZrUttF5rwWYWRTUhQPHVIsA="} {
		if _, e := pool.Exec(ctx, "INSERT INTO node_peer_status (node_id,public_key,last_handshake_at) VALUES ($1,$2,$3)", ids[0], key, now); e != nil {
			t.Fatalf("seed freshness: %v", e)
		}
	}
	g0, _ := svc.GetHubSet(ctx, org)
	for i := 0; i < 3; i++ {
		if e := svc.failoverOrg(ctx, org, time.Now()); e != nil {
			t.Fatalf("tick %d: %v", i, e)
		}
	}
	g1, _ := svc.GetHubSet(ctx, org)
	if g1.Generation != g0.Generation {
		t.Fatalf("a stable world must not churn the generation across ticks: %d -> %d", g0.Generation, g1.Generation)
	}
}

// TestDevicePeerWidenedAcrossHubSet — WF-A D-WFA-5b: a device assigned to a hub-set member is HOSTED on
// EVERY member's DesiredState, so the promoted hub already knows it when the re-homed dial lands. On the
// ACTIVE PRIMARY the device peer carries its /32; on a STANDBY it is WARM (empty AllowedIPs — pubkey known,
// the /32 rides the promotion recompile). Without the widening the standby lacks the device (node_id-scoped)
// → the post-promotion dial would fail → (C) a half-fix.
func TestDevicePeerWidenedAcrossHubSet(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	org := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,'O',$2)", org, "wd-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, "DELETE FROM devices WHERE org_id=$1", org)
		_, _ = pool.Exec(bg, "DELETE FROM users WHERE id IN (SELECT user_id FROM devices WHERE org_id=$1)", org)
		_, _ = pool.Exec(bg, "DELETE FROM nodes WHERE org_id=$1", org)
		_, _ = pool.Exec(bg, "DELETE FROM organizations WHERE id=$1", org)
	})
	site := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'s')", site, org); e != nil {
		t.Fatalf("seed site: %v", e)
	}
	g1, g2 := uuid.New(), uuid.New()
	mk := func(id uuid.UUID, name, key string, prio int) {
		if _, e := pool.Exec(ctx, "INSERT INTO nodes (id,org_id,name,cert_serial,site_id,wg_public_key,endpoint,hub_priority) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
			id, org, name, "cs-"+id.String()[:8], site, key, "e:51820", prio); e != nil {
			t.Fatalf("seed %s: %v", name, e)
		}
	}
	mk(g1, "g1", "PwbD2C7DxRQtXmpFkZ2Dlb0sDx0sOlc6xoZSkw3D16s=", 1) // primary
	mk(g2, "g2", "5Di08LsTWbS8MfB626cjFTO56X9FTOJbjJX4mcHaAZk=", 2) // standby
	usr, dev := uuid.New(), uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO users (id,email,name) VALUES ($1,$2,'U')", usr, usr.String()+"@t"); e != nil {
		t.Fatalf("seed user: %v", e)
	}
	// The peer query gates on current membership (offboarding parity) — seed it.
	if _, e := pool.Exec(ctx, "INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')", org, usr); e != nil {
		t.Fatalf("seed membership: %v", e)
	}
	// The device is assigned to g1 (node_id=g1). Its /32 is 10.99.0.2.
	if _, e := pool.Exec(ctx, "INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip) VALUES ($1, $2, $3, $4, 'laptop', 'b/eRpG2AcImXjRtZlbNUKdUzFDeN5yt3OnT3qq2OZKk=', '10.99.0.2')",
		dev, org, usr, g1); e != nil {
		t.Fatalf("seed device: %v", e)
	}

	svc := NewService(pool, nil, nil)
	if _, e := svc.ReconcileHubSet(ctx, org); e != nil { // configured=[g1,g2], g1 the active primary
		t.Fatalf("reconcile hub set: %v", e)
	}

	devPeer := func(ds DesiredState) (present bool, allowed []string) {
		for _, p := range ds.Peers {
			if p.PublicKey == "b/eRpG2AcImXjRtZlbNUKdUzFDeN5yt3OnT3qq2OZKk=" {
				return true, p.AllowedIPs
			}
		}
		return false, nil
	}

	// ACTIVE PRIMARY (g1): the device peer present WITH its /32.
	ds1, e := svc.DesiredState(ctx, sqlc.Node{ID: g1, OrgID: org, SiteID: pgtype.UUID{Bytes: site, Valid: true}})
	if e != nil {
		t.Fatalf("DesiredState(g1): %v", e)
	}
	if present, allowed := devPeer(ds1); !present || len(allowed) != 1 || allowed[0] != "10.99.0.2/32" {
		t.Fatalf("primary g1 must host the device with its /32, got present=%v allowed=%v", present, allowed)
	}

	// STANDBY (g2): the device peer PRESENT (widened) but WARM — empty AllowedIPs.
	ds2, e := svc.DesiredState(ctx, sqlc.Node{ID: g2, OrgID: org, SiteID: pgtype.UUID{Bytes: site, Valid: true}})
	if e != nil {
		t.Fatalf("DesiredState(g2): %v", e)
	}
	present, allowed := devPeer(ds2)
	if !present {
		t.Fatal("standby g2 must HOST the device peer (widening) so a post-promotion dial's handshake completes")
	}
	if len(allowed) != 0 {
		t.Fatalf("standby g2 must hold the device WARM (empty AllowedIPs); the /32 rides promotion, got %v", allowed)
	}
}

// TestOVPNDeviceNeverAWireGuardPeerAcrossHubSet is the WF-OVPN-10 blast-radius red: a KEYLESS (OpenVPN)
// device homed to a hub-set member must NEVER appear as a WireGuard peer on ANY member's DesiredState —
// an empty PublicKey renders `PublicKey = ` and makes `wg syncconf` reject the ENTIRE config, bricking
// the member's whole WG reconcile (one OpenVPN client bricking the WireGuard fleet). The guard now lives
// at the SOURCE (ListActiveWireGuardPeersForNode's `public_key <> ”`), consumed by both the per-node path
// and widenedDevicePeers. The red pins BOTH halves: (a) no empty-pubkey peer anywhere, AND (b) the OVPN
// device's /32 is still delivered — via the OVPN roster (assigned_ip) — so the B1 data half is unaffected.
func TestOVPNDeviceNeverAWireGuardPeerAcrossHubSet(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	org := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,'O',$2)", org, "ov-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, "DELETE FROM devices WHERE org_id=$1", org)
		_, _ = pool.Exec(bg, "DELETE FROM users WHERE id IN (SELECT user_id FROM devices WHERE org_id=$1)", org)
		_, _ = pool.Exec(bg, "DELETE FROM nodes WHERE org_id=$1", org)
		_, _ = pool.Exec(bg, "DELETE FROM sites WHERE org_id=$1", org)
		_, _ = pool.Exec(bg, "DELETE FROM organizations WHERE id=$1", org)
	})
	site := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'s')", site, org); e != nil {
		t.Fatalf("seed site: %v", e)
	}
	g1, g2 := uuid.New(), uuid.New()
	mk := func(id uuid.UUID, name, key string, prio int) {
		if _, e := pool.Exec(ctx, "INSERT INTO nodes (id,org_id,name,cert_serial,site_id,wg_public_key,endpoint,hub_priority) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
			id, org, name, "cs-"+id.String()[:8], site, key, "e:51820", prio); e != nil {
			t.Fatalf("seed %s: %v", name, e)
		}
	}
	mk(g1, "g1", "PwbD2C7DxRQtXmpFkZ2Dlb0sDx0sOlc6xoZSkw3D16s=", 1) // active primary
	mk(g2, "g2", "5Di08LsTWbS8MfB626cjFTO56X9FTOJbjJX4mcHaAZk=", 2) // standby
	usr := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO users (id,email,name) VALUES ($1,$2,'U')", usr, usr.String()+"@t"); e != nil {
		t.Fatalf("seed user: %v", e)
	}
	// review #1: the OVPN roster now requires the owner be an ACTIVE, CURRENT member — seed the membership.
	if _, e := pool.Exec(ctx, "INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')", org, usr); e != nil {
		t.Fatalf("seed membership: %v", e)
	}
	// A WireGuard device (keyed) AND an OpenVPN device (keyless, public_key='', transport='openvpn'),
	// BOTH homed to the active primary g1.
	wgDev, ovDev := uuid.New(), uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip) VALUES ($1, $2, $3, $4, 'wg-laptop', '8NSMqx2d2Xa7o7u83pq7bH4gdfMzIEpoXlzQulP8Ed0=', '10.99.0.2')",
		wgDev, org, usr, g1); e != nil {
		t.Fatalf("seed wg device: %v", e)
	}
	if _, e := pool.Exec(ctx, "INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,transport) VALUES ($1, $2, $3, $4, 'ovpn-mac', '', '10.99.0.6', 'openvpn')",
		ovDev, org, usr, g1); e != nil {
		t.Fatalf("seed ovpn device: %v", e)
	}

	svc := NewService(pool, nil, nil)
	if _, e := svc.ReconcileHubSet(ctx, org); e != nil {
		t.Fatalf("reconcile hub set: %v", e)
	}

	// (a) NEITHER member's DesiredState may carry an empty-PublicKey peer (the config-brick vector), and
	// the keyed WG device must still be hosted (the fix drops keyless ONLY).
	for _, n := range []struct {
		id   uuid.UUID
		name string
	}{{g1, "g1"}, {g2, "g2"}} {
		ds, e := svc.DesiredState(ctx, sqlc.Node{ID: n.id, OrgID: org, SiteID: pgtype.UUID{Bytes: site, Valid: true}})
		if e != nil {
			t.Fatalf("DesiredState(%s): %v", n.name, e)
		}
		wgHosted := false
		for _, p := range ds.Peers {
			if p.PublicKey == "" {
				t.Fatalf("%s hosts an EMPTY-PublicKey peer — this bricks `wg syncconf` for the whole interface (WF-OVPN-10)", n.name)
			}
			if p.PublicKey == "8NSMqx2d2Xa7o7u83pq7bH4gdfMzIEpoXlzQulP8Ed0=" {
				wgHosted = true
			}
		}
		if !wgHosted {
			t.Fatalf("%s must still host the KEYED WireGuard device (the fix excludes keyless devices only)", n.name)
		}
	}

	// (b) the OVPN device's /32 is still DELIVERED — via the OVPN roster on its home node — so the B1 data
	// half is unaffected (it reaches the data plane by assigned_ip, never the WG peer list).
	roster, e := sqlc.New(pool).ListActiveOVPNDevicesForNode(ctx, g1)
	if e != nil {
		t.Fatalf("ovpn roster: %v", e)
	}
	found := false
	for _, r := range roster {
		if r.AssignedIp != nil && *r.AssignedIp == "10.99.0.6" {
			found = true
		}
	}
	if !found {
		t.Fatal("the OpenVPN device's /32 must still be delivered via the OVPN roster (assigned_ip) — B1 data half intact")
	}
}

// TestDeviceDialAuthAndDerivation — WF-A D-WFA-6 cond 2: a device fetches ONLY its own dial. The org-scoped
// GetDevice is the cross-ORG guard; the owner check is the cross-DEVICE guard. A non-owner (or wrong-org)
// caller gets device_not_found (no-oracle). The owner gets the ACTIVE-HUB dial (endpoint+pubkey of the
// active primary) — the re-home target — because the device's node is a hub-set member.
func TestDeviceDialAuthAndDerivation(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	org := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,'O',$2)", org, "dd-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, "DELETE FROM devices WHERE org_id=$1", org)
		_, _ = pool.Exec(bg, "DELETE FROM users WHERE email LIKE $1", "dd-%")
		_, _ = pool.Exec(bg, "DELETE FROM nodes WHERE org_id=$1", org)
		_, _ = pool.Exec(bg, "DELETE FROM organizations WHERE id=$1", org)
	})
	site := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'s')", site, org); e != nil {
		t.Fatalf("seed site: %v", e)
	}
	g1, g2 := uuid.New(), uuid.New()
	mk := func(id uuid.UUID, name, key string, prio int) {
		if _, e := pool.Exec(ctx, "INSERT INTO nodes (id,org_id,name,cert_serial,site_id,wg_public_key,endpoint,hub_priority) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
			id, org, name, "cs-"+id.String()[:8], site, key, name+".example:51820", prio); e != nil {
			t.Fatalf("seed %s: %v", name, e)
		}
	}
	mk(g1, "g1", "PwbD2C7DxRQtXmpFkZ2Dlb0sDx0sOlc6xoZSkw3D16s=", 1) // active primary
	mk(g2, "g2", "5Di08LsTWbS8MfB626cjFTO56X9FTOJbjJX4mcHaAZk=", 2) // standby
	owner, other, dev := uuid.New(), uuid.New(), uuid.New()
	for _, u := range []uuid.UUID{owner, other} {
		if _, e := pool.Exec(ctx, "INSERT INTO users (id,email,name) VALUES ($1,$2,'U')", u, "dd-"+u.String()[:8]+"@t"); e != nil {
			t.Fatalf("seed user: %v", e)
		}
	}
	// The device is assigned to g2 (a standby member) but OWNED by `owner`.
	if _, e := pool.Exec(ctx, "INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip) VALUES ($1, $2, $3, $4, 'laptop', 'b/eRpG2AcImXjRtZlbNUKdUzFDeN5yt3OnT3qq2OZKk=', '10.99.0.2')",
		dev, org, owner, g2); e != nil {
		t.Fatalf("seed device: %v", e)
	}

	svc := NewService(pool, nil, nil)
	if _, e := svc.ReconcileHubSet(ctx, org); e != nil { // configured=[g1,g2], g1 the active primary
		t.Fatalf("reconcile hub set: %v", e)
	}

	// OWNER → the ACTIVE PRIMARY's dial (g1), even though the device is assigned to g2 (the re-home target).
	ep, pk, derived, e := svc.DeviceDial(ctx, org, dev, owner)
	if e != nil || !derived || ep != "g1.example:51820" || pk != "PwbD2C7DxRQtXmpFkZ2Dlb0sDx0sOlc6xoZSkw3D16s=" {
		t.Fatalf("owner must get the ACTIVE-PRIMARY dial, got ep=%q pk=%q derived=%v err=%v", ep, pk, derived, e)
	}

	// CROSS-DEVICE: a different user must NOT fetch this device's dial → device_not_found (no-oracle).
	if _, _, _, e := svc.DeviceDial(ctx, org, dev, other); e == nil {
		t.Fatal("cross-device: a non-owner must be refused (device_not_found), got nil error")
	}

	// CROSS-ORG: a device id under a different org → not found (the org-scoped GetDevice guard).
	if _, _, _, e := svc.DeviceDial(ctx, uuid.New(), dev, owner); e == nil {
		t.Fatal("cross-org: a device under a different org must be refused, got nil error")
	}

	// PENDING (review #3): a not-yet-active device has no gateway peer — its dial is refused (no-oracle),
	// so the API never contradicts the data-plane's "peers only when active" rule. Same device_not_found.
	pend := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,status) VALUES ($1, $2, $3, $4, 'pending-laptop', 'QmlnJHSZOgd/KJmhdIsavEMbdDoh6QwB9P2wufHjoQI=', '10.99.0.3', 'pending')",
		pend, org, owner, g2); e != nil {
		t.Fatalf("seed pending device: %v", e)
	}
	if _, _, _, e := svc.DeviceDial(ctx, org, pend, owner); e == nil {
		t.Fatal("pending: a non-active device's dial must be refused, got nil error")
	}
}

// TestOVPNWidenAndRemotesParityAcrossHubSet is the WF-OVPN-9 red: the OVPN roster is WIDENED across all
// hub-set members (a device homed on g1 has its CCD on g2 too — warm), and OVPNRemotes lists the SAME
// members in priority order — one hub-set authority, two consumers. Parity: the profile's remote node set
// equals the set of members whose widened roster hosts the device. A non-hub-set node gets nil (single remote).
func TestOVPNWidenAndRemotesParityAcrossHubSet(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	org := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,'O',$2)", org, "ow-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, "DELETE FROM devices WHERE org_id=$1", org)
		_, _ = pool.Exec(bg, "DELETE FROM memberships WHERE org_id=$1", org)
		_, _ = pool.Exec(bg, "DELETE FROM users WHERE id IN (SELECT user_id FROM memberships WHERE org_id=$1)", org)
		_, _ = pool.Exec(bg, "DELETE FROM nodes WHERE org_id=$1", org)
		_, _ = pool.Exec(bg, "DELETE FROM sites WHERE org_id=$1", org)
		_, _ = pool.Exec(bg, "DELETE FROM organizations WHERE id=$1", org)
	})
	site := uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'s')", site, org); e != nil {
		t.Fatalf("seed site: %v", e)
	}
	g1, g2 := uuid.New(), uuid.New()
	mk := func(id uuid.UUID, name, host string, prio int) {
		if _, e := pool.Exec(ctx, "INSERT INTO nodes (id,org_id,name,cert_serial,site_id,wg_public_key,endpoint,hub_priority) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
			// ⛔ A DERIVED, REAL-SHAPED KEY. `"K"+name` produced a 3-character placeholder, which
			// ListSiteGatewaysForOrg now filters (`^[A-Za-z0-9+/]{43}=`) — so the gateway vanished from the
			// hub set and this test read as a product failure. A computed key is the member of this class a
			// literal sweep cannot see.
			id, org, name, "cs-"+id.String()[:8], site, testWGKey(name), host, prio); e != nil {
			t.Fatalf("seed %s: %v", name, e)
		}
	}
	mk(g1, "g1", "h1.example:51820", 1) // active primary
	mk(g2, "g2", "h2.example:51820", 2) // standby
	usr, dev := uuid.New(), uuid.New()
	if _, e := pool.Exec(ctx, "INSERT INTO users (id,email,name) VALUES ($1,$2,'U')", usr, usr.String()+"@t"); e != nil {
		t.Fatalf("seed user: %v", e)
	}
	if _, e := pool.Exec(ctx, "INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')", org, usr); e != nil {
		t.Fatalf("seed membership: %v", e)
	}
	// The OVPN device is homed on g1.
	if _, e := pool.Exec(ctx, "INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,transport) VALUES ($1,$2,$3,$4,'ov',''::text,'10.99.0.6','openvpn')",
		dev, org, usr, g1); e != nil {
		t.Fatalf("seed ovpn device: %v", e)
	}

	svc := NewService(pool, nil, nil)
	if _, e := svc.ReconcileHubSet(ctx, org); e != nil {
		t.Fatalf("reconcile hub set: %v", e)
	}

	rosterHas := func(nodeID uuid.UUID) bool {
		ds, e := svc.DesiredState(ctx, sqlc.Node{ID: nodeID, OrgID: org, SiteID: pgtype.UUID{Bytes: site, Valid: true}})
		if e != nil {
			t.Fatalf("DesiredState: %v", e)
		}
		for _, c := range ds.OVPNClients {
			if c.CommonName == dev.String() {
				return true
			}
		}
		return false
	}

	// WIDENED: the device's CCD is on BOTH g1 (home) and g2 (widened warm) — so a multi-remote failover to g2 accepts.
	if !rosterHas(g1) {
		t.Fatal("g1 (home) must host the OVPN device in its roster")
	}
	if !rosterHas(g2) {
		t.Fatal("WF-OVPN-9: g2 (hub-set member) must host the device's CCD too (widened) — else failover refuses")
	}

	// REMOTES: OVPNRemotes(g1) lists BOTH members' hosts in priority order — the SAME set the roster widened to.
	remotes, e := svc.OVPNRemotes(ctx, org, g1)
	if e != nil {
		t.Fatalf("OVPNRemotes: %v", e)
	}
	if len(remotes) != 2 || remotes[0] != "h1.example" || remotes[1] != "h2.example" {
		t.Fatalf("remotes must be both members in priority order [h1,h2]; got %v", remotes)
	}

	// NON-hub-set node → nil remotes (single remote; zero-config golden).
	if r, _ := svc.OVPNRemotes(ctx, org, uuid.New()); r != nil {
		t.Fatalf("a non-hub-set node must get nil remotes (single remote); got %v", r)
	}
}

// testWGKey derives a WELL-FORMED WireGuard public key from a seed — 32 bytes, base64, 43 chars plus '='.
//
// ⛔ FIXTURES MUST BE SHAPED LIKE THE THING THEY STAND IN FOR. A placeholder the DATABASE accepts and the
// DATA PLANE rejects is not a fixture, it is a second product with different rules — and it hid a real
// defect until an agent enrolled against a real interface and left a gateway with ZERO peers (S15.3).
func testWGKey(seed string) string {
	sum := sha256.Sum256([]byte("tunnex-test-" + seed))
	return base64.StdEncoding.EncodeToString(sum[:])
}
