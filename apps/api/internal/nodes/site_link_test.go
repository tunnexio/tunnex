package nodes

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// TestPushedHashMatchesServedForRoutedGateway — S8.2 review #1 fix (was a MERGE-BLOCKER): the pushed-hash
// baseline and the served artifact are finalized the SAME way (single source), so a route-carrying
// ENFORCING site gateway compares CLEAN — no permanent false silent_desync. Before the fix the served
// artifact bumped to v5 (routes present) while the pushed hash stayed v4 (route-less); Version is
// in-hash → pushed != applied forever. This is the routed-but-dropped scenario (routes, no grant).
func TestPushedHashMatchesServedForRoutedGateway(t *testing.T) {
	svc := &Service{policy: fakeProvider{}} // enterprise path (policy != nil)
	siteA, siteB := uuid.New(), uuid.New()
	nodeA := uuid.New()
	topo := siteTopology{
		gws: []sqlc.ListSiteGatewaysForOrgRow{
			{ID: nodeA, SiteID: pgtype.UUID{Bytes: siteA, Valid: true}, WgPublicKey: "/RLJQov+0n5q0hNM2/ZkqzUO/GFUcoziClpzUvI+5j4=", Endpoint: "a:51820"},
			{ID: uuid.New(), SiteID: pgtype.UUID{Bytes: siteB, Valid: true}, WgPublicKey: "jeuLUCD31rxHRxXujNPrQUQpEDbjfIXK3zj68octp1k="},
		},
		subnets: map[uuid.UUID][]string{siteA: {"10.1.0.0/24"}, siteB: {"10.2.0.0/24"}},
	}
	node := sqlc.Node{ID: nodeA, SiteID: pgtype.UUID{Bytes: siteA, Valid: true}}
	mkRouteless := func() *policyspec.Compiled { // route-less enforcing artifact (routed-but-dropped: no grant)
		return &policyspec.Compiled{Version: policyspec.RequiredVersion(policyspec.Compiled{Mode: "enforcing"}), NodeID: nodeA.String(), Mode: "enforcing"}
	}
	if mkRouteless().Version != 4 {
		t.Fatalf("precondition: a route-less enforcing artifact is v4, got %d", mkRouteless().Version)
	}
	served := svc.finalizeArtifact(topo, node, mkRouteless()) // what the agent applies
	if served.Version != 5 || len(served.Routes) == 0 {
		t.Fatalf("finalize must attach routes + bump to v5, got v%d routes=%d", served.Version, len(served.Routes))
	}
	applied := policyspec.CanonicalHash(*served)
	pushed := svc.pushedHash(topo, node, mkRouteless()) // finalized the SAME way
	if pushed != applied {
		t.Fatalf("#1: pushed(%s) must equal applied(%s) for a routed enforcing gateway — false desync", pushed, applied)
	}
}

// TestFinalizeAttachesDNSForwardsOutOfHash — S8.4 D1/D5: finalizeArtifact attaches the org DNS forwarding
// table onto a routed gateway, and it is OUT-of-hash — the pushed/applied hash is byte-identical with or
// without DNS (a DNS-only change never false-alarms silent_desync; every gateway carries the whole table).
func TestFinalizeAttachesDNSForwardsOutOfHash(t *testing.T) {
	svc := &Service{policy: fakeProvider{}}
	siteA, siteB, nodeA := uuid.New(), uuid.New(), uuid.New()
	base := siteTopology{
		gws: []sqlc.ListSiteGatewaysForOrgRow{
			{ID: nodeA, SiteID: pgtype.UUID{Bytes: siteA, Valid: true}, WgPublicKey: "/RLJQov+0n5q0hNM2/ZkqzUO/GFUcoziClpzUvI+5j4=", Endpoint: "a:51820"},
			{ID: uuid.New(), SiteID: pgtype.UUID{Bytes: siteB, Valid: true}, WgPublicKey: "jeuLUCD31rxHRxXujNPrQUQpEDbjfIXK3zj68octp1k="},
		},
		subnets: map[uuid.UUID][]string{siteA: {"10.1.0.0/24"}, siteB: {"10.2.0.0/24"}},
	}
	node := sqlc.Node{ID: nodeA, SiteID: pgtype.UUID{Bytes: siteA, Valid: true}}
	mkRouteless := func() *policyspec.Compiled {
		return &policyspec.Compiled{Version: policyspec.RequiredVersion(policyspec.Compiled{Mode: "enforcing"}), NodeID: nodeA.String(), Mode: "enforcing"}
	}
	withDNS := base
	withDNS.dnsForwards = []policyspec.DNSForward{{Domain: "corp.local", ResolverIP: "10.2.0.53"}}

	got := svc.finalizeArtifact(withDNS, node, mkRouteless())
	if len(got.DNSForwards) != 1 || got.DNSForwards[0].Domain != "corp.local" {
		t.Fatalf("finalize must attach the org DNS table onto the gateway, got %+v", got.DNSForwards)
	}
	// Out-of-hash: the finalized hash is identical with vs without DNS.
	noDNS := svc.finalizeArtifact(base, node, mkRouteless())
	if policyspec.CanonicalHash(*got) != policyspec.CanonicalHash(*noDNS) {
		t.Fatal("DNSForwards must be out-of-hash — attaching DNS changed the artifact hash (false-desync risk)")
	}
	if got.Version != noDNS.Version {
		t.Fatalf("DNSForwards must not bump the version; got v%d vs v%d", got.Version, noDNS.Version)
	}
}

// TestElectSiteHubIsTheOneElection — S8.3 D2: the hub designation the Node API projects (is_site_hub) reads
// electSiteHub, the SAME picker the site-link graph + health use — endpoint-bearing, lowest id, ties by id,
// nil when all NAT'd. siteTopoHasHub is exactly (electSiteHub != nil), so existence and designation never
// disagree (no second election in the UI, the overrule's point).
func TestElectSiteHubIsTheOneElection(t *testing.T) {
	lo, hi := uuid.New(), uuid.New()
	if lo.String() > hi.String() {
		lo, hi = hi, lo // ensure lo has the lower id
	}
	now := time.Now()
	// Two endpoint-bearing gateways (with keys) → the lower id wins (no pins, equal health → id tie-break).
	topo := siteTopology{gws: []sqlc.ListSiteGatewaysForOrgRow{
		{ID: hi, Endpoint: "b:51820", WgPublicKey: "xFpkJr76SJwtMLvFYqpt8o835n5B3v1Nqsppcn2q0sk="}, {ID: lo, Endpoint: "a:51820", WgPublicKey: "rlEFum3hee1UCCt3w/kH64Adf2O9RuuCqIlMa/XBen0="},
	}}
	hub := electSiteHub(topo, now)
	if hub == nil || hub.ID != lo {
		t.Fatalf("the endpoint-bearing lowest-id gateway must be the hub, got %+v", hub)
	}
	if !siteTopoHasHub(topo) {
		t.Fatal("siteTopoHasHub must agree with electSiteHub (one election)")
	}
	// A NAT'd gateway (no endpoint) is never the hub even with a lower id.
	topo.gws = []sqlc.ListSiteGatewaysForOrgRow{{ID: lo, WgPublicKey: "rlEFum3hee1UCCt3w/kH64Adf2O9RuuCqIlMa/XBen0="}, {ID: hi, Endpoint: "b:51820", WgPublicKey: "xFpkJr76SJwtMLvFYqpt8o835n5B3v1Nqsppcn2q0sk="}}
	if h := electSiteHub(topo, now); h == nil || h.ID != hi {
		t.Fatalf("a NAT'd gateway cannot be the hub; the endpoint-bearing one wins, got %+v", h)
	}
	// All NAT'd → no hub (B2 no-carrier), and siteTopoHasHub agrees.
	topo.gws = []sqlc.ListSiteGatewaysForOrgRow{{ID: lo, WgPublicKey: "rlEFum3hee1UCCt3w/kH64Adf2O9RuuCqIlMa/XBen0="}, {ID: hi, WgPublicKey: "xFpkJr76SJwtMLvFYqpt8o835n5B3v1Nqsppcn2q0sk="}}
	if electSiteHub(topo, now) != nil || siteTopoHasHub(topo) {
		t.Fatal("all-NAT'd → no hub (both electSiteHub and siteTopoHasHub must say so)")
	}
}

func TestSingleSiteTopologyHasNoSiteLinkTransit(t *testing.T) {
	site := uuid.New()
	topo := siteTopology{gws: []sqlc.ListSiteGatewaysForOrgRow{
		{ID: uuid.New(), SiteID: pgtype.UUID{Bytes: site, Valid: true}},
	}}
	if siteTopologyHasTransit(topo) {
		t.Fatal("a directly attached one-site topology must not require a site-link peer")
	}

	other := uuid.New()
	topo.gws = append(topo.gws, sqlc.ListSiteGatewaysForOrgRow{
		ID: uuid.New(), SiteID: pgtype.UUID{Bytes: other, Valid: true},
	})
	if !siteTopologyHasTransit(topo) {
		t.Fatal("two distinct sites must retain site-link transit health")
	}
}

// TestSiteLinkNoHubNoRoutes — S8.2 B2: no gateway has a public endpoint (all NAT'd) → no carrier, so
// siteLinkGraphFrom emits ZERO routes + ZERO peers (routes with no peer to carry them are the silent
// blackhole), and siteHubMissing flags the condition so it surfaces as site_hub_down.
func TestSiteLinkNoHubNoRoutes(t *testing.T) {
	siteA, siteB := uuid.New(), uuid.New()
	nodeA := uuid.New()
	topo := siteTopology{
		gws: []sqlc.ListSiteGatewaysForOrgRow{
			{ID: nodeA, SiteID: pgtype.UUID{Bytes: siteA, Valid: true}, WgPublicKey: "/RLJQov+0n5q0hNM2/ZkqzUO/GFUcoziClpzUvI+5j4="},      // no endpoint
			{ID: uuid.New(), SiteID: pgtype.UUID{Bytes: siteB, Valid: true}, WgPublicKey: "jeuLUCD31rxHRxXujNPrQUQpEDbjfIXK3zj68octp1k="}, // no endpoint
		},
		subnets: map[uuid.UUID][]string{siteA: {"10.1.0.0/24"}, siteB: {"10.2.0.0/24"}},
	}
	node := sqlc.Node{ID: nodeA, SiteID: pgtype.UUID{Bytes: siteA, Valid: true}}
	if peers, routes := siteLinkGraphFrom(topo, node); len(peers) != 0 || len(routes) != 0 {
		t.Fatalf("no hub → no peers + no routes (no silent blackhole), got peers=%d routes=%d", len(peers), len(routes))
	}
	if !siteHubMissing(siteTopoHasHub(topo), topo, node) {
		t.Fatal("no hub + remote subnets → siteHubMissing must be true (surfaces site_hub_down)")
	}
	topo.gws[1].Endpoint = "b.example:51820" // give one gateway an endpoint → a hub now exists
	if siteHubMissing(siteTopoHasHub(topo), topo, node) {
		t.Fatal("a hub exists → siteHubMissing must be false")
	}
}

// TestK8sHandoffGraphUsesLocalEdgePair proves the Kubernetes connector is not
// accidentally treated as a client edge merely because it shares a site. The
// client pool and service VIPs each have one crypto-routing owner; standby
// peers stay warm without an AllowedIPs route.
func TestK8sHandoffGraphUsesLocalEdgePair(t *testing.T) {
	site := uuid.New()
	connector, primary, standby, ordinary := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	row := func(id uuid.UUID, key, endpoint string) sqlc.ListSiteGatewaysForOrgRow {
		return sqlc.ListSiteGatewaysForOrgRow{ID: id, SiteID: pgtype.UUID{Bytes: site, Valid: true}, WgPublicKey: key, Endpoint: endpoint}
	}
	topo := siteTopology{
		// The connector is deliberately first to prove it is excluded from the
		// client-facing local edge pair even if stale hub membership contains it.
		hubMembers: []sqlc.ListSiteGatewaysForOrgRow{
			row(connector, "connector-key", "172.31.85.85:51820"),
			row(primary, "primary-key", "54.153.246.169:51820"),
			row(standby, "standby-key", "13.55.222.136:51820"),
		},
		poolCIDR: "10.99.0.0/16",
		k8sConnectors: map[uuid.UUID]k8sConnector{
			connector: {nodeID: connector, siteID: site, publicKey: "connector-key", endpoint: "172.31.85.85:51820", vips: []string{"100.64.0.2/32", "100.64.0.3/32"}},
		},
	}
	peerByKey := func(peers []Peer, key string) (Peer, bool) {
		for _, p := range peers {
			if p.PublicKey == key {
				return p, true
			}
		}
		return Peer{}, false
	}

	connectorPeers, connectorRoutes := k8sHandoffGraph(topo, sqlc.Node{ID: connector, SiteID: pgtype.UUID{Bytes: site, Valid: true}})
	if p, ok := peerByKey(connectorPeers, "primary-key"); !ok || len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "10.99.0.0/16" {
		t.Fatalf("connector must crypto-route the client pool only through the local primary, got %+v", connectorPeers)
	}
	if p, ok := peerByKey(connectorPeers, "standby-key"); !ok || len(p.AllowedIPs) != 0 {
		t.Fatalf("connector standby must remain warm without a route, got %+v", connectorPeers)
	}
	if _, ok := peerByKey(connectorPeers, "connector-key"); ok || len(connectorRoutes) != 1 || connectorRoutes[0].DstCIDR != "10.99.0.0/16" {
		t.Fatalf("connector must not self-peer and must install only the pool return route, peers=%+v routes=%+v", connectorPeers, connectorRoutes)
	}

	primaryPeers, primaryRoutes := k8sHandoffGraph(topo, sqlc.Node{ID: primary, SiteID: pgtype.UUID{Bytes: site, Valid: true}})
	if p, ok := peerByKey(primaryPeers, "connector-key"); !ok || len(p.AllowedIPs) != 2 || p.AllowedIPs[0] != "100.64.0.2/32" || p.AllowedIPs[1] != "100.64.0.3/32" {
		t.Fatalf("primary must crypto-route DNS and service VIPs to the connector, got %+v", primaryPeers)
	}
	if len(primaryRoutes) != 2 || primaryRoutes[0].DstCIDR != "100.64.0.2/32" || primaryRoutes[1].DstCIDR != "100.64.0.3/32" {
		t.Fatalf("primary must install DNS and service VIP routes, got %+v", primaryRoutes)
	}

	standbyPeers, standbyRoutes := k8sHandoffGraph(topo, sqlc.Node{ID: standby, SiteID: pgtype.UUID{Bytes: site, Valid: true}})
	if p, ok := peerByKey(standbyPeers, "connector-key"); !ok || len(p.AllowedIPs) != 0 || len(standbyRoutes) != 0 {
		t.Fatalf("standby must retain a warm connector peer but no VIP route, peers=%+v routes=%+v", standbyPeers, standbyRoutes)
	}
	if peers, routes := k8sHandoffGraph(topo, sqlc.Node{ID: ordinary, SiteID: pgtype.UUID{Bytes: site, Valid: true}}); len(peers) != 0 || len(routes) != 0 {
		t.Fatalf("unselected same-site gateway must not receive the handoff, peers=%+v routes=%+v", peers, routes)
	}
}

// TestK8sHandoffGraphKeepsNonHubPoolStandbyWarm models the live HA shape:
// one client-facing CP edge is the site's only hub, while A and B are pool
// members outside that hub set. B must still receive the edge peer in its base
// so a later serving overlay can assign the return CIDR; the edge must retain B
// only as an empty-AllowedIPs warm peer while A alone owns the service VIP.
func TestK8sHandoffGraphKeepsNonHubPoolStandbyWarm(t *testing.T) {
	site := uuid.New()
	edge, connectorA, connectorB := uuid.New(), uuid.New(), uuid.New()
	row := func(id uuid.UUID, key, endpoint string) sqlc.ListSiteGatewaysForOrgRow {
		return sqlc.ListSiteGatewaysForOrgRow{ID: id, SiteID: pgtype.UUID{Bytes: site, Valid: true}, WgPublicKey: key, Endpoint: endpoint}
	}
	topo := siteTopology{
		hubMembers: []sqlc.ListSiteGatewaysForOrgRow{
			row(edge, "edge-key", "20.0.0.1:51820"),
		},
		poolCIDR: "10.99.0.0/24",
		k8sConnectors: map[uuid.UUID]k8sConnector{
			connectorA: {nodeID: connectorA, siteID: site, publicKey: "connector-a-key", endpoint: "20.0.0.2:51820", vips: []string{"100.64.64.3/32"}},
			connectorB: {nodeID: connectorB, siteID: site, publicKey: "connector-b-key", endpoint: "20.0.0.3:51820"},
		},
	}
	findPeer := func(peers []Peer, key string) (Peer, bool) {
		for _, peer := range peers {
			if peer.PublicKey == key {
				return peer, true
			}
		}
		return Peer{}, false
	}

	edgePeers, edgeRoutes := k8sHandoffGraph(topo, sqlc.Node{ID: edge, SiteID: pgtype.UUID{Bytes: site, Valid: true}})
	if peer, ok := findPeer(edgePeers, "connector-a-key"); !ok || len(peer.AllowedIPs) != 1 || peer.AllowedIPs[0] != "100.64.64.3/32" {
		t.Fatalf("edge must route the VIP only to active connector A, peers=%+v", edgePeers)
	}
	if peer, ok := findPeer(edgePeers, "connector-b-key"); !ok || len(peer.AllowedIPs) != 0 {
		t.Fatalf("edge must retain connector B as a warm empty-AllowedIPs peer, peers=%+v", edgePeers)
	}
	if len(edgeRoutes) != 1 || edgeRoutes[0].DstCIDR != "100.64.64.3/32" {
		t.Fatalf("warm connector B must not duplicate the edge VIP route, routes=%+v", edgeRoutes)
	}

	standbyPeers, standbyRoutes := k8sHandoffGraph(topo, sqlc.Node{ID: connectorB, SiteID: pgtype.UUID{Bytes: site, Valid: true}})
	if peer, ok := findPeer(standbyPeers, "edge-key"); !ok || len(peer.AllowedIPs) != 1 || peer.AllowedIPs[0] != "10.99.0.0/24" {
		t.Fatalf("non-hub connector B must contain the edge peer for a serving overlay, peers=%+v", standbyPeers)
	}
	if len(standbyRoutes) != 1 || standbyRoutes[0].DstCIDR != "10.99.0.0/24" {
		t.Fatalf("connector B base must expose the fenceable return route, routes=%+v", standbyRoutes)
	}
}

func TestResolveK8sConnectorReadKeepsLegacyAndPoolModesSeparate(t *testing.T) {
	legacy, active := uuid.New(), uuid.New()
	legacyPG := pgtype.UUID{Bytes: legacy, Valid: true}
	activePG := pgtype.UUID{Bytes: active, Valid: true}
	generation := int64(4)

	if got, ok := resolveK8sConnectorRead(false, legacyPG, pgtype.UUID{}, nil); !ok || got != legacy {
		t.Fatalf("legacy connector = %s, %v; want %s, true", got, ok, legacy)
	}
	if got, ok := resolveK8sConnectorRead(true, legacyPG, activePG, &generation); !ok || got != active {
		t.Fatalf("pool connector = %s, %v; want %s, true", got, ok, active)
	}
	if got, ok := resolveK8sConnectorRead(true, legacyPG, pgtype.UUID{}, &generation); ok || got != uuid.Nil {
		t.Fatalf("pool mode must not fall back to legacy connector: %s, %v", got, ok)
	}
	zero := int64(0)
	if got, ok := resolveK8sConnectorRead(true, legacyPG, activePG, &zero); ok || got != uuid.Nil {
		t.Fatalf("non-positive pool generation must fail closed: %s, %v", got, ok)
	}
}

// TestDesiredStateFailsWholeFetchOnTopologyError — S8.2 F1/R1/B3 (terminal): a site-topology load error
// FAILS the whole DesiredState fetch (atomic + fail-static), so the agent holds last-good everything and
// tears nothing down. NOT the omit-and-teardown attempt (full-sweep reconcile deletes an omitted section).
func TestDesiredStateFailsWholeFetchOnTopologyError(t *testing.T) {
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
	org, node, site := uuid.New(), uuid.New(), uuid.New()
	ex := func(q string, a ...any) {
		if _, e := pool.Exec(ctx, q, a...); e != nil {
			t.Fatalf("seed %q: %v", q, e)
		}
	}
	ex(`INSERT INTO organizations (id,name,slug) VALUES ($1,'F1',$2)`, org, "f1-"+org.String()[:8])
	ex(`INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'A')`, site, org)
	ex(`INSERT INTO nodes (id,org_id,name,cert_serial,agent_version,site_id) VALUES ($1,$2,'gw',$4,'0.1.0',$3)`, node, org, site, "f1s-"+node.String())
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	svc := &Service{pool: pool, q: sqlc.New(pool)}
	siteNode := sqlc.Node{ID: node, OrgID: org, SiteID: pgtype.UUID{Bytes: site, Valid: true}}

	svc.siteTopoLoad = func(context.Context, uuid.UUID) (siteTopology, error) {
		return siteTopology{}, errors.New("topology DB blip")
	}
	if _, err := svc.DesiredState(ctx, siteNode); err == nil {
		t.Fatal("F1: a topology-load error must FAIL the whole fetch (fail-static), not serve a partial artifact")
	}
	// With the real loader the fetch succeeds (site section present, no fault).
	svc.siteTopoLoad = svc.loadSiteTopology
	if _, err := svc.DesiredState(ctx, siteNode); err != nil {
		t.Fatalf("with topology loading OK, the fetch must succeed: %v", err)
	}
}

func sliceHas(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// TestSiteLinkGraphHubSpokeAndFullSweep — S8.2 Slice-2 CP red: siteLinkGraph builds the hub-and-spoke
// site-link peers + per-node routes, and a site unbind sweeps them (full-sweep). The hub (a gateway
// with a public endpoint) peers with each spoke (AllowedIPs = that spoke's subnet); a spoke peers ONLY
// with the hub (AllowedIPs = all remote subnets, hub endpoint). Routes = every remote site subnet.
func TestSiteLinkGraphHubSpokeAndFullSweep(t *testing.T) {
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
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	svc := &Service{q: sqlc.New(tx)}

	org := uuid.New()
	siteA, siteB := uuid.New(), uuid.New()
	nodeHub, nodeSpoke := uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		if _, e := tx.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("seed %q: %v", sql, e)
		}
	}
	ex(`INSERT INTO organizations (id,name,slug) VALUES ($1,'O',$2)`, org, "sl-"+org.String()[:8])
	ex(`INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'A'),($3,$2,'B')`, siteA, org, siteB)
	// Hub = has a public endpoint; spoke = none. Both have WG keys + site bindings.
	ex(`INSERT INTO nodes (id,org_id,name,cert_serial,agent_version,wg_public_key,endpoint,site_id)
	    VALUES ($1,$2,'hub','s1','0.1.0','GWOmhHpqg/vBW5HtkAIOs3Vnur+qGKxCwx3QXbvzNZ4=','hub.example:51820',$3)`, nodeHub, org, siteA)
	ex(`INSERT INTO nodes (id,org_id,name,cert_serial,agent_version,wg_public_key,endpoint,site_id)
	    VALUES ($1,$2,'spoke','s2','0.1.0','M7WMHm1BCV1HuqZYhlw5QoBM6aLrjlgUhFYu9K6xInc=','',$3)`, nodeSpoke, org, siteB)
	ex(`INSERT INTO site_subnets (site_id,cidr,status) VALUES ($1,'10.1.0.0/24','approved'),($2,'10.2.0.0/24','approved')`, siteA, siteB)

	hubNode := sqlc.Node{ID: nodeHub, OrgID: org, SiteID: pgtype.UUID{Bytes: siteA, Valid: true}}
	spokeNode := sqlc.Node{ID: nodeSpoke, OrgID: org, SiteID: pgtype.UUID{Bytes: siteB, Valid: true}}

	graph := func(node sqlc.Node) ([]Peer, []policyspec.Route) {
		topo, e := svc.loadSiteTopology(ctx, org)
		if e != nil {
			t.Fatalf("load topology: %v", e)
		}
		return siteLinkGraphFrom(topo, node)
	}

	// Hub: peers with the spoke (AllowedIPs = the spoke's subnet); routes to the spoke subnet.
	hp, hr := graph(hubNode)
	if len(hp) != 1 || hp[0].PublicKey != "M7WMHm1BCV1HuqZYhlw5QoBM6aLrjlgUhFYu9K6xInc=" || !sliceHas(hp[0].AllowedIPs, "10.2.0.0/24") {
		t.Fatalf("hub must peer with the spoke (AllowedIPs = its subnet), got %+v", hp)
	}
	if hp[0].PersistentKeepalive != siteLinkKeepaliveSecs { // S8.3 CK: every site-link peer carries the keepalive
		t.Fatalf("site-link peer must carry keepalive=%d, got %d", siteLinkKeepaliveSecs, hp[0].PersistentKeepalive)
	}
	if len(hr) != 1 || hr[0].DstCIDR != "10.2.0.0/24" {
		t.Fatalf("hub routes must reach the spoke subnet, got %+v", hr)
	}

	// Spoke: peers ONLY with the hub (endpoint set, AllowedIPs = all remote); routes to the hub subnet.
	sp, sr := graph(spokeNode)
	if len(sp) != 1 || sp[0].PublicKey != "GWOmhHpqg/vBW5HtkAIOs3Vnur+qGKxCwx3QXbvzNZ4=" || sp[0].Endpoint != "hub.example:51820" || !sliceHas(sp[0].AllowedIPs, "10.1.0.0/24") {
		t.Fatalf("spoke must peer with the hub (endpoint + remote AllowedIPs), got %+v", sp)
	}
	if len(sr) != 1 || sr[0].DstCIDR != "10.1.0.0/24" {
		t.Fatalf("spoke routes must reach the hub subnet, got %+v", sr)
	}

	// FULL-SWEEP: unbind the spoke's node from its site → the hub sees no site peer + no route.
	ex(`UPDATE nodes SET site_id=NULL WHERE id=$1`, nodeSpoke)
	hp2, hr2 := graph(hubNode)
	if len(hp2) != 0 || len(hr2) != 0 {
		t.Fatalf("after unbinding the spoke, the hub must have no site peer/route (full-sweep), got peers=%+v routes=%+v", hp2, hr2)
	}
}

// TestSpokePrimaryCarriesPoolStandbyEmpty — A3b D-A3b-1/4 + the failover-symmetry red. The device POOL
// rides the spoke's hub-PRIMARY peer AllowedIPs (the far half of device→remote-site transit: inbound wg
// admits device-sourced packets via the hub; outbound, replies to pool addrs crypto-route back). Primary
// ONLY — the standby stays AllowedIPs-EMPTY (the S8.6 single-valued invariant; pool on two peers would be
// the overlapping-AllowedIPs nondeterminism). Promotion (hubMembers reorder) moves the pool WITH the
// routes onto the new primary — no pool-special failover path.
func TestSpokePrimaryCarriesPoolStandbyEmpty(t *testing.T) {
	siteA, siteB := uuid.New(), uuid.New()
	hub1, hub2, spoke := uuid.New(), uuid.New(), uuid.New()
	g1 := sqlc.ListSiteGatewaysForOrgRow{ID: hub1, SiteID: pgtype.UUID{Bytes: siteA, Valid: true}, WgPublicKey: "Mpe5reh63f4n4Yf0FiABIDwOiFxUs0/OEyDNloUWz1w=", Endpoint: "h1.example:51820"}
	g2 := sqlc.ListSiteGatewaysForOrgRow{ID: hub2, SiteID: pgtype.UUID{Bytes: siteA, Valid: true}, WgPublicKey: "XgK1YHwlTcrURWnz/gLDpFt0ri/njQgHP9ycQpnmesk=", Endpoint: "h2.example:51820"}
	gs := sqlc.ListSiteGatewaysForOrgRow{ID: spoke, SiteID: pgtype.UUID{Bytes: siteB, Valid: true}, WgPublicKey: "lmkAVY7h68xntjC83P/a+d1QgLujIvkLiXSfmi2dPsk="}
	topo := siteTopology{
		gws:        []sqlc.ListSiteGatewaysForOrgRow{g1, g2, gs},
		subnets:    map[uuid.UUID][]string{siteA: {"10.1.0.0/24"}, siteB: {"10.2.0.0/24"}},
		hubMembers: []sqlc.ListSiteGatewaysForOrgRow{g1, g2},
		poolCIDR:   "10.99.0.0/24",
	}
	spokeNode := sqlc.Node{ID: spoke, SiteID: pgtype.UUID{Bytes: siteB, Valid: true}}

	peers, _ := siteLinkGraphFrom(topo, spokeNode)
	var prim, stand *Peer
	for i := range peers {
		switch peers[i].PublicKey {
		case "Mpe5reh63f4n4Yf0FiABIDwOiFxUs0/OEyDNloUWz1w=":
			prim = &peers[i]
		case "XgK1YHwlTcrURWnz/gLDpFt0ri/njQgHP9ycQpnmesk=":
			stand = &peers[i]
		}
	}
	if prim == nil || stand == nil {
		t.Fatalf("spoke must peer with primary + standby, got %+v", peers)
	}
	if !sliceHas(prim.AllowedIPs, "10.99.0.0/24") || !sliceHas(prim.AllowedIPs, "10.1.0.0/24") {
		t.Fatalf("hub-PRIMARY peer must carry the pool alongside the routes, got %v", prim.AllowedIPs)
	}
	if len(stand.AllowedIPs) != 0 {
		t.Fatalf("standby must stay AllowedIPs-EMPTY (single-valued invariant), got %v", stand.AllowedIPs)
	}

	// FAILOVER SYMMETRY: promotion (order flip) moves the pool onto the NEW primary; the demoted drains.
	topo.hubMembers = []sqlc.ListSiteGatewaysForOrgRow{g2, g1}
	peers2, _ := siteLinkGraphFrom(topo, spokeNode)
	for i := range peers2 {
		switch peers2[i].PublicKey {
		case "XgK1YHwlTcrURWnz/gLDpFt0ri/njQgHP9ycQpnmesk=":
			if !sliceHas(peers2[i].AllowedIPs, "10.99.0.0/24") {
				t.Fatalf("promotion must move the pool onto the new primary, got %v", peers2[i].AllowedIPs)
			}
		case "Mpe5reh63f4n4Yf0FiABIDwOiFxUs0/OEyDNloUWz1w=":
			if len(peers2[i].AllowedIPs) != 0 {
				t.Fatalf("the demoted member must drain to empty (pool included), got %v", peers2[i].AllowedIPs)
			}
		}
	}

	// An empty pool (soft-deleted org edge) emits routes only — no empty-string AllowedIP artifact.
	topo.poolCIDR = ""
	peers3, _ := siteLinkGraphFrom(topo, spokeNode)
	for i := range peers3 {
		if peers3[i].PublicKey == "XgK1YHwlTcrURWnz/gLDpFt0ri/njQgHP9ycQpnmesk=" && sliceHas(peers3[i].AllowedIPs, "") {
			t.Fatalf("empty pool must not emit an empty AllowedIP, got %v", peers3[i].AllowedIPs)
		}
	}
}

// TestFinalizeAttachesPoolV6 — A3b: finalizeArtifact attaches PoolCIDR to a route-carrying site-gateway
// artifact and the content-derived version lands at 6; a topo WITHOUT routes (single-site org) returns the
// artifact UNCHANGED (no pool, pre-v6 bytes — the content-derived blast-radius guard).
func TestFinalizeAttachesPoolV6(t *testing.T) {
	siteA, siteB := uuid.New(), uuid.New()
	hub, spoke := uuid.New(), uuid.New()
	topo := siteTopology{
		gws: []sqlc.ListSiteGatewaysForOrgRow{
			{ID: hub, SiteID: pgtype.UUID{Bytes: siteA, Valid: true}, WgPublicKey: "+ZIM+AfT0udGzth0JB3oCtFlBiB/gSWrJZt9ZXnRXVU=", Endpoint: "h:51820"},
			{ID: spoke, SiteID: pgtype.UUID{Bytes: siteB, Valid: true}, WgPublicKey: "lmkAVY7h68xntjC83P/a+d1QgLujIvkLiXSfmi2dPsk="},
		},
		subnets:  map[uuid.UUID][]string{siteA: {"10.1.0.0/24"}, siteB: {"10.2.0.0/24"}},
		poolCIDR: "10.99.0.0/24",
	}
	svc := &Service{}
	spokeNode := sqlc.Node{ID: spoke, SiteID: pgtype.UUID{Bytes: siteB, Valid: true}}
	final := svc.finalizeArtifact(topo, spokeNode, nil)
	if final == nil || final.PoolCIDR != "10.99.0.0/24" {
		t.Fatalf("a route-carrying site artifact must carry the pool, got %+v", final)
	}
	if final.Version != 6 {
		t.Fatalf("pool-carrying artifact must derive v6 (content-derived), got %d", final.Version)
	}

	// single-site (no remote routes): unchanged — no pool, no v6 (the blast-radius guard).
	soloTopo := siteTopology{
		gws:      []sqlc.ListSiteGatewaysForOrgRow{{ID: hub, SiteID: pgtype.UUID{Bytes: siteA, Valid: true}, WgPublicKey: "+ZIM+AfT0udGzth0JB3oCtFlBiB/gSWrJZt9ZXnRXVU=", Endpoint: "h:51820"}},
		subnets:  map[uuid.UUID][]string{siteA: {"10.1.0.0/24"}},
		poolCIDR: "10.99.0.0/24",
	}
	hubNode := sqlc.Node{ID: hub, SiteID: pgtype.UUID{Bytes: siteA, Valid: true}}
	if got := svc.finalizeArtifact(soloTopo, hubNode, nil); got != nil {
		t.Fatalf("a single-site (route-less) gateway must stay unchanged (nil artifact stays nil), got %+v", got)
	}
}

// TestFinalizeAttachesVIPMapPerGatewayOnly (S10.3): finalizeArtifact staples THIS gateway's OWN cluster's
// VIP map (never another cluster's — per-gateway isolation), triggers v7, and rides independent of site
// routes (a connector with no ordinary site route still gets its map). A different gateway is UNCHANGED
// (no map, no bump — the zero-config golden).
func TestFinalizeAttachesVIPMapPerGatewayOnly(t *testing.T) {
	siteA, siteC := uuid.New(), uuid.New()
	connectorA, connectorB := uuid.New(), uuid.New()
	topo := siteTopology{
		vipMappings: map[uuid.UUID][]policyspec.VIPMapping{
			connectorA: {{VIP: "100.64.0.5", Namespace: "prod", Service: "api"}},
			connectorB: {{VIP: "100.65.0.5", Namespace: "prod", Service: "web"}},
		},
	}
	svc := &Service{}
	nodeA := sqlc.Node{ID: connectorA, SiteID: pgtype.UUID{Bytes: siteA, Valid: true}}
	got := svc.finalizeArtifact(topo, nodeA, &policyspec.Compiled{NodeID: "a", Mode: "enforcing"})
	if got == nil || len(got.VIPMappings) != 1 || got.VIPMappings[0].VIP != "100.64.0.5" {
		t.Fatalf("selected connector must carry ONLY its own cluster's VIP map, got %+v", got)
	}
	if got.Version != 7 {
		t.Fatalf("a VIP-map artifact must derive v7 (content-derived), got %d", got.Version)
	}
	if got.PoolCIDR != "" {
		t.Fatalf("a route-less cluster gateway must NOT carry the pool (route-gated), got %q", got.PoolCIDR)
	}
	// Zero-config golden: a same-site non-connector is returned UNCHANGED.
	base := &policyspec.Compiled{NodeID: "c", Mode: "enforcing", Version: 4}
	nodeC := sqlc.Node{ID: uuid.New(), SiteID: pgtype.UUID{Bytes: siteC, Valid: true}}
	if out := svc.finalizeArtifact(topo, nodeC, base); out != base || len(out.VIPMappings) != 0 || out.Version != 4 {
		t.Fatalf("a non-connector must be byte-identical (no map, no bump), got %+v", out)
	}
}

// TestLoadSiteTopologyGroupsVIPMapByConnector (S10.3a, DB): loadSiteTopology groups exposed Services under
// the explicit in-cluster connector, never every gateway in the cluster's site.
func TestLoadSiteTopologyGroupsVIPMapByConnector(t *testing.T) {
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
	org, site, cluster, connector := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ex := func(q string, a ...any) {
		if _, e := pool.Exec(ctx, q, a...); e != nil {
			t.Fatalf("seed %q: %v", q, e)
		}
	}
	ex(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'K',$2,'10.99.0.0/24')`, org, "kt-"+org.String()[:8])
	ex(`INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'A')`, site, org)
	ex(`INSERT INTO nodes (id,org_id,name,cert_serial,site_id,wg_public_key,endpoint,status) VALUES ($1,$2,'connector',$3,$4,'c2VydmVycHVia2V5MDAwMDAwMDAwMDAwMDAwMDAwMD0=','172.31.1.10:51820','active')`, connector, org, "kc-"+connector.String(), site)
	ex(`INSERT INTO k8s_clusters (id,org_id,site_id,connector_node_id,name,vip_range) VALUES ($1,$2,$3,$4,'c','100.64.0.0/16')`, cluster, org, site, connector)
	ex(`INSERT INTO k8s_services (id,org_id,cluster_id,name,namespace,protocol,vip) VALUES ($1,$2,$3,'api','prod','tcp','100.64.0.5')`, uuid.New(), org, cluster)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	svc := &Service{pool: pool, q: sqlc.New(pool)}
	topo, e := svc.loadSiteTopology(ctx, org)
	if e != nil {
		t.Fatal(e)
	}
	m := topo.vipMappings[connector]
	if len(m) != 1 || m[0].VIP != "100.64.0.5" || m[0].Service != "api" || m[0].Namespace != "prod" {
		t.Fatalf("loadSiteTopology must group the exposed Service under its explicit connector, got %+v", m)
	}
}

func TestLoadSiteTopologyWithdrawsIneligiblePoolConnector(t *testing.T) {
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
	org, site, cluster, connector, connectorPool := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ex := func(q string, a ...any) {
		if _, e := pool.Exec(ctx, q, a...); e != nil {
			t.Fatalf("seed %q: %v", q, e)
		}
	}
	ex(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'Pool topology',$2,'10.99.0.0/24')`, org, "kpt-"+org.String()[:8])
	ex(`INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'A')`, site, org)
	ex(`INSERT INTO nodes (id,org_id,name,cert_serial,site_id,wg_public_key,endpoint,status) VALUES ($1,$2,'connector',$3,$4,'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','172.31.1.10:51820','active')`, connector, org, "kpc-"+connector.String(), site)
	ex(`INSERT INTO k8s_clusters (id,org_id,site_id,name,vip_range,service_cidr,dns_zone,dns_vip) VALUES ($1,$2,$3,'pool','100.65.0.0/16','10.96.0.0/12','cluster.test','100.65.0.2')`, cluster, org, site)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `INSERT INTO k8s_connector_pools (id,org_id,site_id,cluster_id,preferred_node_id,active_node_id) VALUES ($1,$2,$3,$4,$5,$5)`, connectorPool, org, site, cluster, connector); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO k8s_connector_pool_members (pool_id,org_id,site_id,node_id) VALUES ($1,$2,$3,$4)`, connectorPool, org, site, connector); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE k8s_clusters SET connector_pool_id=$1 WHERE id=$2`, connectorPool, cluster); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	ex(`INSERT INTO k8s_services (id,org_id,cluster_id,name,namespace,protocol,port_low,port_high,vip) VALUES ($1,$2,$3,'api','prod','tcp',443,443,'100.65.0.3')`, uuid.New(), org, cluster)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	svc := &Service{pool: pool, q: sqlc.New(pool)}
	assertTopology := func(t *testing.T, wantProgrammed bool) {
		t.Helper()
		topo, err := svc.loadSiteTopology(ctx, org)
		if err != nil {
			t.Fatal(err)
		}
		programmed := len(topo.vipMappings[connector]) != 0 || len(topo.k8sDNS[connector]) != 0
		_, hasConnector := topo.k8sConnectors[connector]
		if programmed != wantProgrammed || hasConnector != wantProgrammed {
			t.Fatalf("pool connector programmed=%v registered=%v, want %v; vip=%+v dns=%+v", programmed, hasConnector, wantProgrammed, topo.vipMappings, topo.k8sDNS)
		}
	}

	assertTopology(t, true)
	for name, invalidate := range map[string]string{
		"inactive revoked status": `UPDATE nodes SET status='revoked' WHERE id=$1`,
		"revoked marker":          `UPDATE nodes SET revoked_at=now() WHERE id=$1`,
		"malformed key":           `UPDATE nodes SET wg_public_key='malformed' WHERE id=$1`,
		"empty endpoint":          `UPDATE nodes SET endpoint='   ' WHERE id=$1`,
	} {
		t.Run(name, func(t *testing.T) {
			ex(`UPDATE nodes SET status='active', revoked_at=NULL, wg_public_key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', endpoint='172.31.1.10:51820' WHERE id=$1`, connector)
			ex(invalidate, connector)
			assertTopology(t, false)
		})
	}
}

// TestLoadSiteTopologyKeepsPostCASPoolMembersWarm reproduces the live topology
// gap: CP edge is the only site hub, A/B are connector-pool members, and the
// durable handoff is post-CAS but nonterminal. Resolution must remain withdrawn
// until completion, while both member identities remain in the handoff graph so
// B's serving overlay has an existing edge peer to promote.
func TestLoadSiteTopologyKeepsPostCASPoolMembersWarm(t *testing.T) {
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

	org, site, cluster, connectorPool := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	edge, connectorA, connectorB := uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("seed post-CAS topology: %v\n%s", err, query)
		}
	}
	exec(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'post-CAS topology',$2,'10.99.0.0/24')`, org, "post-cas-"+org.String()[:8])
	exec(`INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'A')`, site, org)
	for _, node := range []struct {
		id            uuid.UUID
		name          string
		key, endpoint string
	}{
		{edge, "edge", "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=", "20.0.0.1:51820"},
		{connectorA, "connector-a", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "20.0.0.2:51820"},
		{connectorB, "connector-b", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "20.0.0.3:51820"},
	} {
		exec(`INSERT INTO nodes (id,org_id,site_id,name,cert_serial,agent_version,status,wg_public_key,endpoint)
			VALUES ($1,$2,$3,$4,$5,'test','active',$6,$7)`, node.id, org, site, node.name+"-"+node.id.String()[:8], "post-cas-"+node.id.String(), node.key, node.endpoint)
	}
	exec(`INSERT INTO org_hub_set (org_id,configured,demoted,generation) VALUES ($1,$2,'{}',1)`, org, []uuid.UUID{edge})
	exec(`INSERT INTO k8s_clusters (id,org_id,site_id,name,vip_range,service_cidr,dns_zone,dns_vip)
		VALUES ($1,$2,$3,'ha','100.64.64.0/20','10.247.0.0/16','ha.example','100.64.64.2')`, cluster, org, site)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO k8s_connector_pools (id,org_id,site_id,cluster_id,preferred_node_id,active_node_id,generation)
		VALUES ($1,$2,$3,$4,$5,$5,1)`, connectorPool, org, site, cluster, connectorA); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	for _, connector := range []uuid.UUID{connectorA, connectorB} {
		if _, err = tx.Exec(ctx, `INSERT INTO k8s_connector_pool_members (pool_id,org_id,site_id,node_id)
			VALUES ($1,$2,$3,$4)`, connectorPool, org, site, connector); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE k8s_clusters SET connector_pool_id=$1 WHERE id=$2 AND org_id=$3`, connectorPool, cluster, org); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO k8s_services (id,org_id,cluster_id,name,namespace,protocol,port_low,port_high,vip)
		VALUES ($1,$2,$3,'ha-echo','default','tcp',80,80,'100.64.64.3')`, uuid.New(), org, cluster)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	scope := k8s.HandoffPoolScope{OrgID: org, SiteID: site, ClusterID: cluster, PoolID: connectorPool}
	plan := testHandoffPlan(HandoffTickIntent{
		OperationID:        uuid.New(),
		Scope:              scope,
		ExpectedActiveID:   connectorA,
		CandidateID:        connectorB,
		ExpectedGeneration: 1,
		TargetGeneration:   2,
	}, time.Now().UTC())
	insertTickOperation(t, ctx, pool, plan)
	advanceTickOperationPastCAS(t, ctx, pool, plan)

	rows, err := sqlc.New(pool).ListActiveK8sServicesForOrg(ctx, org)
	if err != nil || len(rows) != 1 || rows[0].PoolConnectorEligible {
		t.Fatalf("post-CAS active connector must remain resolution-ineligible while operation is nonterminal, rows=%+v err=%v", rows, err)
	}
	svc := &Service{pool: pool, q: sqlc.New(pool)}
	topo, err := svc.loadSiteTopology(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	if len(topo.vipMappings) != 0 || len(topo.k8sDNS) != 0 {
		t.Fatalf("nonterminal active connector must not receive VIP/DNS ownership, vip=%+v dns=%+v", topo.vipMappings, topo.k8sDNS)
	}
	if len(topo.k8sConnectors) != 2 || len(topo.k8sConnectors[connectorA].vips) != 0 || len(topo.k8sConnectors[connectorB].vips) != 0 {
		t.Fatalf("A and B must remain warm identities without VIP ownership, connectors=%+v", topo.k8sConnectors)
	}
	if len(topo.hubMembers) != 1 || topo.hubMembers[0].ID != edge {
		t.Fatalf("pool members must not be inferred into the site hub set, hubs=%+v", topo.hubMembers)
	}

	edgePeers, edgeRoutes := k8sHandoffGraph(topo, sqlc.Node{ID: edge, SiteID: pgtype.UUID{Bytes: site, Valid: true}})
	if len(edgePeers) != 2 || len(edgeRoutes) != 0 {
		t.Fatalf("edge must retain A/B warm peers without VIP routes, peers=%+v routes=%+v", edgePeers, edgeRoutes)
	}
	for _, peer := range edgePeers {
		if len(peer.AllowedIPs) != 0 {
			t.Fatalf("post-CAS warm edge peer acquired VIP ownership: %+v", peer)
		}
	}
	standbyPeers, standbyRoutes := k8sHandoffGraph(topo, sqlc.Node{ID: connectorB, SiteID: pgtype.UUID{Bytes: site, Valid: true}})
	if len(standbyPeers) != 1 || standbyPeers[0].PublicKey != "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=" || len(standbyPeers[0].AllowedIPs) != 1 || standbyPeers[0].AllowedIPs[0] != "10.99.0.0/24" {
		t.Fatalf("B must receive the ordinary edge peer required by serving projection, peers=%+v", standbyPeers)
	}
	if len(standbyRoutes) != 1 || standbyRoutes[0].DstCIDR != "10.99.0.0/24" {
		t.Fatalf("B must receive the fenceable ordinary return route, routes=%+v", standbyRoutes)
	}
}

// TestActiveHubDialFromWF_A — WF-A D-WFA-5 (C): a device whose assigned node is a hub-set member DIALS the
// active primary (endpoint follows promotions); a device on a non-member gateway is NOT derived (keeps its
// own endpoint — the deferred spoke-device case). Identity (node_id) is untouched either way.
func TestActiveHubDialFromWF_A(t *testing.T) {
	primary, standby, spoke := uuid.New(), uuid.New(), uuid.New()
	// Active order: [primary, standby] (deriveActive's head is the active primary).
	active := []sqlc.ListSiteGatewaysForOrgRow{
		{ID: primary, Endpoint: "primary.example:51820", WgPublicKey: "mAmJLPTeOOw+Ux2g2W3edsBX0rE41ChqzbZmpKLlrbo="},
		{ID: standby, Endpoint: "standby.example:51820", WgPublicKey: "psCRjpxV+pauI/rPviBz4BfnA5tgWNftVHyKBxcKLzo="},
	}

	// A device on the PRIMARY → dials the primary (itself).
	if ep, pk, ok := activeHubDialFrom(primary, active); !ok || ep != "primary.example:51820" || pk != "mAmJLPTeOOw+Ux2g2W3edsBX0rE41ChqzbZmpKLlrbo=" {
		t.Fatalf("device on primary must dial the primary, got (%q,%q,%v)", ep, pk, ok)
	}
	// A device on the STANDBY → STILL dials the ACTIVE PRIMARY (the re-home target), not the standby.
	if ep, pk, ok := activeHubDialFrom(standby, active); !ok || ep != "primary.example:51820" || pk != "mAmJLPTeOOw+Ux2g2W3edsBX0rE41ChqzbZmpKLlrbo=" {
		t.Fatalf("device on a hub member must dial the ACTIVE PRIMARY, got (%q,%q,%v)", ep, pk, ok)
	}
	// A device on a NON-member spoke → NOT derived (caller keeps the node's own endpoint).
	if _, _, ok := activeHubDialFrom(spoke, active); ok {
		t.Fatalf("device on a non-member gateway must NOT be hub-derived (spoke-device case deferred)")
	}
	// After a promotion (order flips to [standby, primary]), the SAME device on `primary` now dials `standby`.
	flipped := []sqlc.ListSiteGatewaysForOrgRow{active[1], active[0]}
	if ep, _, ok := activeHubDialFrom(primary, flipped); !ok || ep != "standby.example:51820" {
		t.Fatalf("post-promotion the dial must follow the new active primary, got (%q,%v)", ep, ok)
	}
	// Empty hub set → not derived.
	if _, _, ok := activeHubDialFrom(primary, nil); ok {
		t.Fatal("no hub members → not derived")
	}
}
