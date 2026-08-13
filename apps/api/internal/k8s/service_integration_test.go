package k8s

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedOrgSite makes an org (device pool 10.99.0.0/24) + a site; returns their ids.
func seedOrgSite(t *testing.T, pool *pgxpool.Pool) (org, site uuid.UUID) {
	org, site, _ = seedOrgSiteActor(t, pool)
	return org, site
}

// seedOrgSiteActor also seeds a user (the audit actor — actor_user_id FKs users) and returns it.
func seedOrgSiteActor(t *testing.T, pool *pgxpool.Pool) (org, site, actor uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	org, site, actor = uuid.New(), uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("seed %q: %v", sql, e)
		}
	}
	ex(`INSERT INTO organizations (id, name, slug, pool_cidr) VALUES ($1,'K',$2,'10.99.0.0/24')`, org, "k8s-"+org.String()[:8])
	ex(`INSERT INTO sites (id, org_id, name) VALUES ($1,$2,'site')`, site, org)
	ex(`INSERT INTO users (id, email) VALUES ($1,$2)`, actor, "k8s-"+actor.String()[:8]+"@ex.com")
	return org, site, actor
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// p32 is a *int32 for a specific exposed Service port (WF-K5 M8/M9: ExposeService now requires one).
func p32(v int32) *int32 { return &v }

// TestRegisterClusterRejectsOverlap: a VIP range overlapping the device pool OR an approved site subnet
// is refused with the TYPED class in the teaching message (never silently accepted — ambiguous routing).
func TestRegisterClusterRejectsOverlap(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, site := seedOrgSite(t, pool)
	// An approved site subnet the VIP range must also avoid.
	if _, e := pool.Exec(ctx, `INSERT INTO site_subnets (id, site_id, cidr, status) VALUES ($1,$2,'10.20.0.0/24','approved')`, uuid.New(), site); e != nil {
		t.Fatal(e)
	}

	// Overlaps the device pool.
	if _, err := svc.RegisterCluster(ctx, org, site, "c-pool", pfx("10.99.0.0/25"), pfx("10.96.0.0/12"), "k8s.acme.com", uuid.Nil, uuid.Nil, "", ""); err == nil || !strings.Contains(err.Error(), "pool") {
		t.Fatalf("want a pool-class overlap refusal, got %v", err)
	}
	// Overlaps the approved site subnet.
	if _, err := svc.RegisterCluster(ctx, org, site, "c-site", pfx("10.20.0.128/25"), pfx("10.96.0.0/12"), "k8s.acme.com", uuid.Nil, uuid.Nil, "", ""); err == nil || !strings.Contains(err.Error(), "site_subnet") {
		t.Fatalf("want a site_subnet-class overlap refusal, got %v", err)
	}
	// A disjoint range is accepted.
	if _, err := svc.RegisterCluster(ctx, org, site, "c-ok", pfx("100.64.0.0/16"), pfx("10.96.0.0/12"), "k8s.acme.com", uuid.Nil, uuid.Nil, "", ""); err != nil {
		t.Fatalf("a disjoint VIP range must be accepted, got %v", err)
	}
}

// TestRegisterClusterRejectsBadName: the cluster name is a DNS label and the zone a DNS domain (they build
// the exposed-Service hostname); malformed values are refused with typed teaching errors, never reach the wire.
func TestRegisterClusterRejectsBadName(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, site := seedOrgSite(t, pool)
	if _, err := svc.RegisterCluster(ctx, org, site, "Prod Cluster", pfx("100.64.0.0/16"), pfx("10.96.0.0/12"), "k8s.acme.com", uuid.Nil, uuid.Nil, "", ""); err == nil || !strings.Contains(err.Error(), "invalid_cluster_name") {
		t.Fatalf("want invalid_cluster_name for a non-label name, got %v", err)
	}
	if _, err := svc.RegisterCluster(ctx, org, site, "prod", pfx("100.64.0.0/16"), pfx("10.96.0.0/12"), "not a domain", uuid.Nil, uuid.Nil, "", ""); err == nil || !strings.Contains(err.Error(), "invalid_dns_zone") {
		t.Fatalf("want invalid_dns_zone for a malformed zone, got %v", err)
	}
}

// TestRegisterClusterRejectsZoneCollidingForwardedDomain — S10.3 (A) cross-mechanism one-zone-one-resolver:
// a cluster whose DNS zone <cluster>.<dns_zone> collides with a domain already forwarded by a site is refused
// (the mirror of the check in sites.SetDNSForward).
func TestRegisterClusterRejectsZoneCollidingForwardedDomain(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, site := seedOrgSite(t, pool)
	// The site already forwards prod.k8s.acme.com.
	if _, e := pool.Exec(ctx, `UPDATE sites SET dns_forwarding=$2 WHERE id=$1`, site, `[{"domain":"prod.k8s.acme.com","resolver_ip":"10.20.0.53"}]`); e != nil {
		t.Fatal(e)
	}
	// Registering cluster "prod" in zone "k8s.acme.com" would claim that exact zone → refused.
	if _, err := svc.RegisterCluster(ctx, org, site, "prod", pfx("100.64.0.0/16"), pfx("10.96.0.0/12"), "k8s.acme.com", uuid.Nil, uuid.Nil, "", ""); err == nil || !strings.Contains(err.Error(), "dns_domain_conflict") {
		t.Fatalf("a cluster zone colliding with a forwarded domain must refuse, got %v", err)
	}
}

// TestRegisterClusterReservesDNSVIP: the DNS VIP is the range's first allocatable (.2), reserved at
// registration so a Service can NEVER be handed it (the gateway answers DNS on it). A range too small to
// fit the DNS VIP PLUS one Service VIP is refused honestly.
func TestRegisterClusterReservesDNSVIP(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, site := seedOrgSite(t, pool)
	// /30 has exactly ONE allocatable (.2) — it would be all DNS, no Service room: refused.
	if _, err := svc.RegisterCluster(ctx, org, site, "tiny", pfx("100.66.0.0/30"), pfx("10.96.0.0/12"), "k8s.acme.com", uuid.Nil, uuid.Nil, "", ""); err == nil || !strings.Contains(err.Error(), "vip_range_too_small") {
		t.Fatalf("a range with no room past the DNS VIP must refuse (too_small), got %v", err)
	}
	c, err := svc.RegisterCluster(ctx, org, site, "dnsr", pfx("100.66.0.0/29"), pfx("10.96.0.0/12"), "k8s.acme.com", uuid.Nil, uuid.Nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.DnsVip == nil || c.DnsVip.String() != "100.66.0.2" {
		t.Fatalf("DNS VIP must be reserved at .2, got %v", c.DnsVip)
	}
	// The first exposed Service gets .3 — proof .2 is reserved and never handed out.
	s1, err := svc.ExposeService(ctx, org, c.ID, "api", "prod", "tcp", p32(80), p32(80), uuid.Nil, uuid.Nil, "", "")
	if err != nil {
		t.Fatalf("first expose: %v", err)
	}
	if s1.Vip.String() != "100.66.0.3" {
		t.Fatalf("first Service VIP must skip the reserved .2, got %s", s1.Vip)
	}
}

// TestSecondClusterCannotOverlapFirst proves the collector's 7th-caller path LIVE: a second cluster's VIP
// range is checked against the FIRST cluster's range (fed in by Collect) and refused with the vip_range class.
func TestSecondClusterCannotOverlapFirst(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, site := seedOrgSite(t, pool)

	if _, err := svc.RegisterCluster(ctx, org, site, "a", pfx("100.64.0.0/16"), pfx("10.96.0.0/12"), "k8s.acme.com", uuid.Nil, uuid.Nil, "", ""); err != nil {
		t.Fatalf("first cluster: %v", err)
	}
	if _, err := svc.RegisterCluster(ctx, org, site, "b", pfx("100.64.5.0/24"), pfx("10.96.0.0/12"), "k8s.acme.com", uuid.Nil, uuid.Nil, "", ""); err == nil || !strings.Contains(err.Error(), "vip_range") {
		t.Fatalf("a second cluster overlapping the first's VIP range must be refused (vip_range class), got %v", err)
	}
}

// TestExposeAllocatesThenExhausts: a /29 range yields the DNS VIP (.2, reserved) plus four Service VIPs;
// the fifth expose is refused HONESTLY (vip_range_exhausted), never silently reusing an address.
func TestExposeAllocatesThenExhausts(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, site := seedOrgSite(t, pool)
	c, err := svc.RegisterCluster(ctx, org, site, "small", pfx("100.66.0.0/29"), pfx("10.96.0.0/12"), "k8s.acme.com", uuid.Nil, uuid.Nil, "", "") // .2 DNS + .3-.6 Services
	if err != nil {
		t.Fatal(err)
	}
	svc1, err := svc.ExposeService(ctx, org, c.ID, "api", "prod", "tcp", p32(80), p32(80), uuid.Nil, uuid.Nil, "", "")
	if err != nil {
		t.Fatalf("first expose: %v", err)
	}
	if svc1.Vip.String() != "100.66.0.3" {
		t.Fatalf("first Service VIP skips the reserved DNS .2, got %s", svc1.Vip)
	}
	// Consume the remaining three Service VIPs (.4, .5, .6).
	for i, n := range []string{"web", "cache", "queue"} {
		if _, err := svc.ExposeService(ctx, org, c.ID, n, "prod", "tcp", p32(80), p32(80), uuid.Nil, uuid.Nil, "", ""); err != nil {
			t.Fatalf("expose %d (%s): %v", i, n, err)
		}
	}
	if _, err := svc.ExposeService(ctx, org, c.ID, "extra", "prod", "tcp", p32(80), p32(80), uuid.Nil, uuid.Nil, "", ""); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("exposing past the range must refuse honestly (exhausted), got %v", err)
	}
}

// TestUnexposeServiceSweeps — S10.3 sweep: soft-deleting a Service removes it from the LIVE resolution
// (VIP map recompiles without it) AND frees its VIP for immediate reuse (used-set is live-only). A re-expose
// mints a fresh identity; VIP reuse is safe because the compiler resolves id -> CURRENT VIP.
func TestUnexposeServiceSweeps(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, site, actor := seedOrgSiteActor(t, pool)
	c, err := svc.RegisterCluster(ctx, org, site, "sweep", pfx("100.64.0.0/28"), pfx("10.96.0.0/12"), "k8s.acme.com", uuid.Nil, uuid.Nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	s1, err := svc.ExposeService(ctx, org, c.ID, "api", "prod", "tcp", p32(80), p32(80), uuid.Nil, uuid.Nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if s1.Vip.String() != "100.64.0.3" {
		t.Fatalf("first Service VIP, got %s", s1.Vip)
	}
	// Present in the LIVE resolution.
	live, _ := svc.q.ListActiveK8sServicesForOrg(ctx, org)
	if len(live) != 1 {
		t.Fatalf("exposed Service must be in the live resolution, got %d", len(live))
	}
	// Unexpose → gone from the resolution.
	if err := svc.UnexposeService(ctx, actor, "", "", org, s1.ID); err != nil {
		t.Fatalf("unexpose: %v", err)
	}
	// H2: the unexpose is audited.
	var unexposed int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='k8s.service_unexposed'`, org).Scan(&unexposed)
	if unexposed != 1 {
		t.Fatalf("unexpose must be audited once, got %d", unexposed)
	}
	live, _ = svc.q.ListActiveK8sServicesForOrg(ctx, org)
	if len(live) != 0 {
		t.Fatalf("unexposed Service must vanish from the resolution, got %d", len(live))
	}
	// The freed VIP is reusable — a re-expose gets .3 again (not skipped, not exhausted-around).
	s2, err := svc.ExposeService(ctx, org, c.ID, "api", "prod", "tcp", p32(80), p32(80), uuid.Nil, uuid.Nil, "", "")
	if err != nil {
		t.Fatalf("re-expose: %v", err)
	}
	if s2.Vip.String() != "100.64.0.3" {
		t.Fatalf("the freed VIP must be reusable (.3), got %s", s2.Vip)
	}
	if s2.ID == s1.ID {
		t.Fatal("a re-expose must mint a NEW identity, not resurrect the soft-deleted one")
	}
}

// TestDeregisterClusterSweeps — S10.3 sweep: deregistering a cluster CASCADE-removes its Services and frees
// the whole VIP range + DNS zone for reuse in ONE atomic delete. A new cluster may then claim the same range.
func TestDeregisterClusterSweeps(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, site, actor := seedOrgSiteActor(t, pool)
	c, err := svc.RegisterCluster(ctx, org, site, "gone", pfx("100.64.0.0/24"), pfx("10.96.0.0/12"), "k8s.acme.com", uuid.Nil, uuid.Nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	exposed, err := svc.ExposeService(ctx, org, c.ID, "api", "prod", "tcp", p32(80), p32(80), uuid.Nil, uuid.Nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	// Seed a Zero-Trust grant reaching that Service — the FK cascade must hard-delete it on deregister, and
	// the audit must record it (grants_deleted). A group source satisfies the exactly-one-src CHECK.
	grp := uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO user_groups (id,org_id,name) VALUES ($1,$2,'g')`, grp, org); e != nil {
		t.Fatal(e)
	}
	if _, e := pool.Exec(ctx, `INSERT INTO policy_rules (id,org_id,src_kind,src_group_id,dst_kind,dst_k8s_service_id) VALUES ($1,$2,'group',$3,'k8s_service',$4)`, uuid.New(), org, grp, exposed.ID); e != nil {
		t.Fatal(e)
	}
	// A same-range/same-zone re-register is refused WHILE the cluster lives (overlap + would-collide).
	if _, err := svc.RegisterCluster(ctx, org, site, "gone2", pfx("100.64.0.0/24"), pfx("10.96.0.0/12"), "other.acme.com", uuid.Nil, uuid.Nil, "", ""); err == nil {
		t.Fatal("a live cluster's VIP range must block a second claim")
	}
	// Deregister → services gone, range + zone freed.
	if err := svc.DeregisterCluster(ctx, actor, "", "", org, c.ID); err != nil {
		t.Fatalf("deregister: %v", err)
	}
	live, _ := svc.q.ListActiveK8sServicesForOrg(ctx, org)
	if len(live) != 0 {
		t.Fatalf("deregister must CASCADE-remove exposed Services, got %d", len(live))
	}
	// H2: the deregister is audited WITH the cascade counts (1 exposed Service was destroyed).
	var svcDeleted *int
	if err := pool.QueryRow(ctx, `SELECT (metadata->>'services_deleted')::int FROM audit_logs WHERE org_id=$1 AND action='k8s.cluster_deregistered'`, org).Scan(&svcDeleted); err != nil {
		t.Fatalf("deregister must be audited with cascade counts: %v", err)
	}
	if svcDeleted == nil || *svcDeleted != 1 {
		t.Fatalf("the deregister audit must record services_deleted=1, got %v", svcDeleted)
	}
	var grantsDeleted *int
	_ = pool.QueryRow(ctx, `SELECT (metadata->>'grants_deleted')::int FROM audit_logs WHERE org_id=$1 AND action='k8s.cluster_deregistered'`, org).Scan(&grantsDeleted)
	if grantsDeleted == nil || *grantsDeleted != 1 {
		t.Fatalf("the deregister audit must record grants_deleted=1 (the cascaded grant), got %v", grantsDeleted)
	}
	// And the grant is actually gone (the FK cascade fired, not just counted).
	var rulesLeft int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM policy_rules WHERE org_id=$1`, org).Scan(&rulesLeft)
	if rulesLeft != 0 {
		t.Fatalf("the cascaded grant must be hard-deleted, got %d rules left", rulesLeft)
	}
	// The freed range is now reclaimable, AND the freed zone no longer conflicts.
	if _, err := svc.RegisterCluster(ctx, org, site, "reborn", pfx("100.64.0.0/24"), pfx("10.96.0.0/12"), "k8s.acme.com", uuid.Nil, uuid.Nil, "", ""); err != nil {
		t.Fatalf("the freed VIP range + zone must be reclaimable after deregister, got %v", err)
	}
}

// TestVIPAllocationClusterScoped: two clusters allocate from their OWN ranges (independent used-sets) —
// exposing in cluster A does not consume cluster B's addresses.
func TestVIPAllocationClusterScoped(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, site := seedOrgSite(t, pool)
	a, err := svc.RegisterCluster(ctx, org, site, "ca", pfx("100.64.0.0/28"), pfx("10.96.0.0/12"), "k8s.acme.com", uuid.Nil, uuid.Nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.RegisterCluster(ctx, org, site, "cb", pfx("100.65.0.0/28"), pfx("10.96.0.0/12"), "k8s.acme.com", uuid.Nil, uuid.Nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	sa, err := svc.ExposeService(ctx, org, a.ID, "s", "ns", "any", p32(80), p32(80), uuid.Nil, uuid.Nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	sb, err := svc.ExposeService(ctx, org, b.ID, "s", "ns", "any", p32(80), p32(80), uuid.Nil, uuid.Nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	// Each got the low Service VIP of its OWN range (.3, past the reserved DNS .2) — used-set is per-cluster.
	if sa.Vip.String() != "100.64.0.3" || sb.Vip.String() != "100.65.0.3" {
		t.Fatalf("cluster-scoped allocation expected 100.64.0.3 / 100.65.0.3, got %s / %s", sa.Vip, sb.Vip)
	}
}

// TestRegisterClusterSerializesDisjointness — M6: RegisterCluster takes the org advisory lock BEFORE its
// disjointness read, so a concurrent range write cannot slip an OVERLAPPING range past the READ-COMMITTED
// check. Deterministic: a holder tx takes the SAME lock, commits an overlapping cluster range, and only THEN
// releases — the blocked RegisterCluster must wake, SEE the committed range, and refuse with the typed class.
// RED (remove the LockDeviceKey in RegisterCluster): both commit → two overlapping ranges persist.
func TestRegisterClusterSerializesDisjointness(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	mkPool := func() *pgxpool.Pool {
		cfg, _ := pgxpool.ParseConfig(dsn)
		cfg.MaxConns = 1 // a dedicated conn per party so the advisory lock genuinely contends
		p, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatalf("pool: %v", err)
		}
		return p
	}
	poolHold, poolReg := mkPool(), mkPool()
	t.Cleanup(poolHold.Close)
	t.Cleanup(poolReg.Close)

	org, site := uuid.New(), uuid.New()
	if _, e := poolHold.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'K',$2,'10.99.0.0/24')`, org, "m6-"+org.String()[:8]); e != nil {
		t.Fatal(e)
	}
	if _, e := poolHold.Exec(ctx, `INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'s')`, site, org); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _, _ = poolHold.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	// Holder: take the org advisory lock, commit an overlapping cluster range, then release — but hold the
	// window open until the registrar is proven blocked.
	tx, err := poolHold.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, org.String()); e != nil {
		t.Fatal(e)
	}
	if _, e := tx.Exec(ctx, `INSERT INTO k8s_clusters (id,org_id,site_id,name,vip_range,service_cidr,dns_zone) VALUES ($1,$2,$3,'held','100.64.0.0/16','10.96.0.0/12','k8s.acme.com')`, uuid.New(), org, site); e != nil {
		t.Fatal(e)
	}

	regErr := make(chan error, 1)
	go func() {
		svc := NewService(poolReg)
		_, err := svc.RegisterCluster(ctx, org, site, "b", pfx("100.64.5.0/24"), pfx("10.96.0.0/12"), "other.acme.com", uuid.Nil, uuid.Nil, "", "")
		regErr <- err
	}()

	// The registrar must be BLOCKED on the lock — it has not returned.
	select {
	case e := <-regErr:
		t.Fatalf("RegisterCluster must BLOCK on the org lock, but returned early: %v", e)
	case <-time.After(400 * time.Millisecond):
	}

	// Release: commit the holder's overlapping range. The registrar wakes, sees it, and refuses.
	if e := tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-regErr:
		if e == nil || !strings.Contains(e.Error(), "vip_range") {
			t.Fatalf("the unblocked RegisterCluster must refuse the overlap (vip_range class), got %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RegisterCluster did not return after the lock released")
	}
}

// TestMachineActorAuditsSystemNotUser — S10.2 D3: a MACHINE-driven mutation attributes to a SYSTEM actor
// (actor_system, with a cause), NEVER a user id. The NEGATIVE (actor_user_id NULL) is asserted alongside
// the positive AND the human inverse is asserted too — so a future refactor cannot quietly re-attribute
// operator changes to a person (the confidently-wrong-attribution failure D3 exists to prevent).
func TestMachineActorAuditsSystemNotUser(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, site, actor := seedOrgSiteActor(t, pool)

	// MACHINE deregister: actorUserID == uuid.Nil, actorSystem set, cause set.
	cm, err := svc.RegisterCluster(ctx, org, site, "m", pfx("100.70.0.0/16"), pfx("10.96.0.0/12"), "k8s.acme.com", uuid.Nil, uuid.Nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DeregisterCluster(ctx, uuid.Nil, "operator:gitops", "machine_credential:abc", org, cm.ID); err != nil {
		t.Fatal(err)
	}
	var sys, usr, cause *string
	if err := pool.QueryRow(ctx,
		`SELECT actor_system, actor_user_id::text, metadata->>'cause' FROM audit_logs
		   WHERE org_id=$1 AND action='k8s.cluster_deregistered' AND target_id=$2`, org, cm.ID.String()).
		Scan(&sys, &usr, &cause); err != nil {
		t.Fatal(err)
	}
	if sys == nil || *sys != "operator:gitops" {
		t.Fatalf("machine mutation must attribute actor_system=operator:gitops, got %v", sys)
	}
	if usr != nil { // THE NEGATIVE — never a user id for a machine change
		t.Fatalf("machine mutation must have actor_user_id NULL, got %v", *usr)
	}
	if cause == nil || *cause != "machine_credential:abc" {
		t.Fatalf("machine mutation must record the cause, got %v", cause)
	}

	// HUMAN deregister: the inverse — actor_user_id set, actor_system NULL.
	ch, err := svc.RegisterCluster(ctx, org, site, "h", pfx("100.71.0.0/16"), pfx("10.96.0.0/12"), "k8s.acme.com", uuid.Nil, uuid.Nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DeregisterCluster(ctx, actor, "", "", org, ch.ID); err != nil {
		t.Fatal(err)
	}
	var sys2, usr2 *string
	if err := pool.QueryRow(ctx,
		`SELECT actor_system, actor_user_id::text FROM audit_logs
		   WHERE org_id=$1 AND action='k8s.cluster_deregistered' AND target_id=$2`, org, ch.ID.String()).
		Scan(&sys2, &usr2); err != nil {
		t.Fatal(err)
	}
	if sys2 != nil {
		t.Fatalf("human mutation must have actor_system NULL, got %v", *sys2)
	}
	if usr2 == nil {
		t.Fatal("human mutation must set actor_user_id")
	}
}

// TestOwnershipMarkerSetOnMachineCreate — S10.2 Slice 3a: a MACHINE-created cluster/service records
// managed_by_machine (the operator's credential); a human-created one (uuid.Nil) leaves it NULL — inert,
// no behavior change (the zero-config golden's ownership analog). The dashboard SURFACE is Slice 4; the
// marker is recorded now so that surface never retrofits live rows.
func TestOwnershipMarkerSetOnMachineCreate(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, site := seedOrgSite(t, pool)

	// A machine credential (the FK target for managed_by_machine).
	mid := uuid.New()
	if _, e := pool.Exec(ctx,
		`INSERT INTO machine_credentials (id, org_id, name, role, token_hash, fingerprint) VALUES ($1,$2,'gitops','operator',$3,'fp')`,
		mid, org, []byte(mid.String())); e != nil {
		t.Fatal(e)
	}

	// MACHINE-created cluster → marker set.
	cm, err := svc.RegisterCluster(ctx, org, site, "own-m", pfx("100.72.0.0/16"), pfx("10.96.0.0/12"), "k8s.acme.com", mid, uuid.Nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var mb *string
	if err := pool.QueryRow(ctx, `SELECT managed_by_machine::text FROM k8s_clusters WHERE id=$1`, cm.ID).Scan(&mb); err != nil {
		t.Fatal(err)
	}
	if mb == nil || *mb != mid.String() {
		t.Fatalf("machine-created cluster must record managed_by_machine=%s, got %v", mid, mb)
	}

	// MACHINE-created service → marker set.
	sm, err := svc.ExposeService(ctx, org, cm.ID, "api", "prod", "tcp", p32(80), p32(80), mid, uuid.Nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT managed_by_machine::text FROM k8s_services WHERE id=$1`, sm.ID).Scan(&mb); err != nil {
		t.Fatal(err)
	}
	if mb == nil || *mb != mid.String() {
		t.Fatalf("machine-created service must record managed_by_machine, got %v", mb)
	}

	// HUMAN-created (uuid.Nil) → NULL, inert.
	ch, err := svc.RegisterCluster(ctx, org, site, "own-h", pfx("100.73.0.0/16"), pfx("10.96.0.0/12"), "k8s.acme.com", uuid.Nil, uuid.Nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var mbh *string
	if err := pool.QueryRow(ctx, `SELECT managed_by_machine::text FROM k8s_clusters WHERE id=$1`, ch.ID).Scan(&mbh); err != nil {
		t.Fatal(err)
	}
	if mbh != nil {
		t.Fatalf("human-created cluster must have managed_by_machine NULL, got %v", *mbh)
	}
}

// TestMachineCreateAudits — S10.2 M1: the CREATE paths (register/expose) now audit, machine-aware. A machine
// create attributes actor_system=operator:<name> + cause (the CR), NEVER a user id; a human create attributes
// actor_user_id. (F-3a-1 closed: creates were unaudited; with a machine principal that was a hole — "who
// exposed payments-api and why" must be answerable about an automated actor.)
func TestMachineCreateAudits(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, site, actor := seedOrgSiteActor(t, pool)

	// MACHINE register (managedByMachine=Nil to dodge the FK; the audit actor tuple is what's under test).
	cm, err := svc.RegisterCluster(ctx, org, site, "cm", pfx("100.74.0.0/16"), pfx("10.96.0.0/12"), "k8s.acme.com",
		uuid.Nil, uuid.Nil, "operator:gitops", "tunnexcluster:default/prod")
	if err != nil {
		t.Fatal(err)
	}
	var sys, usr, cause *string
	if err := pool.QueryRow(ctx,
		`SELECT actor_system, actor_user_id::text, metadata->>'cause' FROM audit_logs
		   WHERE org_id=$1 AND action='k8s.cluster_registered' AND target_id=$2`, org, cm.ID.String()).
		Scan(&sys, &usr, &cause); err != nil {
		t.Fatal(err)
	}
	if sys == nil || *sys != "operator:gitops" || usr != nil || cause == nil || *cause != "tunnexcluster:default/prod" {
		t.Fatalf("machine register must audit actor_system+cause, not a user; got sys=%v usr=%v cause=%v", sys, usr, cause)
	}

	// MACHINE expose → same seam.
	sm, err := svc.ExposeService(ctx, org, cm.ID, "api", "prod", "tcp", p32(80), p32(80),
		uuid.Nil, uuid.Nil, "operator:gitops", "tunnexexposedservice:default/api")
	if err != nil {
		t.Fatal(err)
	}
	var esys *string
	if err := pool.QueryRow(ctx,
		`SELECT actor_system FROM audit_logs WHERE org_id=$1 AND action='k8s.service_exposed' AND target_id=$2`,
		org, sm.ID.String()).Scan(&esys); err != nil {
		t.Fatal(err)
	}
	if esys == nil || *esys != "operator:gitops" {
		t.Fatalf("machine expose must audit actor_system, got %v", esys)
	}

	// HUMAN register → the inverse (actor_user_id set, actor_system NULL).
	ch, err := svc.RegisterCluster(ctx, org, site, "ch", pfx("100.75.0.0/16"), pfx("10.96.0.0/12"), "k8s.acme.com",
		uuid.Nil, actor, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var hsys, husr *string
	if err := pool.QueryRow(ctx,
		`SELECT actor_system, actor_user_id::text FROM audit_logs WHERE org_id=$1 AND action='k8s.cluster_registered' AND target_id=$2`,
		org, ch.ID.String()).Scan(&hsys, &husr); err != nil {
		t.Fatal(err)
	}
	if hsys != nil || husr == nil {
		t.Fatalf("human register must attribute actor_user_id, not system; got sys=%v usr=%v", hsys, husr)
	}
}
