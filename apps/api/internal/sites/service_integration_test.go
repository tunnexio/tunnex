package sites

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresources"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// TestSiteTransportCheckRefusesUnknown is the D4 refuse-don't-guess confirmation (Slice-2 ruling 1):
// the link_transport CHECK constraint must REJECT a non-wireguard value with a loud 23514, not
// silently accept it — the schema twin of the version gate's refuse-don't-guess. A future transport
// (ipsec) is unusable until its migration lands.
func TestSiteTransportCheckRefusesUnknown(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	org := uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug) VALUES ($1,'S',$2)`, org, "tck-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	_, err := pool.Exec(ctx, `INSERT INTO sites (org_id,name,link_transport) VALUES ($1,'ipsec-site','ipsec')`, org)
	if err == nil {
		t.Fatal("link_transport='ipsec' must be REFUSED by the CHECK until its migration lands (refuse-don't-guess)")
	}
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "23514" {
		t.Fatalf("want a CHECK violation (23514), got %v", err)
	}
}

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

// TestReplaceNodePreservesSiteEntity is the S8.1 D6 replace-node red: a SITE is an ENTITY that owns
// its gateway node, NOT an attribute of the node. Replacing a site's gateway (unbind old, bind new)
// must leave the site's identity AND its subnets intact — the exact operational reason the model is
// entity-not-attribute (a failed gateway box is swapped without losing the site). Also pins
// single-node v1: binding a second node to an occupied site is refused (site_has_gateway 409).
func TestReplaceNodePreservesSiteEntity(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()

	org, nodeA, nodeB := uuid.New(), uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("seed %q: %v", sql, e)
		}
	}
	ex(`INSERT INTO organizations (id, name, slug) VALUES ($1,'S',$2)`, org, "site-"+org.String()[:8])
	ex(`INSERT INTO nodes (id, org_id, name, cert_serial, enrolled_kind) VALUES ($1,$2,'gw-a',$3,'gateway')`, nodeA, org, "cs-a-"+nodeA.String()[:8])
	ex(`INSERT INTO nodes (id, org_id, name, cert_serial, enrolled_kind) VALUES ($1,$2,'gw-b',$3,'gateway')`, nodeB, org, "cs-b-"+nodeB.String()[:8])
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	site, err := svc.RegisterSite(ctx, org, "hq")
	if err != nil {
		t.Fatalf("register site: %v", err)
	}
	if err := svc.BindNode(ctx, org, site.ID, nodeA); err != nil {
		t.Fatalf("bind A: %v", err)
	}
	sub, err := svc.AddSubnet(ctx, org, site.ID, netip.MustParsePrefix("10.20.0.0/24"))
	if err != nil {
		t.Fatalf("add subnet: %v", err)
	}

	// S8.6 LIFT: binding a SECOND gateway to a site is now ALLOWED (the HA hub set — the single-node v1
	// partial unique index was dropped in 0037 precisely so a site can hold primary + standby gateways).
	if err := svc.BindNode(ctx, org, site.ID, nodeB); err != nil {
		t.Fatalf("S8.6: a site may now hold multiple gateways (HA hub set); bind B must succeed, got %v", err)
	}

	// REPLACE the node: unbind A, bind B (a same-site no-op now — B is already bound; the point is the site
	// entity survives the node churn).
	if err := svc.UnbindNode(ctx, org, nodeA); err != nil {
		t.Fatalf("unbind A: %v", err)
	}
	if err := svc.BindNode(ctx, org, site.ID, nodeB); err != nil {
		t.Fatalf("bind B after unbind: %v", err)
	}

	// The SITE entity survives the node swap (identity intact).
	got, err := svc.GetSite(ctx, org, site.ID)
	if err != nil || got.ID != site.ID || got.Name != site.Name {
		t.Fatalf("site identity must survive node replacement: %v (%+v)", err, got)
	}
	// The subnet survives — it is site-scoped, not node-scoped.
	subs, err := svc.ListSubnets(ctx, org, site.ID)
	if err != nil || len(subs) != 1 || subs[0].ID != sub.ID {
		t.Fatalf("site subnet must survive node replacement, got %d subnets (%v)", len(subs), err)
	}
	// B is now the site's gateway; A is unbound.
	var bSite uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT site_id FROM nodes WHERE id=$1`, nodeB).Scan(&bSite); err != nil || bSite != site.ID {
		t.Fatalf("the replacement node B must be the site's gateway, got %v (%v)", bSite, err)
	}
}

// TestDeleteSiteCascadesAndAudits — S8.3 D4: deleteSite removes the site and CASCADES its subnets + any
// policy rule naming it (src/dst), and UNBINDS the gateway. GetReferences reports the real counts the UI
// previews; the audit records those counts (never "may affect"); a re-delete is a clean 404.
func TestDeleteSiteCascadesAndAudits(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()

	org, user, node, grp := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("seed %q: %v", sql, e)
		}
	}
	ex(`INSERT INTO organizations (id, name, slug) VALUES ($1,'S',$2)`, org, "del-"+org.String()[:8])
	ex(`INSERT INTO users (id, email, name) VALUES ($1,$2,'U')`, user, "del-"+user.String()[:8]+"@t.io")
	ex(`INSERT INTO nodes (id, org_id, name, cert_serial, enrolled_kind) VALUES ($1,$2,'gw',$3,'gateway')`, node, org, "cs-"+node.String()[:8])
	ex(`INSERT INTO user_groups (id, org_id, name) VALUES ($1,$2,'g')`, grp, org)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	site, err := svc.RegisterSite(ctx, org, "hq")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := svc.BindNode(ctx, org, site.ID, node); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if _, err := svc.AddSubnet(ctx, org, site.ID, netip.MustParsePrefix("10.20.0.0/24")); err != nil {
		t.Fatalf("subnet: %v", err)
	}
	// A policy rule naming the site as dst → referenced (must cascade on delete).
	ex(`INSERT INTO policy_rules (id, org_id, src_kind, src_group_id, dst_kind, dst_site_id)
	    VALUES ($1,$2,'group',$3,'site',$4)`, uuid.New(), org, grp, site.ID)

	// GetReferences reports the real cascade counts the UI previews.
	refs, err := svc.GetReferences(ctx, org, site.ID)
	if err != nil || refs.RuleCount != 1 || refs.SubnetCount != 1 {
		t.Fatalf("references must be {rules:1, subnets:1}, got %+v (%v)", refs, err)
	}

	if err := svc.DeleteSite(ctx, user, org, site.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// Site gone; the referencing rule + subnet cascaded; the gateway unbound.
	if _, err := svc.GetSite(ctx, org, site.ID); err == nil {
		t.Fatal("site must be gone after delete")
	}
	var rules, subs int
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM policy_rules WHERE dst_site_id=$1`, site.ID).Scan(&rules)
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM site_subnets WHERE site_id=$1`, site.ID).Scan(&subs)
	if rules != 0 || subs != 0 {
		t.Fatalf("cascade must remove referencing rules + subnets, got rules=%d subs=%d", rules, subs)
	}
	var bound int
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM nodes WHERE site_id=$1`, site.ID).Scan(&bound)
	if bound != 0 {
		t.Fatalf("the gateway must be unbound after site delete, still bound: %d", bound)
	}
	// The audit row records the REAL cascade counts (never "may affect").
	var auditRules, auditSubs int
	err = pool.QueryRow(ctx, `SELECT (metadata->>'rules_deleted')::int, (metadata->>'subnets_released')::int
	    FROM audit_logs WHERE org_id=$1 AND action='site.deleted'`, org).Scan(&auditRules, &auditSubs)
	if err != nil || auditRules != 1 || auditSubs != 1 {
		t.Fatalf("site.deleted audit must record real counts {1,1}, got {%d,%d} (%v)", auditRules, auditSubs, err)
	}
	// A re-delete is a clean 404, not a crash.
	if err := svc.DeleteSite(ctx, user, org, site.ID); err == nil {
		t.Fatal("re-deleting an absent site must be a 404")
	}
}

// TestApproveSubnetDisjointness — S8.1 Slice-4 D5/D7: approval runs the ONE disjointness validator.
// A subnet overlapping an APPROVED site subnet or the pool is REFUSED (typed, stays pending, audited);
// an ADJACENT (touching-but-disjoint) subnet is APPROVED; approvals + refusals are both audited.
func TestApproveSubnetDisjointness(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, actor := uuid.New(), uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'S',$2,'10.99.0.0/24')`, org, "adv-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	if _, e := pool.Exec(ctx, `INSERT INTO users (id,email) VALUES ($1,$2)`, actor, "a-"+actor.String()[:8]+"@ex.com"); e != nil {
		t.Fatalf("seed actor: %v", e)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor)
	})
	site, err := svc.RegisterSite(ctx, org, "hq")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	add := func(cidr string) sqlc.SiteSubnet {
		s, e := svc.AddSubnet(ctx, org, site.ID, netip.MustParsePrefix(cidr))
		if e != nil {
			t.Fatalf("add %s: %v", cidr, e)
		}
		return s
	}
	status := func(id uuid.UUID) string {
		var st string
		_ = pool.QueryRow(ctx, `SELECT status FROM site_subnets WHERE id=$1`, id).Scan(&st)
		return st
	}

	// Disjoint → APPROVED.
	s1 := add("10.20.0.0/24")
	if err := svc.ApproveSubnet(ctx, actor, org, s1.ID); err != nil {
		t.Fatalf("disjoint approve: %v", err)
	}
	if status(s1.ID) != "approved" {
		t.Fatal("disjoint subnet must be approved")
	}
	// Overlaps the approved s1 → REFUSED (stays pending).
	s2 := add("10.20.0.128/25")
	if err := svc.ApproveSubnet(ctx, actor, org, s2.ID); err == nil || status(s2.ID) != "pending" {
		t.Fatalf("overlapping-approved must be refused + stay pending (err=%v status=%s)", err, status(s2.ID))
	}
	// Overlaps the POOL (10.99.0.0/24) → REFUSED.
	s3 := add("10.99.0.0/25")
	if err := svc.ApproveSubnet(ctx, actor, org, s3.ID); err == nil {
		t.Fatal("overlapping-pool must be refused")
	}
	// ADJACENT to approved s1 (10.20.1.0/24 touches but does not overlap 10.20.0.0/24) → APPROVED.
	s4 := add("10.20.1.0/24")
	if err := svc.ApproveSubnet(ctx, actor, org, s4.ID); err != nil || status(s4.ID) != "approved" {
		t.Fatalf("adjacent-but-disjoint must approve (err=%v status=%s)", err, status(s4.ID))
	}

	var refused, approved int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='site.subnet_approval_refused'`, org).Scan(&refused)
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='site.subnet_approved'`, org).Scan(&approved)
	if refused < 2 {
		t.Fatalf("both refusals must be audited (outcome-not-error), got %d", refused)
	}
	if approved < 2 {
		t.Fatalf("both approvals must be audited, got %d", approved)
	}
}

// TestApproveSubnetCrossSiteDuplicate is the #1 story-end-review regression red. site_subnets
// uniqueness is per-SITE, so two DIFFERENT sites CAN advertise the same CIDR — and the disjointness
// check must catch it. A prior candidate-self-filter (a.Cidr != sub.Cidr) BYPASSED exactly this class;
// the original red's fixture had only ONE site, so it passed green over the bypass. This is the missing
// fixture family: two sites, same CIDR (exact) + a contained CIDR (containment) — both must refuse.
func TestApproveSubnetCrossSiteDuplicate(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, actor := uuid.New(), uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'S',$2,'10.99.0.0/24')`, org, "xd-"+org.String()[:8]); e != nil {
		t.Fatalf("org: %v", e)
	}
	if _, e := pool.Exec(ctx, `INSERT INTO users (id,email) VALUES ($1,$2)`, actor, "x-"+actor.String()[:8]+"@ex.com"); e != nil {
		t.Fatalf("actor: %v", e)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor)
	})
	siteA, _ := svc.RegisterSite(ctx, org, "site-a")
	siteB, _ := svc.RegisterSite(ctx, org, "site-b")
	addTo := func(siteID uuid.UUID, cidr string) sqlc.SiteSubnet {
		s, e := svc.AddSubnet(ctx, org, siteID, netip.MustParsePrefix(cidr))
		if e != nil {
			t.Fatalf("add %s: %v", cidr, e)
		}
		return s
	}
	status := func(id uuid.UUID) string {
		var st string
		_ = pool.QueryRow(ctx, `SELECT status FROM site_subnets WHERE id=$1`, id).Scan(&st)
		return st
	}
	// Approve 10.30.0.0/24 on site A.
	a1 := addTo(siteA.ID, "10.30.0.0/24")
	if err := svc.ApproveSubnet(ctx, actor, org, a1.ID); err != nil {
		t.Fatalf("approve A: %v", err)
	}
	// site B, EXACT-DUPLICATE CIDR across sites → REFUSED (the bypass class the filter exempted).
	b1 := addTo(siteB.ID, "10.30.0.0/24")
	if err := svc.ApproveSubnet(ctx, actor, org, b1.ID); err == nil || status(b1.ID) != "pending" {
		t.Fatalf("an exact-duplicate CIDR across sites must be refused (err=%v status=%s)", err, status(b1.ID))
	}
	// site B, CONTAINED CIDR (10.30.0.0/25 ⊂ site A's /24) → REFUSED (containment via the same path).
	b2 := addTo(siteB.ID, "10.30.0.0/25")
	if err := svc.ApproveSubnet(ctx, actor, org, b2.ID); err == nil || status(b2.ID) != "pending" {
		t.Fatalf("a contained CIDR across sites must be refused (err=%v status=%s)", err, status(b2.ID))
	}
}

// TestUnbindSiteNode is the S8.6 #3 red (explicit-node-id unbind): a site holds TWO gateways (post the
// single-node lift); UnbindSiteNode detaches EXACTLY the named one — the other stays bound (no arbitrary
// :one pick). A second unbind of the same node is a typed 404 (not bound to this site).
func TestUnbindSiteNode(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, nodeA, nodeB := uuid.New(), uuid.New(), uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug) VALUES ($1,'S',$2)`, org, "ub-"+org.String()[:8]); e != nil {
		t.Fatalf("org: %v", e)
	}
	for i, node := range []uuid.UUID{nodeA, nodeB} {
		if _, e := pool.Exec(ctx, `INSERT INTO nodes (id,org_id,name,cert_serial,enrolled_kind) VALUES ($1,$2,$3,$4,'gateway')`,
			node, org, "gw"+string(rune('A'+i)), "cs-ub-"+node.String()[:8]); e != nil {
			t.Fatalf("node: %v", e)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })
	site, _ := svc.RegisterSite(ctx, org, "hq")
	if err := svc.BindNode(ctx, org, site.ID, nodeA); err != nil {
		t.Fatalf("bind A: %v", err)
	}
	if err := svc.BindNode(ctx, org, site.ID, nodeB); err != nil {
		t.Fatalf("bind B (a site may hold multiple gateways): %v", err)
	}
	// Unbind EXACTLY nodeA — nodeB must stay bound (the #3 proof: the named node, never an arbitrary pick).
	if err := svc.UnbindSiteNode(ctx, org, site.ID, nodeA); err != nil {
		t.Fatalf("unbind A: %v", err)
	}
	var aSite, bBound *uuid.UUID
	_ = pool.QueryRow(ctx, `SELECT site_id FROM nodes WHERE id=$1`, nodeA).Scan(&aSite)
	if aSite != nil {
		t.Fatalf("nodeA must be unbound, still bound to %v", *aSite)
	}
	_ = pool.QueryRow(ctx, `SELECT site_id FROM nodes WHERE id=$1`, nodeB).Scan(&bBound)
	if bBound == nil || *bBound != site.ID {
		t.Fatalf("nodeB must REMAIN bound to the site (only the named node unbinds), got %v", bBound)
	}
	// A second unbind of nodeA (no longer bound to this site) is a typed 404.
	if err := svc.UnbindSiteNode(ctx, org, site.ID, nodeA); err == nil {
		t.Fatal("unbinding a node not bound to this site must 404")
	}
}

// TestDNSForwardCRUD — S8.4 D7: a forwarded zone is added (resolver validated inside an approved subnet),
// a duplicate domain on ANOTHER site is refused (D1-addition), removal is audited + full-sweep.
func TestDNSForwardCRUD(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, actor := uuid.New(), uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'S',$2,'10.99.0.0/24')`, org, "dns-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	if _, e := pool.Exec(ctx, `INSERT INTO users (id,email) VALUES ($1,$2)`, actor, "a-"+actor.String()[:8]+"@ex.com"); e != nil {
		t.Fatalf("seed actor: %v", e)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor)
	})
	siteA, err := svc.RegisterSite(ctx, org, "hq")
	if err != nil {
		t.Fatalf("register A: %v", err)
	}
	sub, err := svc.AddSubnet(ctx, org, siteA.ID, netip.MustParsePrefix("10.20.0.0/24"))
	if err != nil {
		t.Fatalf("add subnet: %v", err)
	}
	if err := svc.ApproveSubnet(ctx, actor, org, sub.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Resolver NOT in an approved subnet → refused.
	if err := svc.SetDNSForward(ctx, actor, org, siteA.ID, "corp.local", "192.168.9.9"); err == nil {
		t.Fatal("a resolver outside the site's approved subnets must be refused")
	}
	// Resolver inside the approved subnet → accepted + audited + compiled.
	if err := svc.SetDNSForward(ctx, actor, org, siteA.ID, "Corp.Local.", "10.20.0.53"); err != nil {
		t.Fatalf("set dns forward: %v", err)
	}
	fwds, _ := svc.q.ListSiteDNSForwardsForOrg(ctx, org)
	if len(fwds) == 0 {
		t.Fatal("the forward must be persisted")
	}
	var audited int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='site.dns_forwarding_set'`, org).Scan(&audited)
	if audited != 1 {
		t.Fatalf("set must be audited; got %d", audited)
	}

	// Another site claiming the same domain (normalized) → conflict.
	siteB, _ := svc.RegisterSite(ctx, org, "branch")
	subB, _ := svc.AddSubnet(ctx, org, siteB.ID, netip.MustParsePrefix("10.30.0.0/24"))
	_ = svc.ApproveSubnet(ctx, actor, org, subB.ID)
	if err := svc.SetDNSForward(ctx, actor, org, siteB.ID, "corp.local", "10.30.0.53"); err == nil {
		t.Fatal("a domain already forwarded by another site must conflict (one zone → one resolver)")
	}

	// Remove → gone + audited.
	if err := svc.RemoveDNSForward(ctx, actor, org, siteA.ID, "corp.local"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	var removed int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='site.dns_forwarding_removed'`, org).Scan(&removed)
	if removed != 1 {
		t.Fatalf("remove must be audited; got %d", removed)
	}
	// After removal siteB may now claim it (no longer a conflict).
	if err := svc.SetDNSForward(ctx, actor, org, siteB.ID, "corp.local", "10.30.0.53"); err != nil {
		t.Fatalf("after removal the domain is free for another site: %v", err)
	}
}

// TestSetDNSForwardRejectsK8sZoneCollision — S10.3 (A) cross-mechanism one-zone-one-resolver: a site cannot
// forward a domain that collides with a registered K8s cluster's DNS zone (<cluster>.<dns_zone>). The
// resolver is inside an approved subnet so the check reached is the zone-collision one, not the subnet gate.
func TestSetDNSForwardRejectsK8sZoneCollision(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, actor := uuid.New(), uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'S',$2,'10.99.0.0/24')`, org, "kz-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	if _, e := pool.Exec(ctx, `INSERT INTO users (id,email) VALUES ($1,$2)`, actor, "a-"+actor.String()[:8]+"@ex.com"); e != nil {
		t.Fatalf("seed actor: %v", e)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor)
	})
	site, _ := svc.RegisterSite(ctx, org, "hq")
	sub, _ := svc.AddSubnet(ctx, org, site.ID, netip.MustParsePrefix("10.20.0.0/24"))
	_ = svc.ApproveSubnet(ctx, actor, org, sub.ID)
	// A K8s cluster owns zone prod.k8s.acme.com.
	if _, e := pool.Exec(ctx, `INSERT INTO k8s_clusters (id,org_id,site_id,name,vip_range,dns_zone) VALUES ($1,$2,$3,'prod','100.64.0.0/16','k8s.acme.com')`, uuid.New(), org, site.ID); e != nil {
		t.Fatalf("seed cluster: %v", e)
	}
	// Forwarding that exact zone (resolver IN the approved subnet, so it clears the subnet gate) → refused.
	if err := svc.SetDNSForward(ctx, actor, org, site.ID, "prod.k8s.acme.com", "10.20.0.53"); err == nil || !strings.Contains(err.Error(), "dns_domain_conflict") {
		t.Fatalf("forwarding a domain that collides with a K8s cluster zone must refuse, got %v", err)
	}
}

// TestRemoveSubnet — WF-5: a mis-advertised subnet is removable without deleting the whole site; the
// removal is audited, and it is org-scoped (a foreign org can't remove it).
func TestRemoveSubnet(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, actor := uuid.New(), uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'S',$2,'10.99.0.0/24')`, org, "rm-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	if _, e := pool.Exec(ctx, `INSERT INTO users (id,email) VALUES ($1,$2)`, actor, "a-"+actor.String()[:8]+"@ex.com"); e != nil {
		t.Fatalf("seed actor: %v", e)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor)
	})
	site, err := svc.RegisterSite(ctx, org, "hq")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	sub, err := svc.AddSubnet(ctx, org, site.ID, netip.MustParsePrefix("10.20.0.0/24"))
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	// Cross-org safety: a DIFFERENT org can't remove this subnet.
	if err := svc.RemoveSubnet(ctx, actor, uuid.New(), sub.ID); err == nil {
		t.Fatal("removing a subnet from a foreign org must fail (subnet_not_found)")
	}
	var stillThere int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM site_subnets WHERE id=$1`, sub.ID).Scan(&stillThere)
	if stillThere != 1 {
		t.Fatal("a cross-org remove must NOT delete the subnet")
	}
	// Owning org removes it → gone + audited.
	if err := svc.RemoveSubnet(ctx, actor, org, sub.ID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	var gone int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM site_subnets WHERE id=$1`, sub.ID).Scan(&gone)
	if gone != 0 {
		t.Fatal("the subnet must be removed")
	}
	var audited int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='site.subnet_removed'`, org).Scan(&audited)
	if audited != 1 {
		t.Fatalf("the removal must be audited (site.subnet_removed); got %d", audited)
	}
}

// TestRemoveSubnetSweepsDependentDNS (F4) — the full-sweep law's DNS instance: removing a subnet also
// removes any DNS forward whose resolver lived inside it (that resolver is now unrouted), in the same tx;
// a forward with a resolver elsewhere survives. The swept set is named in the audit.
func TestRemoveSubnetSweepsDependentDNS(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, actor := uuid.New(), uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'S',$2,'10.99.0.0/24')`, org, "sw-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	if _, e := pool.Exec(ctx, `INSERT INTO users (id,email) VALUES ($1,$2)`, actor, "a-"+actor.String()[:8]+"@ex.com"); e != nil {
		t.Fatalf("seed actor: %v", e)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor)
	})
	site, err := svc.RegisterSite(ctx, org, "hq")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	// Two approved subnets; a forward resolver in each.
	subA, _ := svc.AddSubnet(ctx, org, site.ID, netip.MustParsePrefix("10.20.0.0/24"))
	subB, _ := svc.AddSubnet(ctx, org, site.ID, netip.MustParsePrefix("10.30.0.0/24"))
	if err := svc.ApproveSubnet(ctx, actor, org, subA.ID); err != nil {
		t.Fatalf("approve A: %v", err)
	}
	if err := svc.ApproveSubnet(ctx, actor, org, subB.ID); err != nil {
		t.Fatalf("approve B: %v", err)
	}
	if err := svc.SetDNSForward(ctx, actor, org, site.ID, "corp.local", "10.20.0.53"); err != nil {
		t.Fatalf("forward A: %v", err)
	}
	if err := svc.SetDNSForward(ctx, actor, org, site.ID, "branch.local", "10.30.0.53"); err != nil {
		t.Fatalf("forward B: %v", err)
	}
	// Remove subnet A → corp.local (resolver 10.20.0.53) swept; branch.local survives.
	if err := svc.RemoveSubnet(ctx, actor, org, subA.ID); err != nil {
		t.Fatalf("remove subnet A: %v", err)
	}
	left, _ := svc.ListDNSForwards(ctx, org, site.ID)
	if len(left) != 1 || left[0].Domain != "branch.local" {
		t.Fatalf("only the in-subnet forward must be swept; left=%+v", left)
	}
	var meta string
	_ = pool.QueryRow(ctx, `SELECT metadata::text FROM audit_logs WHERE org_id=$1 AND action='site.subnet_removed' ORDER BY created_at DESC LIMIT 1`, org).Scan(&meta)
	if !strings.Contains(meta, "corp.local") {
		t.Fatalf("the removal audit must name the swept forward; meta=%s", meta)
	}
}

// TestListRoutedRanges (S8.5 Slice 2b) — the routed-ranges channel: APPROVED-only, org-scoped (the
// comparison-set law's hidden collision: the SAME CIDR declared in two orgs, org A sees only its own),
// canonical + sorted + deterministic, and EMPTY is a first-class answer.
func TestListRoutedRanges(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	orgA, orgB, orgC, actor := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for i, org := range []uuid.UUID{orgA, orgB, orgC} {
		if _, e := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'S',$2,'10.99.0.0/24')`, org, "rr-"+org.String()[:8]); e != nil {
			t.Fatalf("seed org %d: %v", i, e)
		}
	}
	if _, e := pool.Exec(ctx, `INSERT INTO users (id,email) VALUES ($1,$2)`, actor, "a-"+actor.String()[:8]+"@ex.com"); e != nil {
		t.Fatalf("seed actor: %v", e)
	}
	t.Cleanup(func() {
		for _, org := range []uuid.UUID{orgA, orgB, orgC} {
			_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org)
		}
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor)
	})
	approve := func(org uuid.UUID, site string, cidr string) {
		s, err := svc.RegisterSite(ctx, org, site)
		if err != nil {
			t.Fatalf("register %s: %v", site, err)
		}
		sub, err := svc.AddSubnet(ctx, org, s.ID, netip.MustParsePrefix(cidr))
		if err != nil {
			t.Fatalf("add %s: %v", cidr, err)
		}
		if err := svc.ApproveSubnet(ctx, actor, org, sub.ID); err != nil {
			t.Fatalf("approve %s: %v", cidr, err)
		}
	}
	// org A: two APPROVED (added out of sorted order) + one PENDING (advertised, NOT approved).
	approve(orgA, "hq", "10.20.0.0/24")
	approve(orgA, "dc", "10.10.0.0/24")
	siteP, _ := svc.RegisterSite(ctx, orgA, "pending-site")
	if _, err := svc.AddSubnet(ctx, orgA, siteP.ID, netip.MustParsePrefix("10.30.0.0/24")); err != nil {
		t.Fatalf("add pending: %v", err)
	} // left pending
	// org B: the SAME 10.20.0.0/24 (cross-org — allowed; disjointness is per-org) + one of its own.
	approve(orgB, "b1", "10.20.0.0/24")
	approve(orgB, "b2", "172.16.0.0/24")

	// (1) approved-only + cross-org: org A returns ONLY its two APPROVED, sorted+canonical, pending EXCLUDED,
	// org B's collision EXCLUDED.
	got, err := svc.ListRoutedRanges(ctx, orgA)
	if err != nil {
		t.Fatalf("list A: %v", err)
	}
	if want := []string{"10.10.0.0/24", "10.20.0.0/24"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("org A ranges: got %v want %v (pending must be absent, org B's collision must not leak)", got, want)
	}
	// (2) deterministic: a second call is byte-identical (the client's churn-free merge depends on it).
	if got2, _ := svc.ListRoutedRanges(ctx, orgA); !reflect.DeepEqual(got, got2) {
		t.Fatalf("non-deterministic: %v vs %v", got, got2)
	}
	// (3) org B sees only its own (the collision belongs to whoever declared it, scoped).
	if gotB, _ := svc.ListRoutedRanges(ctx, orgB); !reflect.DeepEqual(gotB, []string{"10.20.0.0/24", "172.16.0.0/24"}) {
		t.Fatalf("org B ranges: %v", gotB)
	}
	// (4) empty is first-class: a no-ranges org returns [] (non-nil, len 0), zero client work downstream.
	gotC, err := svc.ListRoutedRanges(ctx, orgC)
	if err != nil {
		t.Fatalf("list C: %v", err)
	}
	if gotC == nil || len(gotC) != 0 {
		t.Fatalf("empty must be a non-nil [], got %#v", gotC)
	}
}

// TestListRoutedForwardsGating (S8.5 Slice 3, D4) — the DNS handoff's split-horizon gate: a forward is
// handed to a device ONLY if its resolver is REACHABLE via the device's routed ranges. Two sites each
// declare an approved subnet + a forwarded zone; with BOTH ranges routed, both forwards return — but drop
// one range from the routed set and its site's forward vanishes (a resolver you can't reach is never a
// SERVFAIL generator wearing a feature's face). Empty ranges → zero forwards, first-class.
func TestListRoutedForwardsGating(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, actor := uuid.New(), uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'S',$2,'10.99.0.0/24')`, org, "rf-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	if _, e := pool.Exec(ctx, `INSERT INTO users (id,email) VALUES ($1,$2)`, actor, "a-"+actor.String()[:8]+"@ex.com"); e != nil {
		t.Fatalf("seed actor: %v", e)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor)
	})
	mkSite := func(name, cidr, domain, resolver string) {
		s, err := svc.RegisterSite(ctx, org, name)
		if err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
		sub, err := svc.AddSubnet(ctx, org, s.ID, netip.MustParsePrefix(cidr))
		if err != nil {
			t.Fatalf("add %s: %v", cidr, err)
		}
		if err := svc.ApproveSubnet(ctx, actor, org, sub.ID); err != nil {
			t.Fatalf("approve %s: %v", cidr, err)
		}
		if err := svc.SetDNSForward(ctx, actor, org, s.ID, domain, resolver); err != nil {
			t.Fatalf("forward %s: %v", domain, err)
		}
	}
	mkSite("hq", "10.20.0.0/24", "corp.local", "10.20.0.53")
	mkSite("branch", "10.30.0.0/24", "branch.internal", "10.30.0.53")

	ranges, err := svc.ListRoutedRanges(ctx, org)
	if err != nil {
		t.Fatalf("ranges: %v", err)
	}
	// (1) BOTH ranges routed → BOTH forwards reachable, domain-sorted + deduped.
	both, err := svc.ListRoutedForwards(ctx, org, ranges)
	if err != nil {
		t.Fatalf("forwards: %v", err)
	}
	want := []DNSForward{{Domain: "branch.internal", ResolverIP: "10.30.0.53"}, {Domain: "corp.local", ResolverIP: "10.20.0.53"}}
	if !reflect.DeepEqual(both, want) {
		t.Fatalf("both-reachable forwards: got %v want %v", both, want)
	}
	// (2) GATE: drop the branch range from the routed set → branch's resolver is unreachable → its forward
	// is EXCLUDED (by construction, not assumed). Only corp.local survives.
	gated, err := svc.ListRoutedForwards(ctx, org, []string{"10.20.0.0/24"})
	if err != nil {
		t.Fatalf("gated forwards: %v", err)
	}
	if !reflect.DeepEqual(gated, []DNSForward{{Domain: "corp.local", ResolverIP: "10.20.0.53"}}) {
		t.Fatalf("gated forwards: got %v — an unreachable resolver must NOT be handed over", gated)
	}
	// (3) empty ranges → zero forwards, non-nil [].
	none, err := svc.ListRoutedForwards(ctx, org, nil)
	if err != nil {
		t.Fatalf("empty-range forwards: %v", err)
	}
	if none == nil || len(none) != 0 {
		t.Fatalf("no reachable ranges must yield a non-nil [], got %#v", none)
	}
}

// TestListRoutedForwardsIncludesFQDNResolverProfiles is the missing S21 desktop
// handoff regression: the resolver profile used by Gateway DNS RPC must also
// reach the desktop through the existing routed-ranges `forwards` payload. The
// user must not duplicate the profile under Site DNS Forwarding.
func TestListRoutedForwardsIncludesFQDNResolverProfiles(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, actor, gateway := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'FQDN',$2,'10.99.0.0/24')`, org, "fqdn-forward-"+org.String()[:8]); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id,email) VALUES ($1,$2)`, actor, "fqdn-forward-"+actor.String()[:8]+"@ex.com"); err != nil {
		t.Fatalf("seed actor: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor)
	})

	site, err := svc.RegisterSite(ctx, org, "azure-private")
	if err != nil {
		t.Fatalf("register site: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO nodes (id,org_id,site_id,name,cert_serial,enrolled_kind) VALUES ($1,$2,$3,'azure-gateway',$4,'gateway')`, gateway, org, site.ID, "fqdn-forward-"+gateway.String()[:8]); err != nil {
		t.Fatalf("seed gateway: %v", err)
	}
	subnet, err := svc.AddSubnet(ctx, org, site.ID, netip.MustParsePrefix("172.16.0.0/16"))
	if err != nil {
		t.Fatalf("add routed subnet: %v", err)
	}
	if err := svc.ApproveSubnet(ctx, actor, org, subnet.ID); err != nil {
		t.Fatalf("approve routed subnet: %v", err)
	}

	resolverSvc := fqdnresources.New(pool)
	if _, err := resolverSvc.SetResolverProfiles(ctx, org, site.ID, gateway, actor, "", "test", []fqdnresources.ResolverProfile{{
		Name:         "Azure private DNS",
		ProviderHint: "azure",
		ZoneSuffixes: []string{"internal.tunnex.io"},
		Endpoints: []fqdnresources.ResolverEndpoint{
			// TCP-only and non-standard-port endpoints are valid for Gateway DNS
			// RPC but cannot be represented by /etc/resolver or NRPT.
			{Address: "172.16.2.2", Port: 53, Transport: "tcp"},
			{Address: "172.16.2.3", Port: 5353, Transport: "udp"},
			{Address: "172.16.2.4", Port: 53, Transport: "udp"},
		},
	}}); err != nil {
		t.Fatalf("configure resolver profile: %v", err)
	}

	ranges, err := svc.ListRoutedRanges(ctx, org)
	if err != nil {
		t.Fatalf("list routed ranges: %v", err)
	}
	got, err := svc.ListRoutedForwards(ctx, org, ranges)
	if err != nil {
		t.Fatalf("list routed forwards: %v", err)
	}
	want := []DNSForward{{Domain: "internal.tunnex.io", ResolverIP: "172.16.2.4"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FQDN profile forward: got %+v want %+v", got, want)
	}

	// The same active profile is withheld when its endpoint is outside the
	// device's routed set; a knowingly unreachable resolver is never installed.
	gated, err := svc.ListRoutedForwards(ctx, org, []string{"10.20.0.0/24"})
	if err != nil {
		t.Fatalf("list gated forwards: %v", err)
	}
	if gated == nil || len(gated) != 0 {
		t.Fatalf("unreachable profile resolver must yield a non-nil empty set, got %#v", gated)
	}
}

// TestRoutedChannelIncludesK8s — S10.3 fork-1 (the CLIENT half of the exposed-Service feature): the org's
// K8s VIP range joins the device's routed set, and the cluster-zone → reserved-DNS-VIP mapping rides the
// routed-FORWARDS channel (so a split-tunnel/OVPN client both ROUTES the VIP range and RESOLVES the zone).
// The reachability gate holds by construction (the DNS VIP is inside the routed VIP range). Zero-config is
// covered by the existing TestListRoutedRanges passing unchanged for non-cluster orgs.
func TestRoutedChannelIncludesK8s(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, site := uuid.New(), uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'K',$2,'10.99.0.0/24')`, org, "k8srr-"+org.String()[:8]); e != nil {
		t.Fatal(e)
	}
	if _, e := pool.Exec(ctx, `INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'s')`, site, org); e != nil {
		t.Fatal(e)
	}
	connID := uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO nodes (id,org_id,site_id,name,cert_serial,enrolled_kind) VALUES ($1,$2,$3,$4,$5,'gateway')`, connID, org, site, "k8s-connector-"+connID.String()[:8], connID.String()); e != nil {
		t.Fatal(e)
	}
	// A registered cluster with a VIP range + reserved DNS VIP (.2, inside the range).
	clusterID := uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO k8s_clusters (id,org_id,connector_node_id,site_id,name,vip_range,service_cidr,dns_zone,dns_vip) VALUES ($1,$2,$3,$4,'prod','100.64.0.0/16','10.96.0.0/12','k8s.acme.com','100.64.0.2')`, clusterID, org, connID, site); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	// (1) the VIP range is in the device's routed set (WireGuard AllowedIPs) — as soon as the cluster exists
	// (routing the range is independent of whether a Service is exposed yet).
	ranges, err := svc.ListRoutedRanges(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range ranges {
		if r == "100.64.0.0/16" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the K8s VIP range must be in the device's routed set, got %v", ranges)
	}
	// (L2) a cluster with ZERO exposed Services emits NO zone forward — the gateway would REFUSE it (no
	// K8sDNSZone), so the client must not install a resolver for it (consumer/producer agree by construction).
	pre, err := svc.ListRoutedForwards(ctx, org, ranges)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range pre {
		if f.Domain == "prod.k8s.acme.com" {
			t.Fatalf("a cluster with no exposed Service must emit NO zone forward, got %v", pre)
		}
	}
	// Expose a Service → the gateway now serves the zone → the forward APPEARS.
	if _, e := pool.Exec(ctx, `INSERT INTO k8s_services (id,org_id,cluster_id,name,namespace,protocol,vip) VALUES ($1,$2,$3,'api','prod','tcp','100.64.0.3')`, uuid.New(), org, clusterID); e != nil {
		t.Fatal(e)
	}
	// (2) the cluster-zone → DNS-VIP resolver rides the routed-forwards channel, reachable via that range.
	fwds, err := svc.ListRoutedForwards(ctx, org, ranges)
	if err != nil {
		t.Fatal(err)
	}
	gotZone := false
	for _, f := range fwds {
		if f.Domain == "prod.k8s.acme.com" && f.ResolverIP == "100.64.0.2" {
			gotZone = true
		}
	}
	if !gotZone {
		t.Fatalf("once a Service is exposed the cluster zone must forward to its reserved DNS VIP, got %v", fwds)
	}
	// (3) GATE by construction: if the VIP range is NOT routed, the DNS-VIP resolver is unreachable → dropped.
	gated, err := svc.ListRoutedForwards(ctx, org, []string{"10.20.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range gated {
		if f.ResolverIP == "100.64.0.2" {
			t.Fatalf("an unroutable DNS VIP must NOT be handed over, got %v", gated)
		}
	}
}

// TestRouteLANByteIdentical (S8.5 Slice 2d, D1) — the one-screen RouteLAN produces DB state + an audit
// trail BYTE-IDENTICAL to the four-step long ceremony. Same code composed, so the short path is exactly
// as auditable as the long one (four constituent events, never a composite).
func TestRouteLANByteIdentical(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	orgA, orgB, actor, nodeA, nodeB := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("seed %q: %v", sql, e)
		}
	}
	ex(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'A',$2,'10.99.0.0/24')`, orgA, "rla-"+orgA.String()[:8])
	ex(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'B',$2,'10.99.0.0/24')`, orgB, "rlb-"+orgB.String()[:8])
	ex(`INSERT INTO users (id,email) VALUES ($1,$2)`, actor, "a-"+actor.String()[:8]+"@ex.com")
	ex(`INSERT INTO nodes (id,org_id,name,cert_serial,enrolled_kind) VALUES ($1,$2,'gw',$3,'gateway')`, nodeA, orgA, "cs-a-"+nodeA.String()[:8])
	ex(`INSERT INTO nodes (id,org_id,name,cert_serial,enrolled_kind) VALUES ($1,$2,'gw',$3,'gateway')`, nodeB, orgB, "cs-b-"+nodeB.String()[:8])
	t.Cleanup(func() {
		for _, org := range []uuid.UUID{orgA, orgB} {
			_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org)
		}
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor)
	})
	cidr := netip.MustParsePrefix("10.20.0.0/24")

	// SHORT path (org A): one call.
	siteA, subA, err := svc.RouteLAN(ctx, actor, orgA, nodeA, "hq", cidr)
	if err != nil {
		t.Fatalf("routeLAN: %v", err)
	}
	// LONG path (org B): the four manual steps.
	siteB, err := svc.RegisterSite(ctx, orgB, "hq")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := svc.BindNode(ctx, orgB, siteB.ID, nodeB); err != nil {
		t.Fatalf("bind: %v", err)
	}
	subB, err := svc.AddSubnet(ctx, orgB, siteB.ID, cidr)
	if err != nil {
		t.Fatalf("advertise: %v", err)
	}
	if err := svc.ApproveSubnet(ctx, actor, orgB, subB.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// DB STATE: the gateway is bound to the site; the subnet is approved — in BOTH orgs.
	boundNode := func(node uuid.UUID) string {
		var sid uuid.UUID
		_ = pool.QueryRow(ctx, `SELECT site_id FROM nodes WHERE id=$1`, node).Scan(&sid)
		return sid.String()
	}
	if boundNode(nodeA) != siteA.ID.String() || boundNode(nodeB) != siteB.ID.String() {
		t.Fatalf("both gateways must be bound: A=%s(site %s) B=%s(site %s)", boundNode(nodeA), siteA.ID, boundNode(nodeB), siteB.ID)
	}
	subStatus := func(sub uuid.UUID) string {
		var st string
		_ = pool.QueryRow(ctx, `SELECT status FROM site_subnets WHERE id=$1`, sub).Scan(&st)
		return st
	}
	if subStatus(subA.ID) != "approved" || subStatus(subB.ID) != "approved" {
		t.Fatalf("both subnets must be approved: A=%s B=%s", subStatus(subA.ID), subStatus(subB.ID))
	}

	// AUDIT TRAIL: the same multiset of actions in both orgs (the four constituent events, never a composite).
	auditActions := func(org uuid.UUID) []string {
		rows, e := pool.Query(ctx, `SELECT action FROM audit_logs WHERE org_id=$1 ORDER BY action`, org)
		if e != nil {
			t.Fatalf("audit query: %v", e)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var a string
			_ = rows.Scan(&a)
			out = append(out, a)
		}
		return out
	}
	aA, aB := auditActions(orgA), auditActions(orgB)
	if !reflect.DeepEqual(aA, aB) {
		t.Fatalf("audit trails must be IDENTICAL (same code, four constituent events): short=%v long=%v", aA, aB)
	}
	if len(aA) == 0 {
		t.Fatal("expected constituent audit events, got none")
	}
}

// TestGatewayCarrierEligibility closes the Route a LAN/UI seam at the service boundary:
// an AI Agent is a Node row, but cannot be made into a Site carrier by a crafted request.
func TestGatewayCarrierEligibility(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, actor, agent, gateway := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	ex(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'carrier',$2,'10.99.0.0/24')`, org, "carrier-"+org.String()[:8])
	ex(`INSERT INTO users (id,email) VALUES ($1,$2)`, actor, "carrier-"+actor.String()[:8]+"@example.test")
	ex(`INSERT INTO nodes (id,org_id,name,cert_serial,enrolled_kind) VALUES ($1,$2,'agent-node',$3,'agent')`, agent, org, "agent-"+agent.String()[:8])
	ex(`INSERT INTO nodes (id,org_id,name,cert_serial,enrolled_kind) VALUES ($1,$2,'gateway-node',$3,'gateway')`, gateway, org, "gateway-"+gateway.String()[:8])
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor)
	})

	site, err := svc.RegisterSite(ctx, org, "site")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := svc.BindNode(ctx, org, site.ID, agent); !hasCode(err, "node_not_gateway_eligible") {
		t.Fatalf("BindNode(agent) error = %v, want node_not_gateway_eligible", err)
	}
	if _, _, err := svc.RouteLAN(ctx, actor, org, agent, "agent-lan", netip.MustParsePrefix("10.88.0.0/24")); !hasCode(err, "node_not_gateway_eligible") {
		t.Fatalf("RouteLAN(agent) error = %v, want node_not_gateway_eligible", err)
	}
	var sites int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sites WHERE org_id=$1`, org).Scan(&sites); err != nil || sites != 1 {
		t.Fatalf("agent RouteLAN must not create a site: count=%d err=%v", sites, err)
	}
	if _, _, err := svc.RouteLAN(ctx, actor, org, gateway, "gateway-lan", netip.MustParsePrefix("10.77.0.0/24")); err != nil {
		t.Fatalf("RouteLAN(gateway): %v", err)
	}
}

func hasCode(err error, want string) bool {
	var apiErr *apierr.Error
	return errors.As(err, &apiErr) && apiErr.Code == want
}

// TestBindNodeRefusesRehome (S8.5 #2 standalone) — BindNode must NEVER silently re-home a bound gateway:
// a second bind to a DIFFERENT site refuses `node_already_bound_to_site`, the gateway stays on site1, and
// a re-bind to the SAME site is an idempotent no-op (RouteLAN's resume relies on it).
func TestBindNodeRefusesRehome(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, node := uuid.New(), uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'S',$2,'10.99.0.0/24')`, org, "rh-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	if _, e := pool.Exec(ctx, `INSERT INTO nodes (id,org_id,name,cert_serial,enrolled_kind) VALUES ($1,$2,'gw',$3,'gateway')`, node, org, "cs-"+node.String()[:8]); e != nil {
		t.Fatalf("seed node: %v", e)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	site1, _ := svc.RegisterSite(ctx, org, "s1")
	site2, _ := svc.RegisterSite(ctx, org, "s2")
	if err := svc.BindNode(ctx, org, site1.ID, node); err != nil {
		t.Fatalf("first bind: %v", err)
	}
	// Same-site re-bind: idempotent no-op.
	if err := svc.BindNode(ctx, org, site1.ID, node); err != nil {
		t.Fatalf("same-site re-bind must be a no-op, got %v", err)
	}
	// Different-site bind: REFUSED, gateway stays on site1 (no silent re-home).
	err := svc.BindNode(ctx, org, site2.ID, node)
	if err == nil {
		t.Fatal("re-home must be refused")
	}
	if ae, ok := err.(*apierr.Error); !ok || ae.Code != "node_already_bound_to_site" {
		t.Fatalf("want node_already_bound_to_site, got %v", err)
	}
	var boundSite uuid.UUID
	_ = pool.QueryRow(ctx, `SELECT site_id FROM nodes WHERE id=$1`, node).Scan(&boundSite)
	if boundSite != site1.ID {
		t.Fatalf("gateway must stay on site1 (%s), got %s", site1.ID, boundSite)
	}
}

// TestRouteLANResumeRetrySafe (S8.5 #2) — RouteLAN is retry-safe by RESUME: a disjointness refusal leaves
// site+bind+pending; a resubmit with a CORRECTED CIDR advances the SAME site (no second site, gateway not
// re-homed) and converges to ONE approved subnet (the abandoned pending is dropped).
func TestRouteLANResumeRetrySafe(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, actor, node := uuid.New(), uuid.New(), uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'S',$2,'10.99.0.0/24')`, org, "rr2-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	if _, e := pool.Exec(ctx, `INSERT INTO users (id,email) VALUES ($1,$2)`, actor, "a-"+actor.String()[:8]+"@ex.com"); e != nil {
		t.Fatalf("seed actor: %v", e)
	}
	if _, e := pool.Exec(ctx, `INSERT INTO nodes (id,org_id,name,cert_serial,enrolled_kind) VALUES ($1,$2,'gw',$3,'gateway')`, node, org, "cs-"+node.String()[:8]); e != nil {
		t.Fatalf("seed node: %v", e)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor)
	})

	// First attempt: a CIDR colliding with the pool (10.99.0.0/24) → approval refused; site+bind+pending persist.
	bad := netip.MustParsePrefix("10.99.0.0/24")
	site1, _, err := svc.RouteLAN(ctx, actor, org, node, "hq", bad)
	if err == nil {
		t.Fatal("a pool-colliding CIDR must be refused at approve")
	}
	if site1.ID == uuid.Nil {
		t.Fatal("the refused attempt must still persist its site (resume target)")
	}
	// Corrected CIDR resubmit → RESUME site1 (not a second site), gateway still homed, one approved subnet.
	good := netip.MustParsePrefix("10.9.0.0/24")
	site2, sub, err := svc.RouteLAN(ctx, actor, org, node, "hq", good)
	if err != nil {
		t.Fatalf("corrected resubmit: %v", err)
	}
	if site2.ID != site1.ID {
		t.Fatalf("resume must reuse the SAME site (no second site): first=%s second=%s", site1.ID, site2.ID)
	}
	// Exactly ONE site for this org's gateway, gateway still bound to it.
	var siteCount int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM sites WHERE org_id=$1`, org).Scan(&siteCount)
	if siteCount != 1 {
		t.Fatalf("retry must leave exactly ONE site, got %d", siteCount)
	}
	var boundSite uuid.UUID
	_ = pool.QueryRow(ctx, `SELECT site_id FROM nodes WHERE id=$1`, node).Scan(&boundSite)
	if boundSite != site1.ID {
		t.Fatalf("gateway must stay homed to the resumed site")
	}
	// The corrected CIDR is approved.
	var status, cidrStr string
	_ = pool.QueryRow(ctx, `SELECT status, cidr::text FROM site_subnets WHERE id=$1`, sub.ID).Scan(&status, &cidrStr)
	if status != "approved" || cidrStr != "10.9.0.0/24" {
		t.Fatalf("the resumed subnet must be the corrected CIDR, approved: status=%s cidr=%s", status, cidrStr)
	}
	// The abandoned CIDR (the first attempt's pending) SURVIVES — RouteLAN mutates nothing that exists
	// (re-review #1: resume must NOT hard-delete a pending advertisement; two await review, both truthful).
	var badPending int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM site_subnets WHERE site_id=$1 AND status='pending' AND cidr='10.99.0.0/24'`, site1.ID).Scan(&badPending)
	if badPending != 1 {
		t.Fatalf("the abandoned pending advertisement must survive (no destructive cleanup), got %d", badPending)
	}
}

// TestRouteLANResumeLeavesForeignPending (re-review #1) — RouteLAN resume must NEVER hard-delete a bound
// site's PENDING advertisement (a long-path admin's awaited work). Resume advertises its own CIDR and
// mutates nothing that exists.
func TestRouteLANResumeLeavesForeignPending(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, actor, node := uuid.New(), uuid.New(), uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'S',$2,'10.99.0.0/24')`, org, "fp-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	if _, e := pool.Exec(ctx, `INSERT INTO users (id,email) VALUES ($1,$2)`, actor, "a-"+actor.String()[:8]+"@ex.com"); e != nil {
		t.Fatalf("seed actor: %v", e)
	}
	if _, e := pool.Exec(ctx, `INSERT INTO nodes (id,org_id,name,cert_serial,enrolled_kind) VALUES ($1,$2,'gw',$3,'gateway')`, node, org, "cs-"+node.String()[:8]); e != nil {
		t.Fatalf("seed node: %v", e)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor)
	})

	// Long-path: a site on the gateway with a subnet advertised (PENDING, awaiting review — not approved).
	site, _ := svc.RegisterSite(ctx, org, "long-path")
	if err := svc.BindNode(ctx, org, site.ID, node); err != nil {
		t.Fatalf("bind: %v", err)
	}
	pend, err := svc.AddSubnet(ctx, org, site.ID, netip.MustParsePrefix("10.0.0.0/24"))
	if err != nil {
		t.Fatalf("advertise: %v", err)
	}

	// RouteLAN the SAME gateway with a different CIDR → resumes the site + advertises 192.168.1.0/24.
	if _, _, err := svc.RouteLAN(ctx, actor, org, node, "", netip.MustParsePrefix("192.168.1.0/24")); err != nil {
		t.Fatalf("routeLAN resume: %v", err)
	}
	// The admin's pending advertisement SURVIVES (still pending, not deleted).
	var st string
	if e := pool.QueryRow(ctx, `SELECT status FROM site_subnets WHERE id=$1`, pend.ID).Scan(&st); e != nil {
		t.Fatalf("the admin's pending subnet was DELETED (data loss): %v", e)
	}
	if st != "pending" {
		t.Fatalf("the admin's advertisement must stay pending, got %s", st)
	}
}

// TestRouteLANResumeSameCIDRNoDup (re-review #1 additive guard) — a resume whose CIDR already exists on the
// site reuses that subnet (idempotent), never a duplicate row.
func TestRouteLANResumeSameCIDRNoDup(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, actor, node := uuid.New(), uuid.New(), uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'S',$2,'10.99.0.0/24')`, org, "sc-"+org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	if _, e := pool.Exec(ctx, `INSERT INTO users (id,email) VALUES ($1,$2)`, actor, "a-"+actor.String()[:8]+"@ex.com"); e != nil {
		t.Fatalf("seed actor: %v", e)
	}
	if _, e := pool.Exec(ctx, `INSERT INTO nodes (id,org_id,name,cert_serial,enrolled_kind) VALUES ($1,$2,'gw',$3,'gateway')`, node, org, "cs-"+node.String()[:8]); e != nil {
		t.Fatalf("seed node: %v", e)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor)
	})

	cidr := netip.MustParsePrefix("10.20.0.0/24")
	site, _, err := svc.RouteLAN(ctx, actor, org, node, "hq", cidr)
	if err != nil {
		t.Fatalf("first routeLAN: %v", err)
	}
	// Same-CIDR resubmit (e.g. a double-click): reuse the approved subnet, no duplicate.
	if _, _, err := svc.RouteLAN(ctx, actor, org, node, "hq", cidr); err != nil {
		t.Fatalf("same-CIDR resume: %v", err)
	}
	var n int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM site_subnets WHERE site_id=$1`, site.ID).Scan(&n)
	if n != 1 {
		t.Fatalf("same-CIDR resume must NOT duplicate the subnet row, got %d", n)
	}
}

// TestBindNodeConcurrentClaimNoOrphan (re-review #2) — the re-home refusal must be a WRITE-enforced atomic
// claim, not a read-then-write race: two concurrent binds of an unbound gateway to DIFFERENT sites →
// exactly one succeeds, the other gets node_already_bound_to_site, and NEITHER site is orphaned (the loser's
// site has no gateway; the gateway points to the winner).
func TestBindNodeConcurrentClaimNoOrphan(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, node := uuid.New(), uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'S',$2,'cc-'||$3)`, org, org, org.String()[:8]); e != nil {
		t.Fatalf("seed org: %v", e)
	}
	if _, e := pool.Exec(ctx, `INSERT INTO nodes (id,org_id,name,cert_serial,enrolled_kind) VALUES ($1,$2,'gw',$3,'gateway')`, node, org, "cs-"+node.String()[:8]); e != nil {
		t.Fatalf("seed node: %v", e)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	siteX, _ := svc.RegisterSite(ctx, org, "X")
	siteY, _ := svc.RegisterSite(ctx, org, "Y")
	var wg sync.WaitGroup
	errs := make([]error, 2)
	start := make(chan struct{})
	for i, sid := range []uuid.UUID{siteX.ID, siteY.ID} {
		wg.Add(1)
		go func(i int, sid uuid.UUID) {
			defer wg.Done()
			<-start // release both together to contend
			errs[i] = svc.BindNode(ctx, org, sid, node)
		}(i, sid)
	}
	close(start)
	wg.Wait()

	// Exactly one nil, one node_already_bound_to_site — never two successes (the orphan class).
	nils, refused := 0, 0
	for _, e := range errs {
		if e == nil {
			nils++
		} else if ae, ok := e.(*apierr.Error); ok && ae.Code == "node_already_bound_to_site" {
			refused++
		} else {
			t.Fatalf("unexpected bind error: %v", e)
		}
	}
	if nils != 1 || refused != 1 {
		t.Fatalf("concurrent claim must yield exactly one success + one refusal, got nils=%d refused=%d", nils, refused)
	}
	// The gateway points to exactly one site; the other is NOT orphaned (has no gateway).
	var boundSite uuid.UUID
	_ = pool.QueryRow(ctx, `SELECT site_id FROM nodes WHERE id=$1`, node).Scan(&boundSite)
	if boundSite != siteX.ID && boundSite != siteY.ID {
		t.Fatalf("gateway must be bound to one of the two sites, got %s", boundSite)
	}
	var gwCount int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM nodes WHERE site_id IN ($1,$2)`, siteX.ID, siteY.ID).Scan(&gwCount)
	if gwCount != 1 {
		t.Fatalf("exactly ONE site may own the gateway (no double-owned / orphan), got %d", gwCount)
	}
}

// TestUnbindSiteNodeBodyless — S8.6 #6 compat: a bodyless unbind (nodeID=Nil, the legacy caller shape)
// resolves the site's SOLE gateway; a multi-gateway site requires an explicit id (409 multiple_gateways).
func TestUnbindSiteNodeBodyless(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool)
	ctx := context.Background()
	org, nodeA, nodeB := uuid.New(), uuid.New(), uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug) VALUES ($1,'S',$2)`, org, "bl-"+org.String()[:8]); e != nil {
		t.Fatalf("org: %v", e)
	}
	for i, n := range []uuid.UUID{nodeA, nodeB} {
		if _, e := pool.Exec(ctx, `INSERT INTO nodes (id,org_id,name,cert_serial,enrolled_kind) VALUES ($1,$2,$3,$4,'gateway')`,
			n, org, "gw"+string(rune('A'+i)), "cs-bl-"+n.String()[:8]); e != nil {
			t.Fatalf("node: %v", e)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })
	site, _ := svc.RegisterSite(ctx, org, "hq")
	if err := svc.BindNode(ctx, org, site.ID, nodeA); err != nil {
		t.Fatalf("bind A: %v", err)
	}
	// SOLE gateway → a bodyless unbind (nil node id) resolves + unbinds it.
	if err := svc.UnbindSiteNode(ctx, org, site.ID, uuid.Nil); err != nil {
		t.Fatalf("bodyless unbind of the sole gateway must succeed, got %v", err)
	}
	var bound int
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM nodes WHERE site_id=$1`, site.ID).Scan(&bound)
	if bound != 0 {
		t.Fatalf("the sole gateway must be unbound, still bound=%d", bound)
	}
	// Now TWO gateways → a bodyless unbind is ambiguous → 409 multiple_gateways.
	if err := svc.BindNode(ctx, org, site.ID, nodeA); err != nil {
		t.Fatalf("rebind A: %v", err)
	}
	if err := svc.BindNode(ctx, org, site.ID, nodeB); err != nil {
		t.Fatalf("bind B: %v", err)
	}
	err := svc.UnbindSiteNode(ctx, org, site.ID, uuid.Nil)
	if err == nil {
		t.Fatal("a bodyless unbind of a multi-gateway site must be refused (409 multiple_gateways)")
	}
}
