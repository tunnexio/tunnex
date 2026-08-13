package policy_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// fakeNotifier records the NotifyMany fan-out so push-FIRES tests can assert which
// gateways a mutation signalled.
type fakeNotifier struct{ calls [][]uuid.UUID }

func (f *fakeNotifier) NotifyMany(ids []uuid.UUID) { f.calls = append(f.calls, ids) }
func (f *fakeNotifier) fired() bool                { return len(f.calls) > 0 }

// fixture seeds an org + verified owner + active node + one active FULL-TUNNEL device,
// returning the ids. Raw inserts keep the test independent of the higher services.
type fixture struct {
	org, user, node, device uuid.UUID
	ctx                     context.Context
}

func seed(t *testing.T, pool *pgxpool.Pool) fixture {
	t.Helper()
	ctx := context.Background()
	f := fixture{org: uuid.New(), user: uuid.New(), node: uuid.New(), device: uuid.New()}
	exec := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1,$2,$3)`, f.org, "ZT Org", "zt-"+f.org.String()[:8])
	exec(`INSERT INTO users (id, email) VALUES ($1,$2)`, f.user, "owner-"+f.user.String()[:8]+"@ex.com")
	exec(`INSERT INTO memberships (org_id, user_id, role) VALUES ($1,$2,'owner')`, f.org, f.user)
	exec(`INSERT INTO nodes (id, org_id, name, cert_serial) VALUES ($1,$2,'gw',$3)`, f.node, f.org, "serial-"+f.node.String())
	exec(`INSERT INTO devices (id, org_id, user_id, node_id, name, public_key, assigned_ip, full_tunnel) VALUES ($1, $2, $3, $4, 'laptop', 'ZzN444nzLsFjGeLNmSE9lzuvLAWI7mGMU2Z3fLroWnc=', '10.99.0.10', true)`, f.device, f.org, f.user, f.node)
	// An authed owner principal so mutations pass their own membership checks.
	f.ctx = authctx.WithOrg(authctx.WithPrincipal(ctx,
		&authctx.Principal{UserID: f.user, EmailVerified: true, Roles: map[uuid.UUID]string{f.org: "owner"}}), f.org)
	// cleanup cascades from the org.
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, f.org) })
	return f
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

// AffectedNodeIDs (S7.1-ledgered direct test): the revocation-push targeting function
// returns exactly the org's ACTIVE gateways.
func TestAffectedNodeIDsTargetsActiveOrgNodes(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	svc := policy.NewService(pool)

	ids, err := svc.AffectedNodeIDs(f.ctx, f.org)
	if err != nil {
		t.Fatalf("AffectedNodeIDs: %v", err)
	}
	if len(ids) != 1 || ids[0] != f.node {
		t.Fatalf("want [%s], got %v", f.node, ids)
	}

	// A REVOKED node drops out of the target set.
	if _, err := pool.Exec(f.ctx, `UPDATE nodes SET status='revoked' WHERE id=$1`, f.node); err != nil {
		t.Fatal(err)
	}
	if ids, _ := svc.AffectedNodeIDs(f.ctx, f.org); len(ids) != 0 {
		t.Fatalf("revoked node must not be a push target, got %v", ids)
	}
}

// Per-trigger push-FIRES: each compiler-input mutation signals the org's gateways.
func TestMutationsFirePush(t *testing.T) {
	pool := testPool(t)

	newSvc := func() (*policy.Service, *fakeNotifier) {
		n := &fakeNotifier{}
		s := policy.NewService(pool)
		s.SetNotifier(n)
		return s, n
	}

	t.Run("create group", func(t *testing.T) {
		f := seed(t, pool)
		s, n := newSvc()
		if _, err := s.CreateGroup(f.ctx, f.org, "eng", ""); err != nil {
			t.Fatal(err)
		}
		if !n.fired() || n.calls[0][0] != f.node {
			t.Fatalf("create group did not push the org node: %v", n.calls)
		}
	})

	t.Run("add + remove member", func(t *testing.T) {
		f := seed(t, pool)
		s, n := newSvc()
		g, err := s.CreateGroup(f.ctx, f.org, "admins", "")
		if err != nil {
			t.Fatal(err)
		}
		before := len(n.calls)
		if err := s.AddGroupMember(f.ctx, f.org, g.ID, f.user); err != nil {
			t.Fatal(err)
		}
		if len(n.calls) <= before {
			t.Fatal("add member did not push")
		}
		mid := len(n.calls)
		if err := s.RemoveGroupMember(f.ctx, f.org, g.ID, f.user); err != nil {
			t.Fatal(err)
		}
		if len(n.calls) <= mid {
			t.Fatal("remove member did not push")
		}
	})

	t.Run("resource + rule + mode", func(t *testing.T) {
		f := seed(t, pool)
		s, n := newSvc()
		g, _ := s.CreateGroup(f.ctx, f.org, "g", "")
		res, err := s.CreateResource(f.ctx, f.org, policyResource(), nil)
		if err != nil {
			t.Fatal(err)
		}
		rid := res.ID
		fired := len(n.calls)
		if _, err := s.CreatePolicyRule(f.ctx, f.org, ruleTo(g.ID, rid), uuid.Nil, uuid.Nil, "", ""); err != nil {
			t.Fatal(err)
		}
		if len(n.calls) <= fired {
			t.Fatal("create rule did not push")
		}
		before := len(n.calls)
		mode, affected, err := s.SetMode(f.ctx, f.org, policy.ModeEnforcing)
		if err != nil {
			t.Fatal(err)
		}
		if len(n.calls) <= before {
			t.Fatal("set mode did not push")
		}
		if mode != policy.ModeEnforcing {
			t.Fatalf("mode = %q", mode)
		}
		// Mode-enable ENUMERATION (2a): the seeded full-tunnel device is reported.
		if len(affected) != 1 || affected[0].ID != f.device {
			t.Fatalf("enable enforcing must enumerate the full-tunnel device, got %v", affected)
		}
		// Disabling returns no affected list.
		_, off, err := s.SetMode(f.ctx, f.org, policy.ModeOff)
		if err != nil {
			t.Fatal(err)
		}
		if len(off) != 0 {
			t.Fatalf("disabling must not enumerate devices, got %v", off)
		}
	})
}

func policyResource() policyspec.ResourceInput {
	return policyspec.ResourceInput{Name: "db", CIDR: "10.0.5.0/24", Protocol: "any"}
}

func ruleTo(srcGroup, dstResource uuid.UUID) policyspec.RuleInput {
	return policyspec.RuleInput{SrcGroupID: srcGroup, DstKind: "resource", DstResourceID: &dstResource}
}

// TestPerUserGrantDropsOnMemberRemoval is the S7.5.4 D1 rider proof (the F1
// committed-removal-must-push class): a per-user grant's src_user_id → memberships
// ON DELETE CASCADE deletes the rule row STRUCTURALLY when the member is removed —
// AND that removal must reach the WIRE: the compiled artifact, rebuilt after the
// cascade, must no longer contain that user's /32. Cascade-correct-in-DB but
// stale-in-compile would be the S7.5.2 committed-removal-must-push bug.
func TestPerUserGrantDropsOnMemberRemoval(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	ctx := f.ctx
	exec := func(sql string, args ...any) {
		if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
			t.Fatalf("exec %q: %v", sql, err)
		}
	}
	// A second member (bob) with an active device — the subject of the per-user grant.
	bob, bobDev := uuid.New(), uuid.New()
	exec(`INSERT INTO users (id, email) VALUES ($1,$2)`, bob, "bob-"+bob.String()[:8]+"@ex.com")
	exec(`INSERT INTO memberships (org_id, user_id, role) VALUES ($1,$2,'member')`, f.org, bob)
	exec(`INSERT INTO devices (id, org_id, user_id, node_id, name, public_key, assigned_ip) VALUES ($1, $2, $3, $4, 'bob-laptop', '+moqMY7wkFw8jxZ8s2v+Bw8lpvOFeEYCT9/LCKbJIA4=', '10.99.0.11')`, bobDev, f.org, bob, f.node)

	s := policy.NewService(pool)
	s.SetNotifier(&fakeNotifier{})
	res, err := s.CreateResource(ctx, f.org, policyResource(), nil)
	if err != nil {
		t.Fatal(err)
	}
	rid := res.ID
	// A PER-USER grant for bob (not a group).
	if _, err := s.CreatePolicyRule(ctx, f.org, policyspec.RuleInput{
		SrcKind: "user", SrcUserID: &bob, DstKind: "resource", DstResourceID: &rid,
	}, uuid.Nil, uuid.Nil, "", ""); err != nil {
		t.Fatalf("create per-user rule: %v", err)
	}
	if _, _, err := s.SetMode(ctx, f.org, policy.ModeEnforcing); err != nil {
		t.Fatal(err)
	}

	// BEFORE removal: bob's /32 is granted the resource in the compiled artifact.
	compiledHas := func(srcIP string) bool {
		snap, err := s.BuildSnapshot(context.Background(), f.org)
		if err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		for _, c := range policy.Compile(snap) {
			for _, e := range c.Allow {
				if e.SrcIP == srcIP && e.DstCIDR == "10.0.5.0/24" {
					return true
				}
			}
		}
		return false
	}
	if !compiledHas("10.99.0.11") {
		t.Fatal("per-user grant must put bob's /32 in the compiled artifact before removal")
	}

	// REMOVE bob from the org (delete the memberships row — the cascade trigger).
	exec(`DELETE FROM memberships WHERE org_id=$1 AND user_id=$2`, f.org, bob)

	// (a) STRUCTURAL cascade: the per-user policy_rules row is gone.
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM policy_rules WHERE org_id=$1 AND src_user_id=$2`, f.org, bob).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("membership removal must cascade-delete the per-user grant, %d rows remain", n)
	}
	// (b) WIRE freshness: the rebuilt artifact no longer grants bob's /32.
	if compiledHas("10.99.0.11") {
		t.Fatal("cascade-correct but gateway-STALE: bob's /32 still in the compiled artifact after removal")
	}
}

// tempGrant creates a group→resource rule expiring at `at` (raw, so tests can place
// it in the past to simulate a lapsed grant the API would refuse to create).
func tempGrant(t *testing.T, pool *pgxpool.Pool, f fixture, at time.Time) (ruleID, groupID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	groupID, res := uuid.New(), uuid.New()
	mustExec := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("exec %q: %v", sql, err)
		}
	}
	uniq := groupID.String()[:8] // group/resource names are unique per org
	mustExec(`INSERT INTO user_groups (id, org_id, name) VALUES ($1,$2,$3)`, groupID, f.org, "g-"+uniq)
	mustExec(`INSERT INTO group_members (org_id, group_id, user_id) VALUES ($1,$2,$3)`, f.org, groupID, f.user)
	mustExec(`INSERT INTO resources (id, org_id, name, cidr, protocol) VALUES ($1,$2,$3,'10.0.5.0/24','any')`, res, f.org, "db-"+uniq)
	ruleID = uuid.New()
	mustExec(`INSERT INTO policy_rules (id, org_id, src_kind, src_group_id, dst_kind, dst_resource_id, expires_at)
	          VALUES ($1,$2,'group',$3,'resource',$4,$5)`, ruleID, f.org, groupID, res, at)
	return ruleID, groupID
}

// code extracts an apierr code for asserting typed 4xx failures.
func code(err error) string {
	var a *apierr.Error
	if err != nil && errors.As(err, &a) {
		return a.Code
	}
	return ""
}

// TestSiteSourceRuleAuditsSiteID — S8.2 M6: a src_kind='site' rule audits its src_site_id, NEVER a
// nil-UUID src_group_id (the misattribution the else-branch caused).
func TestSiteSourceRuleAuditsSiteID(t *testing.T) {
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
	// ⚠ TWO SITES, AND THE SECOND IS NOT DECORATION. This test's subject is that the AUDIT records
	// `src_site_id`; using one site for both ends was incidental convenience, and it happens to build the
	// one rule the product now refuses (`invalid_rule_self_site`, S15.4) — a LAN cannot reach itself through
	// its own gateway, so the compiled allow could never match. The guard caught it here, in a fixture,
	// which is the guard working rather than the test failing.
	org, site, dstSite := uuid.New(), uuid.New(), uuid.New()
	ex := func(q string, a ...any) {
		if _, e := pool.Exec(ctx, q, a...); e != nil {
			t.Fatalf("seed %q: %v", q, e)
		}
	}
	ex(`INSERT INTO organizations (id,name,slug) VALUES ($1,'M6',$2)`, org, "m6-"+org.String()[:8])
	ex(`INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'A')`, site, org)
	ex(`INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'B')`, dstSite, org)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	s := policy.NewService(pool)
	s.SetNotifier(&fakeNotifier{})
	if _, err := s.CreatePolicyRule(ctx, org, policyspec.RuleInput{SrcKind: "site", SrcSiteID: &site, DstKind: "site", DstSiteID: &dstSite}, uuid.Nil, uuid.Nil, "", ""); err != nil {
		t.Fatalf("create site-src rule: %v", err)
	}
	var srcSiteID, srcGroupID *string
	if err := pool.QueryRow(ctx, `SELECT metadata->>'src_site_id', metadata->>'src_group_id' FROM audit_logs WHERE org_id=$1 AND action='policy.rule_created'`, org).Scan(&srcSiteID, &srcGroupID); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if srcSiteID == nil || *srcSiteID != site.String() {
		t.Fatalf("M6: audit must record src_site_id=%s, got %v", site, srcSiteID)
	}
	if srcGroupID != nil {
		t.Fatalf("M6: a site-source audit must NOT record a src_group_id, got %q", *srcGroupID)
	}
}

// TestK8sServiceRuleCreation — S10.3: a grant with dst_kind=k8s_service resolves against a LIVE exposed
// Service (created); a bogus/absent Service is refused (k8s_service_not_found). The EXISTING rule whose
// Service later vanishes is the read-time warn, not this creation gate.
func TestK8sServiceRuleCreation(t *testing.T) {
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
	org, site, cluster, svc, grp := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ex := func(q string, a ...any) {
		if _, e := pool.Exec(ctx, q, a...); e != nil {
			t.Fatalf("seed %q: %v", q, e)
		}
	}
	ex(`INSERT INTO organizations (id,name,slug) VALUES ($1,'K8s',$2)`, org, "k8s-"+org.String()[:8])
	ex(`INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'A')`, site, org)
	ex(`INSERT INTO k8s_clusters (id,org_id,site_id,name,vip_range,dns_zone) VALUES ($1,$2,$3,'prod','100.64.0.0/16','k8s.acme.com')`, cluster, org, site)
	ex(`INSERT INTO k8s_services (id,org_id,cluster_id,name,namespace,protocol,vip) VALUES ($1,$2,$3,'api','prod','tcp','100.64.0.5')`, svc, org, cluster)
	ex(`INSERT INTO user_groups (id,org_id,name) VALUES ($1,$2,'admins')`, grp, org)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	s := policy.NewService(pool)
	s.SetNotifier(&fakeNotifier{})
	// A grant reaching the LIVE Service is accepted.
	if _, err := s.CreatePolicyRule(ctx, org, policyspec.RuleInput{SrcKind: "group", SrcGroupID: grp, DstKind: "k8s_service", DstK8sServiceID: &svc}, uuid.Nil, uuid.Nil, "", ""); err != nil {
		t.Fatalf("a k8s_service grant to a live Service must be accepted, got %v", err)
	}
	// A grant to an absent Service is refused with the typed error.
	bogus := uuid.New()
	if _, err := s.CreatePolicyRule(ctx, org, policyspec.RuleInput{SrcKind: "group", SrcGroupID: grp, DstKind: "k8s_service", DstK8sServiceID: &bogus}, uuid.Nil, uuid.Nil, "", ""); err == nil || !strings.Contains(err.Error(), "k8s_service_not_found") {
		t.Fatalf("a k8s_service grant to an absent Service must refuse (k8s_service_not_found), got %v", err)
	}
	// dst_kind=k8s_service with NO dst_k8s_service_id is a shape error.
	if _, err := s.CreatePolicyRule(ctx, org, policyspec.RuleInput{SrcKind: "group", SrcGroupID: grp, DstKind: "k8s_service"}, uuid.Nil, uuid.Nil, "", ""); err == nil || !strings.Contains(err.Error(), "dst_k8s_service_id") {
		t.Fatalf("dst_kind=k8s_service without an id must refuse, got %v", err)
	}
}

func auditCount(t *testing.T, pool *pgxpool.Pool, org uuid.UUID, action string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action=$2`, org, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestExtendGrantWindow — the happy path: a live temporary grant's window moves in place.
func TestExtendGrantWindow(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	rid, _ := tempGrant(t, pool, f, time.Now().Add(30*time.Minute))
	s := policy.NewService(pool)
	// Notifier attached AFTER tempGrant, so .fired() strictly captures the EXTEND's push (if any).
	n := &fakeNotifier{}
	s.SetNotifier(n)
	newExp := time.Now().Add(4 * time.Hour)
	r, err := s.ExtendGrant(f.ctx, f.org, rid, newExp)
	if err != nil {
		t.Fatalf("extend: %v", err)
	}
	if !r.ExpiresAt.Valid || r.ExpiresAt.Time.Sub(newExp).Abs() > time.Second {
		t.Fatalf("window not moved: %+v", r.ExpiresAt)
	}
	// S7.5.4 box-walk RED: extend moves ONLY expires_at, which is NOT in the compiled
	// enforcement artifact — so it must NOT trigger a push. Pre-fix ExtendGrant went through
	// mutate's unconditional pushOrg, which recompiled the org and re-applied a byte-identical
	// ruleset on every gateway (the wire showed the /32 allow's nft handle churn + counter reset),
	// contradicting the ExtendPolicyRule comment's "no spurious push" intent. This pins it shut.
	if n.fired() {
		t.Fatalf("extend must NOT push (expires_at is not in the enforcement artifact); pushed: %v", n.calls)
	}
	if auditCount(t, pool, f.org, "policy.grant_extended") != 1 {
		t.Fatal("extend must audit policy.grant_extended")
	}
	// [6] D7: the audit records the OLD->NEW window, and old != new (the pre-update value, not
	// the post-update one — the fold-induced defect the re-review caught).
	var oldA, newA string
	if err := pool.QueryRow(context.Background(),
		`SELECT metadata->>'old_expires_at', metadata->>'new_expires_at' FROM audit_logs
		 WHERE org_id=$1 AND action='policy.grant_extended'`, f.org).Scan(&oldA, &newA); err != nil {
		t.Fatal(err)
	}
	if oldA == "" || newA == "" || oldA == newA {
		t.Fatalf("extend audit must record distinct old->new window, got old=%q new=%q", oldA, newA)
	}
}

// TestExtendRefusesPermanentAndLapsed — the two 409s: a permanent grant has no window,
// and a lapsed grant is terminal.
func TestExtendRefusesPermanentAndLapsed(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	s := policy.NewService(pool)
	s.SetNotifier(&fakeNotifier{})

	// permanent: create a normal rule (no expiry) -> not_temporary.
	perm, _ := tempGrant(t, pool, f, time.Now().Add(time.Hour))
	if _, err := pool.Exec(context.Background(), `UPDATE policy_rules SET expires_at=NULL WHERE id=$1`, perm); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExtendGrant(f.ctx, f.org, perm, time.Now().Add(time.Hour)); code(err) != "not_temporary" {
		t.Fatalf("permanent grant extend must be 409 not_temporary, got %v", err)
	}

	// lapsed: a grant already past its expiry -> grant_lapsed.
	lapsed, _ := tempGrant(t, pool, f, time.Now().Add(-time.Minute))
	if _, err := s.ExtendGrant(f.ctx, f.org, lapsed, time.Now().Add(time.Hour)); code(err) != "grant_lapsed" {
		t.Fatalf("lapsed grant extend must be 409 grant_lapsed, got %v", err)
	}
}

// TestExtendVsSweepRace is the disposition RED: extend and the expiry sweeper compose on
// the row lock, so a grant at its lapse boundary resolves DETERMINISTICALLY to
// extended-OR-409, never torn. The FOR UPDATE lock guarantees that under real concurrency
// exactly ONE of these two serial orderings occurs — both are asserted correct here.
func TestExtendVsSweepRace(t *testing.T) {
	pool := testPool(t)
	s := policy.NewService(pool)
	s.SetNotifier(&fakeNotifier{})

	t.Run("sweep wins -> grant DELETED, extend is 404 (row gone), exactly one action", func(t *testing.T) {
		f := seed(t, pool)
		rid, _ := tempGrant(t, pool, f, time.Now().Add(-time.Second)) // already lapsed
		// Sweeper claims it: DELETEs + audits grant_expired (this org).
		if _, err := s.SweepExpiredGrants(context.Background()); err != nil {
			t.Fatal(err)
		}
		if auditCount(t, pool, f.org, "policy.grant_expired") != 1 {
			t.Fatal("sweep must audit grant_expired once for this org")
		}
		// Extend now finds NO row (deleted) -> 404. No double-action (no grant_extended).
		if _, err := s.ExtendGrant(f.ctx, f.org, rid, time.Now().Add(time.Hour)); code(err) != "rule_not_found" {
			t.Fatalf("post-sweep extend must be rule_not_found (row deleted), got %v", err)
		}
		if auditCount(t, pool, f.org, "policy.grant_extended") != 0 {
			t.Fatal("a swept grant must NOT also record an extend (torn state)")
		}
	})

	t.Run("extend wins -> sweep does NOT delete/expire it", func(t *testing.T) {
		f := seed(t, pool)
		rid, _ := tempGrant(t, pool, f, time.Now().Add(2*time.Second)) // live, near boundary
		if _, err := s.ExtendGrant(f.ctx, f.org, rid, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("extend: %v", err)
		}
		// The row now has a future expires_at, so delete-on-sweep skips it.
		if _, err := s.SweepExpiredGrants(context.Background()); err != nil {
			t.Fatal(err)
		}
		if auditCount(t, pool, f.org, "policy.grant_expired") != 0 {
			t.Fatal("an extended grant must NOT be swept (this org)")
		}
		var n int
		pool.QueryRow(context.Background(), `SELECT count(*) FROM policy_rules WHERE id=$1`, rid).Scan(&n)
		if n != 1 {
			t.Fatal("an extended grant's row must survive the sweep")
		}
	})
}

// TestRegrantAfterLapseSucceeds is the [1] RED (story-end review): the linger dead-end is
// GONE — after a grant lapses and is SWEPT (deleted), re-creating the same (src,dst) grant
// SUCCEEDS (no lingering row to collide on the unique index). Under linger this 409'd with
// no in-UI escape.
func TestRegrantAfterLapseSucceeds(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	s := policy.NewService(pool)
	s.SetNotifier(&fakeNotifier{})
	res, err := s.CreateResource(f.ctx, f.org, policyResource(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// A temporary group->resource grant, created via the service so the unique index applies.
	g, _ := s.CreateGroup(f.ctx, f.org, "g", "")
	past := time.Now().Add(time.Hour)
	rid, err := s.CreatePolicyRule(f.ctx, f.org, policyspec.RuleInput{
		SrcKind: "group", SrcGroupID: g.ID, DstKind: "resource", DstResourceID: &res.ID, ExpiresAt: &past,
	}, uuid.Nil, uuid.Nil, "", "")
	if err != nil {
		t.Fatalf("create temp grant: %v", err)
	}
	// Force it lapsed, then sweep (delete).
	if _, err := pool.Exec(context.Background(), `UPDATE policy_rules SET expires_at=now()-interval '1 second' WHERE id=$1`, rid.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SweepExpiredGrants(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The SAME (src,dst) grant re-creates cleanly — no lingering row, no 409.
	future := time.Now().Add(2 * time.Hour)
	if _, err := s.CreatePolicyRule(f.ctx, f.org, policyspec.RuleInput{
		SrcKind: "group", SrcGroupID: g.ID, DstKind: "resource", DstResourceID: &res.ID, ExpiresAt: &future,
	}, uuid.Nil, uuid.Nil, "", ""); err != nil {
		t.Fatalf("re-grant after lapse must SUCCEED (delete-on-sweep, no linger dead-end), got %v", err)
	}
}

// TestSweepStatelessAcrossDowntime is the [4]/[5] RED: the stateless sweep audits EVERY
// currently-expired grant, so grants that lapsed while the sweeper was NOT running (a
// failed tick / server downtime) are still deleted+audited on the next sweep — no window,
// no audit hole. Idempotent: a second sweep finds nothing new.
func TestSweepStatelessAcrossDowntime(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	s := policy.NewService(pool)
	s.SetNotifier(&fakeNotifier{})
	// THREE grants that all lapsed "during downtime" (no sweeper ran).
	for i := 0; i < 3; i++ {
		tempGrant(t, pool, f, time.Now().Add(-time.Duration(i+1)*time.Minute))
	}
	// One sweep (post-restart) catches ALL of them — no window to miss the downtime lapses.
	if _, err := s.SweepExpiredGrants(context.Background()); err != nil {
		t.Fatal(err)
	}
	if auditCount(t, pool, f.org, "policy.grant_expired") != 3 {
		t.Fatalf("stateless sweep must audit ALL downtime lapses, got %d", auditCount(t, pool, f.org, "policy.grant_expired"))
	}
	// Idempotent: nothing left to sweep.
	before := auditCount(t, pool, f.org, "policy.grant_expired")
	if _, err := s.SweepExpiredGrants(context.Background()); err != nil {
		t.Fatal(err)
	}
	if auditCount(t, pool, f.org, "policy.grant_expired") != before {
		t.Fatal("a second sweep must be a no-op (grants already deleted)")
	}
}

// TestSweepPushesOrgWide — a lapsed grant's expiry pushes the org's gateways (F1: the
// /32 must leave every gateway, not just the subject's node) + audits (system actor).
func TestSweepPushesOrgWide(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	tempGrant(t, pool, f, time.Now().Add(-time.Second))
	n := &fakeNotifier{}
	s := policy.NewService(pool)
	s.SetNotifier(n)
	if _, err := s.SweepExpiredGrants(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The sweep is system-wide (may push several orgs from the shared DB); assert THIS
	// org's gateway is among the pushes.
	pushedThisNode := false
	for _, call := range n.calls {
		for _, id := range call {
			if id == f.node {
				pushedThisNode = true
			}
		}
	}
	if !pushedThisNode {
		t.Fatalf("expiry sweep must push this org's gateway (%s), got %v", f.node, n.calls)
	}
	var actor *string
	if err := pool.QueryRow(context.Background(),
		`SELECT actor_system FROM audit_logs WHERE org_id=$1 AND action='policy.grant_expired'`, f.org).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	if actor == nil || *actor != "policy-grants" {
		t.Fatalf("expiry must be a SYSTEM-actor audit (policy-grants), got %v", actor)
	}
}

// TestAuditedDeletesPersistMetadata pins the S7.4a-walk finding: every audited DELETE goes
// through writeAudit with nil meta, which inserted SQL NULL into audit_logs.metadata (NOT
// NULL) → 23502 → the mutation 500'd + rolled back (so the rule/group/resource could never
// be deleted via the UI). RED on main for all THREE nil-meta callsites; GREEN once writeAudit
// defaults nil → '{}'. (Latent because no box proof ever deleted an audited entity on the wire.)
func TestAuditedDeletesPersistMetadata(t *testing.T) {
	pool := testPool(t)

	assertAudit := func(t *testing.T, f fixture, action, targetID string) {
		t.Helper()
		var meta []byte
		if err := pool.QueryRow(f.ctx,
			`SELECT metadata FROM audit_logs WHERE org_id=$1 AND action=$2 AND target_id=$3`,
			f.org, action, targetID).Scan(&meta); err != nil {
			t.Fatalf("%s audit row missing: %v", action, err)
		}
		if len(meta) == 0 || string(meta) == "null" {
			t.Fatalf("%s metadata must be non-null JSON, got %q", action, meta)
		}
	}

	t.Run("group.deleted", func(t *testing.T) {
		f := seed(t, pool)
		s := policy.NewService(pool)
		g, err := s.CreateGroup(f.ctx, f.org, "doomed", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteGroup(f.ctx, f.org, g.ID); err != nil {
			t.Fatalf("audited delete errored (nil-meta NOT NULL bug): %v", err)
		}
		assertAudit(t, f, "group.deleted", g.ID.String())
	})

	t.Run("resource.deleted", func(t *testing.T) {
		f := seed(t, pool)
		s := policy.NewService(pool)
		r, err := s.CreateResource(f.ctx, f.org, policyResource(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteResource(f.ctx, f.org, r.ID); err != nil {
			t.Fatalf("audited delete errored (nil-meta NOT NULL bug): %v", err)
		}
		assertAudit(t, f, "resource.deleted", r.ID.String())
	})

	t.Run("policy.rule_deleted", func(t *testing.T) {
		f := seed(t, pool)
		s := policy.NewService(pool)
		g, _ := s.CreateGroup(f.ctx, f.org, "g", "")
		r, err := s.CreateResource(f.ctx, f.org, policyResource(), nil)
		if err != nil {
			t.Fatal(err)
		}
		rule, err := s.CreatePolicyRule(f.ctx, f.org, ruleTo(g.ID, r.ID), uuid.Nil, uuid.Nil, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.DeletePolicyRule(f.ctx, f.org, rule.ID, uuid.Nil, "", ""); err != nil {
			t.Fatalf("audited delete errored (nil-meta NOT NULL bug): %v", err)
		}
		assertAudit(t, f, "policy.rule_deleted", rule.ID.String())
	})
}

// TestCIDRWarnShedsWhenRangeLands — S8.7 D1 warn-not-refuse: a src_kind='cidr' rule whose CIDR is in no
// current site subnet WARNS (cidr_outside_org_ranges), and the warning SHEDS at READ time once a containing
// subnet lands — no rule edit. Both directions: warn appears (out-of-world), warn clears (in-world).
func TestCIDRWarnShedsWhenRangeLands(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	svc := policy.NewService(pool)
	org, site := uuid.New(), uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'O',$2,'10.99.0.0/24')`, org, "cw-"+org.String()[:8]); e != nil {
		t.Fatalf("org: %v", e)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })
	if _, e := pool.Exec(ctx, `INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'A')`, site, org); e != nil {
		t.Fatalf("site: %v", e)
	}
	res, e := svc.CreateResource(ctx, org, policyspec.ResourceInput{Name: "r", CIDR: "10.0.0.4/32", Protocol: "any"}, nil)
	if e != nil {
		t.Fatalf("resource: %v", e)
	}
	cidr := "172.31.17.64/32"
	rule, e := svc.CreatePolicyRule(ctx, org, policyspec.RuleInput{SrcKind: "cidr", SrcCIDR: &cidr, DstKind: "resource", DstResourceID: &res.ID}, uuid.Nil, uuid.Nil, "", "")
	if e != nil {
		t.Fatalf("cidr rule: %v", e)
	}
	rules := []sqlc.PolicyRule{rule}
	warn := func() bool {
		w, e := svc.PolicyRuleCidrWarnings(ctx, org, rules)
		if e != nil {
			t.Fatalf("warnings: %v", e)
		}
		return w[rule.ID]
	}
	// (a) No containing subnet → WARN (out-of-world; places nowhere).
	if !warn() {
		t.Fatal("an out-of-world cidr rule must WARN (cidr_outside_org_ranges)")
	}
	// (b) [9] The containing subnet lands, but the site has NO bound gateway → STILL WARNS: the grant places
	// nowhere without a gateway (warn ⟺ won't-place, the [9] fix — a clean rule must never silently no-op).
	if _, e := pool.Exec(ctx, `INSERT INTO site_subnets (site_id,cidr,status) VALUES ($1,'172.31.0.0/16','approved')`, site); e != nil {
		t.Fatalf("subnet: %v", e)
	}
	if !warn() {
		t.Fatal("[9]: a cidr in a subnet of a NODE-LESS site must still WARN (it compiles to nothing)")
	}
	// (c) A gateway is bound → NOW it places (containing subnet + bound node) → the warning SHEDS, read-time,
	// no rule edit. Both directions of the warn⟺place biconditional exercised.
	gw := uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO nodes (id,org_id,name,cert_serial,site_id,wg_public_key,endpoint) VALUES ($1,$2,'gw',$3,$4,'KGW',':51820')`, gw, org, "cs-"+gw.String()[:8], site); e != nil {
		t.Fatalf("bind gateway: %v", e)
	}
	if warn() {
		t.Fatal("the warning must SHED once the range lands AND a gateway is bound (read-time, no edit)")
	}
}

// TestSetPolicyRuleEnabledNoOpNoPushNoAudit (F-A1) — a NO-OP toggle (re-disabling an already-disabled rule
// via the idempotent PATCH) must NOT push and must NOT emit an audit row: an audit row must ALWAYS
// correspond to a REAL change (the swallowed-audit law's MIRROR — that law says a change always leaves a
// row; this says a row always corresponds to a change), or the two-action "who cut access at 3am" read is
// corrupted. The guard's INVERSE is pinned too: a GENUINE toggle still pushes + audits exactly once.
func TestSetPolicyRuleEnabledNoOpNoPushNoAudit(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	s := policy.NewService(pool)
	g, err := s.CreateGroup(f.ctx, f.org, "g", "")
	if err != nil {
		t.Fatalf("group: %v", err)
	}
	res, err := s.CreateResource(f.ctx, f.org, policyResource(), nil)
	if err != nil {
		t.Fatalf("resource: %v", err)
	}
	rule, err := s.CreatePolicyRule(f.ctx, f.org, ruleTo(g.ID, res.ID), uuid.Nil, uuid.Nil, "", "")
	if err != nil {
		t.Fatalf("rule: %v", err)
	}
	n := &fakeNotifier{}
	s.SetNotifier(n) // AFTER the creates → only toggles are captured

	// REAL disable → pushes + audits rule_disabled ONCE.
	if _, err := s.SetPolicyRuleEnabled(f.ctx, f.org, rule.ID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if len(n.calls) != 1 {
		t.Fatalf("a real disable must push exactly once, got %d", len(n.calls))
	}
	if auditCount(t, pool, f.org, "policy.rule_disabled") != 1 {
		t.Fatal("disable must audit policy.rule_disabled once")
	}
	// NO-OP disable (already disabled) → NO push, NO 2nd audit row.
	if _, err := s.SetPolicyRuleEnabled(f.ctx, f.org, rule.ID, false); err != nil {
		t.Fatalf("noop disable: %v", err)
	}
	if len(n.calls) != 1 {
		t.Fatalf("a no-op disable must NOT push, got %d total", len(n.calls))
	}
	if auditCount(t, pool, f.org, "policy.rule_disabled") != 1 {
		t.Fatal("a no-op disable must NOT emit a 2nd audit row (audit-honesty — the swallowed-audit mirror)")
	}
	// GENUINE enable → pushes again + audits rule_enabled once (the guard's inverse — real changes still fire).
	if _, err := s.SetPolicyRuleEnabled(f.ctx, f.org, rule.ID, true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if len(n.calls) != 2 {
		t.Fatalf("a real enable must push (2 total), got %d", len(n.calls))
	}
	if auditCount(t, pool, f.org, "policy.rule_enabled") != 1 {
		t.Fatal("a real enable must audit policy.rule_enabled once")
	}
}

// TestGrantOwnershipMarker — S10.2 Slice 3a: a MACHINE-created grant records managed_by_machine; a human
// (uuid.Nil) leaves it NULL/inert. Same ownership seam as k8s cluster/service (the third create path).
func TestGrantOwnershipMarker(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	svc := policy.NewService(pool)
	org := uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'O',$2,'10.99.0.0/24')`, org, "own-"+org.String()[:8]); e != nil {
		t.Fatalf("org: %v", e)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })
	mid := uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO machine_credentials (id,org_id,name,role,token_hash,fingerprint) VALUES ($1,$2,'gitops','operator',$3,'fp')`, mid, org, []byte(mid.String())); e != nil {
		t.Fatalf("machine: %v", e)
	}
	res, e := svc.CreateResource(ctx, org, policyspec.ResourceInput{Name: "r", CIDR: "10.0.0.4/32", Protocol: "any"}, nil)
	if e != nil {
		t.Fatalf("resource: %v", e)
	}
	cidr := "172.31.17.64/32"

	// MACHINE-created grant → marker set.
	rm, e := svc.CreatePolicyRule(ctx, org, policyspec.RuleInput{SrcKind: "cidr", SrcCIDR: &cidr, DstKind: "resource", DstResourceID: &res.ID}, mid, uuid.Nil, "", "")
	if e != nil {
		t.Fatalf("machine rule: %v", e)
	}
	var mb *string
	if err := pool.QueryRow(ctx, `SELECT managed_by_machine::text FROM policy_rules WHERE id=$1`, rm.ID).Scan(&mb); err != nil {
		t.Fatal(err)
	}
	if mb == nil || *mb != mid.String() {
		t.Fatalf("machine-created grant must record managed_by_machine=%s, got %v", mid, mb)
	}

	// HUMAN-created (uuid.Nil) → NULL. DISTINCT cidr — an identical (src,dst) would conflict with the machine
	// rule above (the CP refuses a duplicate rule); this test is about the ownership marker, not dedup.
	cidr2 := "172.31.17.65/32"
	rh, e := svc.CreatePolicyRule(ctx, org, policyspec.RuleInput{SrcKind: "cidr", SrcCIDR: &cidr2, DstKind: "resource", DstResourceID: &res.ID}, uuid.Nil, uuid.Nil, "", "")
	if e != nil {
		t.Fatalf("human rule: %v", e)
	}
	var mbh *string
	if err := pool.QueryRow(ctx, `SELECT managed_by_machine::text FROM policy_rules WHERE id=$1`, rh.ID).Scan(&mbh); err != nil {
		t.Fatal(err)
	}
	if mbh != nil {
		t.Fatalf("human-created grant must have managed_by_machine NULL, got %v", *mbh)
	}
}

// TestPolicyMachineAudits — S10.2 M1b: the policy audit path is now machine-aware (writeAuditAs). A machine's
// grant create AND delete attribute actor_system=operator:<name> + cause, with actor_user_id NULL. The DELETE
// half is the regression catch: before M1b, DeletePolicyRule audited via actorPg, which stamps a machine's
// uuid.Nil UserID as a VALID ZERO user-id (actor_user_id NOT NULL) — the confidently-wrong attribution D3
// exists to prevent, and the walk's Leg 6 audit row. This red asserts actor_user_id IS NULL, catching it.
func TestPolicyMachineAudits(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	svc := policy.NewService(pool)
	org := uuid.New()
	if _, e := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'O',$2,'10.99.0.0/24')`, org, "aud-"+org.String()[:8]); e != nil {
		t.Fatalf("org: %v", e)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })
	res, e := svc.CreateResource(ctx, org, policyspec.ResourceInput{Name: "r", CIDR: "10.0.0.4/32", Protocol: "any"}, nil)
	if e != nil {
		t.Fatalf("resource: %v", e)
	}
	cidr := "172.31.9.0/32"

	// MACHINE create.
	rm, e := svc.CreatePolicyRule(ctx, org, policyspec.RuleInput{SrcKind: "cidr", SrcCIDR: &cidr, DstKind: "resource", DstResourceID: &res.ID},
		uuid.Nil, uuid.Nil, "operator:gitops", "tunnexgrant:default/g")
	if e != nil {
		t.Fatalf("machine create: %v", e)
	}
	var sys, usr, cause *string
	if err := pool.QueryRow(ctx,
		`SELECT actor_system, actor_user_id::text, metadata->>'cause' FROM audit_logs
		   WHERE org_id=$1 AND action='policy.rule_created' AND target_id=$2`, org, rm.ID.String()).
		Scan(&sys, &usr, &cause); err != nil {
		t.Fatal(err)
	}
	if sys == nil || *sys != "operator:gitops" || usr != nil || cause == nil || *cause != "tunnexgrant:default/g" {
		t.Fatalf("machine create must audit actor_system+cause, not a user; got sys=%v usr=%v cause=%v", sys, usr, cause)
	}

	// MACHINE delete — the regression catch: actor_user_id MUST be NULL (not a zero uuid).
	if err := svc.DeletePolicyRule(ctx, org, rm.ID, uuid.Nil, "operator:gitops", "tunnexgrant:default/g"); err != nil {
		t.Fatal(err)
	}
	var dsys, dusr *string
	if err := pool.QueryRow(ctx,
		`SELECT actor_system, actor_user_id::text FROM audit_logs
		   WHERE org_id=$1 AND action='policy.rule_deleted' AND target_id=$2`, org, rm.ID.String()).
		Scan(&dsys, &dusr); err != nil {
		t.Fatal(err)
	}
	if dsys == nil || *dsys != "operator:gitops" {
		t.Fatalf("machine grant-delete must attribute actor_system, got %v", dsys)
	}
	if dusr != nil { // THE NEGATIVE — a machine delete must NOT stamp a (zero) user id
		t.Fatalf("machine grant-delete must have actor_user_id NULL, got %v (the M1b confidently-wrong attribution)", *dusr)
	}
}
