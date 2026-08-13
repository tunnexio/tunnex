package policy_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// TestRevokedGatewayGetsNoSitePlacement — the S13.1 Slice 2 red, both halves, against the real queries.
//
// WHAT WENT WRONG (EPIC 11 WF-S11-14). Two queries feed related decisions about a site's gateways and only one
// filtered revoked rows. The hub-set input at sites.sql:77 filters, and its own comment says revocation must drop
// a gateway there "no blackhole". ListSiteNodesForOrg — the POLICY COMPILER's input — did not.
//
// The consequence was worse than a wasted artifact. The compiler reduces those rows into
// `siteNode[site_id] = node_id`, a SINGLE-VALUE map, and the query had no ORDER BY. So for a site holding both a
// revoked and an active gateway, the placement slot went to whichever row the database happened to return last —
// NON-DETERMINISTICALLY, and it could flip between compiles. A site grant would land on a dead gateway while the
// live one never received it: traffic denied, policy reading correct, nothing in the health surface pointing at
// the cause (the gateway rendering the problem is revoked, so it shows no badge at all).
//
// The walk's own fleet had exactly this shape: `aws-site` held a revoked `aws-gw-1` and an active `aws-gw-2`, both
// with site_id set.
//
// This test asserts BOTH ruled halves, at the seams where they live:
//   - the FILTER: ListSiteNodesForOrg returns only active gateways;
//   - the UNBIND: RevokeNode clears site_id, removing the stale binding at source.
//
// It is DB-backed on purpose. A fixture-level test would assert what the compiler does with a list, and the defect
// was never in the compiler — it was in what reached it.
//
// AND IT CALLS THE GENERATED QUERIES, not hand-typed SQL. The first draft of this test inlined the SELECT and the
// UPDATE; mutating sites.sql then changed nothing it could see, so removing the status filter PASSED. A red that
// re-types the query it guards tests the author's intent rather than the shipped statement — fixture fidelity at
// the query seam (docs/laws.md, COULD THIS CHECK HAVE FAILED?).
func TestRevokedGatewayGetsNoSitePlacement(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)

	// A site with TWO bound gateways: the seeded one, plus a second we add. Two, because the single-value
	// reduction is the whole defect — with one gateway per site a missing filter is invisible.
	var siteID uuid.UUID
	if err := pool.QueryRow(f.ctx,
		`INSERT INTO sites (org_id, name) VALUES ($1,'revoked-seam-site') RETURNING id`, f.org).Scan(&siteID); err != nil {
		t.Fatalf("create site: %v", err)
	}
	var second uuid.UUID
	if err := pool.QueryRow(f.ctx,
		`INSERT INTO nodes (org_id, name, cert_serial, agent_version, site_id, wg_public_key, endpoint)
		 VALUES ($1,'seam-gw-2','seam-serial-2','v0',$2,'pubkey-2','203.0.113.9:51820') RETURNING id`,
		f.org, siteID).Scan(&second); err != nil {
		t.Fatalf("create second gateway: %v", err)
	}
	if _, err := pool.Exec(f.ctx, `UPDATE nodes SET site_id=$1, wg_public_key='pubkey-1' WHERE id=$2`,
		siteID, f.node); err != nil {
		t.Fatalf("bind seeded node: %v", err)
	}

	q := sqlc.New(pool)

	// THE SHIPPED QUERY — the compiler's actual input, not a paraphrase of it.
	siteBound := func() map[uuid.UUID]bool {
		t.Helper()
		rows, err := q.ListSiteNodesForOrg(f.ctx, f.org)
		if err != nil {
			t.Fatalf("ListSiteNodesForOrg: %v", err)
		}
		out := map[uuid.UUID]bool{}
		for _, r := range rows {
			out[r.ID] = true
		}
		return out
	}

	// Baseline: both are compiler input while both are active. Without this the test could pass on a query that
	// returns nothing at all — the vacuous-check trap (docs/laws.md).
	if got := siteBound(); !got[f.node] || !got[second] {
		t.Fatalf("baseline: both active site gateways must be compiler input, got %v", got)
	}

	// THE SHIPPED REVOKE — sqlc's RevokeNode, so the unbind half is tested where it lives.
	if err := q.RevokeNode(f.ctx, sqlc.RevokeNodeParams{OrgID: f.org, ID: f.node}); err != nil {
		t.Fatalf("RevokeNode: %v", err)
	}

	// HALF 1 — the FILTER: the revoked gateway is no longer compiler input, so it can never take the site's
	// single placement slot.
	got := siteBound()
	if got[f.node] {
		t.Errorf("a REVOKED gateway must not reach the policy compiler as a site binding: it competes for the "+
			"site's single placement slot, so a site grant can land on a dead gateway while the live one never "+
			"receives it (node %s)", f.node)
	}
	if !got[second] {
		t.Errorf("the surviving ACTIVE gateway must still be compiler input — filtering must remove the dead "+
			"one, not the site (node %s)", second)
	}

	// THE BINDING IS PRESERVED — ASSERTION REVERSED, and the reversal is a ruling overturned on evidence.
	//
	// This previously asserted that revocation must CLEAR site_id ("no stale binding for an unfiltered reader to
	// find"). Review found the unbind bought nothing and cost three things, so it was reverted and the filter kept:
	//
	//   1. BindNodeToSite authorizes purely on site_id being NULL and has no status guard, so an
	//      unbound-by-revocation gateway could be bound to any site via API/CLI/GitOps — previously refused as
	//      already-bound. The site then held a dead gateway the status-filtered compiler input excludes, so
	//      cross-site traffic was silently denied while the UI showed a gateway present.
	//   2. assembleTopology joins on `n.site_id === s.id`, so a revoked gateway vanished from the Sites card
	//      entirely — indistinguishable from a site that never had one, and it made the badge-suppression fix from
	//      the same commit unreachable.
	//   3. Nothing recorded which site the gateway served, while the docs told the operator to re-apply it.
	//
	// REVOCATION PRESERVES WHAT IT INVALIDATES. Marking the row revoked is the job; destroying the facts that
	// explain it is not. Readers that must ignore a revoked gateway filter on status — one predicate in one place,
	// versus three consequences across three surfaces.
	var boundAfter *uuid.UUID
	if err := pool.QueryRow(f.ctx, `SELECT site_id FROM nodes WHERE id=$1`, f.node).Scan(&boundAfter); err != nil {
		t.Fatalf("read binding: %v", err)
	}
	if boundAfter == nil {
		t.Error("revocation must PRESERVE the site binding: it is the only surviving record of which site the " +
			"gateway served, the Sites card needs it to render the revoked row at all, and clearing it unguards " +
			"BindNodeToSite. The status filter is what keeps a revoked gateway out of compilation")
	}
}

// TestStaleBindingOnAnAlreadyRevokedNodeIsFilteredOut proves HALF 1 INDEPENDENTLY, and it exists because the two
// halves turned out to be redundant for the case above: once RevokeNode clears site_id, the row fails
// `site_id IS NOT NULL` and drops out whether or not the status filter is there. Mutating the filter alone did not
// fail the first test, which is the honest reason this second one exists.
//
// THE FILTER IS LOAD-BEARING FOR A STATE THE UNBIND CANNOT REACH: a node that is already revoked AND still carries
// site_id. That is not hypothetical — the unbind is FORWARD-ONLY, so every row revoked before this change is in
// exactly that state on every existing deployment. The EPIC 11 walk's `aws-gw-1` was: `revoked`, with
// `site_id 019f8e4a-…` intact.
//
// There is deliberately NO backfill clearing those rows. The stale binding is the only surviving record of which
// site a revoked gateway served, and D5's cascade-restore may need it. So the filter is not transitional
// belt-and-braces — it is the permanent defence, and this red is what keeps it.
func TestStaleBindingOnAnAlreadyRevokedNodeIsFilteredOut(t *testing.T) {
	pool := testPool(t)
	f := seed(t, pool)
	q := sqlc.New(pool)

	var siteID uuid.UUID
	if err := pool.QueryRow(f.ctx,
		`INSERT INTO sites (org_id, name) VALUES ($1,'stale-binding-site') RETURNING id`, f.org).Scan(&siteID); err != nil {
		t.Fatalf("create site: %v", err)
	}
	// A pre-fix row, written exactly as one exists in the wild: revoked, and STILL BOUND.
	var stale uuid.UUID
	if err := pool.QueryRow(f.ctx,
		`INSERT INTO nodes (org_id, name, cert_serial, agent_version, site_id, wg_public_key, status, revoked_at)
		 VALUES ($1,'stale-gw','stale-serial','v0',$2,'stale-pubkey','revoked', now()) RETURNING id`,
		f.org, siteID).Scan(&stale); err != nil {
		t.Fatalf("create stale-bound revoked node: %v", err)
	}
	// And a live gateway on the same site, so the single-value placement reduction has a correct answer to give.
	var live uuid.UUID
	if err := pool.QueryRow(f.ctx,
		`INSERT INTO nodes (org_id, name, cert_serial, agent_version, site_id, wg_public_key, endpoint)
		 VALUES ($1,'live-gw','live-serial','v0',$2,'live-pubkey','203.0.113.10:51820') RETURNING id`,
		f.org, siteID).Scan(&live); err != nil {
		t.Fatalf("create live gateway: %v", err)
	}

	rows, err := q.ListSiteNodesForOrg(f.ctx, f.org)
	if err != nil {
		t.Fatalf("ListSiteNodesForOrg: %v", err)
	}
	seen := map[uuid.UUID]bool{}
	for _, r := range rows {
		seen[r.ID] = true
	}

	if seen[stale] {
		t.Errorf("an ALREADY-REVOKED node that still carries site_id must not reach the policy compiler (node "+
			"%s). Every row revoked before the unbind shipped is in this state, and the compiler reduces these "+
			"rows into a SINGLE placement slot per site — so without the status filter a dead gateway can take "+
			"the slot from the live one, non-deterministically, and a site grant lands where nothing is listening",
			stale)
	}
	if !seen[live] {
		t.Errorf("the live gateway on that site must still be compiler input (node %s)", live)
	}
}
