//go:build enterprise

package http

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/accesslog"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

// The enterprise access-log port pages by keyset (created_at, id) and filters the denies
// feed. Seeds via the real Ingester, then reads through the port.
func TestAccessLogPortKeysetAndDeniesFilter(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	org := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug) VALUES ($1,'al',$2)`, org, "al-"+org.String()[:8]); err != nil {
		t.Fatalf("org: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org) })

	ing := accesslog.NewIngester(pool, accesslog.SQLGrantResolver{Q: sqlc.New(pool)}, accesslog.SQLDeviceResolver{Q: sqlc.New(pool)}, nil, nil)
	batch := []accesslog.WireEvent{
		{OccurredAt: time.Now().UTC(), Verdict: "allow", SrcIP: "10.99.0.10", DstIP: "10.0.5.5", Protocol: "tcp", DstPort: 443},
		{OccurredAt: time.Now().UTC(), Verdict: "deny", SrcIP: "10.99.0.11", DstIP: "10.0.5.6", Protocol: "tcp", DstPort: 22},
		{OccurredAt: time.Now().UTC(), Verdict: "deny", SrcIP: "10.99.0.12", DstIP: "10.0.5.7", Protocol: "tcp", DstPort: 3389},
	}
	if err := ing.IngestBatch(ctx, org, uuid.New(), batch, 0); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	port := NewAccessLogPort(pool, accesslog.NewHealth())
	future := time.Now().Add(time.Hour)

	// Full feed: 3 events, newest-first (created_at DESC, id DESC).
	all, err := port.List(ctx, org, nil, false, future, maxUUID, 100)
	if err != nil || len(all) != 3 {
		t.Fatalf("full list: got %d (err %v), want 3", len(all), err)
	}
	// denies_only: the 2 denies (2 <= aggregate threshold, so individual).
	denies, err := port.List(ctx, org, nil, true, future, maxUUID, 100)
	if err != nil || len(denies) != 2 {
		t.Fatalf("denies feed: got %d, want 2", len(denies))
	}
	for _, e := range denies {
		if e.Decision == accesslog.DecisionAllow {
			t.Fatalf("denies feed leaked an allow: %+v", e)
		}
	}

	// Keyset: page of 2, then the cursor (last.created_at, last.id) yields the remaining 1,
	// with no overlap.
	page1, err := port.List(ctx, org, nil, false, future, maxUUID, 2)
	if err != nil || len(page1) != 2 {
		t.Fatalf("page1: got %d, want 2", len(page1))
	}
	last := page1[len(page1)-1]
	page2, err := port.List(ctx, org, nil, false, last.CreatedAt, last.ID, 2)
	if err != nil || len(page2) != 1 {
		t.Fatalf("page2: got %d, want 1", len(page2))
	}
	if page2[0].ID == page1[0].ID || page2[0].ID == page1[1].ID {
		t.Fatalf("keyset page2 overlapped page1: %v", page2[0].ID)
	}

	// These historical IDs are deliberately absent from the live device and
	// membership rosters. The query contract is an exact event-row match, not
	// live validation or an identity lookup.
	target, other := uuid.New(), uuid.New()
	ownerA, ownerB := uuid.New(), uuid.New()
	q := sqlc.New(pool)
	identityEvents := []struct {
		deviceID uuid.UUID
		userID   uuid.UUID
		kind     string
		decision accesslog.Decision
	}{
		{target, ownerA, "agent", accesslog.DecisionDeny},
		{other, ownerB, "agent", accesslog.DecisionDeny},
		// Device filtering is intentionally not narrowed by kind. This also
		// proves that the compatibility src_agent_id filter stays agent-only.
		{target, ownerA, "human", accesslog.DecisionAllow},
	}
	for n, seed := range identityEvents {
		reason := accesslog.ReasonNoMatchingGrant
		if seed.decision == accesslog.DecisionAllow {
			reason = accesslog.ReasonMatchedGrant
		}
		e := accesslog.Event{ID: uuid.New(), CreatedAt: time.Now().UTC(), Seq: int64(4 + n), OrgID: org, OccurredAt: time.Now().UTC(), Decision: seed.decision, DecisionReason: reason, SrcDeviceID: &seed.deviceID, SrcUserID: &seed.userID, SrcKind: seed.kind, SrcIP: "10.99.0.20", DstIP: "10.0.0.1", Protocol: "tcp"}
		if err := q.InsertAccessEvent(ctx, accesslog.InsertParams(e)); err != nil {
			t.Fatalf("identity event: %v", err)
		}
	}

	// Use the same persisted identities in another tenant. Every identity query
	// must retain its org predicate, even though identity IDs are globally shaped UUIDs.
	otherOrg := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug) VALUES ($1,'al-other',$2)`, otherOrg, "al-other-"+otherOrg.String()[:8]); err != nil {
		t.Fatalf("other org: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, otherOrg) })
	foreign := accesslog.Event{ID: uuid.New(), CreatedAt: time.Now().UTC(), Seq: 1, OrgID: otherOrg, OccurredAt: time.Now().UTC(), Decision: accesslog.DecisionDeny, DecisionReason: accesslog.ReasonNoMatchingGrant, SrcDeviceID: &target, SrcUserID: &ownerA, SrcKind: "human", SrcIP: "10.99.0.20", DstIP: "10.0.0.1", Protocol: "tcp"}
	if err := q.InsertAccessEvent(ctx, accesslog.InsertParams(foreign)); err != nil {
		t.Fatalf("foreign identity event: %v", err)
	}

	list := func(identity *accessEventIdentityFilter, deniesOnly bool) []accesslog.Event {
		t.Helper()
		got, err := port.List(ctx, org, identity, deniesOnly, time.Now().Add(time.Hour), maxUUID, 100)
		if err != nil {
			t.Fatalf("identity list: %v", err)
		}
		return got
	}
	agent := list(&accessEventIdentityFilter{Kind: accessEventIdentityAgent, ID: target}, false)
	if len(agent) != 1 || agent[0].SrcKind != "agent" {
		t.Fatalf("agent compatibility filter = %+v, want only the agent event", agent)
	}
	device := list(&accessEventIdentityFilter{Kind: accessEventIdentityDevice, ID: target}, false)
	if len(device) != 2 {
		t.Fatalf("device filter = %+v, want historical human and agent rows", device)
	}
	user := list(&accessEventIdentityFilter{Kind: accessEventIdentityUser, ID: ownerA}, false)
	if len(user) != 2 {
		t.Fatalf("user filter = %+v, want two tenant rows", user)
	}
	userDenies := list(&accessEventIdentityFilter{Kind: accessEventIdentityUser, ID: ownerA}, true)
	if len(userDenies) != 1 || userDenies[0].Decision != accesslog.DecisionDeny {
		t.Fatalf("user denies filter = %+v, want one deny", userDenies)
	}
	deviceDenies := list(&accessEventIdentityFilter{Kind: accessEventIdentityDevice, ID: target}, true)
	if len(deviceDenies) != 1 || deviceDenies[0].Decision != accesslog.DecisionDeny {
		t.Fatalf("device denies filter = %+v, want one deny", deviceDenies)
	}
	filter := &accessEventIdentityFilter{Kind: accessEventIdentityUser, ID: ownerA}
	identityPage1, err := port.List(ctx, org, filter, false, time.Now().Add(time.Hour), maxUUID, 1)
	if err != nil || len(identityPage1) != 1 {
		t.Fatalf("identity page1 = %+v err=%v, want one", identityPage1, err)
	}
	identityPage2, err := port.List(ctx, org, filter, false, identityPage1[0].CreatedAt, identityPage1[0].ID, 1)
	if err != nil || len(identityPage2) != 1 || identityPage2[0].ID == identityPage1[0].ID {
		t.Fatalf("identity page2 = %+v err=%v, want distinct continuation", identityPage2, err)
	}
	if unknown := list(&accessEventIdentityFilter{Kind: accessEventIdentityDevice, ID: uuid.New()}, false); len(unknown) != 0 {
		t.Fatalf("unknown historical identity must return an empty page, got %+v", unknown)
	}
}

func TestAccessLogCollectorsAreTenantScopedAndIndependentOfTraffic(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	org, otherOrg := uuid.New(), uuid.New()
	for _, item := range []struct {
		id   uuid.UUID
		name string
	}{
		{org, "collector-org-" + org.String()[:8]},
		{otherOrg, "collector-other-" + otherOrg.String()[:8]},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug) VALUES ($1,$2,$2)`, item.id, item.name); err != nil {
			t.Fatalf("organization: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=ANY($1::uuid[])`, []uuid.UUID{org, otherOrg})
	})

	node, quietNode, staleNode, foreignNode := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	reportedAt := time.Now().UTC().Truncate(time.Microsecond)
	observedAt := reportedAt.Add(-2 * time.Minute)
	deliveredAt := reportedAt.Add(-time.Minute)
	if _, err := pool.Exec(ctx, `
		INSERT INTO nodes (id,org_id,name,cert_serial,policy_reported_at,capabilities) VALUES
		($1,$4,'active-collector',$6,$9,jsonb_build_object(
			'flow_log_state','active',
			'flow_log_last_observed_at',$10::timestamptz,
			'flow_log_last_delivered_at',$11::timestamptz)),
		($2,$4,'quiet-collector',$7,$9,jsonb_build_object('flow_log_state','active')),
		($3,$5,'foreign-collector',$8,$9,jsonb_build_object('flow_log_state','delivery_error'))`,
		node, quietNode, foreignNode, org, otherOrg,
		"collector-"+node.String(), "collector-"+quietNode.String(), "collector-"+foreignNode.String(),
		reportedAt, observedAt, deliveredAt); err != nil {
		t.Fatalf("nodes: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO nodes (id,org_id,name,cert_serial,policy_reported_at,capabilities)
		VALUES ($1,$2,'stale-collector',$3,$4,jsonb_build_object('flow_log_state','active'))`,
		staleNode, org, "collector-"+staleNode.String(), reportedAt.Add(-2*nodes.ReportFreshnessWindow)); err != nil {
		t.Fatalf("stale node: %v", err)
	}
	eventAt := reportedAt.Add(-30 * time.Second)
	if _, err := pool.Exec(ctx, `INSERT INTO access_events
		(org_id,seq,node_id,occurred_at,decision,src_ip,dst_ip,protocol,created_at)
		VALUES ($1,1,$2,$3,'allow','10.0.0.1','10.0.0.2','tcp',$3)`, org, node, eventAt); err != nil {
		t.Fatalf("access event: %v", err)
	}

	collectors, err := NewAccessLogPort(pool, accesslog.NewHealth()).Collectors(ctx, org)
	if err != nil {
		t.Fatalf("collectors: %v", err)
	}
	if len(collectors) != 3 {
		t.Fatalf("collectors = %+v, want exactly the three tenant gateways", collectors)
	}
	byID := map[uuid.UUID]accessLogCollectorStatus{}
	for _, collector := range collectors {
		byID[collector.NodeID] = collector
	}
	active := byID[node]
	if active.State != "active" || active.LastReportedAt == nil || active.LastObservedAt == nil || active.LastDeliveredAt == nil || active.LastEventAt == nil {
		t.Fatalf("active collector lost heartbeat/event evidence: %+v", active)
	}
	quiet := byID[quietNode]
	if quiet.State != "active" || quiet.LastEventAt != nil || quiet.LastObservedAt != nil || quiet.LastDeliveredAt != nil {
		t.Fatalf("quiet active collector must not be inferred unhealthy: %+v", quiet)
	}
	if stale := byID[staleNode]; stale.State != "stale" || stale.LastReportedAt == nil {
		t.Fatalf("stopped heartbeat must override its last active value: %+v", stale)
	}
	if _, leaked := byID[foreignNode]; leaked {
		t.Fatal("collector query leaked a gateway from another organization")
	}
}
