package accesslog

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

type stubGrants struct {
	dstResource *uuid.UUID
	known       uuid.UUID
}

// TestIngestMaxReportUsesOneCopyStatement is the production-size guard for the
// retention counter's statement-level transition trigger. A full legal report
// must reach PostgreSQL as one COPY statement: reverting to :batchexec would
// invoke the trigger once per event and churn the same tenant state row 16,384
// times while holding the ingest transaction open.
func TestIngestMaxReportUsesOneCopyStatement(t *testing.T) {
	_, pool, org := ingestPool(t)
	ctx := context.Background()

	// Install an independent statement-trigger probe. Its transition-table row
	// total proves both COPY cardinality and the number of SQL statements used by
	// the generated ingest method, without coupling the test to implementation
	// details of the production counter trigger.
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	probeTable := pgx.Identifier{"access_event_copy_probe_" + suffix}.Sanitize()
	probeFunction := pgx.Identifier{"access_event_copy_probe_fn_" + suffix}.Sanitize()
	probeTrigger := pgx.Identifier{"zz_access_event_copy_probe_" + suffix}.Sanitize()
	if _, err := pool.Exec(ctx, fmt.Sprintf(`
		CREATE TABLE %s (
			org_id uuid PRIMARY KEY,
			calls bigint NOT NULL DEFAULT 0,
			rows_seen bigint NOT NULL DEFAULT 0
		)`, probeTable)); err != nil {
		t.Fatalf("create COPY trigger probe: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON access_events`, probeTrigger))
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, probeFunction))
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP TABLE IF EXISTS %s`, probeTable))
	})
	if _, err := pool.Exec(ctx, fmt.Sprintf(`INSERT INTO %s(org_id) VALUES ($1)`, probeTable), org); err != nil {
		t.Fatalf("seed COPY trigger probe: %v", err)
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger AS $probe$
		BEGIN
			UPDATE %s AS probe
			SET calls=calls + 1,
				rows_seen=rows_seen + (
					SELECT count(*) FROM probed_inserted_events inserted
					WHERE inserted.org_id=probe.org_id
				)
			WHERE EXISTS (
				SELECT 1 FROM probed_inserted_events inserted
				WHERE inserted.org_id=probe.org_id
			);
			RETURN NULL;
		END;
		$probe$ LANGUAGE plpgsql`, probeFunction, probeTable)); err != nil {
		t.Fatalf("create COPY trigger probe function: %v", err)
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(`
		CREATE TRIGGER %s
			AFTER INSERT ON access_events
			REFERENCING NEW TABLE AS probed_inserted_events
			FOR EACH STATEMENT EXECUTE FUNCTION %s()`,
		probeTrigger, probeFunction)); err != nil {
		t.Fatalf("install COPY trigger probe: %v", err)
	}

	const maxReportEvents = 16_384
	now := time.Now().UTC()
	events := make([]WireEvent, maxReportEvents)
	for idx := range events {
		events[idx] = WireEvent{
			OccurredAt: now,
			Verdict:    wireAllow,
			SrcIP:      "10.99.0.1",
			DstIP:      "10.0.0.1",
			Protocol:   "tcp",
		}
	}

	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	started := time.Now()
	if err := NewIngester(pool, stubGrants{}, nil, nil, nil).IngestBatch(runCtx, org, uuid.New(), events, 0); err != nil {
		t.Fatalf("ingest maximum legal report: %v", err)
	}
	if elapsed := time.Since(started); elapsed >= 30*time.Second {
		t.Fatalf("maximum legal report exceeded runtime bound: %s", elapsed)
	}

	var count, distinctSeq, minSeq, maxSeq int64
	if err := pool.QueryRow(ctx, `
		SELECT count(*),count(DISTINCT seq),min(seq),max(seq)
		FROM access_events WHERE org_id=$1`, org).Scan(&count, &distinctSeq, &minSeq, &maxSeq); err != nil {
		t.Fatalf("read maximum report sequence proof: %v", err)
	}
	if count != maxReportEvents || distinctSeq != maxReportEvents || minSeq != 1 || maxSeq != maxReportEvents {
		t.Fatalf("maximum report count/distinct/min/max = %d/%d/%d/%d, want %d/%d/1/%d",
			count, distinctSeq, minSeq, maxSeq, maxReportEvents, maxReportEvents, maxReportEvents)
	}
	assertRetainedRows(t, pool, org, maxReportEvents)

	var calls, rowsSeen int64
	if err := pool.QueryRow(ctx, fmt.Sprintf(`SELECT calls,rows_seen FROM %s WHERE org_id=$1`, probeTable), org).Scan(&calls, &rowsSeen); err != nil {
		t.Fatalf("read COPY trigger probe: %v", err)
	}
	if calls != 1 || rowsSeen != maxReportEvents {
		t.Fatalf("COPY statement trigger calls/rows = %d/%d, want 1/%d", calls, rowsSeen, maxReportEvents)
	}
}

func TestIngestCopyFailureRollsBackEventsSequenceAndRetentionState(t *testing.T) {
	_, pool, org := ingestPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin failed-COPY fixture: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	if top, err := q.BumpOrgFlowSeq(ctx, sqlc.BumpOrgFlowSeqParams{OrgID: org, N: 3}); err != nil || top != 3 {
		t.Fatalf("reserve failed-COPY sequence: top=%d err=%v", top, err)
	}

	now := time.Now().UTC()
	rows := make([]sqlc.InsertAccessEventBatchParams, 3)
	for idx, seq := range []int64{1, 1, 2} { // duplicate (org_id,seq) in the middle
		event := Event{
			ID:         uuid.New(),
			OrgID:      org,
			Seq:        seq,
			OccurredAt: now,
			CreatedAt:  now,
			Decision:   DecisionAllow,
			SrcIP:      "10.99.0.1",
			DstIP:      "10.0.0.1",
			Protocol:   "tcp",
		}
		rows[idx] = sqlc.InsertAccessEventBatchParams(InsertParams(event))
	}
	if copied, err := q.InsertAccessEventBatch(ctx, rows); err == nil {
		t.Fatalf("duplicate sequence COPY unexpectedly inserted %d rows", copied)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback failed COPY: %v", err)
	}

	var eventCount, flowSeq int64
	if err := pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM access_events WHERE org_id=$1),
		       (SELECT flow_seq FROM organizations WHERE id=$1)`, org).Scan(&eventCount, &flowSeq); err != nil {
		t.Fatalf("read failed-COPY rollback proof: %v", err)
	}
	if eventCount != 0 || flowSeq != 0 {
		t.Fatalf("failed COPY left event count/flow sequence %d/%d, want 0/0", eventCount, flowSeq)
	}
	assertRetainedRows(t, pool, org, 0)
}

func TestInsertAccessEventBatchQueryAndCodegenUseCopyFrom(t *testing.T) {
	querySource, err := os.ReadFile("../../db/queries/access_events.sql")
	if err != nil {
		t.Fatalf("read access-event queries: %v", err)
	}
	if !strings.Contains(string(querySource), "-- name: InsertAccessEventBatch :copyfrom") ||
		strings.Contains(string(querySource), "-- name: InsertAccessEventBatch :batchexec") {
		t.Fatal("InsertAccessEventBatch must remain a single-statement sqlc :copyfrom query")
	}
	generated, err := os.ReadFile("../../db/sqlc/copyfrom.go")
	if err != nil {
		t.Fatalf("read generated COPY implementation: %v", err)
	}
	generatedSource := string(generated)
	if !strings.Contains(generatedSource, "func (q *Queries) InsertAccessEventBatch") ||
		!strings.Contains(generatedSource, "q.db.CopyFrom(ctx") {
		t.Fatal("sqlc output no longer implements InsertAccessEventBatch through pgx CopyFrom")
	}
}

func (s stubGrants) ResolveGrant(_ context.Context, _ uuid.UUID, ruleID uuid.UUID) (*uuid.UUID, *uuid.UUID, bool) {
	if ruleID == s.known {
		return s.dstResource, nil, true
	}
	return nil, nil, false // deleted / unknown rule
}

type stubDevices struct {
	user  *uuid.UUID
	known uuid.UUID
	kind  string
}

func (s stubDevices) Resolve(_ context.Context, _ uuid.UUID, deviceID uuid.UUID) (*uuid.UUID, string, bool) {
	if deviceID == s.known {
		kind := s.kind
		if kind == "" {
			kind = "agent"
		}
		return s.user, kind, true
	}
	return nil, "", false // unknown / foreign device id
}

// TestIngestStampsDeviceAndJoinsUser (S7.5.4 v3): an agent-stamped src_device_id is
// captured and joined to its owning user CP-side; an UNKNOWN device keeps its id but the
// user stays nil (report-absent, never guessed — no src_ip→device reconstruction).
func TestIngestStampsDeviceAndJoinsUser(t *testing.T) {
	q, pool, org := ingestPool(t)
	ctx := context.Background()
	node := uuid.New()
	dev, user, foreign := uuid.New(), uuid.New(), uuid.New()
	ing := NewIngester(pool, stubGrants{}, stubDevices{user: &user, known: dev}, nil, nil)

	now := time.Now().UTC()
	revision := int64(4)
	batch := []WireEvent{
		{OccurredAt: now, Verdict: "allow", PolicyHash: "abcdef123456", PolicyVersion: 7, SrcIP: "10.99.0.10", SrcDeviceID: dev.String(), SrcDeviceKind: "agent", SrcConfigRevision: &revision, DstIP: "10.0.5.5", Protocol: "tcp"},
		{OccurredAt: now, Verdict: "allow", SrcIP: "10.99.0.11", SrcDeviceID: foreign.String(), DstIP: "10.0.5.6", Protocol: "tcp"},
		{OccurredAt: now, Verdict: "future_verdict", SrcIP: "10.99.0.12", DstIP: "10.0.5.7", Protocol: "tcp"},
	}
	if err := ing.IngestBatch(ctx, org, node, batch, 0); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	rows, err := q.ListAccessEvents(ctx, sqlc.ListAccessEventsParams{OrgID: org, BeforeCreatedAt: time.Now().Add(time.Hour), BeforeID: maxUUID, PageLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	bySrc := map[string]Event{}
	for _, r := range rows {
		bySrc[FromRow(r).SrcIP] = FromRow(r)
	}
	known := bySrc["10.99.0.10"]
	if known.SrcDeviceID == nil || *known.SrcDeviceID != dev || known.SrcUserID == nil || *known.SrcUserID != user {
		t.Fatalf("known device must stamp device + join user, got %+v", known)
	}
	if known.SrcKind != "agent" || known.PolicyHash != "abcdef123456" || known.PolicyVersion != 7 || known.SrcConfigRevision == nil || *known.SrcConfigRevision != 4 || known.DecisionReason != ReasonMatchedGrant {
		t.Fatalf("applied snapshot metadata must round-trip exactly, got %+v", known)
	}
	// [9]: an UNVERIFIED/foreign device id is DROPPED (not persisted) — both device + user nil,
	// so the immutable log never holds an id that doesn't belong to this org (cross-tenant seed).
	_ = foreign
	unknown := bySrc["10.99.0.11"]
	if unknown.SrcDeviceID != nil || unknown.SrcUserID != nil {
		t.Fatalf("unverified device: BOTH device + user must be dropped to unattributed, got %+v", unknown)
	}
	if _, exists := bySrc["10.99.0.12"]; exists {
		t.Fatal("unknown verdict must be rejected, never silently reclassified as allow")
	}
}

func ingestPool(t *testing.T) (*sqlc.Queries, *pgxpool.Pool, uuid.UUID) {
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
	org := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO organizations (id,name,slug) VALUES ($1,'ig',$2)`, org, "ig-"+org.String()[:8]); err != nil {
		t.Fatalf("org: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })
	return sqlc.New(pool), pool, org
}

func TestIngestEnrichAggregateGapSeq(t *testing.T) {
	q, pool, org := ingestPool(t)
	ctx := context.Background()
	node := uuid.New()
	rule := uuid.New()
	res := uuid.New()
	ing := NewIngester(pool, stubGrants{dstResource: &res, known: rule}, nil, nil, func() time.Time { return time.Unix(1000, 0).UTC() })

	now := time.Now().UTC()
	batch := []WireEvent{
		{OccurredAt: now, Verdict: "allow", RuleID: rule.String(), SrcIP: "10.99.0.10", DstIP: "10.0.5.5", Protocol: "tcp", DstPort: 5432},
	}
	// A port scan: 20 denies from one src (> threshold 5) → must collapse to ONE aggregate.
	for p := 0; p < 20; p++ {
		batch = append(batch, WireEvent{OccurredAt: now, Verdict: "deny", SrcIP: "10.99.0.66", DstIP: "10.0.5.5", Protocol: "tcp", DstPort: p + 1})
	}
	// Report also dropped 7 events → a gap marker.
	if err := ing.IngestBatch(ctx, org, node, batch, 7); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	rows, err := q.ListAccessEvents(ctx, sqlc.ListAccessEventsParams{OrgID: org, BeforeCreatedAt: time.Now().Add(time.Hour), BeforeID: maxUUID, PageLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	// Expect exactly 3 rows: 1 allow, 1 deny_aggregate, 1 gap (the 20 denies collapsed).
	if len(rows) != 3 {
		t.Fatalf("want 3 rows (allow + deny_aggregate + gap), got %d", len(rows))
	}
	var sawAllow, sawAgg, sawGap bool
	seqs := map[int64]bool{}
	for _, r := range rows {
		seqs[r.Seq] = true
		e := FromRow(r)
		switch e.Decision {
		case DecisionAllow:
			sawAllow = true
			if e.RuleID == nil || *e.RuleID != rule || e.DstResourceID == nil || *e.DstResourceID != res {
				t.Fatalf("allow must be grant-enriched (rule + dst resource): %+v", e)
			}
			if e.SrcDeviceID != nil || e.SrcUserID != nil {
				t.Fatalf("device/user must be NIL (no IP-map attribution): %+v", e)
			}
		case DecisionDenyAggregate:
			sawAgg = true
			// SIEM-sufficient: src + count + window [start=OccurredAt, end=WindowEnd].
			if e.SrcIP != "10.99.0.66" || e.DenyCount != 20 || e.WindowEnd == nil || e.OccurredAt.IsZero() {
				t.Fatalf("deny_aggregate must carry src + count 20 + window bounds: %+v", e)
			}
			if e.WindowEnd.Before(e.OccurredAt) {
				t.Fatalf("window end must be >= start: %+v", e)
			}
		case DecisionGap:
			sawGap = true
			if e.DenyCount != 7 {
				t.Fatalf("gap must carry the dropped count 7: %+v", e)
			}
		}
	}
	if !sawAllow || !sawAgg || !sawGap {
		t.Fatalf("missing an event kind: allow=%v agg=%v gap=%v", sawAllow, sawAgg, sawGap)
	}
	// Seqs are the monotonic 1..3 (per-org), no rewind.
	if !seqs[1] || !seqs[2] || !seqs[3] {
		t.Fatalf("per-org seq must be monotonic 1..3, got %v", seqs)
	}
}

// A deny burst AT the threshold stays individual (not collapsed) — aggregation only fires
// past the bound.
func TestIngestDenyUnderThresholdNotAggregated(t *testing.T) {
	q, pool, org := ingestPool(t)
	ctx := context.Background()
	ing := NewIngester(pool, stubGrants{}, nil, nil, nil)
	batch := []WireEvent{}
	for p := 0; p < DenyAggregateThreshold; p++ { // exactly threshold, not over
		batch = append(batch, WireEvent{OccurredAt: time.Now().UTC(), Verdict: "deny", SrcIP: "10.99.0.7", DstIP: "10.0.0.1", Protocol: "tcp", DstPort: p + 1})
	}
	if err := ing.IngestBatch(ctx, org, uuid.New(), batch, 0); err != nil {
		t.Fatal(err)
	}
	rows, _ := q.ListAccessDenies(ctx, sqlc.ListAccessDeniesParams{OrgID: org, BeforeCreatedAt: time.Now().Add(time.Hour), BeforeID: maxUUID, PageLimit: 100})
	if len(rows) != DenyAggregateThreshold {
		t.Fatalf("at-threshold denies must stay individual: got %d, want %d", len(rows), DenyAggregateThreshold)
	}
	for _, r := range rows {
		if r.Decision != string(DecisionDeny) {
			t.Fatalf("want plain deny, got %q", r.Decision)
		}
	}
}

func TestDenyAggregationNeverCrossesAppliedSnapshot(t *testing.T) {
	agent, user := uuid.New(), uuid.New()
	r1, r2 := int64(4), int64(5)
	ing := NewIngester(nil, nil, stubDevices{user: &user, known: agent}, nil, nil)
	batch := make([]WireEvent, 0, 12)
	for i := 0; i < 6; i++ {
		batch = append(batch,
			WireEvent{OccurredAt: time.Unix(int64(i), 0), Verdict: "deny", SrcIP: "10.99.0.7", SrcDeviceID: agent.String(), SrcDeviceKind: "agent", SrcConfigRevision: &r1, PolicyHash: "aaaaaaaaaaaa", PolicyVersion: 7},
			WireEvent{OccurredAt: time.Unix(int64(i+10), 0), Verdict: "deny", SrcIP: "10.99.0.7", SrcDeviceID: agent.String(), SrcDeviceKind: "agent", SrcConfigRevision: &r2, PolicyHash: "bbbbbbbbbbbb", PolicyVersion: 7},
		)
	}
	got := ing.aggregate(context.Background(), uuid.New(), uuid.New(), batch)
	if len(got) != 2 {
		t.Fatalf("different applied snapshots must form separate aggregates, got %+v", got)
	}
	seen := map[string]int64{}
	for _, e := range got {
		if e.Decision != DecisionDenyAggregate || e.DenyCount != 6 || e.SrcConfigRevision == nil {
			t.Fatalf("bad snapshot aggregate: %+v", e)
		}
		seen[e.PolicyHash] = *e.SrcConfigRevision
	}
	if seen["aaaaaaaaaaaa"] != 4 || seen["bbbbbbbbbbbb"] != 5 {
		t.Fatalf("snapshot attribution mixed across aggregate: %v", seen)
	}
}

// seq is DB-derived + contiguous across batches — no burn, no false gap.
func TestIngestSeqContiguousAcrossBatches(t *testing.T) {
	q, pool, org := ingestPool(t)
	ctx := context.Background()
	ing := NewIngester(pool, stubGrants{}, nil, nil, nil)
	mk := func(ip string) []WireEvent {
		return []WireEvent{
			{OccurredAt: time.Now().UTC(), Verdict: "allow", SrcIP: ip, DstIP: "10.0.0.1", Protocol: "tcp"},
			{OccurredAt: time.Now().UTC(), Verdict: "allow", SrcIP: ip, DstIP: "10.0.0.2", Protocol: "tcp"},
		}
	}
	if err := ing.IngestBatch(ctx, org, uuid.New(), mk("10.99.0.1"), 0); err != nil {
		t.Fatal(err)
	}
	if err := ing.IngestBatch(ctx, org, uuid.New(), mk("10.99.0.2"), 0); err != nil {
		t.Fatal(err)
	}
	rows, _ := q.ListAccessEvents(ctx, sqlc.ListAccessEventsParams{OrgID: org, BeforeCreatedAt: time.Now().Add(time.Hour), BeforeID: maxUUID, PageLimit: 10})
	got := map[int64]bool{}
	for _, r := range rows {
		got[r.Seq] = true
	}
	for s := int64(1); s <= 4; s++ {
		if !got[s] {
			t.Fatalf("seq must be contiguous 1..4 across batches (DB-derived, no burn), missing %d: %v", s, got)
		}
	}
}

// 6/n seam: a `terminated` wire event (a flow torn down by a rule-revoke) ingests as
// DecisionTerminated, enriched on the SAME rule_id as the revoked grant (the carried
// binding), and is NEVER aggregated.
func TestIngestTerminatedKeyedOnRuleID(t *testing.T) {
	q, pool, org := ingestPool(t)
	ctx := context.Background()
	rule := uuid.New()
	res := uuid.New()
	ing := NewIngester(pool, stubGrants{dstResource: &res, known: rule}, nil, nil, nil)
	batch := []WireEvent{
		{OccurredAt: time.Now().UTC(), Verdict: "terminated", RuleID: rule.String(), SrcIP: "10.99.0.10", DstIP: "10.0.5.5", Protocol: "tcp", DstPort: 5432},
		{OccurredAt: time.Now().UTC(), Verdict: "terminated", RuleID: rule.String(), SrcIP: "10.99.0.10", DstIP: "10.0.5.6", Protocol: "tcp", DstPort: 5433},
	}
	if err := ing.IngestBatch(ctx, org, uuid.New(), batch, 0); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	rows, err := q.ListAccessDenies(ctx, sqlc.ListAccessDeniesParams{OrgID: org, BeforeCreatedAt: time.Now().Add(time.Hour), BeforeID: maxUUID, PageLimit: 10})
	if err != nil {
		t.Fatal(err)
	}
	// Two distinct terminations (never collapsed), each keyed on the revoked grant.
	if len(rows) != 2 {
		t.Fatalf("terminated events must NOT aggregate: got %d, want 2", len(rows))
	}
	for _, r := range rows {
		e := FromRow(r)
		if e.Decision != DecisionTerminated {
			t.Fatalf("want decision=terminated, got %q", e.Decision)
		}
		if e.RuleID == nil || *e.RuleID != rule {
			t.Fatalf("terminated must carry the revoked grant's rule_id: %+v", e)
		}
		if e.DstResourceID == nil || *e.DstResourceID != res {
			t.Fatalf("terminated must be grant-enriched (dst resource): %+v", e)
		}
	}
}
