package accesslog

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

var maxUUID = uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff")

func storeQ(t *testing.T) (*sqlc.Queries, *pgxpool.Pool) {
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
	return sqlc.New(pool), pool
}

func TestStoreInsertList(t *testing.T) {
	q, pool := storeQ(t)
	ctx := context.Background()
	org := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations (id,name,slug) VALUES ($1,'ae',$2)`, org, "ae-"+org.String()[:8]); err != nil {
		t.Fatalf("org: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org) })

	rule := uuid.New()
	srcDevice, srcUser := uuid.New(), uuid.New()
	// Keep created_at fixed so equal-timestamp keyset ordering is deterministic.
	// It remains the retention/keyset clock, not the agent-supplied OccurredAt.
	createdAt := time.Unix(1_000_000, 0).UTC()
	mk := func(seq int64, d Decision) Event {
		return Event{ID: uuid.New(), CreatedAt: createdAt, Seq: seq, OrgID: org, OccurredAt: time.Now().UTC(), Decision: d,
			RuleID: &rule, SrcDeviceID: &srcDevice, SrcUserID: &srcUser, SrcKind: "human",
			SrcIP: "10.99.0.10", DstIP: "10.0.5.5", Protocol: "tcp", DstPort: 5432}
	}
	// Insert 5 events. seq now comes from the per-org counter and is unique by construction,
	// so InsertAccessEvent is a PLAIN insert (review #1): a duplicate (org,seq) FAILS LOUD (a
	// unique-violation error) rather than silently no-op'ing — a would-be silent audit drop.
	for i := int64(1); i <= 5; i++ {
		if err := q.InsertAccessEvent(ctx, InsertParams(mk(i, DecisionDeny))); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	if err := q.InsertAccessEvent(ctx, InsertParams(mk(5, DecisionDeny))); err == nil {
		t.Fatal("duplicate (org,seq) must now FAIL LOUD (unique violation), never a silent no-op")
	}
	// Separate INSERT statements remain correctly accounted for during a rolling
	// upgrade while older binaries are still using the pre-COPY ingest shape.
	assertRetainedRows(t, pool, org, 5)

	// Keyset first page (far-future cursor) → newest-first, FromRow round-trips.
	rows, err := q.ListAccessEvents(ctx, sqlc.ListAccessEventsParams{
		OrgID: org, BeforeCreatedAt: time.Now().Add(time.Hour), BeforeID: maxUUID, PageLimit: 10,
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 5 {
		t.Fatalf("want 5 rows, got %d", len(rows))
	}
	if e := FromRow(rows[0]); e.RuleID == nil || *e.RuleID != rule || e.SrcDeviceID == nil || *e.SrcDeviceID != srcDevice || e.SrcUserID == nil || *e.SrcUserID != srcUser || e.SrcKind != "human" || e.DstPort != 5432 || e.Decision != DecisionDeny {
		t.Fatalf("FromRow round-trip wrong: %+v", e)
	}

	// (seq high-water is now the per-org organizations.flow_seq counter, exercised via
	// IngestBatch in the ingest tests + the concurrency test — not derivable from a direct
	// insert here, which doesn't bump the counter.)

}
