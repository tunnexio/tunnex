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
	defer pool.Close()
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
	all, err := port.List(ctx, org, false, future, maxUUID, 100)
	if err != nil || len(all) != 3 {
		t.Fatalf("full list: got %d (err %v), want 3", len(all), err)
	}
	// denies_only: the 2 denies (2 <= aggregate threshold, so individual).
	denies, err := port.List(ctx, org, true, future, maxUUID, 100)
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
	page1, err := port.List(ctx, org, false, future, maxUUID, 2)
	if err != nil || len(page1) != 2 {
		t.Fatalf("page1: got %d, want 2", len(page1))
	}
	last := page1[len(page1)-1]
	page2, err := port.List(ctx, org, false, last.CreatedAt, last.ID, 2)
	if err != nil || len(page2) != 1 {
		t.Fatalf("page2: got %d, want 1", len(page2))
	}
	if page2[0].ID == page1[0].ID || page2[0].ID == page1[1].ID {
		t.Fatalf("keyset page2 overlapped page1: %v", page2[0].ID)
	}
}
