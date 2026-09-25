package alerts

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOccurrencePostgresLifecycle(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	// A session-local table exercises the real parameter inference and upsert,
	// without reading or mutating any persistent application table.
	_, err = pool.Exec(ctx, `CREATE TEMP TABLE alert_occurrences (
 org_id uuid,event_key text,dedup_key text,resource_type text,resource_id text,resource_name text,
 severity text,subject text,fields jsonb,state text,first_observed_at timestamptz,last_observed_at timestamptz,
 resolved_at timestamptz,occurrence_count bigint,UNIQUE(org_id,event_key,dedup_key))`)
	if err != nil {
		t.Fatal(err)
	}
	store := &PostgresOutbox{pool: pool}
	e := Event{OrgID: uuid.New(), Key: EventIPsecTunnelDown, DedupKey: "test-tunnel", Severity: SeverityWarning, Subject: "test", State: EventStateFiring, Resource: &ResourceRef{Type: "ipsec_connection", ID: "test"}, Fields: map[string]string{}}
	start := time.Now().UTC().Truncate(time.Microsecond)
	if err = store.ObserveOccurrence(ctx, e, start); err != nil {
		t.Fatal(err)
	}
	active, err := store.ListFiringOccurrences(ctx, e.OrgID, []EventKey{e.Key})
	if err != nil || len(active) != 1 {
		t.Fatalf("active occurrence: %d %v", len(active), err)
	}
	e.State = EventStateResolved
	if err = store.ObserveOccurrence(ctx, e, start.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	e.State = EventStateFiring
	if err = store.ObserveOccurrence(ctx, e, start.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	var state string
	var first, last, resolved time.Time
	var count int64
	err = pool.QueryRow(ctx, `SELECT state,first_observed_at,last_observed_at,resolved_at,occurrence_count FROM alert_occurrences`).Scan(&state, &first, &last, &resolved, &count)
	if err != nil {
		t.Fatal(err)
	}
	if state != "resolved" || !first.Equal(start) || !last.Equal(start.Add(time.Minute)) || !resolved.Equal(last) || count != 1 {
		t.Fatal("resolution or stale-observation guard lost")
	}
	e.DedupKey = "resolved-first"
	e.State = EventStateResolved
	if err = store.ObserveOccurrence(ctx, e, start); err != nil {
		t.Fatal(err)
	}
}
