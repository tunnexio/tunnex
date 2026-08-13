package db_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestUpdatedAtTablesHaveTrigger enforces the convention that every table with
// an updated_at column has the set_updated_at trigger bound (see
// db/migrations/README.md). It queries the live schema, so it is gated on
// TUNNEX_TEST_DATABASE_URL and runs in `make e2e`, not in plain unit runs.
//
// It passes trivially today (no domain tables) — that is intentional. It is
// armed for S1.1: the day someone adds a table with updated_at but forgets the
// trigger, this fails.
func TestUpdatedAtTablesHaveTrigger(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	const q = `
		SELECT c.table_name
		FROM information_schema.columns c
		WHERE c.table_schema = 'public'
		  AND c.column_name = 'updated_at'
		  AND NOT EXISTS (
		    SELECT 1
		    FROM pg_trigger t
		    JOIN pg_class cl ON cl.oid = t.tgrelid
		    JOIN pg_namespace ns ON ns.oid = cl.relnamespace
		    WHERE ns.nspname = 'public'
		      AND cl.relname = c.table_name
		      AND NOT t.tgisinternal
		      AND t.tgname = 'set_updated_at'
		  )
		ORDER BY c.table_name;`

	rows, err := pool.Query(ctx, q)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	var offenders []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		offenders = append(offenders, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	if len(offenders) > 0 {
		t.Fatalf("tables with updated_at but no set_updated_at trigger: %v "+
			"(attach: CREATE TRIGGER set_updated_at BEFORE UPDATE ON <table> "+
			"FOR EACH ROW EXECUTE FUNCTION set_updated_at();)", offenders)
	}
}
