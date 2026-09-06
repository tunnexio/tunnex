package db

import (
	"context"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	legacy "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/jackc/pgx/v5"
)

// This fixture is shared only with the opt-in compatibility matrix, never a
// customer DB. Holding the old driver's lock must fence the new driver's Up.
func TestMigrationLockCompatibleWithLegacyDriver(t *testing.T) {
	raw := os.Getenv("TUNNEX_COMPAT_DATABASE_URL")
	if raw == "" {
		t.Skip("requires dedicated PostgreSQL compatibility fixture")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal("invalid fixture URL")
	}
	for _, escaped := range []bool{false, true} {
		name := "plain-path"
		candidate := *u
		if escaped {
			name = "escaped-path"
			// Encode a byte even when the fixture name has no reserved characters.
			if len(candidate.Path) > 1 {
				const hex = "0123456789ABCDEF"
				b := candidate.Path[1]
				candidate.RawPath = "/%" + string([]byte{hex[b>>4], hex[b&15]}) + url.PathEscape(candidate.Path[2:])
			}
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			probe, err := pgx.Connect(ctx, candidate.String())
			if err != nil {
				t.Fatal("fixture connection failed")
			}
			defer probe.Close(context.Background())
			m, err := newMigrator(candidate.String())
			if err != nil {
				t.Fatal("new migration adapter initialization failed")
			}
			defer m.Close()
			oldURL := candidate
			q := oldURL.Query()
			// lib/pq does not recognize this option; the new adapter retains it.
			q.Del("channel_binding")
			oldURL.RawQuery = q.Encode()
			old, err := (&legacy.Postgres{}).Open(oldURL.String())
			if err != nil {
				t.Fatal("legacy migration adapter initialization failed")
			}
			defer old.Close()
			if err := old.Lock(); err != nil {
				t.Fatal("legacy migration lock failed")
			}
			defer old.Unlock()
			finished := make(chan error, 1)
			go func() { finished <- m.Up() }()
			var schema string
			if err := probe.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
				t.Fatal("fixture schema query failed")
			}
			key, err := database.GenerateAdvisoryLockId(candidate.Path, schema, "schema_migrations")
			if err != nil {
				t.Fatal("lock identity failed")
			}
			for {
				select {
				case <-finished:
					t.Fatal("new migrator bypassed the legacy advisory lock")
				default:
				}
				var waiting bool
				err := probe.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND classid=0 AND objid::bigint=$1::bigint AND database=(SELECT oid FROM pg_database WHERE datname=current_database()))`, key).Scan(&waiting)
				if err != nil {
					t.Fatal("new migrator never waited on the legacy lock")
				}
				if waiting {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err := old.Unlock(); err != nil {
				t.Fatal("legacy migration unlock failed")
			}
			select {
			case err := <-finished:
				if err != nil && !errors.Is(err, migrate.ErrNoChange) {
					t.Fatal("new migration did not resume after legacy unlock")
				}
			case <-ctx.Done():
				t.Fatal("new migration did not resume after legacy unlock")
			}
		})
	}
}
