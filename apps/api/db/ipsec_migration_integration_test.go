package db_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
)

// This gate deliberately uses real PostgreSQL, including deferred COMMIT checks.
// Its caller must supply a guarded, disposable database fixture; an absent DSN
// is a skipped gate and is not migration acceptance evidence.
func TestIPsecMigrationPostgres(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set guarded TUNNEX_TEST_DATABASE_URL to run 0158 PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(adminPool.Close)
	base, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	newDB := func(t *testing.T, label string) (string, *pgxpool.Pool) {
		t.Helper()
		name := "tnx_ipsec_" + label + "_" + strings.ReplaceAll(uuid.NewString(), "-", "")
		if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
				t.Errorf("drop scratch database: %v", err)
			}
		})
		u := *base
		u.Path = "/" + name
		pool, err := pgxpool.New(ctx, u.String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		if err := db.MigrateTo(u.String(), 158); err != nil {
			t.Fatalf("0158 up: %v", err)
		}
		return u.String(), pool
	}
	exec := func(t *testing.T, pool *pgxpool.Pool, query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	type owner struct{ org, site, node uuid.UUID }
	seed := func(t *testing.T, pool *pgxpool.Pool) owner {
		t.Helper()
		o := owner{uuid.New(), uuid.New(), uuid.New()}
		exec(t, pool, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'ipsec test',$2,'10.211.0.0/24')`, o.org, o.org.String())
		exec(t, pool, `INSERT INTO sites(id,org_id,name) VALUES($1,$2,'existing WG site')`, o.site, o.org)
		exec(t, pool, `INSERT INTO nodes(id,org_id,name,cert_serial,site_id) VALUES($1,$2,'existing gateway',$3,$4)`, o.node, o.org, o.node.String(), o.site)
		return o
	}
	// Test refusals in a transaction so deferred ownership/shape checks count.
	reject := func(t *testing.T, pool *pgxpool.Pool, query string, args ...any) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, query, args...)
		if err == nil {
			err = tx.Commit(ctx)
		}
		if err == nil {
			t.Fatal("unsafe direct SQL unexpectedly committed")
		}
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || !(strings.HasPrefix(pe.Code, "23") || pe.Code == "P0001") {
			t.Fatalf("expected integrity refusal, got %v", err)
		}
	}
	insertConnection := func(tx pgx.Tx, o owner, id uuid.UUID) error {
		_, err := tx.Exec(ctx, `INSERT INTO ipsec_connections(id,org_id,name,site_id,gateway_node_id,historical_site_id,historical_gateway_node_id) VALUES($1,$2,'disabled configuration',$3,$4,$3,$4)`, id, o.org, o.site, o.node)
		return err
	}
	insertTunnel := func(tx pgx.Tx, o owner, connection, tunnel uuid.UUID, slot int) error {
		if _, err := tx.Exec(ctx, `INSERT INTO ipsec_tunnels(id,org_id,connection_id,slot) VALUES($1,$2,$3,$4)`, tunnel, o.org, connection, slot); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO ipsec_tunnel_secrets(tunnel_id,org_id,connection_id,secret_revision,sealed_psk) VALUES($1,$2,$3,1,'synthetic-sealed-envelope')`, tunnel, o.org, connection)
		return err
	}
	t.Run("empty_up_down_up", func(t *testing.T) {
		dsn, pool := newDB(t, "empty")
		if err := db.DownOne(dsn); err != nil {
			t.Fatalf("empty rollback: %v", err)
		}
		if err := db.MigrateTo(dsn, 158); err != nil {
			t.Fatalf("reapply: %v", err)
		}
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM ipsec_connections`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("reapplied empty schema: count=%d err=%v", n, err)
		}
	})
	t.Run("explicit_setting_blocks_rollback", func(t *testing.T) {
		dsn, pool := newDB(t, "setting")
		o := seed(t, pool)
		exec(t, pool, `INSERT INTO ipsec_org_settings(org_id) VALUES($1)`, o.org)
		var enabled bool
		var revision int64
		if err := pool.QueryRow(ctx, `SELECT enabled,revision FROM ipsec_org_settings WHERE org_id=$1`, o.org).Scan(&enabled, &revision); err != nil || enabled || revision != 1 {
			t.Fatalf("default opt-in enabled=%v revision=%d err=%v", enabled, revision, err)
		}
		reject(t, pool, `UPDATE ipsec_org_settings SET revision=0 WHERE org_id=$1`, o.org)
		reject(t, pool, `UPDATE ipsec_org_settings SET enabled=true WHERE org_id=$1`, o.org)
		reject(t, pool, `UPDATE ipsec_org_settings SET revision=3 WHERE org_id=$1`, o.org)
		reject(t, pool, `DELETE FROM ipsec_org_settings WHERE org_id=$1`, o.org)
		reject(t, pool, `TRUNCATE ipsec_org_settings`)
		exec(t, pool, `UPDATE ipsec_org_settings SET enabled=true,revision=2 WHERE org_id=$1`, o.org)
		if err := db.DownOne(dsn); err == nil {
			t.Fatal("explicitly configured setting must block rollback")
		}
		if err := pool.QueryRow(ctx, `SELECT revision FROM ipsec_org_settings WHERE org_id=$1`, o.org).Scan(&revision); err != nil || revision != 2 {
			t.Fatalf("rollback damaged setting: %d %v", revision, err)
		}
	})
	t.Run("ownership_shape_and_tombstone", func(t *testing.T) {
		dsn, pool := newDB(t, "records")
		a, b := seed(t, pool), seed(t, pool)
		connection, tunnel1, tunnel2 := uuid.New(), uuid.New(), uuid.New()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if err := insertConnection(tx, a, connection); err != nil {
			t.Fatal(err)
		}
		if err := insertTunnel(tx, a, connection, tunnel1, 1); err != nil {
			t.Fatal(err)
		}
		if err := insertTunnel(tx, a, connection, tunnel2, 2); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("valid two-tunnel disabled create: %v", err)
		}
		for _, count := range []int{0, 1} {
			t.Run([]string{"zero_tunnels_refused", "one_tunnel_refused"}[count], func(t *testing.T) {
				id := uuid.New()
				tx, err := pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				if err := insertConnection(tx, a, id); err != nil {
					t.Fatal(err)
				}
				if count == 1 {
					if err := insertTunnel(tx, a, id, uuid.New(), 1); err != nil {
						t.Fatal(err)
					}
				}
				if err := tx.Commit(ctx); err == nil {
					t.Fatal("incomplete two-tunnel shape committed")
				}
				var n int
				if err := pool.QueryRow(ctx, `SELECT count(*) FROM ipsec_connections WHERE id=$1`, id).Scan(&n); err != nil || n != 0 {
					t.Fatalf("failed create leaked row: %d %v", n, err)
				}
			})
		}
		// Build a complete candidate shape so cardinality cannot mask ownership failures.
		attemptShape := func(t *testing.T, o owner, tunnelOrg uuid.UUID, secretOrg uuid.UUID, slot2 int, secret string, wantCode string) {
			t.Helper()
			id := uuid.New()
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			err = insertConnection(tx, o, id)
			for slot := 1; slot <= 2 && err == nil; slot++ {
				tunnel := uuid.New()
				actualSlot := slot
				if slot == 2 {
					actualSlot = slot2
				}
				_, err = tx.Exec(ctx, `INSERT INTO ipsec_tunnels(id,org_id,connection_id,slot) VALUES($1,$2,$3,$4)`, tunnel, tunnelOrg, id, actualSlot)
				if err == nil {
					_, err = tx.Exec(ctx, `INSERT INTO ipsec_tunnel_secrets(tunnel_id,org_id,connection_id,secret_revision,sealed_psk) VALUES($1,$2,$3,1,$4)`, tunnel, secretOrg, id, secret)
				}
			}
			if err == nil {
				err = tx.Commit(ctx)
			}
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != wantCode {
				t.Fatalf("full candidate expected SQLSTATE %s, got %v", wantCode, err)
			}
		}
		t.Run("insert_ownership_and_bounds", func(t *testing.T) {
			// Existing nodes permit an org/site mismatch. This fixture isolates
			// the site ownership FK from the separate bound-gateway FK.
			mismatchedNode := uuid.New()
			exec(t, pool, `INSERT INTO nodes(id,org_id,name,cert_serial,site_id) VALUES($1,$2,'mismatched fixture',$3,$4)`, mismatchedNode, a.org, mismatchedNode.String(), b.site)
			t.Run("site_fk", func(t *testing.T) {
				attemptShape(t, owner{a.org, b.site, mismatchedNode}, a.org, a.org, 2, "sealed", "23503")
			})
			t.Run("gateway_fk", func(t *testing.T) { attemptShape(t, owner{a.org, a.site, b.node}, a.org, a.org, 2, "sealed", "23503") })
			t.Run("tunnel_fk", func(t *testing.T) { attemptShape(t, a, b.org, b.org, 2, "sealed", "23503") })
			t.Run("secret_fk", func(t *testing.T) { attemptShape(t, a, a.org, b.org, 2, "sealed", "23503") })
			t.Run("slot_bound", func(t *testing.T) { attemptShape(t, a, a.org, a.org, 3, "sealed", "23514") })
			t.Run("slot_unique", func(t *testing.T) { attemptShape(t, a, a.org, a.org, 1, "sealed", "23505") })
			t.Run("secret_empty", func(t *testing.T) { attemptShape(t, a, a.org, a.org, 2, "", "23514") })
			t.Run("secret_bound", func(t *testing.T) { attemptShape(t, a, a.org, a.org, 2, strings.Repeat("x", 16385), "23514") })
			exec(t, pool, `DELETE FROM nodes WHERE id=$1`, mismatchedNode)
		})
		checks := []struct {
			name, sql string
			args      []any
		}{
			{"cross_org_site", `INSERT INTO ipsec_connections(id,org_id,name,site_id,gateway_node_id,historical_site_id,historical_gateway_node_id) VALUES($1,$2,'bad',$3,$4,$3,$4)`, []any{uuid.New(), a.org, b.site, a.node}},
			{"cross_org_gateway", `INSERT INTO ipsec_connections(id,org_id,name,site_id,gateway_node_id,historical_site_id,historical_gateway_node_id) VALUES($1,$2,'bad',$3,$4,$3,$4)`, []any{uuid.New(), a.org, a.site, b.node}},
			{"gateway_org_reassign", `UPDATE nodes SET org_id=$1 WHERE id=$2`, []any{b.org, a.node}},
			{"gateway_site_reassign", `UPDATE nodes SET site_id=$1 WHERE id=$2`, []any{b.site, a.node}},
			{"connection_identity", `UPDATE ipsec_connections SET id=$1,desired_revision=2 WHERE id=$2`, []any{uuid.New(), connection}},
			{"historical_identity", `UPDATE ipsec_connections SET historical_site_id=$1,desired_revision=2 WHERE id=$2`, []any{b.site, connection}},
			{"cross_org_tunnel", `UPDATE ipsec_tunnels SET org_id=$1 WHERE id=$2`, []any{b.org, tunnel1}},
			{"cross_org_secret", `UPDATE ipsec_tunnel_secrets SET org_id=$1 WHERE tunnel_id=$2`, []any{b.org, tunnel1}},
			{"invalid_slot", `UPDATE ipsec_tunnels SET slot=3 WHERE id=$1`, []any{tunnel1}},
			{"duplicate_slot", `UPDATE ipsec_tunnels SET slot=1 WHERE id=$1`, []any{tunnel2}},
			{"remove_tunnel", `DELETE FROM ipsec_tunnels WHERE id=$1`, []any{tunnel1}},
			{"remove_secret", `DELETE FROM ipsec_tunnel_secrets WHERE tunnel_id=$1`, []any{tunnel1}},
			{"secret_revision_mismatch", `UPDATE ipsec_tunnel_secrets SET secret_revision=2 WHERE tunnel_id=$1`, []any{tunnel1}},
			{"empty_secret", `UPDATE ipsec_tunnel_secrets SET sealed_psk='' WHERE tunnel_id=$1`, []any{tunnel1}},
			{"oversize_secret", `UPDATE ipsec_tunnel_secrets SET sealed_psk=repeat('x',16385) WHERE tunnel_id=$1`, []any{tunnel1}},
			{"enable_unavailable", `UPDATE ipsec_connections SET desired_intent='enabled',desired_revision=2 WHERE id=$1`, []any{connection}},
			{"stale_revision", `UPDATE ipsec_connections SET name='lost update' WHERE id=$1`, []any{connection}},
			{"revision_jump", `UPDATE ipsec_connections SET desired_revision=3 WHERE id=$1`, []any{connection}},
			{"site_delete", `DELETE FROM sites WHERE id=$1`, []any{a.site}},
			{"gateway_unbind", `UPDATE nodes SET site_id=NULL WHERE id=$1`, []any{a.node}},
			{"gateway_delete", `DELETE FROM nodes WHERE id=$1`, []any{a.node}},
			{"org_soft_delete", `UPDATE organizations SET deleted_at=now() WHERE id=$1`, []any{a.org}},
			{"org_hard_delete", `DELETE FROM organizations WHERE id=$1`, []any{a.org}},
			{"connection_hard_delete", `DELETE FROM ipsec_connections WHERE id=$1`, []any{connection}},
		}
		for _, check := range checks {
			t.Run(check.name, func(t *testing.T) { reject(t, pool, check.sql, check.args...) })
		}
		for _, table := range []string{"ipsec_connections", "ipsec_tunnels", "ipsec_tunnel_secrets"} {
			t.Run("truncate_"+table, func(t *testing.T) { reject(t, pool, "TRUNCATE "+table+" CASCADE") })
		}
		exec(t, pool, `UPDATE nodes SET capabilities='{}'::jsonb WHERE id=$1`, a.node)
		t.Run("concurrent_create_guards", func(t *testing.T) {
			for _, action := range []string{"org_delete", "site_delete", "gateway_unbind"} {
				t.Run(action, func(t *testing.T) {
					o := seed(t, pool)
					id := uuid.New()
					create, err := pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer create.Rollback(ctx)
					if err := insertConnection(create, o, id); err != nil {
						t.Fatal(err)
					}
					for slot := 1; slot <= 2; slot++ {
						if err := insertTunnel(create, o, id, uuid.New(), slot); err != nil {
							t.Fatal(err)
						}
					}
					query := `UPDATE organizations SET deleted_at=now() WHERE id=$1`
					target := o.org
					if action == "site_delete" {
						query = `DELETE FROM sites WHERE id=$1`
						target = o.site
					}
					if action == "gateway_unbind" {
						query = `UPDATE nodes SET site_id=NULL WHERE id=$1`
						target = o.node
					}
					opposite, err := pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer opposite.Rollback(ctx)
					if action == "org_delete" {
						var pid int
						if err := opposite.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
							t.Fatal(err)
						}
						if _, err := opposite.Exec(ctx, `SET LOCAL statement_timeout='5s'`); err != nil {
							t.Fatal(err)
						}
						result := make(chan error, 1)
						go func() { _, err := opposite.Exec(ctx, query, target); result <- err }()
						waitForLock(t, ctx, pool, pid, result)
						if err := create.Commit(ctx); err != nil {
							t.Fatal(err)
						}
						err := <-result
						var pe *pgconn.PgError
						if !errors.As(err, &pe) || pe.Code != "23514" {
							t.Fatalf("resumed org deletion must refuse committed connection: %v", err)
						}
						return
					}
					if _, err := opposite.Exec(ctx, `SET LOCAL lock_timeout='150ms'`); err != nil {
						t.Fatal(err)
					}
					_, err = opposite.Exec(ctx, query, target)
					var pe *pgconn.PgError
					if !errors.As(err, &pe) || pe.Code != "55P03" {
						t.Fatalf("opposing mutation must wait on create ownership lock: %v", err)
					}
					opposite.Rollback(ctx)
					if err := create.Commit(ctx); err != nil {
						t.Fatal(err)
					}
					reject(t, pool, query, target)
				})
			}
		})
		t.Run("concurrent_org_delete_before_create", func(t *testing.T) {
			o := seed(t, pool)
			deletion, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer deletion.Rollback(ctx)
			if _, err := deletion.Exec(ctx, `UPDATE organizations SET deleted_at=now() WHERE id=$1`, o.org); err != nil {
				t.Fatal(err)
			}
			create, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer create.Rollback(ctx)
			var pid int
			if err := create.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			if _, err := create.Exec(ctx, `SET LOCAL statement_timeout='5s'`); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() { result <- insertConnection(create, o, uuid.New()) }()
			waitForLock(t, ctx, pool, pid, result)
			if err := deletion.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			err = <-result
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != "23514" {
				t.Fatalf("resumed creation must refuse deleted organization: %v", err)
			}
		})
		t.Run("repeatable_read_org_delete_cannot_miss_committed_create", func(t *testing.T) {
			o := seed(t, pool)
			old, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer old.Rollback(ctx)
			var count int
			if err := old.QueryRow(ctx, `SELECT count(*) FROM ipsec_connections WHERE org_id=$1`, o.org).Scan(&count); err != nil || count != 0 {
				t.Fatalf("establish old snapshot: %d %v", count, err)
			}
			create, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer create.Rollback(ctx)
			id := uuid.New()
			if err := insertConnection(create, o, id); err != nil {
				t.Fatal(err)
			}
			for slot := 1; slot <= 2; slot++ {
				if err := insertTunnel(create, o, id, uuid.New(), slot); err != nil {
					t.Fatal(err)
				}
			}
			if err := create.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			_, err = old.Exec(ctx, `UPDATE organizations SET deleted_at=now() WHERE id=$1`, o.org)
			if err == nil {
				err = old.Commit(ctx)
			}
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || (pe.Code != "40001" && pe.Code != "23514") {
				t.Fatalf("old snapshot must not hide committed IPsec connection: %v", err)
			}
		})
		// Security revocation must remain available without synthesizing cleanup.
		exec(t, pool, `UPDATE nodes SET status='revoked',revoked_at=now() WHERE id=$1`, a.node)
		reject(t, pool, `DELETE FROM nodes WHERE id=$1`, a.node)
		// A never-delivered connection can finalize atomically, retaining immutable identity.
		tx, err = pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `UPDATE ipsec_connections SET desired_intent='deleted',desired_revision=2,deleted_at=now(),finalized_at=now(),site_id=NULL,gateway_node_id=NULL WHERE id=$1`, connection); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM ipsec_tunnel_secrets WHERE connection_id=$1`, connection); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM ipsec_tunnels WHERE connection_id=$1`, connection); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("never-delivered finalization: %v", err)
		}
		var valid bool
		if err := pool.QueryRow(ctx, `SELECT desired_intent='deleted' AND desired_revision=2 AND site_id IS NULL AND gateway_node_id IS NULL AND historical_site_id=$2 AND historical_gateway_node_id=$3 AND finalized_at IS NOT NULL AND deleted_at IS NOT NULL FROM ipsec_connections WHERE id=$1`, connection, a.site, a.node).Scan(&valid); err != nil || !valid {
			t.Fatalf("tombstone identity: %v %v", valid, err)
		}
		var n int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM ipsec_tunnels WHERE connection_id=$1)+(SELECT count(*) FROM ipsec_tunnel_secrets WHERE connection_id=$1)`, connection).Scan(&n); err != nil || n != 0 {
			t.Fatalf("finalization retained secret/configuration: %d %v", n, err)
		}
		reject(t, pool, `DELETE FROM ipsec_connections WHERE id=$1`, connection)
		reject(t, pool, `UPDATE ipsec_connections SET desired_revision=3 WHERE id=$1`, connection)
		reject(t, pool, `UPDATE ipsec_connections SET desired_intent='disabled',desired_revision=3,deleted_at=NULL,finalized_at=NULL,site_id=$2,gateway_node_id=$3 WHERE id=$1`, connection, a.site, a.node)
		// Shared WG sites remain unchanged, and released ownership no longer blocks their mutations.
		var transport string
		if err := pool.QueryRow(ctx, `SELECT link_transport FROM sites WHERE id=$1`, a.site).Scan(&transport); err != nil || transport != "wireguard" {
			t.Fatalf("shared WG site changed: %q %v", transport, err)
		}
		exec(t, pool, `UPDATE nodes SET site_id=NULL WHERE id=$1`, a.node)
		exec(t, pool, `DELETE FROM nodes WHERE id=$1`, a.node)
		exec(t, pool, `DELETE FROM sites WHERE id=$1`, a.site)
		exec(t, pool, `UPDATE organizations SET deleted_at=now() WHERE id=$1`, a.org)
		exec(t, pool, `UPDATE nodes SET site_id=NULL WHERE id=$1`, b.node)
		exec(t, pool, `DELETE FROM sites WHERE id=$1`, b.site)
		if err := db.DownOne(dsn); err == nil {
			t.Fatal("retained tombstone must refuse rollback")
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM ipsec_connections WHERE id=$1`, connection).Scan(&n); err != nil || n != 1 {
			t.Fatalf("rollback damaged tombstone: %d %v", n, err)
		}
	})
}

// Observe an actual PostgreSQL lock wait before releasing the opposing transaction;
// a fresh retry would not prove that the blocked statement rechecks current state.
func waitForLock(t *testing.T, ctx context.Context, pool *pgxpool.Pool, pid int, result <-chan error) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting bool
		if err := pool.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case err := <-result:
			t.Fatalf("opposing statement completed before ownership lock released: %v", err)
		case <-deadline.C:
			t.Fatal("opposing statement never entered a PostgreSQL lock wait")
		case <-tick.C:
		}
	}
}
