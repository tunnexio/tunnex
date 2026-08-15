package db_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

// TestK8sServicePortExposureIdentityInvariants exercises 0080 in an isolated
// database. It covers the two raw-SQL boundaries service-layer tests cannot
// protect: a child cannot be moved outside its parent's logical identity, and
// simultaneous final-child unexposes retire the shared VIP identity exactly once.
func TestK8sServicePortExposureIdentityInvariants(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this migration/concurrency integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dbName := fmt.Sprintf("tnx_port_migtest_%d", time.Now().UnixNano())
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer adminPool.Close()
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatalf("create isolated database: %v", err)
	}
	defer func() { _, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)") }()

	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + dbName
	dsn := u.String()
	if err := db.MigrateTo(dsn, 80); err != nil {
		t.Fatalf("migrate through 0080: %v", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect isolated database: %v", err)
	}
	defer pool.Close()

	org, site, clusterA, clusterB := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	exec(`INSERT INTO organizations (id, name, slug, pool_cidr) VALUES ($1, 'ports', $2, '10.99.0.0/24')`, org, "ports-"+org.String()[:8])
	exec(`INSERT INTO sites (id, org_id, name) VALUES ($1, $2, 'edge')`, site, org)
	for _, cluster := range []struct {
		id, name, vipRange string
	}{
		{clusterA.String(), "a", "100.64.0.0/24"},
		{clusterB.String(), "b", "100.65.0.0/24"},
	} {
		exec(`INSERT INTO k8s_clusters (id, org_id, site_id, name, vip_range, service_cidr, dns_zone) VALUES ($1, $2, $3, $4, $5, '10.96.0.0/12', 'k8s.acme.com')`, cluster.id, org, site, cluster.name, cluster.vipRange)
	}

	insertChild := func(proto string, port int, vip string) (id, identity uuid.UUID) {
		t.Helper()
		id = uuid.New()
		if err := pool.QueryRow(ctx, `
			INSERT INTO k8s_services (id, org_id, cluster_id, name, namespace, protocol, port_low, port_high, vip)
			VALUES ($1, $2, $3, 'api', 'prod', $4, $5, $5, $6)
			RETURNING identity_id`, id, org, clusterA, proto, port, vip).Scan(&identity); err != nil {
			t.Fatalf("insert %s/%d: %v", proto, port, err)
		}
		return id, identity
	}
	first, identity := insertChild("tcp", 80, "100.64.0.3")
	second, gotIdentity := insertChild("udp", 53, "100.64.0.99") // trigger must reuse .3
	if gotIdentity != identity {
		t.Fatalf("sibling ports must share an identity: first=%s second=%s", identity, gotIdentity)
	}
	var sharedVIP string
	if err := pool.QueryRow(ctx, `SELECT host(vip) FROM k8s_services WHERE id=$1`, second).Scan(&sharedVIP); err != nil || sharedVIP != "100.64.0.3" {
		t.Fatalf("sibling must inherit parent VIP .3, got %q (%v)", sharedVIP, err)
	}

	// Raw updates must fail at the database boundary; callers cannot move a child
	// across any component of the identity tuple while retaining its parent ID.
	for _, tc := range []struct {
		name, sql string
		arg       any
	}{
		{"cluster", `UPDATE k8s_services SET cluster_id=$2 WHERE id=$1`, clusterB},
		{"namespace", `UPDATE k8s_services SET namespace=$2 WHERE id=$1`, "other"},
		{"name", `UPDATE k8s_services SET name=$2 WHERE id=$1`, "other"},
	} {
		t.Run("raw update refuses "+tc.name, func(t *testing.T) {
			if _, err := pool.Exec(ctx, tc.sql, first, tc.arg); err == nil {
				t.Fatalf("raw %s update must violate the full child-parent identity FK", tc.name)
			}
		})
	}
	if _, err := pool.Exec(ctx, `UPDATE k8s_services SET identity_id=NULL WHERE id=$1`, first); err == nil {
		t.Fatal("raw identity NULL update must be rejected after backfill")
	}
	otherChild := uuid.New()
	var otherIdentity uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO k8s_services (id, org_id, cluster_id, name, namespace, protocol, port_low, port_high, vip)
		VALUES ($1, $2, $3, 'other', 'prod', 'tcp', 443, 443, '100.64.0.4')
		RETURNING identity_id`, otherChild, org, clusterA).Scan(&otherIdentity); err != nil {
		t.Fatalf("insert other identity: %v", err)
	}
	if otherIdentity == identity {
		t.Fatal("fixture must create a distinct identity")
	}
	if _, err := pool.Exec(ctx, `UPDATE k8s_services SET identity_id=$2 WHERE id=$1`, first, otherIdentity); err == nil {
		t.Fatal("raw cross-identity update must be rejected")
	}

	// Two final-child soft deletes race on different rows. The parent-row FOR UPDATE
	// in the retirement trigger must block the second transaction until the first
	// commits; only then can it observe zero live children and retire the identity.
	tx1, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer tx1.Rollback(ctx)
	tx2, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer tx2.Rollback(ctx)
	if _, err := tx1.Exec(ctx, `UPDATE k8s_services SET deleted_at=now() WHERE id=$1`, first); err != nil {
		t.Fatalf("first soft delete: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := tx2.Exec(context.Background(), `UPDATE k8s_services SET deleted_at=now() WHERE id=$1`, second)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("second final-child delete must wait on the identity lock, returned early: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if err := tx1.Commit(ctx); err != nil {
		t.Fatalf("commit first delete: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("second delete after first commit: %v", err)
	}
	if err := tx2.Commit(ctx); err != nil {
		t.Fatalf("commit second delete: %v", err)
	}
	var retired bool
	if err := pool.QueryRow(ctx, `SELECT deleted_at IS NOT NULL FROM k8s_service_identities WHERE id=$1`, identity).Scan(&retired); err != nil || !retired {
		t.Fatalf("identity must retire after concurrent final-child deletes, retired=%v err=%v", retired, err)
	}

	// A single-port identity is compatible with the 0080 down migration. Prove
	// the migration can roll back and recreate its identity boundary without
	// stranding the already backfilled rows.
	if err := db.DownOne(dsn); err != nil {
		t.Fatalf("0080 down: %v", err)
	}
	if err := db.MigrateTo(dsn, 80); err != nil {
		t.Fatalf("0080 up after down: %v", err)
	}
	var restoredIdentity uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT identity_id FROM k8s_services WHERE id=$1`, otherChild).Scan(&restoredIdentity); err != nil || restoredIdentity == uuid.Nil {
		t.Fatalf("0080 up after down must restore non-null identity: id=%s err=%v", restoredIdentity, err)
	}
}
