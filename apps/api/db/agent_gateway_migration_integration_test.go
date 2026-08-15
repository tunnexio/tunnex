package db_test

import (
	"context"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

// TestMultiAgentPerGatewayConcurrentIdentity is the F02 real-PostgreSQL proof:
// two independent agent identities can commit concurrently on one gateway after
// 0089, while the existing public-key and org-address backstops still reject
// collisions.
func TestMultiAgentPerGatewayConcurrentIdentity(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	var indexExists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname='devices_agent_node_key'
	)`).Scan(&indexExists); err != nil {
		t.Fatalf("inspect 0089 index: %v", err)
	}
	if indexExists {
		t.Fatal("0089 must remove the one-live-agent-per-gateway index before this proof runs")
	}

	org, owner, node := uuid.New(), uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	ex(`INSERT INTO organizations (id, name, slug, pool_cidr) VALUES ($1,'F02',$2,'10.94.0.0/24')`, org, "f02-"+org.String()[:8])
	ex(`INSERT INTO users (id, email) VALUES ($1,$2)`, owner, "f02-"+owner.String()[:8]+"@example.com")
	ex(`INSERT INTO nodes (id, org_id, name, cert_serial) VALUES ($1,$2,$3,$4)`, node, org, "gw-"+node.String()[:8], "f02-"+node.String()[:8])
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	rows := []struct{ id, key, ip string }{
		{uuid.New().String(), "f02-agent-key-a", "10.94.0.2"},
		{uuid.New().String(), "f02-agent-key-b", "10.94.0.3"},
	}
	start := make(chan struct{})
	errCh := make(chan error, len(rows))
	var wg sync.WaitGroup
	for _, row := range rows {
		row := row
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx, err := pool.Begin(ctx)
			if err != nil {
				errCh <- err
				return
			}
			defer tx.Rollback(ctx)
			<-start
			_, err = tx.Exec(ctx, `INSERT INTO devices
				(id, org_id, user_id, node_id, name, public_key, assigned_ip, status, kind)
				VALUES ($1,$2,$3,$4,$5,$6,$7,'active','agent')`,
				row.id, org, owner, node, "agent-"+row.id[:8], row.key, row.ip)
			if err == nil {
				err = tx.Commit(ctx)
			}
			errCh <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent same-node agent insert failed: %v", err)
		}
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM devices WHERE org_id=$1 AND node_id=$2 AND kind='agent' AND deleted_at IS NULL`, org, node).Scan(&count); err != nil {
		t.Fatalf("count agents: %v", err)
	}
	if count != 2 {
		t.Fatalf("same gateway must retain both independently identified agents, got %d", count)
	}

	rejects := func(name, key, ip string) {
		t.Helper()
		_, err := pool.Exec(ctx, `INSERT INTO devices
			(org_id, user_id, node_id, name, public_key, assigned_ip, status, kind)
			VALUES ($1,$2,$3,$4,$5,$6,'active','agent')`, org, owner, node, name, key, ip)
		if err == nil {
			t.Fatalf("%s: expected identity collision to be rejected", name)
		}
	}
	rejects("duplicate gateway public key", "f02-agent-key-a", "10.94.0.4")
	rejects("duplicate organization tunnel address", "f02-agent-key-c", "10.94.0.2")
}

// TestMultiAgentPerGatewayRollback proves both sides of 0089's reversible
// contract in throwaway PostgreSQL state: one live agent permits restoration of
// the old index, while multiple live agents refuse restoration without deleting
// either row.
func TestMultiAgentPerGatewayRollback(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer adminPool.Close()

	dbName := "tnx_f02_" + uuid.New().String()[:8]
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatalf("create database: %v", err)
	}
	defer func() { _, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+dbName+" WITH (FORCE)") }()

	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("parse admin DSN: %v", err)
	}
	u.Path = "/" + dbName
	dsn := u.String()
	if err := db.MigrateTo(dsn, 89); err != nil {
		t.Fatalf("migrate to 0089: %v", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("test db connect: %v", err)
	}
	org, owner, node := uuid.New(), uuid.New(), uuid.New()
	seed := func() {
		t.Helper()
		statements := []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'F02 rollback',$2,'10.96.0.0/24')`, []any{org, "f02-rb-" + org.String()[:8]}},
			{`INSERT INTO users (id,email) VALUES ($1,$2)`, []any{owner, "f02-rb-" + owner.String()[:8] + "@example.com"}},
			{`INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,$3,$4)`, []any{node, org, "gw-" + node.String()[:8], "rb-" + node.String()[:8]}},
		}
		for _, statement := range statements {
			if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
				t.Fatalf("seed: %v", err)
			}
		}
	}
	seed()
	insertAgent := func(id, key, ip string) {
		t.Helper()
		_, err := pool.Exec(ctx, `INSERT INTO devices
			(id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind)
			VALUES ($1,$2,$3,$4,$5,$6,$7,'active','agent')`,
			id, org, owner, node, "agent-"+id[:8], key, ip)
		if err != nil {
			t.Fatalf("insert agent: %v", err)
		}
	}
	indexExists := func() bool {
		t.Helper()
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname='devices_agent_node_key')`).Scan(&exists); err != nil {
			t.Fatalf("inspect index: %v", err)
		}
		return exists
	}
	countAgents := func() int {
		t.Helper()
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM devices WHERE node_id=$1 AND kind='agent' AND deleted_at IS NULL`, node).Scan(&count); err != nil {
			t.Fatalf("count agents: %v", err)
		}
		return count
	}

	insertAgent(uuid.New().String(), "f02-rb-key-a", "10.96.0.2")
	if err := db.DownOne(dsn); err != nil {
		t.Fatalf("0089 down with one live agent must succeed: %v", err)
	}
	if !indexExists() {
		t.Fatal("0089 down must restore devices_agent_node_key when at most one live agent exists")
	}
	if countAgents() != 1 {
		t.Fatal("successful rollback must preserve the existing agent row")
	}
	if err := db.MigrateTo(dsn, 89); err != nil {
		t.Fatalf("re-apply 0089: %v", err)
	}
	if indexExists() {
		t.Fatal("re-applied 0089 must remove devices_agent_node_key")
	}

	insertAgent(uuid.New().String(), "f02-rb-key-b", "10.96.0.3")
	before := countAgents()
	if before != 2 {
		t.Fatalf("rollback refusal setup must contain two live agents, got %d", before)
	}
	if err := db.DownOne(dsn); err == nil {
		t.Fatal("0089 down must refuse when multiple live agents share a gateway")
	}
	if got := countAgents(); got != before {
		t.Fatalf("refused rollback must preserve all live agents: before=%d after=%d", before, got)
	}
	if indexExists() {
		t.Fatal("refused rollback must not partially restore the one-agent index")
	}
	if v, dirty, ok, err := db.Version(dsn); err != nil || !ok || !dirty || v != 88 {
		t.Fatalf("expected golang-migrate to record the refused down as dirty at version 88: version=%d dirty=%v ok=%v err=%v", v, dirty, ok, err)
	}
	pool.Close()
}
