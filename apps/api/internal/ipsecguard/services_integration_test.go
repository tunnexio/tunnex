package ipsecguard_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/sites"
)

// The caller supplies the guarded, isolated fixture admin database.
// Each test creates and removes only its own uniquely named scratch database.
func resourceFixture(t *testing.T) (context.Context, *pgxpool.Pool, uuid.UUID, uuid.UUID) {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to the isolated fixture database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := "tnx_ipsec_guard_" + uuid.NewString()[:8]
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("scratch database cleanup: %v", err)
		}
	})
	parsed.Path = "/" + name
	if err = db.MigrateTo(parsed.String(), 159); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	org, actor := uuid.New(), uuid.New()
	if _, err = pool.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'IPsec settings',$2,'10.199.0.0/24')`, org, "ipsec-"+org.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO users(id,email) VALUES($1,$2)`, actor, actor.String()+"@ipsec-settings.test"); err != nil {
		t.Fatal(err)
	}
	return ctx, pool, org, actor
}

func TestResourceServicesRefuseIPsecReferences(t *testing.T) {
	ctx, pool, org, actor := resourceFixture(t)
	site, node, connection := uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'protected site')`, site, org)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id) VALUES($1,$2,'protected gateway',$3,$4)`, node, org, node.String(), site)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO ipsec_connections(id,org_id,name,site_id,gateway_node_id,historical_site_id,historical_gateway_node_id) VALUES($1,$2,'disabled',$3,$4,$3,$4)`, connection, org, site, node); err != nil {
		t.Fatal(err)
	}
	for slot := 1; slot <= 2; slot++ {
		tunnel := uuid.New()
		if _, err = tx.Exec(ctx, `INSERT INTO ipsec_tunnels(id,org_id,connection_id,slot) VALUES($1,$2,$3,$4)`, tunnel, org, connection, slot); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO ipsec_tunnel_secrets(tunnel_id,org_id,connection_id,secret_revision,sealed_psk) VALUES($1,$2,$3,1,'synthetic')`, tunnel, org, connection); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	ss, ns := sites.NewService(pool), nodes.NewService(pool, nil, nil)
	check := func(t *testing.T, err error, status int, code string) {
		t.Helper()
		var typed *apierr.Error
		if !errors.As(err, &typed) || typed.Status != status || typed.Code != code {
			t.Fatalf("expected %d %s, got %v", status, code, err)
		}
	}
	for name, op := range map[string]func() error{
		"site delete":     func() error { return ss.DeleteSite(ctx, actor, org, site) },
		"node unbind":     func() error { return ss.UnbindNode(ctx, org, node) },
		"explicit unbind": func() error { return ss.UnbindSiteNode(ctx, org, site, node) },
		"bodyless unbind": func() error { return ss.UnbindSiteNode(ctx, org, site, uuid.Nil) },
	} {
		t.Run(name, func(t *testing.T) { check(t, op(), 409, "ipsec_connection_in_use") })
	}
	check(t, ss.UnbindNode(ctx, uuid.New(), node), 404, "node_not_found")
	check(t, ss.DeleteSite(ctx, actor, uuid.New(), site), 404, "site_not_found")
	// Security revocation stays possible; physical deletion then refuses atomically.
	exec(`UPDATE nodes SET status='revoked',revoked_at=now() WHERE id=$1`, node)
	check(t, ns.DeleteRevokedNode(ctx, actor, org, node), 409, "ipsec_connection_in_use")
	var bound uuid.UUID
	var audits int
	if err := pool.QueryRow(ctx, `SELECT site_id FROM nodes WHERE id=$1`, node).Scan(&bound); err != nil || bound != site {
		t.Fatalf("binding changed: %v %v", bound, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1`, org).Scan(&audits); err != nil || audits != 0 {
		t.Fatalf("failed operation audit persisted: %d %v", audits, err)
	}
	// Finalization releases only live references, restoring existing service behavior.
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, query := range []string{
		`UPDATE ipsec_connections SET desired_intent='deleted',desired_revision=2,site_id=NULL,gateway_node_id=NULL,deleted_at=now(),finalized_at=now() WHERE id=$1`,
		`DELETE FROM ipsec_tunnel_secrets WHERE connection_id=$1`,
		`DELETE FROM ipsec_tunnels WHERE connection_id=$1`,
	} {
		if _, err = tx.Exec(ctx, query, connection); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = ss.UnbindSiteNode(ctx, org, site, node); err != nil {
		t.Fatal(err)
	}
	if err = ns.DeleteRevokedNode(ctx, actor, org, node); err != nil {
		t.Fatal(err)
	}
	if err = ss.DeleteSite(ctx, actor, org, site); err != nil {
		t.Fatal(err)
	}
}
