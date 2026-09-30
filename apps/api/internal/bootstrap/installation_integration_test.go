package bootstrap

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// Opt-in only: migrations and failure injection run against a fresh disposable
// bootstrap-test database, never the default development database.
func TestInstallationTransactionIntegration(t *testing.T) {
	dsn := os.Getenv("TUNNEX_BOOTSTRAP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires an isolated bootstrap-test database")
	}
	u, err := url.Parse(dsn)
	if err != nil || !strings.HasPrefix(u.Path, "/tunnex_bootstrap_") {
		t.Fatal("refusing a database without the bootstrap-test prefix")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var tables int
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'").Scan(&tables); err != nil || tables != 0 {
		t.Fatal("integration test requires a new empty database")
	}
	if err = db.Up(dsn); err != nil {
		t.Fatal(err)
	}
	q := sqlc.New(pool)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	intent := Installation{OrganizationName: "Bootstrap integration", GatewayName: "quickstart-gateway", GatewayTokenHash: strings.Repeat("ab", 32)}
	// A membership failure must roll back the earlier user and organization,
	// leave the first-run gate open, and never publish a credential.
	_, err = pool.Exec(ctx, `CREATE FUNCTION bootstrap_test_refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected membership failure'; END $$;
CREATE TRIGGER bootstrap_test_refuse BEFORE INSERT ON memberships FOR EACH ROW EXECUTE FUNCTION bootstrap_test_refuse()`)
	if err != nil {
		t.Fatal(err)
	}
	var failed bytes.Buffer
	if EnsureInstallation(ctx, pool, logger, &failed, "owner@example.test", nil, intent) == nil {
		t.Fatal("injected failure accepted")
	}
	users, err := q.CountUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	orgs, err := q.CountOrganizationsEver(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if users != 0 || orgs != 0 || failed.Len() != 0 {
		t.Fatal("partial bootstrap survived rollback")
	}
	if _, err = pool.Exec(ctx, "DROP TRIGGER bootstrap_test_refuse ON memberships; DROP FUNCTION bootstrap_test_refuse()"); err != nil {
		t.Fatal(err)
	}
	// Two initial replicas must produce one owner, one organization, one grant
	// and exactly one credential banner, even though both see a fresh start.
	var outputs [2]bytes.Buffer
	var errs [2]error
	var wg sync.WaitGroup
	for i := range outputs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = EnsureInstallation(ctx, pool, logger, &outputs[i], "owner@example.test", nil, intent)
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if (outputs[0].Len() > 0) == (outputs[1].Len() > 0) {
		t.Fatal("expected exactly one credential banner")
	}
	var owners, grants, audits int
	users, err = q.CountUsers(ctx)
	if err != nil || users != 1 {
		t.Fatal("wrong admin count")
	}
	orgs, err = q.CountOrganizationsEver(ctx)
	if err != nil || orgs != 1 {
		t.Fatal("wrong organization count")
	}
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.role='owner' AND u.cp_admin AND u.must_change_password").Scan(&owners); err != nil || owners != 1 {
		t.Fatal("bootstrap owner missing")
	}
	var ownerID uuid.UUID
	if err = pool.QueryRow(ctx, "SELECT id FROM users WHERE email='owner@example.test'").Scan(&ownerID); err != nil {
		t.Fatal(err)
	}
	visible, err := q.ListOrganizationsForUser(ctx, ownerID)
	if err != nil || len(visible) != 1 || visible[0].Name != intent.OrganizationName {
		t.Fatal("first-login organization listing missing")
	}
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM node_join_tokens WHERE node_name='quickstart-gateway' AND enrols_kind='gateway' AND issued_by IS NOT NULL AND expires_at > now() AND expires_at <= now() + interval '1 hour'").Scan(&grants); err != nil || grants != 1 {
		t.Fatal("gateway grant missing")
	}
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE action IN ('org.created','node.token_issued')").Scan(&audits); err != nil || audits != 2 {
		t.Fatal("bootstrap audit missing")
	}
	var restart bytes.Buffer
	intent.OrganizationName = "Must not appear"
	if err = EnsureInstallation(ctx, pool, logger, &restart, "another@example.test", nil, intent); err != nil || restart.Len() != 0 {
		t.Fatal("restart did not remain inert")
	}
	orgs, err = q.CountOrganizationsEver(ctx)
	if err != nil || orgs != 1 {
		t.Fatal("restart created another organization")
	}
}
