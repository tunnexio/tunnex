package tenancy

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
)

// TestSetAgentRuntimeEnabledAuditsAndRollsBack proves that both directions are
// attributable and that an audit failure cannot leave the organization flag
// changed without its corresponding event.
func TestSetAgentRuntimeEnabledAuditsAndRollsBack(t *testing.T) {
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

	org, actor := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO organizations (id,name,slug) VALUES ($1,'F04 opt-in audit',$2)", org, "f04-audit-"+org.String()[:8]); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO users (id,email) VALUES ($1,$2)", actor, "f04-audit-"+actor.String()[:8]+"@example.com"); err != nil {
		t.Fatalf("seed actor: %v", err)
	}
	ctx = authctx.WithPrincipal(ctx, &authctx.Principal{UserID: actor, Email: "actor@example.com"})
	svc := NewService(pool)
	cleanupAuditFailure := func() {
		cleanupCtx := context.Background()
		tx, beginErr := pool.Begin(cleanupCtx)
		if beginErr != nil {
			return
		}
		defer tx.Rollback(cleanupCtx) //nolint:errcheck // cleanup is best effort after a test failure
		_, _ = tx.Exec(cleanupCtx, "DROP TRIGGER IF EXISTS f04_fail_runtime_audit ON audit_logs")
		_, _ = tx.Exec(cleanupCtx, "DROP FUNCTION IF EXISTS f04_fail_runtime_audit()")
		_ = tx.Commit(cleanupCtx)
	}
	// A prior interrupted run may have left this database-level fixture behind.
	// Clear it before the first assertion and register cleanup before creating it.
	cleanupAuditFailure()
	// Register this after pool.Close so it runs first and still has a live
	// connection when the test returns (including t.Fatal/Goexit cleanup).
	defer cleanupAuditFailure()

	set := func(enabled bool) {
		t.Helper()
		if _, err := svc.SetAgentRuntimeEnabled(ctx, org, enabled); err != nil {
			t.Fatalf("set enabled=%v: %v", enabled, err)
		}
	}
	set(true)
	set(false)

	rows, err := pool.Query(ctx, `SELECT action, actor_user_id::text, metadata->>'enabled'
		FROM audit_logs WHERE org_id=$1 AND action IN ('org.agent_runtime_enabled','org.agent_runtime_disabled')
		ORDER BY created_at`, org)
	if err != nil {
		t.Fatalf("read runtime audit: %v", err)
	}
	defer rows.Close()
	wantActions := []string{"org.agent_runtime_enabled", "org.agent_runtime_disabled"}
	for i := range wantActions {
		if !rows.Next() {
			t.Fatalf("missing audit row %d", i)
		}
		var action, actorID, enabled string
		if err := rows.Scan(&action, &actorID, &enabled); err != nil {
			t.Fatalf("scan audit row %d: %v", i, err)
		}
		if action != wantActions[i] || actorID != actor.String() || enabled != map[bool]string{true: "true", false: "false"}[i == 0] {
			t.Fatalf("audit row %d = action=%q actor=%q enabled=%q", i, action, actorID, enabled)
		}
	}
	if rows.Next() {
		t.Fatal("unexpected extra runtime audit row")
	}

	set(true)
	if _, err := pool.Exec(ctx, `CREATE FUNCTION f04_fail_runtime_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	IF NEW.action IN ('org.agent_runtime_enabled', 'org.agent_runtime_disabled') THEN
		RAISE EXCEPTION 'forced F04 audit failure';
	END IF;
	RETURN NEW;
END
$$`); err != nil {
		t.Fatalf("create audit failure function: %v", err)
	}
	if _, err := pool.Exec(ctx, `CREATE TRIGGER f04_fail_runtime_audit
	BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION f04_fail_runtime_audit()`); err != nil {
		t.Fatalf("create audit failure trigger: %v", err)
	}
	if _, err := svc.SetAgentRuntimeEnabled(ctx, org, false); err == nil {
		t.Fatal("forced audit failure must reject the toggle")
	}
	var enabled bool
	if err := pool.QueryRow(ctx, "SELECT managed_agent_runtime_enabled FROM organizations WHERE id=$1", org).Scan(&enabled); err != nil {
		t.Fatalf("read flag after forced audit failure: %v", err)
	}
	if !enabled {
		t.Fatal("failed audit must preserve the prior enabled flag")
	}
	var disabledAudits int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='org.agent_runtime_disabled'", org).Scan(&disabledAudits); err != nil {
		t.Fatalf("count disabled audits: %v", err)
	}
	if disabledAudits != 1 {
		t.Fatalf("failed toggle must not add an audit row, got %d disabled rows", disabledAudits)
	}
}
