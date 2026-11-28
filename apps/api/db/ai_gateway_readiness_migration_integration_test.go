package db_test

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

// TestAIGatewayReadinessMigrationPostgres proves 0259 up, down and up again:
// price bounds and tombstones, cost-setting bounds, once-per-day marks, the
// request log's closed vocabularies, and the two new alert event keys (with
// the static-key alert key from 0258 kept in every list).
func TestAIGatewayReadinessMigrationPostgres(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(adminPool.Close)
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("parse admin DSN: %v", err)
	}
	name := "tnx_aiready1_" + uuid.NewString()[:8]
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		if _, err := adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("drop test database %s: %v", name, err)
		}
	})
	branchURL := *u
	branchURL.Path = "/" + name
	dsn := branchURL.String()
	if err := db.MigrateTo(dsn, 259); err != nil {
		t.Fatalf("migrate to 0259: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	t.Cleanup(pool.Close)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	refuse := func(what, q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err == nil {
			t.Fatalf("%s was accepted", what)
		}
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}

	org := uuid.New()
	exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'A',$2)`, org, "a-"+org.String())

	price := `INSERT INTO ai_model_price_overrides(org_id,model,input_cost_per_token,output_cost_per_token) VALUES($1,$2,$3,$4)`
	refuse("a model without a provider", price, org, "gpt-x", 0.000001, 0.000002)
	refuse("a negative price", price, org, "openai/gpt-x", -0.1, 0.000002)
	refuse("a price above the bound", price, org, "openai/gpt-x", 0.02, 0.000002)
	refuse("a live price without input", price, org, "openai/gpt-x", nil, 0.000002)
	exec(price, org, "gemini/gemini-3.5-flash", 0.0, 0.0)
	refuse("a second price for one model", price, org, "gemini/gemini-3.5-flash", 0.1e-6, 0.2e-6)
	exec(`UPDATE ai_model_price_overrides SET removed=true,input_cost_per_token=NULL,output_cost_per_token=NULL,revision=revision+1 WHERE org_id=$1`, org)
	refuse("applied ahead of the revision", `UPDATE ai_model_price_overrides SET applied_revision=revision+1 WHERE org_id=$1`, org)

	settings := `INSERT INTO ai_gateway_cost_settings(org_id,unknown_price_policy,request_log_retention_days) VALUES($1,$2,$3)`
	refuse("an unknown policy", settings, org, "warn", 30)
	refuse("a retention of zero days", settings, org, "block", 0)
	refuse("a retention above a year", settings, org, "block", 366)
	exec(settings, org, "allow_and_alert", 365)

	mark := `INSERT INTO ai_gateway_alert_marks(org_id,day,mark_key) VALUES($1,current_date,$2) ON CONFLICT DO NOTHING`
	exec(mark, org, "budget:user_group:x:50")
	exec(mark, org, "budget:user_group:x:50")
	if n := count(`SELECT count(*) FROM ai_gateway_alert_marks WHERE org_id=$1`, org); n != 1 {
		t.Fatalf("a mark was recorded %d times in one day", n)
	}

	logRow := `INSERT INTO ai_request_log(id,org_id,occurred_at,subject_kind,model,mode,ingress,status_code,outcome,latency_ms,cost_state,refusal_code,cost_usd) VALUES($1,$2,now(),$3,'openai/gpt-x','chat',$4,200,'ok',12,$5,$6,$7)`
	refuse("an unknown subject kind", logRow, uuid.New(), org, "robot", "public", "pending", nil, nil)
	refuse("an unknown ingress", logRow, uuid.New(), org, "user", "internet", "pending", nil, nil)
	refuse("a refusal message as code", logRow, uuid.New(), org, "user", "public", "not_applicable", "Daily limit reached!", nil)
	refuse("a cost on an uncosted row", logRow, uuid.New(), org, "user", "public", "uncosted", nil, 0.01)
	exec(logRow, uuid.New(), org, "workload", "workload", "costed", nil, 0.01)

	for _, table := range []string{"alert_subscriptions", "alert_deliveries", "alert_delivery_cooldowns", "alert_occurrences"} {
		var def string
		if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname=$1`, table+"_event_key_check").Scan(&def); err != nil {
			t.Fatalf("%s constraint: %v", table, err)
		}
		for _, key := range []string{"ai.budget_threshold", "ai.price_unknown", "ai_workload.static_key_expiring", "agent.mcp_approval_pending", "ipsec.status_unavailable"} {
			if !strings.Contains(def, key) {
				t.Fatalf("%s must accept %s: %s", table, key, def)
			}
		}
	}

	if err := db.MigrateTo(dsn, 257); err != nil {
		t.Fatalf("migrate down to 0257: %v", err)
	}
	if n := count(`SELECT count(*) FROM information_schema.tables WHERE table_name IN ('ai_model_price_overrides','ai_gateway_cost_settings','ai_gateway_alert_marks','ai_request_log')`); n != 0 {
		t.Fatal("rolling back left a table")
	}
	if err := db.MigrateTo(dsn, 259); err != nil {
		t.Fatalf("migrate to 0259 again: %v", err)
	}
	if n := count(`SELECT count(*) FROM information_schema.tables WHERE table_name IN ('ai_model_price_overrides','ai_gateway_cost_settings','ai_gateway_alert_marks','ai_request_log')`); n != 4 {
		t.Fatal("migrating again did not create every table")
	}
}
