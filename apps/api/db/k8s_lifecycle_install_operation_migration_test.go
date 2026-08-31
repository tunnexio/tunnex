package db_test

import (
	"os"
	"strings"
	"testing"
)

func TestK8sLifecycleInstallOperationMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0131_k8s_lifecycle_install_operations.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0131_k8s_lifecycle_install_operations.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	queries, err := os.ReadFile("queries/k8s_lifecycle_claims.sql")
	if err != nil {
		t.Fatal(err)
	}
	upSQL := string(up)
	for _, want := range []string{
		"CREATE TABLE node_lifecycle_install_operations",
		"UNIQUE (token_id, epoch)",
		"install_intent_digest ~ '^sha256:[0-9a-f]{64}$'",
		"requested_duration_seconds BETWEEN 1 AND 900",
		"CREATE TABLE k8s_lifecycle_install_operation_usage",
		"node_lifecycle_guard_token_abort",
		"latest_state <> 'aborted'",
		"node_lifecycle_guard_token_remint",
		"latest_state <> 'released' OR latest_abort_requested_at IS NOT NULL",
		"node_lifecycle_guard_token_consumption",
		"latest_not_after <= clock_timestamp()",
		"SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("0131 up missing %q", want)
		}
	}
	querySQL := string(queries)
	for _, want := range []string{
		"SELECT clock_timestamp()::timestamptz",
		"LEAST(token.expires_at, server_clock.now_at + make_interval",
		"SET heartbeat_at = GREATEST(heartbeat_at, (SELECT now_at FROM server_clock))",
		"operation.not_after > (SELECT now_at FROM server_clock)",
		"state = 'taken_over', epoch = epoch + 1",
	} {
		if !strings.Contains(querySQL, want) {
			t.Fatalf("D13h query contract missing %q", want)
		}
	}
	if strings.Contains(querySQL, "sqlc.arg(now_at)") {
		t.Fatal("D13h lease queries accept an application-supplied clock")
	}
	if strings.Contains(upSQL, "approved_plan_digest") || strings.Contains(querySQL, "approved_plan_digest") {
		t.Fatal("D13h persistence/query contract reused the display-plan digest name instead of install_intent_digest")
	}
	guardName := "node_join_tokens_aa_lifecycle_install_consume_guard_before_update"
	captureName := "node_join_tokens_lifecycle_capture_before_update"
	if !(guardName < captureName) || !strings.Contains(upSQL, "CREATE TRIGGER "+guardName) {
		t.Fatal("0131 consumption guard must sort before the 0130 authorization-capture trigger")
	}
	downSQL := string(down)
	for _, want := range []string{
		"LOCK TABLE node_join_tokens IN ACCESS EXCLUSIVE MODE",
		"LOCK TABLE node_lifecycle_install_operations IN ACCESS EXCLUSIVE MODE",
		"LOCK TABLE k8s_lifecycle_install_operation_usage IN ACCESS EXCLUSIVE MODE",
		"database lifecycle is forward-only",
		"restore a verified pre-0131 backup",
		"DROP FUNCTION IF EXISTS node_lifecycle_guard_token_abort()",
		"DROP FUNCTION IF EXISTS node_lifecycle_guard_token_remint()",
		"DROP FUNCTION IF EXISTS node_lifecycle_guard_token_consumption()",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("0131 down missing %q", want)
		}
	}
}
