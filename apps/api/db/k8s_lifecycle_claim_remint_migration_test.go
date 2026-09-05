package db_test

import (
	"os"
	"strings"
	"testing"
)

func TestK8sLifecycleClaimRemintMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0135_k8s_lifecycle_claim_remint.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0135_k8s_lifecycle_claim_remint.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"LOCK TABLE node_join_tokens IN ACCESS EXCLUSIVE MODE",
		"LOCK TABLE nodes IN ACCESS EXCLUSIVE MODE",
		"ADD COLUMN lifecycle_claim uuid",
		"nodes_lifecycle_claim_key",
		"lifecycle_token_sealed text",
		"node_join_tokens_lifecycle_claim_key",
		"lifecycle_generation > 0",
		"CREATE TABLE k8s_lifecycle_claim_usage",
		"CREATE FUNCTION mark_k8s_lifecycle_claim_usage()",
		"node_join_tokens_lifecycle_usage_after_insert",
		"nodes_lifecycle_usage_after_insert",
		"node_lifecycle_enrollment_authorizations",
		"pg_backend_pid()",
		"txid_current()",
		"IF NEW.lifecycle_aborted_at IS NOT NULL",
		"NEW.lifecycle_token_sealed := NULL",
		"NEW.lifecycle_claim := authorized_claim",
		"SET consumed_node_id = NEW.id",
		"node_lifecycle_consumption_must_bind",
		"DEFERRABLE INITIALLY DEFERRED",
		"SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp",
	} {
		if !strings.Contains(string(up), want) {
			t.Fatalf("0135 up missing %q", want)
		}
	}
	upSQL := string(up)
	upTokenLock := strings.Index(upSQL, "LOCK TABLE node_join_tokens IN ACCESS EXCLUSIVE MODE")
	upNodeLock := strings.Index(upSQL, "LOCK TABLE nodes IN ACCESS EXCLUSIVE MODE")
	firstAlter := strings.Index(upSQL, "ALTER TABLE nodes")
	if upTokenLock < 0 || upNodeLock <= upTokenLock || firstAlter <= upNodeLock {
		t.Fatal("0135 up must lock token then node writers before changing either table")
	}
	for _, want := range []string{
		"LOCK TABLE node_join_tokens IN ACCESS EXCLUSIVE MODE",
		"LOCK TABLE nodes IN ACCESS EXCLUSIVE MODE",
		"LOCK TABLE k8s_lifecycle_claim_usage IN ACCESS EXCLUSIVE MODE",
		"IF EXISTS (SELECT 1 FROM k8s_lifecycle_claim_usage)",
		"EXISTS (SELECT 1 FROM node_join_tokens WHERE lifecycle_claim IS NOT NULL)",
		"OR EXISTS (SELECT 1 FROM nodes WHERE lifecycle_claim IS NOT NULL)",
		"database lifecycle is forward-only",
		"restore a verified pre-0135 backup",
		"DROP TRIGGER IF EXISTS node_lifecycle_consumption_must_bind",
		"DROP FUNCTION IF EXISTS node_lifecycle_capture_consumption()",
		"DROP TABLE IF EXISTS node_lifecycle_enrollment_authorizations",
		"DROP FUNCTION IF EXISTS mark_k8s_lifecycle_claim_usage()",
		"DROP TABLE IF EXISTS k8s_lifecycle_claim_usage",
		"DROP COLUMN IF EXISTS lifecycle_claim",
	} {
		if !strings.Contains(string(down), want) {
			t.Fatalf("0135 down missing populated-state refusal %q", want)
		}
	}
	downSQL := string(down)
	tokenLock := strings.Index(downSQL, "LOCK TABLE node_join_tokens IN ACCESS EXCLUSIVE MODE")
	nodeLock := strings.Index(downSQL, "LOCK TABLE nodes IN ACCESS EXCLUSIVE MODE")
	usageLock := strings.Index(downSQL, "LOCK TABLE k8s_lifecycle_claim_usage IN ACCESS EXCLUSIVE MODE")
	guard := strings.Index(downSQL, "EXISTS (SELECT 1 FROM node_join_tokens WHERE lifecycle_claim IS NOT NULL)")
	if tokenLock < 0 || nodeLock <= tokenLock || usageLock <= nodeLock || guard <= usageLock {
		t.Fatal("0135 down must lock token, node, then usage-sentinel writers before checking the forward-only data guard")
	}
}
