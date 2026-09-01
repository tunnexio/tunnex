package db_test

import (
	"os"
	"strings"
	"testing"
)

func TestK8sLifecycleClaimGenerationZeroTombstoneContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0131_k8s_lifecycle_claim_remint.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	queries, err := os.ReadFile("queries/k8s_lifecycle_claims.sql")
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"lifecycle_generation = 0",
		"lifecycle_aborted_at IS NOT NULL",
		"lifecycle_token_sealed IS NULL",
		"lifecycle_acknowledged_at IS NULL",
		"consumed_at IS NULL",
		"consumed_node_id IS NULL",
		"btrim(node_name) <> ''",
	} {
		if !strings.Contains(string(up), want) {
			t.Fatalf("0131 generation-zero shape missing %q", want)
		}
	}
	for _, want := range []string{
		"-- name: CreateAbortedLifecycleJoinToken :one",
		"TIMESTAMPTZ 'epoch'",
		"lifecycle_generation, lifecycle_request_id",
		"lifecycle_token_sealed, lifecycle_aborted_at",
		"NULL, now()",
		"ON CONFLICT (lifecycle_claim) WHERE lifecycle_claim IS NOT NULL DO NOTHING",
	} {
		if !strings.Contains(string(queries), want) {
			t.Fatalf("generation-zero tombstone query missing %q", want)
		}
	}
}
