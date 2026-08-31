package db_test

import (
	"os"
	"strings"
	"testing"
)

func TestK8sBaseAuthorityDeliveryKindMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0129_k8s_base_authority_delivery_kind.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0129_k8s_base_authority_delivery_kind.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ADD COLUMN authority_kind text NOT NULL DEFAULT 'transition'",
		"ALTER COLUMN transition_revision DROP NOT NULL",
		"authority_kind = 'ordinary_base' AND transition_revision IS NULL",
		"k8s_base_authority_deliveries_transition_replay_idx",
	} {
		if !strings.Contains(string(up), want) {
			t.Fatalf("0129 up missing %q", want)
		}
	}
	for _, want := range []string{
		"LOCK TABLE k8s_base_authority_deliveries IN ACCESS EXCLUSIVE MODE",
		"cannot roll back 0129: ordinary-base authority deliveries exist",
		"ALTER COLUMN transition_revision SET NOT NULL",
		"DROP COLUMN authority_kind",
	} {
		if !strings.Contains(string(down), want) {
			t.Fatalf("0129 down missing %q", want)
		}
	}
}
