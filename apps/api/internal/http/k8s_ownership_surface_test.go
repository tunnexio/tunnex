package http

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// TestManagedByOperatorSurfaced — S10.2 Slice 4 (D2 cond 1): the response DTOs expose managed_by_operator
// derived from the managed_by_machine ownership marker (Slice 3a). A machine-owned row surfaces true (the
// dashboard badges it + warns on manual edit); a human-created row (NULL marker) surfaces false (freely
// editable). Pure mapper — no DB.
func TestManagedByOperatorSurfaced(t *testing.T) {
	owned := pgtype.UUID{Bytes: uuid.New(), Valid: true}
	none := pgtype.UUID{Valid: false}

	if !toAPIK8sCluster(sqlc.K8sCluster{ManagedByMachine: owned}).ManagedByOperator {
		t.Fatal("machine-owned cluster must surface managed_by_operator=true")
	}
	if toAPIK8sCluster(sqlc.K8sCluster{ManagedByMachine: none}).ManagedByOperator {
		t.Fatal("human-created cluster must surface managed_by_operator=false")
	}

	if !toAPIK8sService(sqlc.K8sService{ManagedByMachine: owned}, "svc.ns.svc.c.z", uuid.Nil).ManagedByOperator {
		t.Fatal("machine-owned service must surface managed_by_operator=true")
	}
	if toAPIK8sService(sqlc.K8sService{ManagedByMachine: none}, "", uuid.Nil).ManagedByOperator {
		t.Fatal("human-created service must surface managed_by_operator=false")
	}
	// K8N-4: an exposure made by a namespace rule names the rule; one made by hand names none. Neither
	// is the operator's.
	rule := uuid.New()
	if got := toAPIK8sService(sqlc.K8sService{ManagedByMachine: none}, "", rule); got.NamespaceRuleId == nil || *got.NamespaceRuleId != rule || got.ManagedByOperator {
		t.Fatalf("rule-made service must surface namespace_rule_id and not managed_by_operator: %+v", got)
	}
	if toAPIK8sService(sqlc.K8sService{ManagedByMachine: none}, "", uuid.Nil).NamespaceRuleId != nil {
		t.Fatal("hand-made service must surface namespace_rule_id=null")
	}

	if !toAPIRule(sqlc.PolicyRule{ManagedByMachine: owned}, false, false).ManagedByOperator {
		t.Fatal("machine-owned grant must surface managed_by_operator=true")
	}
	if toAPIRule(sqlc.PolicyRule{ManagedByMachine: none}, false, false).ManagedByOperator {
		t.Fatal("human-created grant must surface managed_by_operator=false")
	}
}
