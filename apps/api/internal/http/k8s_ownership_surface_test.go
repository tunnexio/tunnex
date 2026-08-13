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

	if !toAPIK8sService(sqlc.K8sService{ManagedByMachine: owned}, "svc.ns.svc.c.z").ManagedByOperator {
		t.Fatal("machine-owned service must surface managed_by_operator=true")
	}
	if toAPIK8sService(sqlc.K8sService{ManagedByMachine: none}, "").ManagedByOperator {
		t.Fatal("human-created service must surface managed_by_operator=false")
	}

	if !toAPIRule(sqlc.PolicyRule{ManagedByMachine: owned}, false, false).ManagedByOperator {
		t.Fatal("machine-owned grant must surface managed_by_operator=true")
	}
	if toAPIRule(sqlc.PolicyRule{ManagedByMachine: none}, false, false).ManagedByOperator {
		t.Fatal("human-created grant must surface managed_by_operator=false")
	}
}
