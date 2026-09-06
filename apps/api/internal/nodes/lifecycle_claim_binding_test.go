package nodes

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

func TestLifecycleStatusRequiresImmutableConsumedNodeBinding(t *testing.T) {
	now := time.Now()
	name := "original-enrollment-name"
	node := sqlc.Node{
		ID: uuid.New(), OrgID: uuid.New(), Name: name, Status: "active",
		LifecycleClaim: requiredPGUUID(uuid.New()),
	}
	token := sqlc.NodeJoinToken{
		OrgID: node.OrgID, NodeName: &name, LifecycleClaim: node.LifecycleClaim,
		LifecycleGeneration: 1, LifecycleRequestID: requiredPGUUID(uuid.New()),
		ConsumedAt:     pgtype.Timestamptz{Time: now, Valid: true},
		ConsumedNodeID: requiredPGUUID(node.ID), ExpiresAt: now.Add(time.Hour),
	}
	for _, test := range []struct {
		name   string
		mutate func(*sqlc.NodeJoinToken, *sqlc.Node)
	}{
		{"missing consumed node ID", func(token *sqlc.NodeJoinToken, _ *sqlc.Node) { token.ConsumedNodeID = pgtype.UUID{} }},
		{"nil consumed UUID", func(token *sqlc.NodeJoinToken, node *sqlc.Node) {
			token.ConsumedNodeID = pgtype.UUID{Valid: true}
			node.ID = uuid.Nil
		}},
		{"different consumed node", func(token *sqlc.NodeJoinToken, _ *sqlc.Node) { token.ConsumedNodeID = requiredPGUUID(uuid.New()) }},
		{"missing consumption", func(token *sqlc.NodeJoinToken, _ *sqlc.Node) { token.ConsumedAt = pgtype.Timestamptz{} }},
		{"wrong organization", func(_ *sqlc.NodeJoinToken, node *sqlc.Node) { node.OrgID = uuid.New() }},
		{"wrong claim", func(_ *sqlc.NodeJoinToken, node *sqlc.Node) { node.LifecycleClaim = requiredPGUUID(uuid.New()) }},
		{"missing node claim", func(_ *sqlc.NodeJoinToken, node *sqlc.Node) { node.LifecycleClaim = pgtype.UUID{} }},
		{"nil matching claims", func(token *sqlc.NodeJoinToken, node *sqlc.Node) {
			token.LifecycleClaim = pgtype.UUID{Valid: true}
			node.LifecycleClaim = token.LifecycleClaim
		}},
		{"generation zero", func(token *sqlc.NodeJoinToken, _ *sqlc.Node) { token.LifecycleGeneration = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			badToken, badNode := token, node
			test.mutate(&badToken, &badNode)
			// Every mismatch retains the original, matching display name.
			if status, err := lifecycleStatus(badToken, &badNode, now); err == nil || status.NodeID != nil {
				t.Fatalf("inexact node binding published status=%+v err=%v", status, err)
			}
		})
	}
	for _, nodeState := range []string{"active", "revoked"} {
		t.Run("renamed "+nodeState, func(t *testing.T) {
			renamed := node
			renamed.Name, renamed.Status = "new-display-name", nodeState
			status, err := lifecycleStatus(token, &renamed, now)
			if err != nil || status.State != LifecycleClaimConsumed || status.NodeID == nil || *status.NodeID != node.ID || status.NodeName != name {
				t.Fatalf("renamed exact node status=%+v err=%v", status, err)
			}
		})
	}
}

func TestLifecycleStatusPreservesNodeFreeHistory(t *testing.T) {
	now := time.Now()
	name := "deleted-gateway"
	token := sqlc.NodeJoinToken{
		NodeName: &name, LifecycleClaim: requiredPGUUID(uuid.New()),
		LifecycleGeneration: 1, LifecycleRequestID: requiredPGUUID(uuid.New()),
		ConsumedAt: pgtype.Timestamptz{Time: now, Valid: true}, ExpiresAt: now.Add(-time.Hour),
	}
	for _, aborted := range []bool{false, true} {
		current, expectedState := token, LifecycleClaimConsumed
		if aborted {
			current.LifecycleAbortedAt = pgtype.Timestamptz{Time: now, Valid: true}
			expectedState = LifecycleClaimAborted
		}
		status, err := lifecycleStatus(current, nil, now)
		if err != nil || status.State != expectedState || status.NodeID != nil || status.ConsumedAt == nil {
			t.Fatalf("deleted-node history status=%+v err=%v", status, err)
		}
		current.ConsumedNodeID = requiredPGUUID(uuid.New())
		if status, err := lifecycleStatus(current, nil, now); err == nil || status.NodeID != nil {
			t.Fatalf("unresolved consumed-node reference status=%+v err=%v", status, err)
		}
	}
}
