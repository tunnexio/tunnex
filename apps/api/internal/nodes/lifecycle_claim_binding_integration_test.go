package nodes

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

func lifecycleBindingCAS(fixture lifecycleInstallFixture, epoch int64) LifecycleInstallCAS {
	return LifecycleInstallCAS{
		Claim: fixture.claim, ExpectedGeneration: 1, RequestID: fixture.requestID,
		OperationID: fixture.operation, ExpectedEpoch: epoch,
	}
}

func takeOverLifecycleBindingAbort(t *testing.T, ctx context.Context, fixture lifecycleInstallFixture) LifecycleInstallAbortFinalize {
	t.Helper()
	cas := lifecycleBindingCAS(fixture, 1)
	if _, err := fixture.service.CoordinatedAbortLifecycleClaim(ctx, fixture.actor, fixture.orgID, cas); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.ReleaseLifecycleInstall(ctx, fixture.actor, fixture.orgID, cas); err != nil {
		t.Fatal(err)
	}
	taken, err := fixture.service.CoordinatedAbortLifecycleClaim(ctx, fixture.actor, fixture.orgID, cas)
	if err != nil || taken.OperationStatus == nil || taken.OperationStatus.Epoch != 2 || taken.OperationStatus.State != LifecycleInstallAborting {
		t.Fatalf("takeover=%+v err=%v", taken, err)
	}
	return LifecycleInstallAbortFinalize{LifecycleInstallCAS: lifecycleBindingCAS(fixture, 2), ReleaseAbsent: true}
}

func lifecycleBindingTokenName(t *testing.T, ctx context.Context, pool *pgxpool.Pool, fixture lifecycleInstallFixture) string {
	t.Helper()
	var name string
	if err := pool.QueryRow(ctx, `SELECT node_name FROM node_join_tokens WHERE id=$1`, fixture.tokenID).Scan(&name); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestLifecycleClaimImmutableBindingPostgres(t *testing.T) {
	pool, ctx := lifecycleInstallTestPool(t)

	t.Run("rename before completion preserves exact consumed identity", func(t *testing.T) {
		fixture := seedLifecycleInstallFixture(t, ctx, pool, 120)
		nodeID := consumeAndBindLifecycleNode(t, ctx, pool, fixture)
		originalName := lifecycleBindingTokenName(t, ctx, pool, fixture)
		if _, err := fixture.service.RenameNode(ctx, fixture.actorID, fixture.orgID, nodeID, "renamed-"+nodeID.String()); err != nil {
			t.Fatal(err)
		}
		status, err := fixture.service.GetLifecycleClaimStatus(ctx, fixture.orgID, fixture.claim)
		if err != nil || status.State != LifecycleClaimConsumed || status.NodeID == nil || *status.NodeID != nodeID || status.NodeName != originalName {
			t.Fatalf("renamed status=%+v err=%v", status, err)
		}
		input := LifecycleInstallComplete{LifecycleInstallCAS: lifecycleBindingCAS(fixture, 1), ReleaseReady: true}
		for attempt := 0; attempt < 2; attempt++ {
			completed, err := fixture.service.CompleteLifecycleInstall(ctx, fixture.actor, fixture.orgID, input)
			if err != nil || completed.State != LifecycleInstallCompleted {
				t.Fatalf("renamed completion/replay=%+v err=%v", completed, err)
			}
		}
		if _, err := fixture.service.CoordinatedAbortLifecycleClaim(ctx, fixture.actor, fixture.orgID, input.LifecycleInstallCAS); code(err) != "lifecycle_install_already_completed" {
			t.Fatalf("completed claim became abortable: %v", err)
		}
	})

	t.Run("legacy abort retains request name pin after rename", func(t *testing.T) {
		fixture := seedLifecycleInstallFixture(t, ctx, pool, 120)
		nodeID := consumeAndBindLifecycleNode(t, ctx, pool, fixture)
		// Model the supported pre-D13h claim, whose enrollment has no install
		// operation. The usage sentinel intentionally remains persisted.
		if _, err := pool.Exec(ctx, `DELETE FROM node_lifecycle_install_operations WHERE operation_id=$1`, fixture.operation); err != nil {
			t.Fatal(err)
		}
		originalName := lifecycleBindingTokenName(t, ctx, pool, fixture)
		newName := "renamed-" + nodeID.String()
		if _, err := fixture.service.RenameNode(ctx, fixture.actorID, fixture.orgID, nodeID, newName); err != nil {
			t.Fatal(err)
		}
		input := LifecycleClaimAbort{Claim: fixture.claim, RequestID: fixture.requestID, ExpectedGeneration: 1, NodeName: newName}
		if _, err := fixture.service.AbortLifecycleClaim(ctx, fixture.actor, fixture.orgID, input); code(err) != "lifecycle_claim_identity_mismatch" {
			t.Fatalf("mutable display name replaced historical request pin: %v", err)
		}
		input.NodeName = originalName
		for attempt := 0; attempt < 2; attempt++ {
			aborted, err := fixture.service.AbortLifecycleClaim(ctx, fixture.actor, fixture.orgID, input)
			if err != nil || aborted.State != LifecycleClaimAborted || aborted.NodeID == nil || *aborted.NodeID != nodeID || aborted.NodeName != originalName {
				t.Fatalf("renamed legacy abort/replay=%+v err=%v", aborted, err)
			}
		}
		var state string
		if err := pool.QueryRow(ctx, `SELECT status FROM nodes WHERE id=$1`, nodeID).Scan(&state); err != nil || state != "revoked" {
			t.Fatalf("legacy abort node state=%q err=%v", state, err)
		}
	})

	t.Run("coordinated abort rename replay and canonical deletion", func(t *testing.T) {
		fixture := seedLifecycleInstallFixture(t, ctx, pool, 120)
		nodeID := consumeAndBindLifecycleNode(t, ctx, pool, fixture)
		if _, err := fixture.service.RenameNode(ctx, fixture.actorID, fixture.orgID, nodeID, "renamed-"+nodeID.String()); err != nil {
			t.Fatal(err)
		}
		input := takeOverLifecycleBindingAbort(t, ctx, fixture)
		for attempt := 0; attempt < 2; attempt++ {
			aborted, err := fixture.service.FinalizeLifecycleInstallAbort(ctx, fixture.actor, fixture.orgID, input)
			if err != nil || aborted.State != LifecycleClaimAborted || aborted.NodeID == nil || *aborted.NodeID != nodeID {
				t.Fatalf("renamed coordinated abort/replay=%+v err=%v", aborted, err)
			}
		}
		replayed, err := fixture.service.CoordinatedAbortLifecycleClaim(ctx, fixture.actor, fixture.orgID, input.LifecycleInstallCAS)
		if err != nil || replayed.ClaimStatus == nil || replayed.ClaimStatus.NodeID == nil || *replayed.ClaimStatus.NodeID != nodeID {
			t.Fatalf("coordinated terminal replay=%+v err=%v", replayed, err)
		}
		if err := fixture.service.DeleteRevokedNode(ctx, fixture.actorID, fixture.orgID, nodeID); err != nil {
			t.Fatal(err)
		}
		var tokens, operations, nodes int
		if err := pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM node_join_tokens WHERE id=$1),
			(SELECT count(*) FROM node_lifecycle_install_operations WHERE operation_id=$2),
			(SELECT count(*) FROM nodes WHERE id=$3)`, fixture.tokenID, fixture.operation, nodeID).Scan(&tokens, &operations, &nodes); err != nil || tokens != 0 || operations != 0 || nodes != 0 {
			t.Fatalf("canonical deletion tokens=%d operations=%d nodes=%d err=%v", tokens, operations, nodes, err)
		}
		if _, err := fixture.service.GetLifecycleClaimStatus(ctx, fixture.orgID, fixture.claim); code(err) != "lifecycle_claim_not_found" {
			t.Fatalf("canonical deletion resurrected claim: %v", err)
		}
	})

	t.Run("node-only deletion preserves consumed and aborted history", func(t *testing.T) {
		fixture := seedLifecycleInstallFixture(t, ctx, pool, 120)
		nodeID := consumeAndBindLifecycleNode(t, ctx, pool, fixture)
		if err := fixture.service.Revoke(ctx, fixture.actorID, fixture.orgID, nodeID); err != nil {
			t.Fatal(err)
		}
		status, err := fixture.service.GetLifecycleClaimStatus(ctx, fixture.orgID, fixture.claim)
		if err != nil || status.State != LifecycleClaimConsumed || status.NodeID == nil || *status.NodeID != nodeID {
			t.Fatalf("revoked consumed status=%+v err=%v", status, err)
		}
		complete := LifecycleInstallComplete{LifecycleInstallCAS: lifecycleBindingCAS(fixture, 1), ReleaseReady: true}
		if _, err := fixture.service.CompleteLifecycleInstall(ctx, fixture.actor, fixture.orgID, complete); code(err) != "lifecycle_install_completion_refused" {
			t.Fatalf("revoked node completed install: %v", err)
		}
		// Exercise the existing FK path independently of canonical deletion,
		// which deliberately removes the token and operation as well.
		if _, err := pool.Exec(ctx, `DELETE FROM nodes WHERE id=$1`, nodeID); err != nil {
			t.Fatal(err)
		}
		status, err = fixture.service.GetLifecycleClaimStatus(ctx, fixture.orgID, fixture.claim)
		if err != nil || status.State != LifecycleClaimConsumed || status.ConsumedAt == nil || status.NodeID != nil {
			t.Fatalf("deleted consumed status=%+v err=%v", status, err)
		}
		if _, err := fixture.service.CompleteLifecycleInstall(ctx, fixture.actor, fixture.orgID, complete); code(err) != "lifecycle_install_completion_refused" {
			t.Fatalf("deleted node completed install: %v", err)
		}
		fixture.service.sealer, err = crypto.NewSealer(make([]byte, crypto.KeySize))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.service.RemintLifecycleClaim(ctx, fixture.actor, fixture.orgID, LifecycleClaimRemint{
			Claim: fixture.claim, NodeName: lifecycleBindingTokenName(t, ctx, pool, fixture), ExpectedGeneration: 1, RequestID: uuid.New(),
		}); code(err) != "lifecycle_claim_consumed" {
			t.Fatalf("deleted node authorized remint: %v", err)
		}
		input := takeOverLifecycleBindingAbort(t, ctx, fixture)
		for attempt := 0; attempt < 2; attempt++ {
			aborted, err := fixture.service.FinalizeLifecycleInstallAbort(ctx, fixture.actor, fixture.orgID, input)
			if err != nil || aborted.State != LifecycleClaimAborted || aborted.NodeID != nil || aborted.ConsumedAt == nil {
				t.Fatalf("deleted-node terminal abort/replay=%+v err=%v", aborted, err)
			}
		}
	})
}

func TestLifecycleClaimCorruptBindingRefusesWithoutAbortEffectsPostgres(t *testing.T) {
	pool, ctx := lifecycleInstallTestPool(t)
	for _, test := range []struct {
		name string
		sql  string
	}{
		{"wrong node ID", `UPDATE node_join_tokens SET consumed_node_id=$3 WHERE id=$1`},
		{"missing node ID", `UPDATE node_join_tokens SET consumed_node_id=NULL WHERE id=$1`},
		{"missing consumption", `UPDATE node_join_tokens SET consumed_at=NULL WHERE id=$1`},
		{"foreign organization", `UPDATE nodes SET org_id=$4 WHERE id=$2`},
		{"foreign claim", `UPDATE nodes SET lifecycle_claim=$5 WHERE id=$2`},
		{"missing claim", `UPDATE nodes SET lifecycle_claim=NULL WHERE id=$2`},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := seedLifecycleInstallFixture(t, ctx, pool, 120)
			nodeID := consumeAndBindLifecycleNode(t, ctx, pool, fixture)
			other := seedLifecycleInstallFixture(t, ctx, pool, 120)
			otherNodeID := consumeAndBindLifecycleNode(t, ctx, pool, other)
			// Bind all placeholders so each corruption statement can select its
			// exact target while the untouched same-name node remains available.
			query := `WITH binding_inputs AS (SELECT $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid) ` + test.sql
			if _, err := pool.Exec(ctx, query, fixture.tokenID, nodeID, otherNodeID, other.orgID, uuid.New()); err != nil {
				t.Fatal(err)
			}
			if status, err := fixture.service.GetLifecycleClaimStatus(ctx, fixture.orgID, fixture.claim); err == nil || status.NodeID != nil {
				t.Fatalf("corrupt status=%+v err=%v", status, err)
			}
			if _, err := fixture.service.CompleteLifecycleInstall(ctx, fixture.actor, fixture.orgID, LifecycleInstallComplete{
				LifecycleInstallCAS: lifecycleBindingCAS(fixture, 1), ReleaseReady: true,
			}); code(err) != "lifecycle_install_completion_refused" {
				t.Fatalf("corrupt binding completion error=%v", err)
			}
			input := takeOverLifecycleBindingAbort(t, ctx, fixture)
			var auditBefore int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1`, fixture.orgID).Scan(&auditBefore); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.service.FinalizeLifecycleInstallAbort(ctx, fixture.actor, fixture.orgID, input); err == nil || !strings.Contains(err.Error(), "binding is malformed") {
				t.Fatalf("corrupt binding finalized abort: %v", err)
			}
			var operationState string
			var tokenAborted bool
			var revoked, auditAfter int
			if err := pool.QueryRow(ctx, `SELECT
				(SELECT state FROM node_lifecycle_install_operations WHERE operation_id=$1),
				(SELECT lifecycle_aborted_at IS NOT NULL FROM node_join_tokens WHERE id=$2),
				(SELECT count(*) FROM nodes WHERE id IN ($3,$4) AND status <> 'active'),
				(SELECT count(*) FROM audit_logs WHERE org_id=$5)`, fixture.operation, fixture.tokenID, nodeID, otherNodeID, fixture.orgID).
				Scan(&operationState, &tokenAborted, &revoked, &auditAfter); err != nil || operationState != "taken_over" || tokenAborted || revoked != 0 || auditAfter != auditBefore {
				t.Fatalf("refused abort committed effects: operation=%q token_aborted=%v revoked=%d audits=%d/%d err=%v", operationState, tokenAborted, revoked, auditBefore, auditAfter, err)
			}
		})
	}
}

func TestLifecycleClaimStatusSerializesFirstConsumptionPostgres(t *testing.T) {
	pool, ctx := lifecycleInstallTestPool(t)
	fixture := seedLifecycleInstallFixture(t, ctx, pool, 120)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var holderPID int
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&holderPID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE node_join_tokens SET consumed_at=clock_timestamp() WHERE id=$1`, fixture.tokenID); err != nil {
		t.Fatal(err)
	}
	var nodeID uuid.UUID
	if err := tx.QueryRow(ctx, `INSERT INTO nodes(org_id,name,cert_serial,agent_version,lifecycle_claim)
		SELECT org_id,node_name,$2,'binding-race',lifecycle_claim FROM node_join_tokens WHERE id=$1 RETURNING id`, fixture.tokenID, uuid.NewString()).Scan(&nodeID); err != nil {
		t.Fatal(err)
	}
	type result struct {
		status LifecycleClaimStatus
		err    error
	}
	statusResult := make(chan result, 1)
	go func() {
		status, err := fixture.service.GetLifecycleClaimStatus(ctx, fixture.orgID, fixture.claim)
		statusResult <- result{status: status, err: err}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case early := <-statusResult:
			t.Fatalf("status crossed in-flight consumption without token lock: status=%+v err=%v", early.status, early.err)
		default:
		}
		var waiting bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity
			WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))
			AND query LIKE '%FROM node_join_tokens%FOR UPDATE%')`, holderPID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("status did not wait on the exact enrollment transaction")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case completed := <-statusResult:
		if completed.err != nil || completed.status.State != LifecycleClaimConsumed || completed.status.NodeID == nil || *completed.status.NodeID != nodeID || completed.status.ConsumedAt == nil {
			t.Fatalf("status after enrollment commit=%+v err=%v", completed.status, completed.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("status did not finish after enrollment committed")
	}
}

func TestLifecycleClaimTerminalReplayValidatesBindingPostgres(t *testing.T) {
	pool, ctx := lifecycleInstallTestPool(t)
	for _, test := range []struct {
		name string
		sql  string
	}{
		{"foreign claim", `UPDATE nodes SET lifecycle_claim=$2 WHERE id=$1`},
		{"missing consumed ID", `UPDATE node_join_tokens SET consumed_node_id=NULL WHERE consumed_node_id=$1`},
		{"surviving active node", `UPDATE nodes SET status='active', revoked_at=NULL WHERE id=$1`},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := seedLifecycleInstallFixture(t, ctx, pool, 120)
			nodeID := consumeAndBindLifecycleNode(t, ctx, pool, fixture)
			input := takeOverLifecycleBindingAbort(t, ctx, fixture)
			if _, err := fixture.service.FinalizeLifecycleInstallAbort(ctx, fixture.actor, fixture.orgID, input); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `WITH binding_inputs AS (SELECT $1::uuid, $2::uuid) `+test.sql, nodeID, uuid.New()); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.service.FinalizeLifecycleInstallAbort(ctx, fixture.actor, fixture.orgID, input); err == nil {
				t.Fatal("finalize replay accepted corrupt or active terminal binding")
			}
			if _, err := fixture.service.CoordinatedAbortLifecycleClaim(ctx, fixture.actor, fixture.orgID, input.LifecycleInstallCAS); err == nil {
				t.Fatal("coordinated replay accepted corrupt or active terminal binding")
			}
		})
	}
}
