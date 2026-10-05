package sandboxes

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
)

// ResumeCoordinator preserves enrollment and immutable assets. It only obtains
// fresh execution/network evidence; no token is issued, decrypted or redeemed.
type ResumeCoordinator struct {
	Initial *InitialLaunchCoordinator
}

func (c *ResumeCoordinator) Reconcile(ctx context.Context, id uuid.UUID) (failure error) {
	stage := "resume-configuration"
	defer func() {
		var staged *LaunchStageError
		if failure != nil && !errors.As(failure, &staged) {
			failure = &LaunchStageError{Stage: stage, Cause: failure}
		}
	}()
	if c == nil || c.Initial == nil {
		return ErrDisabled
	}
	i := c.Initial
	if i.Store == nil || i.Provider == nil || i.Network == nil || i.Files == nil || i.Assets == nil || i.ProbeIdentity == nil || i.Policies == nil || i.Probe == nil {
		return ErrDisabled
	}
	stage = "resume-prepare"
	if err := i.Store.PrepareResume(ctx, id, i.Provider); err != nil {
		return err
	}
	stage = "resume-start"
	if err := i.Store.StartBoundRuntime(ctx, id, i.Provider); err != nil {
		return err
	}
	stage = "resume-network"
	if err := i.Store.ActivatePrivateNetwork(ctx, id, i.Network, i.Files); err != nil {
		return err
	}
	stage = "resume-readiness"
	return i.Store.VerifyPrivateReadinessWithTransport(ctx, id, i.Provider, i.Policies, i.Network, i.Assets, i.ProbeIdentity, i.Probe)
}

// PrepareResume creates one durable epoch only after an exact completed stop.
// Reentry into Starting must find the same epoch, never move its timestamp.
func (s *Store) PrepareResume(ctx context.Context, id uuid.UUID, provider sandboxruntime.Provider) error {
	if provider == nil {
		return ErrDisabled
	}
	conn, release, err := s.acquireLifecycle(ctx, id)
	if err != nil {
		return err
	}
	defer release()
	start, err := s.prepareStart(ctx, conn, id)
	if err != nil {
		return err
	}
	if start.sandbox.Revision <= 1 || start.runtimeID == nil || start.sandbox.PeerID == nil {
		return ErrConflict
	}
	target, _, err := confirmedNetworkTarget(ctx, conn, id, start.sandbox.Revision, true)
	if err != nil {
		return err
	}
	hash, err := sandboxruntime.Fingerprint(start.spec)
	if err != nil || target.PeerID != *start.sandbox.PeerID || target.RuntimeID != *start.runtimeID || target.SpecHash != hash {
		return ErrConflict
	}
	var existing bool
	if err = conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sandbox_start_epochs WHERE sandbox_id=$1 AND org_id=$2 AND generation=$3 AND operation_id=$4)`, id, target.OrgID, start.sandbox.Revision, enrollmentOperation(target)).Scan(&existing); err != nil {
		return err
	}
	if existing {
		if start.sandbox.State != StateStarting {
			return ErrConflict
		}
		return nil
	}
	if start.sandbox.State != StateStopped {
		return ErrConflict
	}
	var withdrawn bool
	if err = conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sandbox_network_withdrawals WHERE sandbox_id=$1 AND org_id=$2 AND generation=$3 AND COALESCE(network_epoch_id,operation_id)=$4 AND network_generation=$5 AND peer_id=$6 AND runtime_id=$7 AND spec_hash=$8)`, id, target.OrgID, start.sandbox.Revision-1, target.OperationID, target.Generation, target.PeerID, target.RuntimeID, target.SpecHash).Scan(&withdrawn); err != nil {
		return err
	}
	if !withdrawn {
		return ErrConflict
	}
	status, err := provider.Inspect(ctx, id)
	if err != nil {
		return err
	}
	if err = sandboxruntime.Matches(start.spec, status); err != nil {
		return err
	}
	if status.Running || status.RuntimeID != target.RuntimeID {
		return ErrConflict
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var revision int64
	var state, desired string
	var eligible bool
	if err = tx.QueryRow(ctx, `SELECT generation,observed_state,desired_state,expires_at>now() AND (`+sandboxEligibilitySQL+`) FROM sandboxes s WHERE id=$1 FOR UPDATE OF s`, id).Scan(&revision, &state, &desired, &eligible); err != nil {
		return err
	}
	if revision != start.sandbox.Revision || state != "stopped" || desired != "started" || !eligible {
		return ErrConflict
	}
	// A revoked/deleted peer or runtime credential cannot be revived.
	var admitted bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices d JOIN sandbox_runtime_credentials c ON c.peer_id=d.id AND c.sandbox_id=$1 AND c.org_id=d.org_id WHERE d.id=$2 AND d.org_id=$3 AND d.kind='sandbox' AND d.status='active' AND d.deleted_at IS NULL AND NOT d.health_blocked AND c.revoked_at IS NULL)`, id, target.PeerID, target.OrgID).Scan(&admitted); err != nil {
		return err
	}
	if !admitted {
		return ErrDisabled
	}
	if _, err = tx.Exec(ctx, `INSERT INTO sandbox_start_epochs(sandbox_id,org_id,generation,operation_id) VALUES($1,$2,$3,$4)`, id, target.OrgID, revision, enrollmentOperation(target)); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM device_status WHERE device_id=$1`, target.PeerID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE sandboxes SET observed_state='starting' WHERE id=$1`, id); err != nil {
		return err
	}
	if err = auditSandbox(ctx, tx, target.OrgID, start.sandbox.Identity.CreatorID, start.sandbox, "sandbox.resume_epoch"); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	s.notifyPolicy(ctx, target.OrgID)
	return nil
}

func acknowledgementsAfter(acks []PolicyAcknowledgement, at time.Time) bool {
	if len(acks) == 0 {
		return false
	}
	for _, ack := range acks {
		if ack.ReportedAt.Before(at) {
			return false
		}
	}
	return true
}
