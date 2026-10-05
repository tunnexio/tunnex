package sandboxes

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
)

// Withdrawal is trusted coordinator evidence, never a browser/runtime claim.
type Withdrawal struct {
	SandboxID      uuid.UUID
	PeerID         uuid.UUID
	Generation     int64
	GatewayRemoved bool
}
type CleanupNetwork interface {
	Withdraw(context.Context, Sandbox) (Withdrawal, error)
}

// PendingCleanup is a bounded worker inventory. Creator removal does not prevent
// privileged cleanup; it must not require a revoked human session to finish.
func (s *Store) PendingCleanup(ctx context.Context, limit int) ([]uuid.UUID, error) {
	return s.PendingCleanupAfter(ctx, limit, uuid.Nil)
}

func (s *Store) PendingCleanupAfter(ctx context.Context, limit int, after uuid.UUID) ([]uuid.UUID, error) {
	if limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	if err := s.SweepEligibility(ctx, uuid.Nil, limit); err != nil {
		return nil, err
	}
	if err := s.SweepDelegations(ctx, uuid.Nil, limit); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT id FROM sandboxes WHERE observed_state<>'deleted'
 AND (desired_state IN ('stopped','deleted') OR expires_at<=now())
 AND NOT (desired_state='stopped' AND observed_state='stopped' AND expires_at>now()) AND id>$2 ORDER BY id LIMIT $1`, limit, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ReconcileCleanup holds a per-sandbox session lease, never a transaction across
// external work. It is safe to repeat after uncertain provider/network outcomes.
// There is no default network coordinator and this is not wired to production.
func (s *Store) ReconcileCleanup(ctx context.Context, id uuid.UUID, provider sandboxruntime.Provider, network CleanupNetwork) error {
	if id == uuid.Nil || provider == nil {
		return ErrInvalid
	}
	conn, release, err := s.acquireLifecycle(ctx, id)
	if err != nil {
		return err
	}
	defer release()
	target, err := beginCleanup(ctx, conn, id)
	if err != nil {
		return err
	}
	s.notifyPolicy(ctx, target.Identity.OrgID)
	if target.State == StateDeleted || (target.State == StateStopped && target.DesiredState == "stopped") {
		return nil
	}
	if target.PeerID != nil {
		if network == nil {
			return ErrDisabled
		}
		receipt, e := network.Withdraw(ctx, target)
		if e != nil {
			return e
		}
		if receipt.SandboxID != id || receipt.PeerID != *target.PeerID || receipt.Generation != target.Revision || !receipt.GatewayRemoved {
			return ErrConflict
		}
	}
	if target.DesiredState == "deleted" {
		err = provider.Delete(ctx, id)
	} else {
		err = provider.Stop(ctx, id)
		if errors.Is(err, sandboxruntime.ErrMissing) {
			err = nil
		}
	}
	if err != nil {
		return err
	}
	status, err := provider.Inspect(ctx, id)
	if target.DesiredState == "deleted" {
		if !errors.Is(err, sandboxruntime.ErrMissing) {
			if err != nil {
				return err
			}
			return ErrConflict
		}
	} else if !errors.Is(err, sandboxruntime.ErrMissing) {
		if err != nil {
			return err
		}
		if status.Running {
			return ErrConflict
		}
	}
	return completeCleanup(ctx, conn, target)
}

func beginCleanup(ctx context.Context, conn *pgxpool.Conn, id uuid.UUID) (Sandbox, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return Sandbox{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	out, err := scanSandbox(tx.QueryRow(ctx, `SELECT `+sandboxColumns+` FROM sandboxes WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return Sandbox{}, err
	}
	if out.State == StateDeleted {
		return out, tx.Commit(ctx)
	}
	var expired bool
	if err = tx.QueryRow(ctx, `SELECT expires_at<=now() FROM sandboxes WHERE id=$1`, id).Scan(&expired); err != nil {
		return Sandbox{}, err
	}
	if expired && out.DesiredState != "deleted" {
		out, err = scanSandbox(tx.QueryRow(ctx, `UPDATE sandboxes SET desired_state='deleted',generation=generation+1 WHERE id=$1 RETURNING `+sandboxColumns, id))
		if err != nil {
			return Sandbox{}, err
		}
	}
	if out.DesiredState == "started" {
		return Sandbox{}, ErrConflict
	}
	if out.DesiredState == "stopped" && out.State == StateStopped {
		return out, tx.Commit(ctx)
	}
	state := StateStopping
	if out.DesiredState == "deleted" {
		state = StateDeleting
		if _, err = tx.Exec(ctx, `UPDATE sandbox_runtime_credentials SET revoked_at=COALESCE(revoked_at,now()) WHERE sandbox_id=$1`, id); err != nil {
			return Sandbox{}, err
		}
		// Retain the address until the gateway confirms withdrawal. Never recycle an
		// address while a stale gateway might still associate it with this key.
		if _, err = tx.Exec(ctx, `UPDATE devices SET health_blocked=true WHERE id=$1 AND kind='sandbox'`, out.PeerID); err != nil {
			return Sandbox{}, err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM device_status WHERE device_id=$1`, out.PeerID); err != nil {
			return Sandbox{}, err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE sandboxes SET observed_state=$2 WHERE id=$1`, id, state); err != nil {
		return Sandbox{}, err
	}
	out.State = state
	return out, tx.Commit(ctx)
}

func completeCleanup(ctx context.Context, conn *pgxpool.Conn, target Sandbox) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	current, err := scanSandbox(tx.QueryRow(ctx, `SELECT `+sandboxColumns+` FROM sandboxes WHERE id=$1 FOR UPDATE`, target.Identity.ID))
	if err != nil {
		return err
	}
	if current.Revision != target.Revision || current.DesiredState != target.DesiredState {
		return ErrConflict
	}
	state := StateStopped
	if target.DesiredState == "deleted" {
		state = StateDeleted
		if _, err = tx.Exec(ctx, `UPDATE devices SET status='revoked',revoked_at=COALESCE(revoked_at,now()),revoked_cause='deliberate',assigned_ip=NULL WHERE id=$1 AND kind='sandbox'`, target.PeerID); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE sandboxes SET observed_state=$2 WHERE id=$1`, target.Identity.ID, state); err != nil {
		return err
	}
	if state == StateStopped {
		if err = recordRunnerTrialEvent(ctx, tx, target.Identity.ID, "stopped", target.Revision, map[string]any{
			"sandbox_id": target.Identity.ID, "generation": target.Revision, "peer_id": target.PeerID,
			"provider_stopped": true, "gateway_withdrawal_confirmed": target.PeerID != nil,
		}); err != nil {
			return err
		}
	}
	if err = auditSandbox(ctx, tx, target.Identity.OrgID, target.Identity.CreatorID, target, "sandbox.cleanup_"+string(state)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
