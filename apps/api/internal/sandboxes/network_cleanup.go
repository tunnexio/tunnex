package sandboxes

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

type GatewayAbsenceInspector interface {
	InspectGatewayAbsence(context.Context, PrivateNetworkTarget, []byte) error
}

// PrivateNetworkCleanup is called under Store.ReconcileCleanup's shared lease.
// Only this trusted coordinator writes physical withdrawal checkpoints. A
// durable receipt fences a lost provider-stop response after namespace removal.
type PrivateNetworkCleanup struct {
	Store    *Store
	Network  PrivateNetworkControl
	Gateway  GatewayAbsenceInspector
	Files    LaunchControlTransport
	Policies canonicalPolicyReader
}

func (c *PrivateNetworkCleanup) Withdraw(ctx context.Context, sandbox Sandbox) (Withdrawal, error) {
	if c == nil || c.Store == nil || c.Network == nil || c.Gateway == nil || c.Files == nil || c.Policies == nil || sandbox.PeerID == nil {
		return Withdrawal{}, ErrDisabled
	}
	conn, err := c.Store.pool.Acquire(ctx)
	if err != nil {
		return Withdrawal{}, err
	}
	defer conn.Release()
	target, _, err := confirmedNetworkTarget(ctx, conn, sandbox.Identity.ID, sandbox.Revision, true)
	if err != nil {
		return Withdrawal{}, err
	}
	if target.OrgID != sandbox.Identity.OrgID || target.PeerID != *sandbox.PeerID {
		return Withdrawal{}, ErrConflict
	}
	var confirmed bool
	// A stop receipt proves absence for an immutable network epoch. Deletion
	// may advance intent after that namespace is gone; no later start may have
	// recreated it. Keep exact target identity and the current intent CAS.
	const receiptMatch = `w.sandbox_id=$1 AND w.org_id=$2
 AND COALESCE(w.network_epoch_id,w.operation_id)=$4 AND w.network_generation=$5
 AND w.peer_id=$6 AND w.runtime_id=$7 AND w.spec_hash=$8 AND w.operation_id=$9
 AND s.id=w.sandbox_id AND s.org_id=w.org_id AND s.generation=$3
 AND s.desired_state IN ('stopped','deleted')
 AND (w.generation=$3 OR (s.desired_state='deleted' AND w.generation<$3
 AND w.generation>=w.network_generation
 AND NOT EXISTS(SELECT 1 FROM sandbox_start_epochs e WHERE e.sandbox_id=s.id
 AND e.org_id=s.org_id AND e.generation>w.generation AND e.generation<=s.generation)))`
	args := []any{target.SandboxID, target.OrgID, sandbox.Revision, target.OperationID, target.Generation, target.PeerID, target.RuntimeID, target.SpecHash, enrollmentOperation(target)}
	err = conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sandbox_network_withdrawals w JOIN sandboxes s ON s.id=w.sandbox_id AND s.org_id=w.org_id WHERE `+receiptMatch+`)`, args...).Scan(&confirmed)
	if err != nil {
		return Withdrawal{}, err
	}
	if !confirmed {
		config, err := c.Files.ReadPrivateNetworkConfig(ctx, target)
		if err != nil {
			return Withdrawal{}, err
		}
		if err = c.Network.RemovePrivateNetwork(ctx, target, config); err != nil {
			return Withdrawal{}, err
		}
		if err = c.Gateway.InspectGatewayAbsence(ctx, target, config); err != nil {
			return Withdrawal{}, err
		}
	}
	if _, err = c.Store.CurrentSandboxPolicyAcknowledgements(ctx, target, c.Policies); err != nil {
		return Withdrawal{}, err
	}
	if confirmed {
		// Preserve the physical observation time; only the current intent advances.
		result, err := conn.Exec(ctx, `UPDATE sandbox_network_withdrawals w SET generation=$3 FROM sandboxes s WHERE `+receiptMatch, args...)
		if err != nil {
			return Withdrawal{}, err
		}
		if result.RowsAffected() != 1 {
			return Withdrawal{}, ErrConflict
		}
	}
	if !confirmed {
		result, err := conn.Exec(ctx, `INSERT INTO sandbox_network_withdrawals(sandbox_id,org_id,generation,operation_id,network_generation,peer_id,runtime_id,spec_hash,network_epoch_id) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9 FROM sandboxes s WHERE s.id=$1 AND s.org_id=$2 AND s.generation=$3 AND s.peer_id=$6 AND s.desired_state IN ('stopped','deleted') ON CONFLICT(sandbox_id) DO UPDATE SET generation=EXCLUDED.generation,operation_id=EXCLUDED.operation_id,network_generation=EXCLUDED.network_generation,peer_id=EXCLUDED.peer_id,runtime_id=EXCLUDED.runtime_id,spec_hash=EXCLUDED.spec_hash,network_epoch_id=EXCLUDED.network_epoch_id,observed_at=now() WHERE sandbox_network_withdrawals.org_id=EXCLUDED.org_id`, target.SandboxID, target.OrgID, sandbox.Revision, enrollmentOperation(target), target.Generation, target.PeerID, target.RuntimeID, target.SpecHash, networkEpoch(target))
		if err != nil {
			return Withdrawal{}, err
		}
		if result.RowsAffected() != 1 {
			return Withdrawal{}, ErrConflict
		}
	}
	// Assert current stopped intent even when recovering an old external response.
	var valid bool
	err = conn.QueryRow(ctx, `SELECT generation=$2 AND desired_state IN ('stopped','deleted') AND peer_id=$3 FROM sandboxes WHERE id=$1`, target.SandboxID, sandbox.Revision, target.PeerID).Scan(&valid)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !valid {
		return Withdrawal{}, ErrConflict
	}
	if err != nil {
		return Withdrawal{}, err
	}
	return Withdrawal{target.SandboxID, target.PeerID, sandbox.Revision, true}, nil
}
