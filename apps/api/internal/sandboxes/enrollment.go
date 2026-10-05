package sandboxes

import (
	"context"
	"crypto/sha256"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
)

// ExistingLaunchOperation returns only immutable nonsecret recovery metadata.
// A bound peer can recover persisted control files; no token is decrypted or
// renewed and no replacement operation/runtime/peer is created.
func (s *Store) ExistingLaunchOperation(ctx context.Context, id uuid.UUID) (LaunchHandoff, error) {
	conn, release, err := s.acquireLifecycle(ctx, id)
	if err != nil {
		return LaunchHandoff{}, err
	}
	defer release()
	target, err := s.prepareStart(ctx, conn, id)
	if err != nil {
		return LaunchHandoff{}, err
	}
	var h LaunchHandoff
	err = conn.QueryRow(ctx, `SELECT id,org_id,sandbox_id,gateway_node_id,generation,runtime_id,spec_hash FROM sandbox_launch_operations WHERE sandbox_id=$1 AND generation=$2`, id, target.sandbox.Revision).Scan(&h.OperationID, &h.OrgID, &h.SandboxID, &h.GatewayID, &h.Generation, &h.RuntimeID, &h.SpecHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return LaunchHandoff{}, ErrConflict
	}
	return h, err
}

// EnrollPreparedLaunch composes durable operation, control transport and peer
// confirmation under one lease. It never starts networking or reports Ready.
func (s *Store) EnrollPreparedLaunch(ctx context.Context, h LaunchHandoff, transport LaunchControlTransport) error {
	if transport == nil {
		return ErrDisabled
	}
	conn, release, err := s.acquireLifecycle(ctx, h.SandboxID)
	if err != nil {
		return err
	}
	defer release()
	target, err := s.prepareStart(ctx, conn, h.SandboxID)
	if err != nil {
		return err
	}
	specHash, err := sandboxruntime.Fingerprint(target.spec)
	if err != nil || target.runtimeID == nil || *target.runtimeID != h.RuntimeID || target.sandbox.Revision != h.Generation || target.sandbox.Identity.OrgID != h.OrgID || specHash != h.SpecHash {
		return ErrConflict
	}
	var consumed, unexpired bool
	var tokenHash []byte
	err = conn.QueryRow(ctx, `SELECT t.consumed_at IS NOT NULL,t.expires_at>now(),t.token_hash FROM sandbox_launch_operations l JOIN sandbox_bootstrap_tokens t ON t.id=l.bootstrap_token_id WHERE l.id=$1 AND l.org_id=$2 AND l.sandbox_id=$3 AND l.generation=$4 AND l.gateway_node_id=$5 AND l.runtime_id=$6 AND l.spec_hash=$7`, h.OperationID, h.OrgID, h.SandboxID, h.Generation, h.GatewayID, h.RuntimeID, h.SpecHash).Scan(&consumed, &unexpired, &tokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if target.sandbox.PeerID == nil {
		hash := sha256.Sum256([]byte(h.BootstrapToken))
		if consumed || !unexpired || !equalHash(tokenHash, hash[:]) {
			return ErrConflict
		}
	} else {
		if !consumed {
			return ErrConflict
		}
		h.BootstrapToken = "" // existing files only; never POST a second enrollment
	}
	receipt, err := transport.Enroll(ctx, h)
	if err != nil {
		return err
	}
	if receipt.Handoff.OperationID != h.OperationID || receipt.Handoff.SandboxID != h.SandboxID || receipt.Handoff.Generation != h.Generation || receipt.Handoff.RuntimeID != h.RuntimeID || !receipt.Handoff.Persisted {
		return ErrConflict
	}
	current, err := s.prepareStart(ctx, conn, h.SandboxID)
	if err != nil {
		return err
	}
	if current.sandbox.Revision != h.Generation || current.sandbox.PeerID == nil || *current.sandbox.PeerID != receipt.Handoff.PeerID {
		return ErrConflict
	}
	var public string
	var credentialHash []byte
	err = conn.QueryRow(ctx, `SELECT d.public_key,c.token_hash FROM devices d JOIN sandbox_runtime_credentials c ON c.peer_id=d.id AND c.org_id=d.org_id WHERE d.id=$1 AND d.org_id=$2 AND d.kind='sandbox' AND d.status='active' AND d.deleted_at IS NULL AND NOT d.health_blocked AND c.sandbox_id=$3 AND c.revoked_at IS NULL`, receipt.Handoff.PeerID, h.OrgID, h.SandboxID).Scan(&public, &credentialHash)
	if err != nil || public != receipt.WireGuardPublicKey || !equalHash(credentialHash, receipt.CredentialHash[:]) {
		return ErrConflict
	}
	return confirmLaunch(ctx, conn, receipt.Handoff)
}
