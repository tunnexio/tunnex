package sandboxes

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// This expression uses the sandbox alias s. Eligibility permits execution, never
// cleanup. A NULL terminal retains the legacy unpinned creator-human behavior.
const sandboxEligibilitySQL = `EXISTS(SELECT 1 FROM organizations o
 JOIN sandbox_templates t ON t.org_id=o.id AND t.id=s.template_id
 JOIN memberships m ON m.org_id=o.id AND m.user_id=s.creator_id
 JOIN users u ON u.id=m.user_id
 WHERE o.id=s.org_id AND o.deleted_at IS NULL AND o.zero_trust_mode='enforcing'
 AND ((o.sandboxes_enabled AND t.enabled) OR sandbox_qualification_trial_valid(s.id))
 AND m.access_revoked_at IS NULL AND COALESCE(m.roles,ARRAY[m.role]) && ARRAY['member','admin','owner']::text[]
 AND u.status='active' AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL AND NOT u.must_change_password)
 AND sandbox_delegation_valid(s.id)
 AND sandbox_qualification_trial_authority(s.id)
 AND (s.terminal_device_id IS NULL OR EXISTS(SELECT 1 FROM devices terminal
 JOIN nodes n ON n.id=terminal.node_id AND n.org_id=terminal.org_id AND n.status='active' AND COALESCE(n.enrolled_kind,'gateway')='gateway'
 LEFT JOIN sandbox_remote_terminal_routes route ON route.sandbox_id=s.id AND route.org_id=s.org_id
 WHERE terminal.id=s.terminal_device_id AND terminal.org_id=s.org_id AND terminal.user_id=s.creator_id
 AND terminal.kind='human' AND terminal.status='active' AND terminal.deleted_at IS NULL AND NOT terminal.health_blocked
 AND (s.local_terminal_gateway_id IS NULL OR terminal.node_id=s.local_terminal_gateway_id)
 AND (route.sandbox_id IS NULL OR (route.terminal_device_id=s.terminal_device_id AND terminal.node_id=route.terminal_gateway_id))))`

func sandboxEligible(ctx context.Context, q reservationReader, id uuid.UUID) (bool, error) {
	var eligible bool
	err := q.QueryRow(ctx, `SELECT `+sandboxEligibilitySQL+` FROM sandboxes s WHERE s.id=$1`, id).Scan(&eligible)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return eligible, err
}

// The runtime only withdraws its exact org/profile/gateway inventory. Revoked
// people/devices must not be required to authorize their own safe cleanup.
func (b BoundedRuntimeBinding) eligibilityScope() (string, []any) {
	if r := b.RemoteTerminal; r != nil {
		return `s.org_id=$2 AND s.template_id=ANY($3) AND s.local_terminal_gateway_id IS NULL
 AND EXISTS(SELECT 1 FROM sandbox_remote_terminal_routes route WHERE route.sandbox_id=s.id AND route.org_id=s.org_id
 AND route.terminal_device_id=s.terminal_device_id AND route.terminal_gateway_id=$4 AND route.runtime_gateway_id=$5
 AND route.terminal_gateway_endpoint=$6 AND route.runtime_gateway_endpoint=$7)`, []any{b.OrgID, b.templateIDs(), r.GatewayID, b.GatewayID, r.GatewayEndpoint, r.RuntimeGatewayEndpoint}
	}
	return `s.org_id=$2 AND s.template_id=ANY($3) AND s.local_terminal_gateway_id=$4 AND s.terminal_device_id IS NOT NULL`, []any{b.OrgID, b.templateIDs(), b.GatewayID}
}

func (s *Store) withdrawIneligibleTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) (bool, error) {
	b := s.boundedRuntime
	if b == nil || !b.OrganizationScoped() || id == uuid.Nil {
		return false, nil
	}
	scope, args := b.eligibilityScope()
	args = append([]any{id}, args...)
	out, err := scanSandbox(tx.QueryRow(ctx, `SELECT `+sandboxColumns+` FROM sandboxes s WHERE s.id=$1 AND `+scope+` FOR UPDATE OF s`, args...))
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if out.DesiredState == "deleted" || out.State == StateDeleted {
		return true, nil
	}
	eligible, err := sandboxEligible(ctx, tx, id)
	if err != nil || eligible {
		return false, err
	}
	tag, err := tx.Exec(ctx, `UPDATE sandboxes SET desired_state='deleted',generation=generation+1 WHERE id=$1 AND generation=$2 AND desired_state<>'deleted'`, id, out.Revision)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() != 1 {
		return false, ErrConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE sandbox_runtime_credentials SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE sandbox_id=$1 AND org_id=$2`, id, out.Identity.OrgID); err != nil {
		return false, err
	}
	if out.PeerID != nil {
		if _, err = tx.Exec(ctx, `UPDATE devices SET health_blocked=true WHERE id=$1 AND org_id=$2 AND kind='sandbox'`, *out.PeerID, out.Identity.OrgID); err != nil {
			return false, err
		}
	}
	metadata, _ := json.Marshal(map[string]any{"owner_id": out.Identity.CreatorID, "generation": out.Revision + 1, "desired_state": "deleted", "cleanup_pending": true, "cause": "current_authority_withdrawn"})
	_, err = tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_system,action,target_type,target_id,metadata) VALUES($1,'sandbox-eligibility-reconciler','sandbox.eligibility_withdraw','sandbox',$2,$3)`, out.Identity.OrgID, id.String(), metadata)
	return err == nil, err
}

func (s *Store) WithdrawIneligible(ctx context.Context, id uuid.UUID) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	withdrawn, err := s.withdrawIneligibleTx(ctx, tx, id)
	if err != nil {
		return false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return false, err
	}
	if withdrawn {
		s.notifyPolicy(ctx, s.boundedRuntime.OrgID)
	}
	return withdrawn, nil
}

// SweepEligibility requests bounded cleanup; it never claims provider/network
// removal or immediate termination of a previously established SSH connection.
func (s *Store) SweepEligibility(ctx context.Context, org uuid.UUID, limit int) error {
	if limit < 1 || limit > 100 {
		return ErrInvalid
	}
	b := s.boundedRuntime
	if b == nil || !b.OrganizationScoped() {
		return nil
	}
	if org != uuid.Nil && org != b.OrgID {
		return ErrForbidden
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	scope, args := b.eligibilityScope()
	args = append([]any{limit}, args...)
	rows, err := tx.Query(ctx, `SELECT s.id FROM sandboxes s WHERE `+scope+`
 AND s.observed_state<>'deleted' AND s.desired_state<>'deleted' AND NOT (`+sandboxEligibilitySQL+`)
 ORDER BY s.id LIMIT $1 FOR UPDATE OF s SKIP LOCKED`, args...)
	if err != nil {
		return err
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err = s.withdrawIneligibleTx(ctx, tx, id); err != nil {
			return err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	if len(ids) > 0 {
		s.notifyPolicy(ctx, b.OrgID)
	}
	return nil
}
