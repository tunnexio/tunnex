package sandboxes

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SweepDelegations schedules bounded cleanup of invalid delegation authority.
// It never asserts physical deletion; the existing cleanup reconciler must
// verify network withdrawal/provider removal before observed_state=deleted.
func (s *Store) SweepDelegations(ctx context.Context, org uuid.UUID, limit int) error {
	if limit < 1 || limit > 100 {
		return ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT s.id FROM sandboxes s
 JOIN sandbox_delegated_instances i ON i.sandbox_id=s.id
 WHERE ($1::uuid='00000000-0000-0000-0000-000000000000' OR s.org_id=$1)
 AND s.observed_state<>'deleted' AND s.desired_state<>'deleted' AND NOT sandbox_delegation_valid(s.id)
 ORDER BY s.id LIMIT $2 FOR UPDATE OF s SKIP LOCKED`, org, limit)
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
	changedOrgs := map[uuid.UUID]bool{}
	for _, id := range ids {
		ownerOrg, e := withdrawDelegated(ctx, tx, id, uuid.Nil, "authority_expired_or_withdrawn")
		if e != nil {
			return e
		}
		changedOrgs[ownerOrg] = true
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	for id := range changedOrgs {
		s.notifyPolicy(ctx, id)
	}
	return nil
}
func withdrawDelegated(ctx context.Context, tx pgx.Tx, id, actor uuid.UUID, cause string) (uuid.UUID, error) {
	v, err := scanSandbox(tx.QueryRow(ctx, `SELECT `+sandboxColumns+` FROM sandboxes WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return uuid.Nil, err
	}
	if v.DesiredState == "deleted" || v.State == StateDeleted {
		return v.Identity.OrgID, nil
	}
	tag, err := tx.Exec(ctx, `UPDATE sandboxes SET desired_state='deleted',generation=generation+1 WHERE id=$1 AND generation=$2 AND desired_state<>'deleted'`, id, v.Revision)
	if err != nil {
		return uuid.Nil, err
	}
	if tag.RowsAffected() != 1 {
		return uuid.Nil, ErrConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE sandbox_runtime_credentials SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE sandbox_id=$1`, id); err != nil {
		return uuid.Nil, err
	}
	if v.PeerID != nil {
		if _, err = tx.Exec(ctx, `UPDATE devices SET health_blocked=true WHERE id=$1 AND kind='sandbox'`, *v.PeerID); err != nil {
			return uuid.Nil, err
		}
	}
	var grant uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT delegation_id FROM sandbox_delegated_instances WHERE sandbox_id=$1`, id).Scan(&grant); err != nil {
		return uuid.Nil, err
	}
	metadata, _ := json.Marshal(map[string]any{"owner_id": v.Identity.CreatorID, "delegation_id": grant, "generation": v.Revision + 1, "desired_state": "deleted", "cleanup_pending": true, "cause": cause})
	if actor != uuid.Nil {
		_, err = tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,'sandbox.delegation_withdraw','sandbox',$3,$4)`, v.Identity.OrgID, actor, id.String(), metadata)
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_system,action,target_type,target_id,metadata) VALUES($1,'sandbox-delegation-reconciler','sandbox.delegation_withdraw','sandbox',$2,$3)`, v.Identity.OrgID, id.String(), metadata)
	}
	return v.Identity.OrgID, err
}
func withdrawGrant(ctx context.Context, tx pgx.Tx, org, grant, actor uuid.UUID) error {
	rows, err := tx.Query(ctx, `SELECT s.id FROM sandboxes s JOIN sandbox_delegated_instances i ON i.sandbox_id=s.id WHERE i.delegation_id=$1 AND s.org_id=$2 AND s.observed_state<>'deleted' AND s.desired_state<>'deleted' ORDER BY s.id FOR UPDATE OF s`, grant, org)
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
		if _, err = withdrawDelegated(ctx, tx, id, actor, "explicit_grant_revocation"); err != nil {
			return err
		}
	}
	return nil
}
