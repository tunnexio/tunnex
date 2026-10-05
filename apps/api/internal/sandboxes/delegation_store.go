package sandboxes

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxscope"
	"time"
)

func delegationHuman(ctx context.Context, actor uuid.UUID) error {
	p, ok := authctx.PrincipalFrom(ctx)
	if !ok || p.IsMachine() || p.IsAgent() || p.UserID != actor {
		return ErrForbidden
	}
	return nil
}
func delegationAdmin(ctx context.Context, tx pgx.Tx, org, actor uuid.UUID) error {
	if err := delegationHuman(ctx, actor); err != nil {
		return err
	}
	_, err := authorize(ctx, tx, org, actor, rbac.PermSandboxDelegateManage)
	return err
}

// SetDelegationEnabled is an explicit human organization administration action.
func (s *Store) SetDelegationEnabled(ctx context.Context, org, actor uuid.UUID, enabled bool) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = delegationAdmin(ctx, tx, org, actor); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE organizations SET sandbox_delegation_enabled=$2 WHERE id=$1`, org, enabled); err != nil {
		return err
	}
	if err = delegationAudit(ctx, tx, org, actor, uuid.Nil, "sandbox.delegation_opt_in", map[string]any{"enabled": enabled}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// IssueDelegation binds the current credential owner; request owner/org fields
// must match the authenticated human and path organization.
func (s *Store) IssueDelegation(ctx context.Context, org, actor uuid.UUID, d Delegation) (Delegation, error) {
	if d.OrgID != org || d.OwnerID != actor || d.validate(time.Now()) != nil {
		return Delegation{}, ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Delegation{}, err
	}
	defer tx.Rollback(ctx)
	var enabled bool
	if err = tx.QueryRow(ctx, `SELECT sandbox_delegation_enabled FROM organizations WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, org).Scan(&enabled); err != nil {
		return Delegation{}, err
	}
	if err = delegationAdmin(ctx, tx, org, actor); err != nil {
		return Delegation{}, err
	}
	if !enabled {
		return Delegation{}, ErrDisabled
	}
	for _, perm := range []rbac.Permission{rbac.PermSandboxCreate, rbac.PermSandboxManage} {
		if _, err = authorize(ctx, tx, org, actor, perm); err != nil {
			return Delegation{}, err
		}
	}
	var valid bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM machine_credentials WHERE id=$1 AND org_id=$2 AND user_id=$3 AND revoked_at IS NULL FOR SHARE)`, d.MachineID, org, actor).Scan(&valid); err != nil {
		return Delegation{}, err
	}
	if !valid {
		return Delegation{}, ErrForbidden
	}
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sandbox_templates WHERE id=$1 AND org_id=$2 AND enabled FOR SHARE)`, d.TemplateID, org).Scan(&valid); err != nil {
		return Delegation{}, err
	}
	if !valid {
		return Delegation{}, ErrForbidden
	}
	var templateRaw []byte
	if err = tx.QueryRow(ctx, `SELECT maximum_scope FROM sandbox_templates WHERE id=$1 AND org_id=$2`, d.TemplateID, org).Scan(&templateRaw); err != nil {
		return Delegation{}, err
	}
	var templateScope []Scope
	if json.Unmarshal(templateRaw, &templateScope) != nil {
		return Delegation{}, ErrInvalid
	}
	snapshot, err := policy.BuildSnapshotWithQueries(ctx, sqlc.New(tx), org)
	if err != nil {
		return Delegation{}, err
	}
	if err = sandboxscope.AdmitScope(d.MaximumScope, policy.CreatorStaticScope(snapshot, actor), templateScope); err != nil {
		return Delegation{}, ErrForbidden
	}
	if d.MaximumScope == nil {
		d.MaximumScope = []Scope{}
	}
	for _, id := range d.SkillRevisionIDs {
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sandbox_skill_revisions WHERE id=$1 AND org_id=$2 AND enabled AND (owner_id IS NULL OR owner_id=$3) FOR SHARE)`, id, org, actor).Scan(&valid); err != nil {
			return Delegation{}, err
		}
		if !valid {
			return Delegation{}, ErrForbidden
		}
	}
	raw, _ := json.Marshal(d.MaximumScope)
	if d.SkillRevisionIDs == nil {
		d.SkillRevisionIDs = []uuid.UUID{}
	}
	err = tx.QueryRow(ctx, `INSERT INTO sandbox_delegations(org_id,owner_id,machine_id,template_id,max_ttl_seconds,max_active,maximum_scope,skill_revision_ids,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`, org, actor, d.MachineID, d.TemplateID, d.MaxTTLSeconds, d.MaxActive, raw, d.SkillRevisionIDs, d.ExpiresAt).Scan(&d.ID)
	if err != nil {
		var pgerr *pgconn.PgError
		if errors.As(err, &pgerr) && pgerr.Code == "23505" {
			return Delegation{}, ErrConflict
		}
		return Delegation{}, err
	}
	if err = delegationAudit(ctx, tx, org, actor, d.ID, "sandbox.delegation_issue", d); err != nil {
		return Delegation{}, err
	}
	return d, tx.Commit(ctx)
}
func (s *Store) RevokeDelegation(ctx context.Context, org, actor, id uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = delegationAdmin(ctx, tx, org, actor); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE sandbox_delegations SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE id=$1 AND org_id=$2`, id, org)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	if err = withdrawGrant(ctx, tx, org, id, actor); err != nil {
		return err
	}
	if err = delegationAudit(ctx, tx, org, actor, id, "sandbox.delegation_revoke", map[string]any{"delegation_id": id}); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	s.notifyPolicy(ctx, org)
	return nil
}
func delegationAudit(ctx context.Context, tx pgx.Tx, org, actor, id uuid.UUID, action string, metadata any) error {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,'sandbox_delegation',$4,$5)`, org, actor, action, id.String(), raw)
	return err
}
