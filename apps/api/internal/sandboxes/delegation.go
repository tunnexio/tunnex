package sandboxes

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxscope"
)

// Delegation is immutable authority, not a credential or runtime binding.
type Delegation struct {
	ID               uuid.UUID   `json:"id"`
	OrgID            uuid.UUID   `json:"organization_id"`
	OwnerID          uuid.UUID   `json:"owner_id"`
	MachineID        uuid.UUID   `json:"machine_id"`
	TemplateID       uuid.UUID   `json:"template_id"`
	MaxTTLSeconds    int32       `json:"max_ttl_seconds"`
	MaxActive        int32       `json:"max_active"`
	MaximumScope     []Scope     `json:"maximum_scope"`
	SkillRevisionIDs []uuid.UUID `json:"skill_revision_ids"`
	ExpiresAt        time.Time   `json:"expires_at"`
}

func (d Delegation) validate(now time.Time) error {
	if d.OrgID == uuid.Nil || d.OwnerID == uuid.Nil || d.MachineID == uuid.Nil || d.TemplateID == uuid.Nil || d.MaxTTLSeconds < 300 || d.MaxTTLSeconds > 900 || d.MaxActive < 1 || d.MaxActive > 2 || !d.ExpiresAt.After(now) || len(d.SkillRevisionIDs) > 32 {
		return ErrInvalid
	}
	if _, err := sandboxscope.NormalizeScope(d.MaximumScope); err != nil {
		return ErrInvalid
	}
	seen := map[uuid.UUID]bool{}
	for _, id := range d.SkillRevisionIDs {
		if id == uuid.Nil || seen[id] {
			return ErrInvalid
		}
		seen[id] = true
	}
	return nil
}
func (d Delegation) admit(in CreateInput) error {
	if in.TemplateID != d.TemplateID || in.TTLSeconds < 300 || in.TTLSeconds > d.MaxTTLSeconds {
		return ErrForbidden
	}
	if err := sandboxscope.AdmitScope(in.Requested, d.MaximumScope, d.MaximumScope); err != nil {
		return ErrForbidden
	}
	for _, s := range in.SelectedSkills {
		found := false
		for _, id := range d.SkillRevisionIDs {
			if s.RevisionID == id {
				found = true
			}
		}
		if !found {
			return ErrForbidden
		}
	}
	return nil
}

// delegationForUse holds the grant and credential through commit, ordering
// revocation/owner reassignment against every delegated mutation and read.
func delegationForUse(ctx context.Context, tx pgx.Tx, org, owner uuid.UUID) (*Delegation, error) {
	p, ok := authctx.PrincipalFrom(ctx)
	if !ok {
		return nil, nil
	} // legacy internal human callers retain their contract
	if p.IsAgent() {
		return nil, ErrForbidden
	}
	if !p.IsMachine() {
		if p.UserID != owner {
			return nil, ErrForbidden
		}
		return nil, nil
	}
	if p.AuthMethod != authctx.AuthMachine || p.UserID != uuid.Nil || p.OwnerUserID != owner || owner == uuid.Nil || p.MustChangePassword {
		return nil, ErrForbidden
	}
	if _, ok := p.RoleIn(org); !ok {
		return nil, ErrForbidden
	}
	var d Delegation
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT d.id,d.org_id,d.owner_id,d.machine_id,d.template_id,d.max_ttl_seconds,d.max_active,d.maximum_scope,d.skill_revision_ids,d.expires_at
 FROM sandbox_delegations d JOIN machine_credentials c ON c.id=d.machine_id AND c.org_id=d.org_id AND c.user_id=d.owner_id
 JOIN organizations o ON o.id=d.org_id
 WHERE d.org_id=$1 AND d.owner_id=$2 AND d.machine_id=$3 AND d.revoked_at IS NULL AND d.expires_at>clock_timestamp()
 AND c.revoked_at IS NULL AND o.sandbox_delegation_enabled AND o.deleted_at IS NULL
 FOR SHARE OF d,c,o`, org, owner, p.MachineID).Scan(&d.ID, &d.OrgID, &d.OwnerID, &d.MachineID, &d.TemplateID, &d.MaxTTLSeconds, &d.MaxActive, &raw, &d.SkillRevisionIDs, &d.ExpiresAt)
	if err == pgx.ErrNoRows {
		return nil, ErrForbidden
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(raw, &d.MaximumScope) != nil || d.validate(time.Now()) != nil {
		return nil, ErrForbidden
	}
	return &d, nil
}
func delegatedInstance(ctx context.Context, tx pgx.Tx, d *Delegation, v Sandbox) error {
	if d == nil {
		return nil
	}
	if !v.Identity.CanManage(d.OrgID, d.OwnerID) {
		return ErrForbidden
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sandbox_delegated_instances WHERE sandbox_id=$1 AND delegation_id=$2)`, v.Identity.ID, d.ID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrForbidden
	}
	return d.admit(CreateInput{TemplateID: v.TemplateVersionID, TTLSeconds: int32(v.ExpiresAt.Sub(v.CreatedAt).Seconds()), Requested: v.RequestedScope, SelectedSkills: v.SelectedSkills})
}
