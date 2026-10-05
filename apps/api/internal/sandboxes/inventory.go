package sandboxes

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxscope"
)

type Template struct {
	ID            uuid.UUID
	Name          string
	ImageDigest   string
	MaximumScope  []Scope
	MemoryMiB     int32
	MaxTTLSeconds int32
	AllowedSkills []uuid.UUID
}
type Inventory struct {
	Items               []Sandbox
	NextCursor          *uuid.UUID
	OrganizationEnabled bool
}

func (s *Store) List(ctx context.Context, org, actor, cursor uuid.UUID, limit int) (Inventory, error) {
	if p, ok := authctx.PrincipalFrom(ctx); ok && (p.IsMachine() || p.IsAgent()) {
		return Inventory{}, ErrForbidden
	}

	if limit < 1 || limit > 100 {
		return Inventory{}, ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Inventory{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	roles, err := authorize(ctx, tx, org, actor, rbac.PermSandboxView)
	if err != nil {
		return Inventory{}, err
	}
	out := Inventory{Items: []Sandbox{}}
	if err = tx.QueryRow(ctx, `SELECT sandboxes_enabled AND zero_trust_mode='enforcing' FROM organizations WHERE id=$1`, org).Scan(&out.OrganizationEnabled); err != nil {
		return Inventory{}, err
	}
	rows, err := tx.Query(ctx, `SELECT `+sandboxColumns+` FROM sandboxes WHERE org_id=$1 AND (creator_id=$2 OR $3) AND id>$4 ORDER BY id LIMIT $5`, org, actor, rbac.CanAny(roles, rbac.PermSandboxAdmin), cursor, limit+1)
	if err != nil {
		return Inventory{}, err
	}
	for rows.Next() {
		item, e := scanSandbox(rows)
		if e != nil {
			rows.Close()
			return Inventory{}, e
		}
		out.Items = append(out.Items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return Inventory{}, err
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		id := out.Items[len(out.Items)-1].Identity.ID
		out.NextCursor = &id
	}
	return out, tx.Commit(ctx)
}
func (s *Store) Templates(ctx context.Context, org, actor uuid.UUID) ([]Template, error) {
	if p, ok := authctx.PrincipalFrom(ctx); ok && (p.IsMachine() || p.IsAgent()) {
		return nil, ErrForbidden
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err = authorize(ctx, tx, org, actor, rbac.PermSandboxView); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT t.id,t.name,t.image_digest,t.maximum_scope,t.memory_mib,t.max_ttl_seconds,ARRAY(SELECT a.revision_id FROM sandbox_template_skills a JOIN sandbox_skill_revisions r ON r.id=a.revision_id AND r.org_id=a.org_id AND r.enabled AND r.owner_id IS NULL WHERE a.org_id=t.org_id AND a.template_id=t.id ORDER BY a.revision_id) FROM sandbox_templates t WHERE t.org_id=$1 AND t.enabled ORDER BY t.name,t.id LIMIT 100`, org)
	if err != nil {
		return nil, err
	}
	out := []Template{}
	for rows.Next() {
		var item Template
		var raw []byte
		if err = rows.Scan(&item.ID, &item.Name, &item.ImageDigest, &raw, &item.MemoryMiB, &item.MaxTTLSeconds, &item.AllowedSkills); err != nil {
			rows.Close()
			return nil, err
		}
		if json.Unmarshal(raw, &item.MaximumScope) != nil {
			continue
		}
		if _, err = sandboxscope.NormalizeScope(item.MaximumScope); err != nil {
			continue
		}
		out = append(out, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}
