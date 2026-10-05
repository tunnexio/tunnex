package sandboxes

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// IssueBootstrap is an INTERNAL worker handoff, not a browser credential or
// ordinary inventory field. Caller must retain the returned secret securely;
// retries reconcile the same operation and never replace an uncertain peer.
func (s *Store) IssueBootstrap(ctx context.Context, org, actor, id, gateway uuid.UUID) (string, error) {
	if gateway == uuid.Nil {
		return "", ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	roles, err := authorize(ctx, tx, org, actor, rbac.PermSandboxManage)
	if err != nil {
		return "", err
	}
	var generation int64
	err = tx.QueryRow(ctx, `SELECT s.generation FROM sandboxes s
 JOIN organizations o ON o.id=s.org_id AND o.zero_trust_mode='enforcing'
 JOIN sandbox_templates t ON t.id=s.template_id AND t.org_id=s.org_id
 JOIN users u ON u.id=s.creator_id AND u.status='active' AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL AND NOT u.must_change_password
 JOIN memberships m ON m.org_id=s.org_id AND m.user_id=s.creator_id AND COALESCE(m.roles,ARRAY[m.role]) && ARRAY['member','admin','owner']::text[]
 WHERE s.org_id=$1 AND s.id=$2 AND (s.creator_id=$3 OR $4) AND s.peer_id IS NULL
 AND ((o.sandboxes_enabled AND t.enabled) OR sandbox_qualification_trial_valid(s.id))
 AND sandbox_qualification_trial_authority(s.id)
 AND (s.local_terminal_gateway_id IS NULL OR s.local_terminal_gateway_id=$5)
 AND NOT EXISTS(SELECT 1 FROM sandbox_remote_terminal_routes r WHERE r.sandbox_id=s.id AND r.org_id=s.org_id AND r.runtime_gateway_id<>$5)
 AND s.desired_state='started' AND s.observed_state IN ('creating','starting') AND s.expires_at>now()
 AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(s.selected_skills) selection
 LEFT JOIN sandbox_skill_revisions r ON r.id=(selection->>'revision_id')::uuid AND r.org_id=s.org_id AND r.enabled
 LEFT JOIN sandbox_template_skills a ON a.org_id=s.org_id AND a.template_id=s.template_id AND a.revision_id=r.id
 LEFT JOIN sandbox_custom_skills c ON c.id=r.custom_skill_id AND c.org_id=s.org_id AND c.owner_id=s.creator_id AND c.deleted_at IS NULL
 WHERE r.id IS NULL OR (r.owner_id IS NULL AND a.revision_id IS NULL) OR (r.owner_id IS NOT NULL AND (r.owner_id<>s.creator_id OR c.id IS NULL)))
 FOR UPDATE OF s`, org, id, actor, rbac.CanAny(roles, rbac.PermSandboxAdmin), gateway).Scan(&generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrConflict
	}
	if err != nil {
		return "", err
	}
	var active bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE id=$1 AND org_id=$2 AND status='active' AND endpoint<>'' AND wg_public_key<>'')`, gateway, org).Scan(&active)
	if err != nil {
		return "", err
	}
	if !active {
		return "", ErrDisabled
	}
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", err
	}
	token := "tnx_sandbox_bootstrap_" + base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	var tokenID uuid.UUID
	err = tx.QueryRow(ctx, `INSERT INTO sandbox_bootstrap_tokens(org_id,sandbox_id,gateway_node_id,generation,token_hash,expires_at)
 VALUES($1,$2,$3,$4,$5,now()+interval '1 hour') ON CONFLICT DO NOTHING RETURNING id`, org, id, gateway, generation, hash[:]).Scan(&tokenID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrConflict
	}
	if err != nil {
		return "", err
	}
	if err = tx.Commit(ctx); err != nil {
		return "", err
	}
	return token, nil
}
