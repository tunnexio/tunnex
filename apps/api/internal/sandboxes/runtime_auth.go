package sandboxes

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrRuntimeUnauthorized = errors.New("sandbox runtime authentication failed")

// RuntimeIdentity is a current binding, not a policy grant or readiness receipt.
type RuntimeIdentity struct {
	OrgID      uuid.UUID
	SandboxID  uuid.UUID
	PeerID     uuid.UUID
	Generation int64
}

// AuthenticateRuntime rechecks lifecycle and creator eligibility on every call.
// Agent, bootstrap and human credentials are never accepted here. Desired stop,
// withdrawal and expiry refuse immediately without waiting for provider cleanup.
func (s *Store) AuthenticateRuntime(ctx context.Context, credential string) (RuntimeIdentity, error) {
	var identity RuntimeIdentity
	const prefix = "tnx_sandbox_runtime_"
	if !strings.HasPrefix(credential, prefix) || len(credential) != len(prefix)+43 {
		return identity, ErrRuntimeUnauthorized
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(credential, prefix))
	if err != nil || len(raw) != 32 {
		return identity, ErrRuntimeUnauthorized
	}
	hash := sha256.Sum256([]byte(credential))
	err = s.pool.QueryRow(ctx, `SELECT s.org_id,s.id,s.peer_id,s.generation
 FROM sandbox_runtime_credentials c
 JOIN sandboxes s ON s.id=c.sandbox_id AND s.org_id=c.org_id AND s.peer_id=c.peer_id
 JOIN devices d ON d.id=c.peer_id AND d.org_id=s.org_id AND d.user_id=s.creator_id AND d.kind='sandbox'
 JOIN organizations o ON o.id=s.org_id AND o.deleted_at IS NULL AND o.zero_trust_mode='enforcing'
 JOIN sandbox_templates t ON t.id=s.template_id AND t.org_id=s.org_id
 JOIN users u ON u.id=s.creator_id AND u.status='active' AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL AND NOT u.must_change_password
 JOIN memberships m ON m.org_id=s.org_id AND m.user_id=s.creator_id AND COALESCE(m.roles,ARRAY[m.role]) && ARRAY['member','admin','owner']::text[]
 WHERE c.token_hash=$1 AND c.revoked_at IS NULL AND s.desired_state='started' AND (`+sandboxEligibilitySQL+`)
 AND ((o.sandboxes_enabled AND t.enabled) OR sandbox_qualification_trial_valid(s.id))
 AND s.observed_state IN ('creating','starting','ready') AND s.expires_at>now()
 AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(s.selected_skills) selection
 LEFT JOIN sandbox_skill_revisions r ON r.id=(selection->>'revision_id')::uuid AND r.org_id=s.org_id AND r.enabled
 LEFT JOIN sandbox_template_skills a ON a.org_id=s.org_id AND a.template_id=s.template_id AND a.revision_id=r.id
 LEFT JOIN sandbox_custom_skills c ON c.id=r.custom_skill_id AND c.org_id=s.org_id AND c.owner_id=s.creator_id AND c.deleted_at IS NULL
 WHERE r.id IS NULL OR (r.owner_id IS NULL AND a.revision_id IS NULL) OR (r.owner_id IS NOT NULL AND (r.owner_id<>s.creator_id OR c.id IS NULL)))
 AND d.status='active' AND NOT d.health_blocked AND d.deleted_at IS NULL`, hash[:]).Scan(&identity.OrgID, &identity.SandboxID, &identity.PeerID, &identity.Generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return RuntimeIdentity{}, ErrRuntimeUnauthorized
	}
	if err != nil {
		return RuntimeIdentity{}, err
	}
	return identity, nil
}
