package aigateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/internal/agentruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

const AIAudience = "tunnex-ai"
const AICredentialPrefix = "tnx_ai_"

type PolicyResolver interface {
	// Implementations use this caller-owned transaction for every database
	// read. They must not commit/rollback it or acquire another pool connection.
	CanIssue(context.Context, pgx.Tx, agentruntime.Identity) error
	Resolve(context.Context, pgx.Tx, agentruntime.Identity, string) (Grant, error)
}
type Credential struct {
	Token, Audience, Endpoint string
	ExpiresAt                 time.Time
}
type Settings struct {
	Enabled, Available bool
	Revision           int64
}
type Credentials struct {
	pool      *pgxpool.Pool
	runtime   *agentruntime.Service
	resolver  PolicyResolver
	available atomic.Bool
}

func NewCredentials(pool *pgxpool.Pool, runtime *agentruntime.Service, resolver PolicyResolver) *Credentials {
	return &Credentials{pool: pool, runtime: runtime, resolver: resolver}
}
func (s *Credentials) SetAvailable(v bool) { s.available.Store(v) }
func (s *Credentials) ready() bool {
	return s != nil && s.pool != nil && s.runtime != nil && s.resolver != nil && s.available.Load()
}
func aiUnauthorized() error { return apierr.New(401, "unauthenticated", "authentication required") }
func aiUnavailable() error {
	return apierr.New(503, "ai_gateway_unavailable", "AI gateway is unavailable")
}
func rollbackAI(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

// lockIdentity preserves the canonical device-before-credential lock order.
// The separate lifecycle read gets a fresh snapshot after any device lock wait.
func lockAIIdentity(ctx context.Context, tx pgx.Tx, id agentruntime.Identity) error {
	var locked uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM devices WHERE org_id=$1 AND id=$2 FOR UPDATE`, id.OrgID, id.DeviceID).Scan(&locked); err != nil {
		return aiUnauthorized()
	}
	var valid bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices d
 JOIN organizations o ON o.id=d.org_id
 JOIN users u ON u.id=d.user_id
 JOIN memberships m ON m.org_id=d.org_id AND m.user_id=d.user_id
 JOIN agent_runtime_credentials c ON c.org_id=d.org_id AND c.device_id=d.id
 WHERE d.org_id=$1 AND d.id=$2 AND d.kind='agent' AND d.status='active'
 AND d.deleted_at IS NULL AND NOT d.health_blocked
 AND o.deleted_at IS NULL AND o.ai_gateway_enabled
 AND u.status='active' AND u.deleted_at IS NULL
 AND c.revision=$3 AND c.state='current' AND c.revoked_at IS NULL)`, id.OrgID, id.DeviceID, id.CredentialRevision).Scan(&valid)
	if err != nil || !valid {
		return aiUnauthorized()
	}
	return nil
}

func (s *Credentials) Issue(ctx context.Context, rawRuntime string) (Credential, error) {
	if !s.ready() {
		return Credential{}, aiUnavailable()
	}
	id, err := s.runtime.AuthenticateCurrent(ctx, rawRuntime)
	if err != nil {
		return Credential{}, aiUnauthorized()
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Credential{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	if err = lockAIIdentity(ctx, tx, id); err != nil {
		return Credential{}, err
	}
	if err = s.resolver.CanIssue(ctx, tx, id); err != nil {
		return Credential{}, apierr.New(403, "ai_policy_denied", "AI access is not available under the current policy")
	}
	// Refresh bounds storage for this device without evicting any usable bearer
	// to bypass the live-token cap. Idle devices retain their terminal rows until
	// their next successful issuance or canonical device/org deletion; no global
	// retention sweeper is implied by this opportunistic cleanup.
	if _, err = tx.Exec(ctx, `DELETE FROM ai_gateway_credentials
WHERE org_id=$1 AND device_id=$2
AND (expires_at<=statement_timestamp() OR revoked_at IS NOT NULL OR runtime_revision<>$3)`, id.OrgID, id.DeviceID, id.CredentialRevision); err != nil {
		return Credential{}, aiUnavailable()
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM ai_gateway_credentials WHERE org_id=$1 AND device_id=$2 AND runtime_revision=$3 AND revoked_at IS NULL AND expires_at>statement_timestamp()`, id.OrgID, id.DeviceID, id.CredentialRevision).Scan(&count); err != nil {
		return Credential{}, aiUnavailable()
	}
	if count >= 4 {
		return Credential{}, apierr.New(429, "ai_credential_limit", "too many live AI credentials")
	}
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return Credential{}, aiUnavailable()
	}
	result := Credential{Token: AICredentialPrefix + base64.RawURLEncoding.EncodeToString(b), Audience: AIAudience, Endpoint: "/ai"}
	hash := sha256.Sum256([]byte(result.Token))
	err = tx.QueryRow(ctx, `INSERT INTO ai_gateway_credentials(token_hash,org_id,device_id,runtime_revision,audience,created_at,expires_at) VALUES($1,$2,$3,$4,$5,statement_timestamp(),statement_timestamp()+interval '5 minutes') RETURNING expires_at`, hash[:], id.OrgID, id.DeviceID, id.CredentialRevision, AIAudience).Scan(&result.ExpiresAt)
	if err != nil || tx.Commit(ctx) != nil {
		return Credential{}, aiUnavailable()
	}
	return result, nil
}

func (s *Credentials) Authorize(ctx context.Context, rawAI, model string) (Grant, error) {
	if !s.ready() {
		return Grant{}, aiUnavailable()
	}
	if !strings.HasPrefix(rawAI, AICredentialPrefix) || len(rawAI) != len(AICredentialPrefix)+43 {
		return Grant{}, aiUnauthorized()
	}
	hash := sha256.Sum256([]byte(rawAI))
	var id agentruntime.Identity
	// This untrusted lookup provides only locking scope, never authorization.
	err := s.pool.QueryRow(ctx, `SELECT org_id,device_id,runtime_revision FROM ai_gateway_credentials WHERE token_hash=$1`, hash[:]).Scan(&id.OrgID, &id.DeviceID, &id.CredentialRevision)
	if err != nil {
		return Grant{}, aiUnauthorized()
	}
	id.CredentialState = "current"
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Grant{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	if err = lockAIIdentity(ctx, tx, id); err != nil {
		return Grant{}, err
	}
	var expires time.Time
	err = tx.QueryRow(ctx, `SELECT expires_at FROM ai_gateway_credentials WHERE token_hash=$1 AND org_id=$2 AND device_id=$3 AND runtime_revision=$4 AND audience=$5 AND revoked_at IS NULL AND expires_at>statement_timestamp()`, hash[:], id.OrgID, id.DeviceID, id.CredentialRevision, AIAudience).Scan(&expires)
	if err != nil {
		return Grant{}, aiUnauthorized()
	}
	grant, err := s.resolver.Resolve(ctx, tx, id, model)
	if err != nil {
		return Grant{}, apierr.New(403, "ai_policy_denied", "AI access is not available under the current policy")
	}
	if grant.Tenant != id.OrgID.String() || grant.Agent != id.DeviceID.String() || grant.VirtualKey == "" || !grant.Expires.After(time.Now()) {
		return Grant{}, aiUnauthorized()
	}
	if expires.Before(grant.Expires) {
		grant.Expires = expires
	}
	if !grant.Expires.After(time.Now()) || tx.Commit(ctx) != nil {
		return Grant{}, aiUnauthorized()
	}
	return grant, nil
}

func (s *Credentials) Settings(ctx context.Context, orgID uuid.UUID) (Settings, error) {
	var out Settings
	if s == nil || s.pool == nil {
		return out, aiUnavailable()
	}
	err := s.pool.QueryRow(ctx, `SELECT ai_gateway_enabled,ai_gateway_revision FROM organizations WHERE id=$1 AND deleted_at IS NULL`, orgID).Scan(&out.Enabled, &out.Revision)
	if err != nil {
		return out, aiUnavailable()
	}
	out.Available = s.ready()
	return out, nil
}
func (s *Credentials) SetEnabled(ctx context.Context, orgID, actorID uuid.UUID, enabled bool) (Settings, error) {
	var out Settings
	if s == nil || s.pool == nil {
		return out, aiUnavailable()
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return out, aiUnavailable()
	}
	defer rollbackAI(tx)
	var previous bool
	if err = tx.QueryRow(ctx, `SELECT ai_gateway_enabled FROM organizations WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, orgID).Scan(&previous); err != nil {
		return out, aiUnavailable()
	}
	err = tx.QueryRow(ctx, `UPDATE organizations SET ai_gateway_enabled=$2,ai_gateway_revision=ai_gateway_revision+CASE WHEN ai_gateway_enabled IS DISTINCT FROM $2 THEN 1 ELSE 0 END WHERE id=$1 RETURNING ai_gateway_enabled,ai_gateway_revision`, orgID, enabled).Scan(&out.Enabled, &out.Revision)
	if err != nil {
		return out, aiUnavailable()
	}
	if previous != enabled {
		_, err = tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,'ai_gateway.setting_changed','organization',$3,jsonb_build_object('enabled',$4::boolean,'revision',$5::bigint))`, orgID, actorID, orgID.String(), enabled, out.Revision)
		if err != nil {
			return out, aiUnavailable()
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return out, aiUnavailable()
	}
	out.Available = s.ready()
	return out, nil
}
