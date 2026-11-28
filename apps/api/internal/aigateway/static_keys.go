package aigateway

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

const staticKeyPurpose = "tunnex-ai-workload-static-key"
const maxActiveStaticKeys = 8
const maxStaticKeyTTL = 90 * 24 * time.Hour

// ErrRequestLimited is returned by a resolver when a per-key request limit
// refuses the call. The adapter answers it with its fixed 429 body.
var ErrRequestLimited = errors.New("AI request limit reached")

// RateLimiter counts requests in a store shared by every control-plane
// instance (Redis in production). An error means refuse.
type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
}

// StaticKeys are the second way to connect a workload (AI-KEYS-1). A key
// belongs to one workload and inherits its models and daily threshold, read
// live at each request.
type StaticKeys struct {
	w       *Workloads
	limiter RateLimiter
}

func NewStaticKeys(w *Workloads, limiter RateLimiter) *StaticKeys {
	return &StaticKeys{w: w, limiter: limiter}
}

func (s *StaticKeys) ready() bool { return s != nil && s.w.ready() }

// StaticKeyIngress names the route a key arrived on. Only the route that
// accepted the request builds it; Authorize never guesses (D6). The zero
// value is refused.
type StaticKeyIngress struct {
	kind                string
	client              netip.Addr
	org, node, endpoint uuid.UUID
	peer                netip.Addr
}

// PublicIngress is built only by the control plane's public AI route. client
// is the address from the trusted proxy chain, or invalid when unknown.
func PublicIngress(client netip.Addr) StaticKeyIngress {
	return StaticKeyIngress{kind: "public", client: client.Unmap()}
}

// InternalIngress is built only by the node mTLS route from the node
// certificate and its endpoint row.
func InternalIngress(org, node, endpoint uuid.UUID, peer netip.Addr) StaticKeyIngress {
	return StaticKeyIngress{kind: "internal", org: org, node: node, endpoint: endpoint, peer: peer.Unmap()}
}

func (i StaticKeyIngress) source() netip.Addr {
	if i.kind == "internal" {
		return i.peer
	}
	return i.client
}

type staticKeyRecord struct {
	api.AIWorkloadStaticKey
	org      uuid.UUID
	hash     []byte
	epoch    int64
	native   string
	sealed   string
	revision int64
}

const staticKeyColumns = `id,org_id,workload_id,name,hint,scope,source_cidrs::text[],daily_usd_threshold,rate_limit_per_minute,workload_epoch,expires_at,revoked_at,rotated_from_id,native_key_id,sealed_key,binding_revision,status,last_used_at,last_used_ingress,host(last_used_source),last_used_node_id,last_refused_at,last_refused_reason,last_refused_ingress,host(last_refused_source),created_at,updated_at`

func scanStaticKey(row pgx.Row) (staticKeyRecord, error) {
	var k staticKeyRecord
	var scope, status string
	var usedIngress, refusedIngress *string
	err := row.Scan(&k.Id, &k.org, &k.WorkloadId, &k.Name, &k.Hint, &scope, &k.SourceCidrs, &k.DailyUsdThreshold, &k.RateLimitPerMinute, &k.epoch, &k.ExpiresAt, &k.RevokedAt, &k.RotatedFromId, &k.native, &k.sealed, &k.revision, &status, &k.LastUsedAt, &usedIngress, &k.LastUsedSource, &k.LastUsedNodeId, &k.LastRefusedAt, &k.LastRefusedReason, &refusedIngress, &k.LastRefusedSource, &k.CreatedAt, &k.UpdatedAt)
	k.Scope = api.AIWorkloadStaticKeyScope(scope)
	k.Status = api.AIWorkloadStaticKeyStatus(status)
	if k.RevokedAt == nil && !k.ExpiresAt.After(time.Now()) {
		k.Status = "expired"
	}
	if usedIngress != nil {
		v := api.AIWorkloadStaticKeyLastUsedIngress(*usedIngress)
		k.LastUsedIngress = &v
	}
	if refusedIngress != nil {
		v := api.AIWorkloadStaticKeyLastRefusedIngress(*refusedIngress)
		k.LastRefusedIngress = &v
	}
	if k.SourceCidrs == nil {
		k.SourceCidrs = []string{}
	}
	return k, err
}

func validThreshold(v *float64) bool {
	return v == nil || (*v > 0 && *v <= 100000 && !math.IsNaN(*v) && !math.IsInf(*v, 0))
}
func validRateLimit(v *int) bool { return v == nil || (*v >= 1 && *v <= 60000) }

func staticKeyInvalid(message string) error {
	return apierr.BadRequest("invalid_static_key", message)
}
func staticKeyCapacity() error {
	return apierr.BadRequest("static_key_capacity", "This workload already has 8 active static keys, or the organization's AI binding capacity is reached. Revoke a key first.")
}
func publicStaticKeysDisabled() error {
	return apierr.Forbidden("public_static_keys_disabled", "Public static keys are off for this organization. An AI Gateway administrator can allow them in AI Gateway settings.")
}

type staticKeySettings struct {
	name           string
	cidrs          []string
	threshold      *float64
	rate           *int
	allowAnySource bool
}

// validateSettings checks fields shared by create, update and rotate. The
// workload threshold, when set, caps the key's own threshold.
func (s *StaticKeys) validateSettings(in staticKeySettings, scope string, workloadThreshold *float64) (staticKeySettings, error) {
	if !validWorkloadName(in.name) {
		return in, staticKeyInvalid("Name must be 1 to 100 characters on one line")
	}
	cidrs, ok := canonicalStaticKeyCIDRs(in.cidrs, scope)
	if !ok {
		if scope == "public" {
			return in, staticKeyInvalid("Public keys accept up to 32 distinct public address ranges; private, reserved and all-address ranges are refused")
		}
		return in, staticKeyInvalid("Internal keys accept up to 32 distinct private IPv4 ranges")
	}
	in.cidrs = cidrs
	if scope == "public" && len(cidrs) == 0 && !in.allowAnySource {
		return in, staticKeyInvalid("A public key with no source ranges needs the confirmation \"Allow from any address\"")
	}
	if !validThreshold(in.threshold) {
		return in, staticKeyInvalid("Daily limit must be more than 0 and at most 100000")
	}
	if in.threshold != nil && workloadThreshold != nil && *in.threshold > *workloadThreshold {
		return in, staticKeyInvalid("A key's daily limit cannot be higher than its workload's")
	}
	if !validRateLimit(in.rate) {
		return in, staticKeyInvalid("Requests per minute must be 1 to 60000")
	}
	if in.rate != nil && s.limiter == nil {
		return in, aiUnavailable()
	}
	return in, nil
}

func validStaticKeyExpiry(expires, now time.Time) bool {
	return expires.After(now) && !expires.After(now.Add(maxStaticKeyTTL))
}

func orgAllowsPublicStaticKeys(ctx context.Context, tx pgx.Tx, org uuid.UUID) (bool, error) {
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT COALESCE(s.public_static_keys_allowed,false) FROM organizations o LEFT JOIN ai_static_key_settings s ON s.org_id=o.id WHERE o.id=$1 AND o.deleted_at IS NULL`, org).Scan(&allowed)
	return allowed, err
}

// reserveStaticKeySlot takes the organization's binding lock and checks both
// caps: 8 active keys per workload and 64 active bindings per organization.
func reserveStaticKeySlot(ctx context.Context, tx pgx.Tx, org, workload uuid.UUID) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,150))`, org.String()); err != nil {
		return aiUnavailable()
	}
	var perWorkload, total int
	if tx.QueryRow(ctx, `SELECT count(*) FROM ai_workload_static_keys WHERE org_id=$1 AND workload_id=$2 AND revoked_at IS NULL AND expires_at>now()`, org, workload).Scan(&perWorkload) != nil {
		return aiUnavailable()
	}
	if tx.QueryRow(ctx, `SELECT `+activeBindingCountSQL, org).Scan(&total) != nil {
		return aiUnavailable()
	}
	if perWorkload >= maxActiveStaticKeys || total >= maxAIUsageBindings {
		return staticKeyCapacity()
	}
	return nil
}

// activeBindingCountSQL counts engine bindings toward the 64 cap. Only active
// static keys count (founder decision 1).
const activeBindingCountSQL = `(SELECT count(*) FROM ai_workloads WHERE org_id=$1)+(SELECT count(*) FROM ai_user_model_grants WHERE org_id=$1)+(SELECT count(*) FROM ai_gateway_key_bindings WHERE org_id=$1)+(SELECT count(*) FROM ai_workload_static_keys WHERE org_id=$1 AND revoked_at IS NULL AND expires_at>now())`

func auditStaticKey(ctx context.Context, tx pgx.Tx, org, actor uuid.UUID, k staticKeyRecord, action string) error {
	_, err := tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,$3,'ai_workload_static_key',$4,jsonb_build_object('workload_id',$5::text,'scope',$6::text,'expires_at',$7::timestamptz,'cidr_count',$8::int,'daily_usd_threshold',$9::double precision,'rate_limit_per_minute',$10::int))`,
		org, actor, action, k.Id.String(), k.WorkloadId.String(), string(k.Scope), k.ExpiresAt, len(k.SourceCidrs), k.DailyUsdThreshold, k.RateLimitPerMinute)
	return err
}

// insertStaticKey writes a new key and returns the raw secret once.
func (s *StaticKeys) insertStaticKey(ctx context.Context, tx pgx.Tx, org, actor uuid.UUID, w workloadRecord, scope string, expires time.Time, in staticKeySettings, rotatedFrom *uuid.UUID) (staticKeyRecord, string, error) {
	raw, hash, hint, err := newStaticKey()
	if err != nil {
		return staticKeyRecord{}, "", aiUnavailable()
	}
	id, err := uuid.NewV7()
	if err != nil {
		return staticKeyRecord{}, "", aiUnavailable()
	}
	k, err := scanStaticKey(tx.QueryRow(ctx, `INSERT INTO ai_workload_static_keys(id,org_id,workload_id,name,secret_hash,hint,scope,source_cidrs,daily_usd_threshold,rate_limit_per_minute,workload_epoch,expires_at,rotated_from_id,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8::cidr[],$9,$10,$11,$12,$13,$14) RETURNING `+staticKeyColumns,
		id, org, w.Id, in.name, hash, hint, scope, in.cidrs, in.threshold, in.rate, w.epoch, expires, rotatedFrom, actor))
	if err != nil {
		return staticKeyRecord{}, "", aiUnavailable()
	}
	return k, raw, nil
}

// lockWorkloadForKeys takes the workload lock used by every key mutation.
func lockWorkloadForKeys(ctx context.Context, tx pgx.Tx, org, id uuid.UUID) (workloadRecord, error) {
	w, err := scanWorkload(tx.QueryRow(ctx, `SELECT `+workloadColumns+` FROM ai_workloads WHERE org_id=$1 AND id=$2 FOR UPDATE`, org, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return w, policyNotFound()
	}
	if err != nil {
		return w, aiUnavailable()
	}
	return w, nil
}

func (s *StaticKeys) Create(ctx context.Context, org, actor, workload uuid.UUID, in api.AIWorkloadStaticKeyInput) (api.AIWorkloadStaticKeySecret, error) {
	if !s.ready() {
		return api.AIWorkloadStaticKeySecret{}, aiUnavailable()
	}
	if org == uuid.Nil || actor == uuid.Nil {
		return api.AIWorkloadStaticKeySecret{}, policyInvalid()
	}
	scope := string(in.Scope)
	if scope != "internal" && scope != "public" {
		return api.AIWorkloadStaticKeySecret{}, staticKeyInvalid("Scope must be internal or public")
	}
	if !validStaticKeyExpiry(in.ExpiresAt, time.Now()) {
		return api.AIWorkloadStaticKeySecret{}, staticKeyInvalid("Expiry is required and at most 90 days from now")
	}
	settings := staticKeySettings{name: in.Name, threshold: in.DailyUsdThreshold, rate: in.RateLimitPerMinute}
	if in.SourceCidrs != nil {
		settings.cidrs = *in.SourceCidrs
	}
	if in.AllowAnySource != nil {
		settings.allowAnySource = *in.AllowAnySource
	}
	tx, err := s.w.policies.pool.Begin(ctx)
	if err != nil {
		return api.AIWorkloadStaticKeySecret{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	if err = reserveStaticKeySlot(ctx, tx, org, workload); err != nil {
		return api.AIWorkloadStaticKeySecret{}, err
	}
	w, err := lockWorkloadForKeys(ctx, tx, org, workload)
	if err != nil {
		return api.AIWorkloadStaticKeySecret{}, err
	}
	if !w.Enabled {
		return api.AIWorkloadStaticKeySecret{}, policyDenied()
	}
	if settings, err = s.validateSettings(settings, scope, w.DailyUsdThreshold); err != nil {
		return api.AIWorkloadStaticKeySecret{}, err
	}
	if scope == "public" {
		allowed, e := orgAllowsPublicStaticKeys(ctx, tx, org)
		if e != nil {
			return api.AIWorkloadStaticKeySecret{}, aiUnavailable()
		}
		if !allowed {
			return api.AIWorkloadStaticKeySecret{}, publicStaticKeysDisabled()
		}
	}
	k, raw, err := s.insertStaticKey(ctx, tx, org, actor, w, scope, in.ExpiresAt, settings, nil)
	if err != nil {
		return api.AIWorkloadStaticKeySecret{}, err
	}
	if err = auditStaticKey(ctx, tx, org, actor, k, "ai_workload.static_key_created"); err != nil {
		return api.AIWorkloadStaticKeySecret{}, aiUnavailable()
	}
	k = s.ensureEngineKey(ctx, tx, w, k)
	if tx.Commit(ctx) != nil {
		return api.AIWorkloadStaticKeySecret{}, aiUnavailable()
	}
	return api.AIWorkloadStaticKeySecret{Key: k.AIWorkloadStaticKey, Secret: raw}, nil
}

// ensureEngineKey gives an active key its own engine key with the workload's
// model scopes (D7). A failure leaves status 'error' for maintenance; the key
// cannot authorize until it is applied.
func (s *StaticKeys) ensureEngineKey(ctx context.Context, tx pgx.Tx, w workloadRecord, k staticKeyRecord) staticKeyRecord {
	status := "error"
	native, sealed, revision := k.native, k.sealed, k.revision
	models, err := loadWorkloadModels(ctx, tx, k.org, w.Id)
	if err == nil && len(models) > 0 {
		scopes, e := s.w.workloadScopes(ctx, tx, k.org, models)
		if e == nil {
			key, e := s.w.ensureEngineKey(ctx, "ai-workload-key-"+k.org.String()+"-"+k.Id.String(), scopes)
			if e == nil && key.ID != "" && key.Value != "" && (k.native == "" || k.native == key.ID) {
				if v, e := sealBoundKey(s.w.policies.sealer, staticKeyPurpose, k.org, k.Id, key.ID, w.Revision, key.Value); e == nil {
					native, sealed, revision, status = key.ID, v, w.Revision, "applied"
				}
			}
		}
	} else if err == nil {
		// No models: nothing to call. The key stays unusable until models exist.
		status = "pending"
	}
	if _, err = tx.Exec(ctx, `UPDATE ai_workload_static_keys SET native_key_id=$4,sealed_key=$5,binding_revision=$6,status=$7 WHERE org_id=$1 AND workload_id=$2 AND id=$3 AND revoked_at IS NULL`, k.org, w.Id, k.Id, native, sealed, revision, status); err == nil {
		k.native, k.sealed, k.revision, k.Status = native, sealed, revision, api.AIWorkloadStaticKeyStatus(status)
	}
	return k
}

func (s *StaticKeys) List(ctx context.Context, org, workload, after uuid.UUID, limit int) (api.AIWorkloadStaticKeyPage, error) {
	out := api.AIWorkloadStaticKeyPage{Items: []api.AIWorkloadStaticKey{}}
	if !s.ready() {
		return out, aiUnavailable()
	}
	if limit < 1 || limit > 100 {
		return out, policyInvalid()
	}
	var exists bool
	if s.w.policies.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ai_workloads WHERE org_id=$1 AND id=$2)`, org, workload).Scan(&exists) != nil {
		return out, aiUnavailable()
	}
	if !exists {
		return out, policyNotFound()
	}
	rows, err := s.w.policies.pool.Query(ctx, `SELECT `+staticKeyColumns+` FROM ai_workload_static_keys WHERE org_id=$1 AND workload_id=$2 AND id>$3 ORDER BY id LIMIT $4`, org, workload, after, limit+1)
	if err != nil {
		return out, aiUnavailable()
	}
	defer rows.Close()
	for rows.Next() {
		k, e := scanStaticKey(rows)
		if e != nil {
			return out, aiUnavailable()
		}
		out.Items = append(out.Items, k.AIWorkloadStaticKey)
	}
	if rows.Err() != nil {
		return out, aiUnavailable()
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		last := out.Items[limit-1].Id
		out.NextCursor = &last
	}
	return out, nil
}

func lockStaticKey(ctx context.Context, tx pgx.Tx, org, workload, id uuid.UUID) (staticKeyRecord, error) {
	k, err := scanStaticKey(tx.QueryRow(ctx, `SELECT `+staticKeyColumns+` FROM ai_workload_static_keys WHERE org_id=$1 AND workload_id=$2 AND id=$3 FOR UPDATE`, org, workload, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return k, policyNotFound()
	}
	if err != nil {
		return k, aiUnavailable()
	}
	return k, nil
}

func (s *StaticKeys) Update(ctx context.Context, org, actor, workload, id uuid.UUID, in api.AIWorkloadStaticKeyUpdate) (api.AIWorkloadStaticKey, error) {
	if !s.ready() {
		return api.AIWorkloadStaticKey{}, aiUnavailable()
	}
	if org == uuid.Nil || actor == uuid.Nil {
		return api.AIWorkloadStaticKey{}, policyInvalid()
	}
	tx, err := s.w.policies.pool.Begin(ctx)
	if err != nil {
		return api.AIWorkloadStaticKey{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	w, err := lockWorkloadForKeys(ctx, tx, org, workload)
	if err != nil {
		return api.AIWorkloadStaticKey{}, err
	}
	k, err := lockStaticKey(ctx, tx, org, workload, id)
	if err != nil {
		return api.AIWorkloadStaticKey{}, err
	}
	if !k.UpdatedAt.Equal(in.ExpectedUpdatedAt.Truncate(time.Microsecond)) && !k.UpdatedAt.Equal(in.ExpectedUpdatedAt) {
		return api.AIWorkloadStaticKey{}, policyConflict()
	}
	if k.RevokedAt != nil || !k.ExpiresAt.After(time.Now()) {
		return api.AIWorkloadStaticKey{}, apierr.Conflict("static_key_inactive", "This key is revoked or expired")
	}
	settings := staticKeySettings{name: in.Name, threshold: in.DailyUsdThreshold, rate: in.RateLimitPerMinute}
	if in.SourceCidrs != nil {
		settings.cidrs = *in.SourceCidrs
	}
	if in.AllowAnySource != nil {
		settings.allowAnySource = *in.AllowAnySource
	}
	if settings, err = s.validateSettings(settings, string(k.Scope), w.DailyUsdThreshold); err != nil {
		return api.AIWorkloadStaticKey{}, err
	}
	k, err = scanStaticKey(tx.QueryRow(ctx, `UPDATE ai_workload_static_keys SET name=$4,source_cidrs=$5::cidr[],daily_usd_threshold=$6,rate_limit_per_minute=$7 WHERE org_id=$1 AND workload_id=$2 AND id=$3 RETURNING `+staticKeyColumns, org, workload, id, settings.name, settings.cidrs, settings.threshold, settings.rate))
	if err != nil || auditStaticKey(ctx, tx, org, actor, k, "ai_workload.static_key_updated") != nil || tx.Commit(ctx) != nil {
		return api.AIWorkloadStaticKey{}, aiUnavailable()
	}
	return k.AIWorkloadStaticKey, nil
}

func (s *StaticKeys) Rotate(ctx context.Context, org, actor, workload, id uuid.UUID, in api.AIWorkloadStaticKeyRotate) (api.AIWorkloadStaticKeySecret, error) {
	if !s.ready() {
		return api.AIWorkloadStaticKeySecret{}, aiUnavailable()
	}
	if org == uuid.Nil || actor == uuid.Nil {
		return api.AIWorkloadStaticKeySecret{}, policyInvalid()
	}
	overlap := 24
	if in.OverlapHours != nil {
		overlap = *in.OverlapHours
	}
	now := time.Now()
	if overlap < 1 || overlap > 168 {
		return api.AIWorkloadStaticKeySecret{}, staticKeyInvalid("Overlap must be 1 hour to 7 days")
	}
	if !validStaticKeyExpiry(in.ExpiresAt, now) {
		return api.AIWorkloadStaticKeySecret{}, staticKeyInvalid("Expiry is required and at most 90 days from now")
	}
	tx, err := s.w.policies.pool.Begin(ctx)
	if err != nil {
		return api.AIWorkloadStaticKeySecret{}, aiUnavailable()
	}
	defer rollbackAI(tx)
	if err = reserveStaticKeySlot(ctx, tx, org, workload); err != nil {
		return api.AIWorkloadStaticKeySecret{}, err
	}
	w, err := lockWorkloadForKeys(ctx, tx, org, workload)
	if err != nil {
		return api.AIWorkloadStaticKeySecret{}, err
	}
	if !w.Enabled {
		return api.AIWorkloadStaticKeySecret{}, policyDenied()
	}
	old, err := lockStaticKey(ctx, tx, org, workload, id)
	if err != nil {
		return api.AIWorkloadStaticKeySecret{}, err
	}
	if old.RevokedAt != nil || !old.ExpiresAt.After(now) || old.epoch != w.epoch {
		return api.AIWorkloadStaticKeySecret{}, apierr.Conflict("static_key_inactive", "Only an active key can be rotated")
	}
	if old.Scope == "public" {
		allowed, e := orgAllowsPublicStaticKeys(ctx, tx, org)
		if e != nil {
			return api.AIWorkloadStaticKeySecret{}, aiUnavailable()
		}
		if !allowed {
			return api.AIWorkloadStaticKeySecret{}, publicStaticKeysDisabled()
		}
	}
	settings := staticKeySettings{name: old.Name, cidrs: old.SourceCidrs, threshold: old.DailyUsdThreshold, rate: old.RateLimitPerMinute, allowAnySource: true}
	if settings, err = s.validateSettings(settings, string(old.Scope), w.DailyUsdThreshold); err != nil {
		return api.AIWorkloadStaticKeySecret{}, err
	}
	k, raw, err := s.insertStaticKey(ctx, tx, org, actor, w, string(old.Scope), in.ExpiresAt, settings, &old.Id)
	if err != nil {
		return api.AIWorkloadStaticKeySecret{}, err
	}
	previous, err := scanStaticKey(tx.QueryRow(ctx, `UPDATE ai_workload_static_keys SET expires_at=least(expires_at,now()+make_interval(hours=>$4)) WHERE org_id=$1 AND workload_id=$2 AND id=$3 RETURNING `+staticKeyColumns, org, workload, id, overlap))
	if err != nil || auditStaticKey(ctx, tx, org, actor, k, "ai_workload.static_key_rotated") != nil {
		return api.AIWorkloadStaticKeySecret{}, aiUnavailable()
	}
	k = s.ensureEngineKey(ctx, tx, w, k)
	if tx.Commit(ctx) != nil {
		return api.AIWorkloadStaticKeySecret{}, aiUnavailable()
	}
	return api.AIWorkloadStaticKeySecret{Key: k.AIWorkloadStaticKey, Secret: raw, Previous: &previous.AIWorkloadStaticKey}, nil
}

func (s *StaticKeys) Revoke(ctx context.Context, org, actor, workload, id uuid.UUID) error {
	if !s.ready() {
		return aiUnavailable()
	}
	if org == uuid.Nil || actor == uuid.Nil {
		return policyInvalid()
	}
	tx, err := s.w.policies.pool.Begin(ctx)
	if err != nil {
		return aiUnavailable()
	}
	defer rollbackAI(tx)
	if _, err = lockWorkloadForKeys(ctx, tx, org, workload); err != nil {
		return err
	}
	k, err := lockStaticKey(ctx, tx, org, workload, id)
	if err != nil {
		return err
	}
	if k.RevokedAt == nil {
		k, err = scanStaticKey(tx.QueryRow(ctx, `UPDATE ai_workload_static_keys SET revoked_at=now(),revoked_by=$4,status='revoked' WHERE org_id=$1 AND workload_id=$2 AND id=$3 RETURNING `+staticKeyColumns, org, workload, id, actor))
		if err != nil || auditStaticKey(ctx, tx, org, actor, k, "ai_workload.static_key_revoked") != nil {
			return aiUnavailable()
		}
	}
	if tx.Commit(ctx) != nil {
		return aiUnavailable()
	}
	// The revocation is already committed and checked on every request. The
	// engine key is disabled as defence in depth; maintenance retries it.
	if k.native != "" {
		_ = s.disableEngineKey(ctx, org, workload, id, k.native)
	}
	return nil
}

func (s *StaticKeys) disableEngineKey(ctx context.Context, org, workload, id uuid.UUID, native string) error {
	if s.w.policies.engine.DisableKey(ctx, native) != nil {
		return aiUnavailable()
	}
	if _, err := s.w.policies.pool.Exec(ctx, `UPDATE ai_workload_static_keys SET engine_disabled_at=now(),status=CASE WHEN revoked_at IS NULL THEN status ELSE 'revoked' END WHERE org_id=$1 AND workload_id=$2 AND id=$3`, org, workload, id); err != nil {
		return aiUnavailable()
	}
	return nil
}

// revokeForDisabledWorkload revokes every live key when a workload is
// disabled, in the caller's transaction (D3).
func revokeStaticKeysForDisabledWorkload(ctx context.Context, tx pgx.Tx, org, workload uuid.UUID) error {
	rows, err := tx.Query(ctx, `UPDATE ai_workload_static_keys SET revoked_at=now(),status='revoked' WHERE org_id=$1 AND workload_id=$2 AND revoked_at IS NULL RETURNING id`, org, workload)
	if err != nil {
		return err
	}
	ids := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		if _, err = tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_system,action,target_type,target_id,metadata) VALUES($1,'workload-identity','ai_workload.static_key_revoked','ai_workload_static_key',$2,jsonb_build_object('cause','workload_disabled','workload_id',$3::text))`, org, id.String(), workload.String()); err != nil {
			return err
		}
	}
	return nil
}

// disableEngineKeys disables engine keys of revoked or expired static keys.
// Their native ids stay in the table for usage history.
func (s *StaticKeys) disableEngineKeys(ctx context.Context, limit int) error {
	if !s.ready() {
		return aiUnavailable()
	}
	// lint:cross-org elected maintenance sweep across tenants; each update below
	// is scoped to the row's own organization and workload.
	rows, err := s.w.policies.pool.Query(ctx, `SELECT org_id,workload_id,id,native_key_id FROM ai_workload_static_keys WHERE engine_disabled_at IS NULL AND native_key_id<>'' AND (revoked_at IS NOT NULL OR expires_at<=now()) ORDER BY expires_at,id LIMIT $1`, limit)
	if err != nil {
		return aiUnavailable()
	}
	type ref struct {
		org, workload, id uuid.UUID
		native            string
	}
	refs := []ref{}
	for rows.Next() {
		var v ref
		if rows.Scan(&v.org, &v.workload, &v.id, &v.native) != nil {
			rows.Close()
			return aiUnavailable()
		}
		refs = append(refs, v)
	}
	rows.Close()
	if rows.Err() != nil {
		return aiUnavailable()
	}
	var failed error
	for _, v := range refs {
		if err := s.disableEngineKey(ctx, v.org, v.workload, v.id, v.native); err != nil {
			failed = err
		}
	}
	return failed
}

// SetPublicAllowed flips the organization switch (ai_gateway:manage).
func (s *StaticKeys) SetPublicAllowed(ctx context.Context, org, actor uuid.UUID, allowed bool) (bool, error) {
	if !s.ready() {
		return false, aiUnavailable()
	}
	tx, err := s.w.policies.pool.Begin(ctx)
	if err != nil {
		return false, aiUnavailable()
	}
	defer rollbackAI(tx)
	res, err := tx.Exec(ctx, `INSERT INTO ai_static_key_settings(org_id,public_static_keys_allowed) SELECT o.id,$2 FROM organizations o WHERE o.id=$1 AND o.deleted_at IS NULL ON CONFLICT (org_id) DO UPDATE SET public_static_keys_allowed=EXCLUDED.public_static_keys_allowed`, org, allowed)
	if err != nil {
		return false, aiUnavailable()
	}
	if res.RowsAffected() != 1 {
		return false, policyNotFound()
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_user_id,action,target_type,target_id,metadata) VALUES($1,$2,'ai_gateway.public_static_keys_changed','organization',$3,jsonb_build_object('allowed',$4::boolean))`, org, actor, org.String(), allowed); err != nil || tx.Commit(ctx) != nil {
		return false, aiUnavailable()
	}
	return allowed, nil
}

func (s *StaticKeys) PublicAllowed(ctx context.Context, org uuid.UUID) (bool, error) {
	if !s.ready() {
		return false, aiUnavailable()
	}
	var allowed bool
	err := s.w.policies.pool.QueryRow(ctx, `SELECT COALESCE(s.public_static_keys_allowed,false) FROM organizations o LEFT JOIN ai_static_key_settings s ON s.org_id=o.id WHERE o.id=$1 AND o.deleted_at IS NULL`, org).Scan(&allowed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, policyNotFound()
	}
	if err != nil {
		return false, aiUnavailable()
	}
	return allowed, nil
}

func trimReason(v string) string {
	if len(v) > 64 {
		return v[:64]
	}
	return strings.TrimSpace(v)
}

type bearerAuthorizer interface {
	Authorize(ctx context.Context, raw, model string) (Grant, error)
}

// DefaultAuthorize is the adapter's closure for the public route. A static
// key never has an ingress here: reaching this closure means a path skipped
// the dedicated static key route, so it always fails closed (D6).
func DefaultAuthorize(workloads, credentials bearerAuthorizer) Authorize {
	return func(ctx context.Context, raw, model string) (Grant, error) {
		if LooksLikeStaticKey(raw) {
			return Grant{}, aiUnauthorized()
		}
		if strings.HasPrefix(raw, workloadTokenPrefix) {
			return workloads.Authorize(ctx, raw, model)
		}
		return credentials.Authorize(ctx, raw, model)
	}
}
