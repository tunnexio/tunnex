package aigateway

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// staticKeyRefusal carries the exact reason to the key page and audit log.
// The caller only ever sees the adapter's fixed message for err.
type staticKeyRefusal struct {
	err    error
	reason string
}

func (r *staticKeyRefusal) Error() string { return r.err.Error() }
func (r *staticKeyRefusal) Unwrap() error { return r.err }

func refuse(err error, reason string) error { return &staticKeyRefusal{err: err, reason: reason} }

// auditedRefusals are security signals worth an audit row (at most hourly).
var auditedRefusals = map[string]bool{"wrong_ingress": true, "source_not_allowed": true}

type staticKeyBearer struct {
	key      staticKeyRecord
	workload workloadRecord
}

// authenticate finds the key and runs every check that does not depend on the
// model. It returns the key identity whenever it was found, so refusals can be
// recorded on it.
func (s *StaticKeys) authenticate(ctx context.Context, tx pgx.Tx, raw string, ingress StaticKeyIngress) (staticKeyBearer, *staticKeyRecord, error) {
	if ingress.kind != "public" && ingress.kind != "internal" {
		// A static key that reached a path without an ingress is a bug: fail closed.
		return staticKeyBearer{}, nil, aiUnauthorized()
	}
	if ingress.kind == "internal" && (ingress.org == uuid.Nil || ingress.node == uuid.Nil || ingress.endpoint == uuid.Nil || !ingress.peer.Is4()) {
		return staticKeyBearer{}, nil, aiUnauthorized()
	}
	if !validStaticKeyFormat(raw) {
		return staticKeyBearer{}, nil, aiUnauthorized()
	}
	hash := sha256.Sum256([]byte(raw))
	var org, workload, id uuid.UUID
	// lint:cross-org hashed bearer lookup; every later read is scoped to the
	// stored tenant and workload, never to a caller-provided organization.
	if err := tx.QueryRow(ctx, `SELECT org_id,workload_id,id FROM ai_workload_static_keys WHERE secret_hash=$1`, hash[:]).Scan(&org, &workload, &id); err != nil {
		return staticKeyBearer{}, nil, workloadLookupError(err, aiUnauthorized())
	}
	if ingress.kind == "internal" && org != ingress.org {
		// Another organization's gateway: refuse as unknown, record nothing.
		return staticKeyBearer{}, nil, aiUnauthorized()
	}
	w, err := scanWorkload(tx.QueryRow(ctx, `SELECT `+workloadColumns+` FROM ai_workloads WHERE org_id=$1 AND id=$2 FOR SHARE`, org, workload))
	if err != nil {
		return staticKeyBearer{}, nil, workloadLookupError(err, aiUnauthorized())
	}
	k, err := scanStaticKey(tx.QueryRow(ctx, `SELECT `+staticKeyColumns+` FROM ai_workload_static_keys WHERE org_id=$1 AND workload_id=$2 AND id=$3 FOR SHARE`, org, workload, id))
	if err != nil {
		return staticKeyBearer{}, nil, workloadLookupError(err, aiUnauthorized())
	}
	found := &k
	switch {
	case k.RevokedAt != nil:
		return staticKeyBearer{}, found, refuse(aiUnauthorized(), "revoked")
	case !k.ExpiresAt.After(time.Now()):
		return staticKeyBearer{}, found, refuse(aiUnauthorized(), "expired")
	case !w.Enabled || k.epoch != w.epoch:
		return staticKeyBearer{}, found, refuse(aiUnauthorized(), "workload_disabled")
	case string(k.Scope) != ingress.kind:
		// The same generic 403 as any policy refusal: a leaked key must not
		// learn that it is valid (founder decision 2).
		return staticKeyBearer{}, found, refuse(policyDenied(), "wrong_ingress")
	}
	if ingress.kind == "public" {
		allowed, e := orgAllowsPublicStaticKeys(ctx, tx, org)
		if e != nil {
			return staticKeyBearer{}, found, workloadLookupError(e, aiUnauthorized())
		}
		if !allowed {
			return staticKeyBearer{}, found, refuse(policyDenied(), "public_keys_disabled")
		}
	} else {
		// The route checked the endpoint already; check it again in this
		// transaction so a disabled endpoint refuses at once.
		var cidrs []string
		e := tx.QueryRow(ctx, `SELECT source_cidrs::text[] FROM ai_internal_endpoints WHERE org_id=$1 AND node_id=$2 AND id=$3 AND enabled`, org, ingress.node, ingress.endpoint).Scan(&cidrs)
		if errors.Is(e, pgx.ErrNoRows) {
			return staticKeyBearer{}, found, refuse(policyDenied(), "endpoint_disabled")
		}
		if e != nil {
			return staticKeyBearer{}, found, aiUnavailable()
		}
		if !cidrsContain(cidrs, ingress.peer) {
			return staticKeyBearer{}, found, refuse(policyDenied(), "source_not_allowed")
		}
	}
	if len(k.SourceCidrs) > 0 && !cidrsContain(k.SourceCidrs, ingress.source()) {
		return staticKeyBearer{}, found, refuse(policyDenied(), "source_not_allowed")
	}
	if k.Status != "applied" || k.native == "" {
		return staticKeyBearer{}, found, refuse(aiUnavailable(), "unavailable")
	}
	return staticKeyBearer{key: k, workload: w}, found, nil
}

// Authorize admits one static key request on the ingress its route built.
func (s *StaticKeys) Authorize(ctx context.Context, raw, model string, ingress StaticKeyIngress) (Grant, error) {
	if !s.ready() {
		return Grant{}, aiUnavailable()
	}
	grant, key, err := s.authorize(ctx, raw, model, ingress)
	if key != nil {
		if err != nil {
			var refusal *staticKeyRefusal
			if errors.As(err, &refusal) {
				s.recordRefusal(ctx, *key, refusal.reason, ingress)
			}
		} else {
			s.recordUse(ctx, *key, ingress)
		}
	}
	var refusal *staticKeyRefusal
	if errors.As(err, &refusal) {
		return Grant{}, refusal.err
	}
	return grant, err
}

func (s *StaticKeys) authorize(ctx context.Context, raw, model string, ingress StaticKeyIngress) (Grant, *staticKeyRecord, error) {
	tx, err := s.w.policies.pool.Begin(ctx)
	if err != nil {
		return Grant{}, nil, aiUnavailable()
	}
	defer rollbackAI(tx)
	b, found, err := s.authenticate(ctx, tx, raw, ingress)
	if err != nil {
		return Grant{}, found, err
	}
	g, err := s.resolve(ctx, tx, b, model, true)
	if err != nil {
		return Grant{}, found, err
	}
	if tx.Commit(ctx) != nil {
		return Grant{}, found, aiUnavailable()
	}
	return g, found, nil
}

func (s *StaticKeys) resolve(ctx context.Context, tx pgx.Tx, b staticKeyBearer, model string, admit bool) (Grant, error) {
	w, k := b.workload, b.key
	if w.Status != "applied" || w.AppliedRevision != w.Revision {
		return Grant{}, refuse(policyDenied(), "workload_not_applied")
	}
	var connection uuid.UUID
	var mode ModelMode
	if err := tx.QueryRow(ctx, `SELECT connection_id,mode FROM ai_workload_models WHERE org_id=$1 AND workload_id=$2 AND model=$3`, k.org, w.Id, model).Scan(&connection, &mode); err != nil {
		return Grant{}, refuse(workloadLookupError(err, policyDenied()), "model_not_allowed")
	}
	p, err := scanProvider(tx.QueryRow(ctx, `SELECT `+providerColumns+` FROM ai_provider_connections WHERE org_id=$1 AND id=$2 FOR SHARE`, k.org, connection))
	if err != nil {
		return Grant{}, refuse(workloadLookupError(err, policyDenied()), "model_not_allowed")
	}
	if err = s.w.policies.validateProviderAccess(ctx, tx, k.org, []string{p.KeyID}, []string{model}); err != nil {
		return Grant{}, refuse(err, "model_not_allowed")
	}
	if DefaultModelMode(p.ModelModes[model]) != mode {
		return Grant{}, refuse(policyDenied(), "model_not_allowed")
	}
	// A key reads the live opt-in flag but does not pin the settings revision,
	// so an unrelated settings change does not kill every key (D3).
	if _, err = liveWorkloadOrg(ctx, tx, k.org); err != nil {
		return Grant{}, refuse(err, "ai_gateway_off")
	}
	if admit {
		if k.RateLimitPerMinute != nil {
			if s.limiter == nil {
				return Grant{}, refuse(aiUnavailable(), "unavailable")
			}
			ok, e := s.limiter.Allow(ctx, "ai-static-key:"+k.Id.String(), *k.RateLimitPerMinute, time.Minute)
			if e != nil {
				return Grant{}, refuse(aiUnavailable(), "unavailable")
			}
			if !ok {
				return Grant{}, refuse(ErrRequestLimited, "rate_limited")
			}
		}
		if err = s.w.policies.enforceCostBindings(ctx, tx, k.org, model, mode, k.DailyUsdThreshold, func() ([]string, error) {
			return []string{k.native}, nil
		}); err != nil {
			return Grant{}, refuse(err, costRefusalReason(err))
		}
		if err = s.w.policies.enforceCostBindings(ctx, tx, k.org, model, mode, w.DailyUsdThreshold, func() ([]string, error) {
			return workloadUsageIDsToday(ctx, tx, k.org, w)
		}); err != nil {
			return Grant{}, refuse(err, costRefusalReason(err))
		}
	}
	value, err := openBoundKey(s.w.policies.sealer, staticKeyPurpose, k.org, k.Id, k.native, k.revision, k.sealed)
	if err != nil {
		return Grant{}, aiUnavailable()
	}
	expires := time.Now().Add(30 * time.Second)
	if k.ExpiresAt.Before(expires) {
		expires = k.ExpiresAt
	}
	// The adapter keys concurrency by Tenant/SubjectKind/Agent, so each key
	// gets its own four slots per process (founder decision 10).
	return Grant{Tenant: k.org.String(), Agent: k.Id.String(), SubjectKind: "workload_key", Mode: mode, VirtualKey: value, Expires: expires}, nil
}

// workloadUsageIDsToday is the workload's own engine key plus every static key
// engine key that was active at any time today (UTC). A key revoked today
// still counts today.
func workloadUsageIDsToday(ctx context.Context, tx pgx.Tx, org uuid.UUID, w workloadRecord) ([]string, error) {
	if w.native == "" {
		return nil, aiUnavailable()
	}
	rows, err := tx.Query(ctx, `SELECT native_key_id FROM ai_workload_static_keys WHERE org_id=$1 AND workload_id=$2 AND native_key_id<>'' AND created_at<now() AND coalesce(least(revoked_at,expires_at),expires_at)>date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' ORDER BY native_key_id`, org, w.Id)
	if err != nil {
		return nil, aiUnavailable()
	}
	defer rows.Close()
	ids := []string{w.native}
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			return nil, aiUnavailable()
		}
		ids = append(ids, id)
	}
	if rows.Err() != nil || !validEngineIDs(ids) {
		return nil, aiUnavailable()
	}
	return ids, nil
}

// Models lists the workload's models for GET /v1/models with a static key.
func (s *StaticKeys) Models(ctx context.Context, raw string, ingress StaticKeyIngress) ([]UserModel, error) {
	if !s.ready() {
		return nil, aiUnavailable()
	}
	tx, err := s.w.policies.pool.Begin(ctx)
	if err != nil {
		return nil, aiUnavailable()
	}
	defer rollbackAI(tx)
	b, found, err := s.authenticate(ctx, tx, raw, ingress)
	if err != nil {
		var refusal *staticKeyRefusal
		if found != nil && errors.As(err, &refusal) {
			rollbackAI(tx)
			s.recordRefusal(ctx, *found, refusal.reason, ingress)
		}
		if errors.As(err, &refusal) {
			return nil, refusal.err
		}
		return nil, err
	}
	models, err := loadWorkloadModels(ctx, tx, b.key.org, b.workload.Id)
	if err != nil {
		return nil, err
	}
	out := []UserModel{}
	for _, m := range models {
		g, e := s.resolve(ctx, tx, b, m.Model, false)
		if e != nil {
			var refusal *staticKeyRefusal
			if errors.As(e, &refusal) {
				return nil, refusal.err
			}
			return nil, e
		}
		out = append(out, UserModel{Model: m.Model, Mode: g.Mode})
	}
	return out, nil
}

func ingressSourceText(ingress StaticKeyIngress) *string {
	if a := ingress.source(); a.IsValid() {
		v := a.String()
		return &v
	}
	return nil
}
func ingressNode(ingress StaticKeyIngress) *uuid.UUID {
	if ingress.kind == "internal" {
		return &ingress.node
	}
	return nil
}

// recordUse writes last_used_* at most once a minute. It never changes the
// response.
func (s *StaticKeys) recordUse(ctx context.Context, k staticKeyRecord, ingress StaticKeyIngress) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	_, _ = s.w.policies.pool.Exec(ctx, `UPDATE ai_workload_static_keys SET last_used_at=now(),last_used_ingress=$4,last_used_source=$5::inet,last_used_node_id=$6 WHERE org_id=$1 AND workload_id=$2 AND id=$3 AND (last_used_at IS NULL OR last_used_at<now()-interval '1 minute' OR last_used_ingress IS DISTINCT FROM $4 OR last_used_source IS DISTINCT FROM $5::inet)`,
		k.org, k.WorkloadId, k.Id, ingress.kind, ingressSourceText(ingress), ingressNode(ingress))
}

// recordRefusal writes last_refused_* (at most once a minute per reason) and,
// for security signals, one audit row per key per hour. It runs after the
// admission transaction rolled back and never changes the response.
func (s *StaticKeys) recordRefusal(ctx context.Context, k staticKeyRecord, reason string, ingress StaticKeyIngress) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	reason = trimReason(reason)
	tx, err := s.w.policies.pool.Begin(ctx)
	if err != nil {
		return
	}
	defer rollbackAI(tx)
	var audit bool
	err = tx.QueryRow(ctx, `WITH prior AS (SELECT last_refusal_audit_at FROM ai_workload_static_keys WHERE org_id=$1 AND workload_id=$2 AND id=$3 FOR UPDATE)
 UPDATE ai_workload_static_keys k SET last_refused_at=now(),last_refused_reason=$4,last_refused_ingress=$5,last_refused_source=$6::inet,last_refused_node_id=$7,
 last_refusal_audit_at=CASE WHEN $8 AND (prior.last_refusal_audit_at IS NULL OR prior.last_refusal_audit_at<now()-interval '1 hour') THEN now() ELSE k.last_refusal_audit_at END
 FROM prior WHERE k.org_id=$1 AND k.workload_id=$2 AND k.id=$3
 AND (k.last_refused_at IS NULL OR k.last_refused_at<now()-interval '1 minute' OR k.last_refused_reason IS DISTINCT FROM $4 OR k.last_refused_source IS DISTINCT FROM $6::inet)
 RETURNING $8 AND (prior.last_refusal_audit_at IS NULL OR prior.last_refusal_audit_at<now()-interval '1 hour')`,
		k.org, k.WorkloadId, k.Id, reason, ingress.kind, ingressSourceText(ingress), ingressNode(ingress), auditedRefusals[reason]).Scan(&audit)
	if errors.Is(err, pgx.ErrNoRows) {
		return
	}
	if err != nil {
		return
	}
	if audit {
		if _, err = tx.Exec(ctx, `INSERT INTO audit_logs(org_id,actor_system,action,target_type,target_id,metadata) VALUES($1,'workload-identity','ai_workload.static_key_refused','ai_workload_static_key',$2,jsonb_build_object('reason',$3::text,'ingress',$4::text,'source',$5::text,'node_id',$6::text,'workload_id',$7::text))`,
			k.org, k.Id.String(), reason, ingress.kind, ingressSourceText(ingress), uuidText(ingressNode(ingress)), k.WorkloadId.String()); err != nil {
			return
		}
	}
	_ = tx.Commit(ctx)
}

func costRefusalReason(err error) string {
	var domain *apierr.Error
	if errors.As(err, &domain) {
		switch domain.Code {
		case "ai_daily_threshold_reached":
			return "threshold_reached"
		case "ai_price_unavailable":
			return "price_unavailable"
		}
	}
	return "unavailable"
}

func uuidText(v *uuid.UUID) *string {
	if v == nil {
		return nil
	}
	s := v.String()
	return &s
}
