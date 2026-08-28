// Package fqdnresources owns the S21 storage boundary.  It deliberately does
// not resolve DNS or compile policy: Lane 2 consumes only active immutable
// generations after the organization explicitly enables enforcement.
package fqdnresources

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdn"
)

type Context struct {
	SiteID, GatewayID     uuid.UUID
	SiteName, GatewayName string
	Config                *ResolverConfig
}
type Input struct {
	Name, FQDN, Protocol string
	PortLow, PortHigh    *int
	Label                *string
	Context              *Context
	ExpectedImpactToken  *string
}
type Resource struct {
	ID, OrgID               uuid.UUID
	Name, FQDN, Protocol    string
	PortLow, PortHigh       *int
	Label                   *string
	Context                 *Context
	Generation              *int64
	State                   string
	AnswerCount             int
	EffectiveTTLSeconds     *int
	RefreshedAt, LastGoodAt *time.Time
	CreatedAt, UpdatedAt    time.Time
}
type Impact struct {
	ReferencingRuleCount         int
	ReferencingRuleIDs           []uuid.UUID
	GenerationWithdrawalRequired bool
}
type RuleReference struct {
	ID         uuid.UUID
	SourceKind string
	Enabled    bool
}
type AuditProjection struct {
	LatestEventAt *time.Time
}
type Detail struct {
	Resource             Resource
	ActiveAnswers        []string
	StatusSource         string
	ObservedAt           *time.Time
	FreshUntilAt         *time.Time
	ServerReason         *string
	NextAction           string
	ResolverReady        bool
	ReferencingRuleCount int
	ReferencingRules     []RuleReference
	ReferencesTruncated  bool
	Audit                AuditProjection
}
type MutationPreview struct {
	Impact
	EnforcementInputsChanged bool
	MutationAllowed          bool
	RefusalReason            *string
	ExpectedImpactToken      *string
}
type SettingImpact struct {
	Enabled                   bool
	EnforcementReadyRuleCount int
	EnforcementReadyRuleIDs   []uuid.UUID
	RuleIDsTruncated          bool
	ExpectedImpactToken       *string
	fingerprint               string
}

type Service struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

func valid(in *Input) error {
	n, err := fqdn.Normalize(in.FQDN)
	if err != nil {
		return apierr.BadRequest("invalid_fqdn", "fqdn must be an exact normalized hostname")
	}
	in.FQDN = n
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 128 {
		return apierr.BadRequest("invalid_request", "name must be 1 to 128 characters")
	}
	if in.Label != nil && len(*in.Label) > 60 {
		return apierr.BadRequest("invalid_request", "label must be at most 60 characters")
	}
	if in.Protocol != "any" && in.Protocol != "tcp" && in.Protocol != "udp" {
		return apierr.BadRequest("invalid_request", "protocol must be any, tcp, or udp")
	}
	if in.Protocol == "any" && (in.PortLow != nil || in.PortHigh != nil) {
		return apierr.BadRequest("invalid_request", "ports require tcp or udp")
	}
	if (in.PortLow == nil) != (in.PortHigh == nil) {
		return apierr.BadRequest("invalid_request", "port_low and port_high must be set together (both or neither)")
	}
	if in.PortLow != nil && (*in.PortLow < 1 || *in.PortLow > 65535) || in.PortHigh != nil && (*in.PortHigh < 1 || *in.PortHigh > 65535) || in.PortLow != nil && in.PortHigh != nil && *in.PortLow > *in.PortHigh {
		return apierr.BadRequest("invalid_request", "invalid port range")
	}
	return nil
}

func (s *Service) Create(ctx context.Context, org uuid.UUID, in Input, actor uuid.UUID, actorSystem, cause string) (Resource, error) {
	if err := valid(&in); err != nil {
		return Resource{}, err
	}
	var id uuid.UUID
	var site, gateway *uuid.UUID
	if in.Context != nil {
		site, gateway = &in.Context.SiteID, &in.Context.GatewayID
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Resource{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := lockOrg(ctx, tx, org); err != nil {
		return Resource{}, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO fqdn_resources (org_id,name,fqdn,protocol,port_low,port_high,label,resolver_site_id,resolver_node_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`, org, in.Name, in.FQDN, in.Protocol, in.PortLow, in.PortHigh, in.Label, site, gateway).Scan(&id)
	if err != nil {
		return Resource{}, writeErr(err)
	}
	if err := writeAudit(ctx, tx, org, actor, actorSystem, cause, "fqdn_resource.created", id, map[string]any{"intent": "create", "outcome": "succeeded", "fqdn": in.FQDN}); err != nil {
		return Resource{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Resource{}, err
	}
	return s.Get(ctx, org, id)
}
func (s *Service) Update(ctx context.Context, org, id uuid.UUID, in Input, actor uuid.UUID, actorSystem, cause string) (Resource, error) {
	if err := valid(&in); err != nil {
		return Resource{}, err
	}
	var site, gateway *uuid.UUID
	if in.Context != nil {
		site, gateway = &in.Context.SiteID, &in.Context.GatewayID
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Resource{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := lockOrg(ctx, tx, org); err != nil {
		return Resource{}, err
	}
	var current Resource
	if current, err = scan(tx.QueryRow(ctx, resourceQuery+` WHERE r.org_id=$1 AND r.id=$2 FOR UPDATE`, org, id)); err != nil {
		if err == pgx.ErrNoRows {
			return Resource{}, apierr.NotFound("fqdn_resource_not_found", "FQDN resource not found")
		}
		return Resource{}, err
	}
	changed := current.FQDN != in.FQDN || current.Protocol != in.Protocol || !samePorts(current.PortLow, in.PortLow) || !samePorts(current.PortHigh, in.PortHigh) || !sameContext(current.Context, in.Context)
	if changed {
		impact, e := impactFor(ctx, tx, org, id)
		if e != nil {
			return Resource{}, e
		}
		token := mutationToken(current, in, impact)
		if in.ExpectedImpactToken == nil || *in.ExpectedImpactToken != token {
			return Resource{}, apierr.Conflict("fqdn_resource_stale_preview", "the impact preview is missing or stale; read a new preview and confirm it")
		}
		if impact.ReferencingRuleCount > 0 || impact.GenerationWithdrawalRequired {
			return Resource{}, apierr.Conflict("fqdn_resource_mutation_refused", "referenced resource enforcement inputs cannot be changed while rules or an eligible active generation exist")
		}
	}
	ct, err := tx.Exec(ctx, `UPDATE fqdn_resources SET name=$3,fqdn=$4,protocol=$5,port_low=$6,port_high=$7,label=$8,resolver_site_id=$9,resolver_node_id=$10 WHERE id=$1 AND org_id=$2`, id, org, in.Name, in.FQDN, in.Protocol, in.PortLow, in.PortHigh, in.Label, site, gateway)
	if err != nil {
		return Resource{}, writeErr(err)
	}
	if ct.RowsAffected() == 0 {
		return Resource{}, apierr.NotFound("fqdn_resource_not_found", "FQDN resource not found")
	}
	if err := writeAudit(ctx, tx, org, actor, actorSystem, cause, "fqdn_resource.updated", id, map[string]any{"intent": "update", "outcome": "succeeded", "fqdn": in.FQDN}); err != nil {
		return Resource{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Resource{}, err
	}
	return s.Get(ctx, org, id)
}
func (s *Service) List(ctx context.Context, org uuid.UUID) ([]Resource, error) {
	rows, err := s.pool.Query(ctx, resourceQuery+` WHERE r.org_id=$1 ORDER BY r.created_at`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Resource{}
	for rows.Next() {
		r, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Context == nil {
			continue
		}
		config, err := s.ResolverConfig(ctx, org, out[i].Context.SiteID, out[i].Context.GatewayID)
		if err != nil {
			if isResolverConfigNotFound(err) {
				markUnconfigured(&out[i])
				continue // Bound-but-unconfigured is intentionally visible and fail-closed.
			}
			return nil, err
		}
		out[i].Context.Config = &config
	}
	return out, nil
}
func (s *Service) Get(ctx context.Context, org, id uuid.UUID) (Resource, error) {
	r, err := scan(s.pool.QueryRow(ctx, resourceQuery+` WHERE r.org_id=$1 AND r.id=$2`, org, id))
	if err == pgx.ErrNoRows {
		return Resource{}, apierr.NotFound("fqdn_resource_not_found", "FQDN resource not found")
	}
	if err != nil || r.Context == nil {
		return r, err
	}
	config, configErr := s.ResolverConfig(ctx, org, r.Context.SiteID, r.Context.GatewayID)
	if configErr != nil && !isResolverConfigNotFound(configErr) {
		return r, configErr
	}
	if configErr == nil {
		r.Context.Config = &config
	} else {
		markUnconfigured(&r)
	}
	return r, nil
}

func markUnconfigured(r *Resource) {
	r.State = "unconfigured"
	r.Generation = nil
	r.AnswerCount = 0
	r.EffectiveTTLSeconds = nil
	r.RefreshedAt = nil
}

func isResolverConfigNotFound(err error) bool {
	var e *apierr.Error
	return errors.As(err, &e) && e.Code == "fqdn_resolver_config_not_found"
}
func (s *Service) Impact(ctx context.Context, org, id uuid.UUID) (Impact, error) {
	return impactFor(ctx, s.pool, org, id)
}

type queryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func impactFor(ctx context.Context, q queryRower, org, id uuid.UUID) (i Impact, err error) {
	err = q.QueryRow(ctx, `SELECT (SELECT count(*) FROM policy_rules p WHERE p.org_id=$1 AND p.dst_kind='fqdn_resource' AND p.dst_fqdn_resource_id=$2), COALESCE((SELECT array_agg(p.id ORDER BY p.id) FROM policy_rules p WHERE p.org_id=$1 AND p.dst_kind='fqdn_resource' AND p.dst_fqdn_resource_id=$2), ARRAY[]::uuid[]), EXISTS(SELECT 1 FROM fqdn_resource_answer_generations g JOIN fqdn_resources r ON r.id=g.resource_id AND r.org_id=g.org_id AND r.resolver_site_id=g.resolver_site_id AND r.resolver_node_id=g.resolver_node_id JOIN fqdn_resolver_context_configs c ON c.id=g.resolver_config_id AND c.org_id=g.org_id AND c.site_id=g.resolver_site_id AND c.gateway_id=g.resolver_node_id AND c.state='active' WHERE g.org_id=$1 AND g.resource_id=$2 AND g.state='active') FROM fqdn_resources r WHERE r.org_id=$1 AND r.id=$2`, org, id).Scan(&i.ReferencingRuleCount, &i.ReferencingRuleIDs, &i.GenerationWithdrawalRequired)
	if err == pgx.ErrNoRows {
		return i, apierr.NotFound("fqdn_resource_not_found", "FQDN resource not found")
	}
	return i, err
}

// Detail projects only stored, bounded facts. It never resolves DNS or turns a
// missing projection into an empty/healthy claim.
func (s *Service) Detail(ctx context.Context, org, id uuid.UUID) (Detail, error) {
	r, err := s.Get(ctx, org, id)
	if err != nil {
		return Detail{}, err
	}
	d := Detail{Resource: r, StatusSource: "resource_configuration", NextAction: "edit_resource", ActiveAnswers: []string{}, ReferencingRules: []RuleReference{}}
	if r.Context != nil {
		d.StatusSource, d.NextAction = "resolver_configuration", "configure_resolver"
		d.ResolverReady = r.Context.Config != nil
		if d.ResolverReady {
			d.NextAction = "wait_for_resolution"
		}
	}
	var generationID *uuid.UUID
	var state string
	var resolved *time.Time
	var ttl *time.Duration
	var failure *string
	err = s.pool.QueryRow(ctx, `SELECT g.id,g.state,g.resolved_at,g.effective_ttl,g.failure_code FROM fqdn_resource_answer_generations g JOIN fqdn_resources r ON r.id=g.resource_id AND r.org_id=g.org_id AND r.resolver_site_id=g.resolver_site_id AND r.resolver_node_id=g.resolver_node_id JOIN fqdn_resolver_context_configs c ON c.id=g.resolver_config_id AND c.org_id=g.org_id AND c.site_id=g.resolver_site_id AND c.gateway_id=g.resolver_node_id AND c.state='active' WHERE g.org_id=$1 AND g.resource_id=$2 ORDER BY g.generation DESC LIMIT 1`, org, id).Scan(&generationID, &state, &resolved, &ttl, &failure)
	if err != nil && err != pgx.ErrNoRows {
		return Detail{}, err
	}
	if err == nil {
		d.StatusSource, d.ObservedAt, d.ServerReason = "latest_generation", resolved, failure
		switch state {
		case "active":
			d.StatusSource, d.NextAction = "active_generation", "refresh"
		case "pending":
			d.NextAction = "wait_for_resolution"
		case "withdrawn":
			d.NextAction = "review_resolver"
		default:
			d.NextAction = "refresh"
		}
		if state == "active" && generationID != nil {
			if ttl != nil && resolved != nil {
				fresh := resolved.Add(*ttl)
				d.FreshUntilAt = &fresh
				if time.Now().Before(fresh) {
					d.NextAction = "none"
				}
			}
			rows, e := s.pool.Query(ctx, `SELECT host(address)::text FROM fqdn_resource_generation_answers WHERE org_id=$1 AND generation_id=$2 ORDER BY family(address), host(address) LIMIT 32`, org, *generationID)
			if e != nil {
				return Detail{}, e
			}
			for rows.Next() {
				var address string
				if e = rows.Scan(&address); e != nil {
					rows.Close()
					return Detail{}, e
				}
				d.ActiveAnswers = append(d.ActiveAnswers, address)
			}
			if e = rows.Err(); e != nil {
				rows.Close()
				return Detail{}, e
			}
			rows.Close()
		}
	}
	if err = s.pool.QueryRow(ctx, `SELECT count(*) FROM policy_rules WHERE org_id=$1 AND dst_kind='fqdn_resource' AND dst_fqdn_resource_id=$2`, org, id).Scan(&d.ReferencingRuleCount); err != nil {
		return Detail{}, err
	}
	rows, err := s.pool.Query(ctx, `SELECT id,src_kind,NOT disabled FROM policy_rules WHERE org_id=$1 AND dst_kind='fqdn_resource' AND dst_fqdn_resource_id=$2 ORDER BY id LIMIT 32`, org, id)
	if err != nil {
		return Detail{}, err
	}
	for rows.Next() {
		var ref RuleReference
		if err = rows.Scan(&ref.ID, &ref.SourceKind, &ref.Enabled); err != nil {
			rows.Close()
			return Detail{}, err
		}
		d.ReferencingRules = append(d.ReferencingRules, ref)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return Detail{}, err
	}
	rows.Close()
	d.ReferencesTruncated = d.ReferencingRuleCount > len(d.ReferencingRules)
	if err = s.pool.QueryRow(ctx, `SELECT max(created_at) FROM audit_logs WHERE org_id=$1 AND target_type='fqdn_resource' AND target_id=$2`, org, id.String()).Scan(&d.Audit.LatestEventAt); err != nil {
		return Detail{}, err
	}
	return d, nil
}

func (s *Service) Preview(ctx context.Context, org, id uuid.UUID, in Input) (MutationPreview, error) {
	if err := valid(&in); err != nil {
		return MutationPreview{}, err
	}
	current, err := s.Get(ctx, org, id)
	if err != nil {
		return MutationPreview{}, err
	}
	impact, err := s.Impact(ctx, org, id)
	if err != nil {
		return MutationPreview{}, err
	}
	changed := current.FQDN != in.FQDN || current.Protocol != in.Protocol || !samePorts(current.PortLow, in.PortLow) || !samePorts(current.PortHigh, in.PortHigh) || !sameContext(current.Context, in.Context)
	p := MutationPreview{Impact: impact, EnforcementInputsChanged: changed, MutationAllowed: true}
	if changed {
		token := mutationToken(current, in, impact)
		p.ExpectedImpactToken = &token
	}
	if changed && (impact.ReferencingRuleCount > 0 || impact.GenerationWithdrawalRequired) {
		p.MutationAllowed = false
		reason := "referenced resource enforcement inputs cannot be predicted safely; remove rule references and withdraw the active generation first"
		p.RefusalReason = &reason
	}
	return p, nil
}

func samePorts(a, b *int) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }
func sameContext(a, b *Context) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && a.SiteID == b.SiteID && a.GatewayID == b.GatewayID)
}

func (s *Service) SettingImpact(ctx context.Context, org uuid.UUID) (SettingImpact, error) {
	enabled, err := s.Setting(ctx, org)
	if err != nil {
		return SettingImpact{}, err
	}
	return settingImpactFor(ctx, s.pool, org, enabled)
}
func settingImpactFor(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, org uuid.UUID, enabled bool) (SettingImpact, error) {
	out := SettingImpact{Enabled: enabled, EnforcementReadyRuleIDs: []uuid.UUID{}}
	if err := q.QueryRow(ctx, `SELECT count(*) FROM (`+eligibleRuleIDsSQL()+`) eligible`, org).Scan(&out.EnforcementReadyRuleCount); err != nil {
		return out, err
	}
	rows, err := q.Query(ctx, eligibleRuleIDsSQL()+` ORDER BY id LIMIT 32`, org)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			return out, err
		}
		out.EnforcementReadyRuleIDs = append(out.EnforcementReadyRuleIDs, id)
	}
	if err = rows.Err(); err != nil {
		return out, err
	}
	out.RuleIDsTruncated = out.EnforcementReadyRuleCount > len(out.EnforcementReadyRuleIDs)
	if err = q.QueryRow(ctx, `SELECT COALESCE(array_agg(DISTINCT p.id::text || ':' || g.id::text || ':' || g.resolver_config_id::text ORDER BY p.id::text || ':' || g.id::text || ':' || g.resolver_config_id::text)::text, '') FROM policy_rules p JOIN fqdn_resources r ON r.id=p.dst_fqdn_resource_id AND r.org_id=p.org_id JOIN fqdn_resource_answer_generations g ON g.org_id=p.org_id AND g.resource_id=p.dst_fqdn_resource_id AND g.state='active' AND g.resolver_site_id=r.resolver_site_id AND g.resolver_node_id=r.resolver_node_id JOIN fqdn_resolver_context_configs c ON c.id=g.resolver_config_id AND c.org_id=g.org_id AND c.site_id=g.resolver_site_id AND c.gateway_id=g.resolver_node_id AND c.state='active' JOIN fqdn_resolver_context_endpoints e ON e.config_id=c.id AND e.org_id=c.org_id JOIN fqdn_resource_generation_answers a ON a.generation_id=g.id AND a.org_id=g.org_id WHERE p.org_id=$1 AND p.dst_kind='fqdn_resource' AND NOT p.disabled`, org).Scan(&out.fingerprint); err != nil {
		return out, err
	}
	token := settingToken(out)
	out.ExpectedImpactToken = &token
	return out, nil
}
func eligibleRuleIDsSQL() string {
	return `SELECT DISTINCT p.id FROM policy_rules p JOIN fqdn_resources r ON r.id=p.dst_fqdn_resource_id AND r.org_id=p.org_id JOIN fqdn_resource_answer_generations g ON g.org_id=p.org_id AND g.resource_id=p.dst_fqdn_resource_id AND g.state='active' AND g.resolver_site_id=r.resolver_site_id AND g.resolver_node_id=r.resolver_node_id JOIN fqdn_resolver_context_configs c ON c.id=g.resolver_config_id AND c.org_id=g.org_id AND c.site_id=g.resolver_site_id AND c.gateway_id=g.resolver_node_id AND c.state='active' JOIN fqdn_resolver_context_endpoints e ON e.config_id=c.id AND e.org_id=c.org_id JOIN fqdn_resource_generation_answers a ON a.generation_id=g.id AND a.org_id=g.org_id WHERE p.org_id=$1 AND p.dst_kind='fqdn_resource' AND NOT p.disabled`
}

func mutationToken(current Resource, in Input, impact Impact) string {
	return token("resource", current.ID, current.UpdatedAt.UTC().Format(time.RFC3339Nano), in.FQDN, in.Protocol, in.PortLow, in.PortHigh, contextToken(in.Context), impact.ReferencingRuleCount, impact.ReferencingRuleIDs, impact.GenerationWithdrawalRequired)
}
func settingToken(i SettingImpact) string {
	return token("setting", i.Enabled, i.EnforcementReadyRuleCount, i.EnforcementReadyRuleIDs, i.fingerprint)
}
func contextToken(c *Context) string {
	if c == nil {
		return ""
	}
	return c.SiteID.String() + ":" + c.GatewayID.String()
}
func token(parts ...any) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%#v", parts)))
	return fmt.Sprintf("%x", sum[:])
}
func lockOrg(ctx context.Context, tx pgx.Tx, org uuid.UUID) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, org)
	return err
}
func (s *Service) Delete(ctx context.Context, org, id, actor uuid.UUID, actorSystem, cause string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var count int
	var active bool
	if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM policy_rules WHERE org_id=$1 AND dst_kind='fqdn_resource' AND dst_fqdn_resource_id=$2), EXISTS(SELECT 1 FROM fqdn_resource_answer_generations WHERE org_id=$1 AND resource_id=$2 AND state='active') FROM fqdn_resources WHERE org_id=$1 AND id=$2 FOR UPDATE`, org, id).Scan(&count, &active); err != nil {
		if err == pgx.ErrNoRows {
			return apierr.NotFound("fqdn_resource_not_found", "FQDN resource not found")
		}
		return err
	}
	if count > 0 || active {
		return apierr.Conflict("fqdn_resource_in_use", "FQDN resource has rule or live-generation impact; inspect impact before recovery")
	}
	var historical bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM fqdn_resource_answer_generations WHERE org_id=$1 AND resource_id=$2)`, org, id).Scan(&historical); err != nil {
		return err
	}
	if historical {
		return apierr.Conflict("fqdn_resource_generation_history", "FQDN resource has immutable generation history and cannot be deleted")
	}
	ct, err := tx.Exec(ctx, `DELETE FROM fqdn_resources WHERE org_id=$1 AND id=$2`, org, id)
	if err != nil {
		return writeErr(err)
	}
	if ct.RowsAffected() == 0 {
		return apierr.NotFound("fqdn_resource_not_found", "FQDN resource not found")
	}
	if err := writeAudit(ctx, tx, org, actor, actorSystem, cause, "fqdn_resource.deleted", id, map[string]any{"intent": "delete", "outcome": "succeeded"}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Service) Setting(ctx context.Context, org uuid.UUID) (bool, error) {
	var enabled bool
	err := s.pool.QueryRow(ctx, `SELECT fqdn_resources_enabled FROM organizations WHERE id=$1 AND deleted_at IS NULL`, org).Scan(&enabled)
	if err == pgx.ErrNoRows {
		return false, apierr.NotFound("organization_not_found", "organization not found")
	}
	return enabled, err
}
func (s *Service) SetSetting(ctx context.Context, org uuid.UUID, enabled bool, expectedImpactToken *string, actor uuid.UUID, actorSystem, cause string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := lockOrg(ctx, tx, org); err != nil {
		return err
	}
	if enabled {
		var current bool
		if err := tx.QueryRow(ctx, `SELECT fqdn_resources_enabled FROM organizations WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, org).Scan(&current); err == pgx.ErrNoRows {
			return apierr.NotFound("organization_not_found", "organization not found")
		} else if err != nil {
			return err
		}
		impact, err := settingImpactFor(ctx, tx, org, current)
		if err != nil {
			return err
		}
		if expectedImpactToken == nil || *expectedImpactToken != settingToken(impact) {
			return apierr.Conflict("fqdn_resource_stale_preview", "the setting impact preview is missing or stale; read a new preview and confirm it")
		}
	}
	ct, err := tx.Exec(ctx, `UPDATE organizations SET fqdn_resources_enabled=$2,updated_at=now() WHERE id=$1 AND deleted_at IS NULL`, org, enabled)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return apierr.NotFound("organization_not_found", "organization not found")
	}
	if err := writeAudit(ctx, tx, org, actor, actorSystem, cause, "org.fqdn_resources_enabled", org, map[string]any{"intent": "set_enforcement_opt_in", "outcome": "succeeded", "enabled": enabled}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func writeAudit(ctx context.Context, tx pgx.Tx, org, actor uuid.UUID, actorSystem, cause, action string, target uuid.UUID, meta map[string]any) error {
	if meta == nil {
		meta = map[string]any{}
	}
	if cause != "" {
		meta["cause"] = cause
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	q := sqlc.New(tx)
	targetType := "fqdn_resource"
	if strings.HasPrefix(action, "org.") {
		targetType = "organization"
	}
	if actorSystem != "" {
		as, tt, tid := actorSystem, targetType, target.String()
		_, err = q.InsertSystemAuditLog(ctx, sqlc.InsertSystemAuditLogParams{OrgID: pgtype.UUID{Bytes: org, Valid: true}, ActorSystem: &as, Action: action, TargetType: &tt, TargetID: &tid, Metadata: b})
		return err
	}
	tt, tid := targetType, target.String()
	_, err = q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{OrgID: pgtype.UUID{Bytes: org, Valid: true}, ActorUserID: pgtype.UUID{Bytes: actor, Valid: actor != uuid.Nil}, Action: action, TargetType: &tt, TargetID: &tid, Metadata: b})
	return err
}

const resourceQuery = `SELECT r.id,r.org_id,r.name,r.fqdn,r.protocol,r.port_low,r.port_high,r.label,r.created_at,r.updated_at,s.id,s.name,n.id,n.name,g.generation,g.state,g.failure_code,g.effective_ttl,g.resolved_at,g.last_good_at,COALESCE((SELECT count(*) FROM fqdn_resource_generation_answers a WHERE a.generation_id=g.id),0) FROM fqdn_resources r LEFT JOIN sites s ON s.id=r.resolver_site_id LEFT JOIN nodes n ON n.id=r.resolver_node_id LEFT JOIN LATERAL (SELECT * FROM fqdn_resource_answer_generations x WHERE x.resource_id=r.id ORDER BY x.generation DESC LIMIT 1) g ON true`

type scanner interface{ Scan(...any) error }

func scan(row scanner) (Resource, error) {
	var r Resource
	var siteID, gatewayID *uuid.UUID
	var siteName, gatewayName *string
	var state, failure *string
	var ttl *time.Duration
	var refreshed *time.Time
	err := row.Scan(&r.ID, &r.OrgID, &r.Name, &r.FQDN, &r.Protocol, &r.PortLow, &r.PortHigh, &r.Label, &r.CreatedAt, &r.UpdatedAt, &siteID, &siteName, &gatewayID, &gatewayName, &r.Generation, &state, &failure, &ttl, &refreshed, &r.LastGoodAt, &r.AnswerCount)
	if err != nil {
		return r, err
	}
	if siteID != nil && gatewayID != nil {
		r.Context = &Context{SiteID: *siteID, GatewayID: *gatewayID, SiteName: *siteName, GatewayName: *gatewayName}
	}
	r.State = "draft"
	if r.Context != nil {
		r.State = "resolving"
	}
	if state != nil {
		switch *state {
		case "active":
			r.State = "healthy"
		case "pending":
			r.State = "resolving"
		case "retired":
			r.State = "stale"
		case "withdrawn":
			if failure != nil && strings.EqualFold(*failure, "NXDOMAIN") {
				r.State = "nxdomain"
			} else {
				r.State = "failed"
			}
		}
	}
	if r.State != "healthy" {
		r.Generation = nil
		r.AnswerCount = 0
	} else if ttl != nil {
		seconds := int(ttl.Seconds())
		r.EffectiveTTLSeconds = &seconds
		r.RefreshedAt = refreshed
	}
	return r, nil
}
func writeErr(err error) error {
	if err == nil {
		return nil
	}
	return apierr.Conflict("fqdn_resource_conflict", err.Error())
}
