// Package fqdnresources owns the S21 storage boundary.  It deliberately does
// not resolve DNS or compile policy: Lane 2 consumes only active immutable
// generations after the organization explicitly enables enforcement.
package fqdnresources

import (
	"context"
	"encoding/json"
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
}
type Input struct {
	Name, FQDN, Protocol string
	PortLow, PortHigh    *int
	Label                *string
	Context              *Context
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
	return out, rows.Err()
}
func (s *Service) Get(ctx context.Context, org, id uuid.UUID) (Resource, error) {
	r, err := scan(s.pool.QueryRow(ctx, resourceQuery+` WHERE r.org_id=$1 AND r.id=$2`, org, id))
	if err == pgx.ErrNoRows {
		return Resource{}, apierr.NotFound("fqdn_resource_not_found", "FQDN resource not found")
	}
	return r, err
}
func (s *Service) Impact(ctx context.Context, org, id uuid.UUID) (Impact, error) {
	var i Impact
	err := s.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM policy_rules p WHERE p.org_id=$1 AND p.dst_kind='fqdn_resource' AND p.dst_fqdn_resource_id=$2), COALESCE((SELECT array_agg(p.id ORDER BY p.id) FROM policy_rules p WHERE p.org_id=$1 AND p.dst_kind='fqdn_resource' AND p.dst_fqdn_resource_id=$2), ARRAY[]::uuid[]), EXISTS(SELECT 1 FROM fqdn_resource_answer_generations WHERE org_id=$1 AND resource_id=$2 AND state='active') FROM fqdn_resources r WHERE r.org_id=$1 AND r.id=$2`, org, id).Scan(&i.ReferencingRuleCount, &i.ReferencingRuleIDs, &i.GenerationWithdrawalRequired)
	if err == pgx.ErrNoRows {
		return i, apierr.NotFound("fqdn_resource_not_found", "FQDN resource not found")
	}
	return i, err
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
func (s *Service) SetSetting(ctx context.Context, org uuid.UUID, enabled bool, actor uuid.UUID, actorSystem, cause string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
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
