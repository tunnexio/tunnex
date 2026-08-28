package fqdnresources

import (
	"context"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// ResolverEndpoint is a direct, server-managed DNS transport target. Address
// is deliberately a literal IP: resolving an endpoint hostname would create
// the very host/public-DNS fallback this contract prohibits.
type ResolverEndpoint struct {
	Address   string
	Port      int
	Transport string
}

// ResolverConfig is an immutable revision for one tenant-owned Site/Gateway
// pair. Only the active revision may be sent to the authenticated gateway RPC.
type ResolverConfig struct {
	ID, OrgID, SiteID, GatewayID uuid.UUID
	Version                      int64
	State                        string
	Endpoints                    []ResolverEndpoint
	CreatedAt                    time.Time
}

func validateEndpoints(in []ResolverEndpoint) error {
	if len(in) == 0 || len(in) > 8 {
		return apierr.BadRequest("invalid_resolver_endpoints", "resolver configuration requires 1 to 8 direct endpoints")
	}
	seen := make(map[string]struct{}, len(in))
	for i := range in {
		in[i].Address = strings.TrimSpace(in[i].Address)
		ip, err := netip.ParseAddr(in[i].Address)
		if err != nil || !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return apierr.BadRequest("invalid_resolver_endpoint", "resolver endpoint address must be a direct routable IP address")
		}
		in[i].Address = ip.String()
		if in[i].Port == 0 {
			in[i].Port = 53
		}
		if in[i].Port < 1 || in[i].Port > 65535 || (in[i].Transport != "udp" && in[i].Transport != "tcp") {
			return apierr.BadRequest("invalid_resolver_endpoint", "resolver endpoint requires udp or tcp and a port from 1 to 65535")
		}
		key := in[i].Address + ":" + strconv.Itoa(in[i].Port) + ":" + in[i].Transport
		if _, ok := seen[key]; ok {
			return apierr.BadRequest("invalid_resolver_endpoint", "resolver endpoints must be distinct")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func configEndpoints(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, configID, org uuid.UUID) ([]ResolverEndpoint, error) {
	rows, err := q.Query(ctx, `SELECT host(address)::text, port, transport FROM fqdn_resolver_context_endpoints WHERE config_id=$1 AND org_id=$2 ORDER BY ordinal`, configID, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ResolverEndpoint{}
	for rows.Next() {
		var endpoint ResolverEndpoint
		if err := rows.Scan(&endpoint.Address, &endpoint.Port, &endpoint.Transport); err != nil {
			return nil, err
		}
		out = append(out, endpoint)
	}
	return out, rows.Err()
}

// lockResolverOrg serializes configuration changes with resolver answer
// generation changes and resource confirmation in the owning organization.
func lockResolverOrg(ctx context.Context, tx pgx.Tx, org uuid.UUID) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, org)
	return err
}

func (s *Service) ResolverConfig(ctx context.Context, org, site, gateway uuid.UUID) (ResolverConfig, error) {
	return resolverConfig(ctx, s.pool, org, site, gateway)
}

// resolverConfigQuerier keeps resolver configuration and endpoint reads on a
// caller-owned database snapshot when required by a higher-level read.
type resolverConfigQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func resolverConfig(ctx context.Context, q resolverConfigQuerier, org, site, gateway uuid.UUID) (ResolverConfig, error) {
	var out ResolverConfig
	err := q.QueryRow(ctx, `SELECT id,org_id,site_id,gateway_id,version,state,created_at FROM fqdn_resolver_context_configs WHERE org_id=$1 AND site_id=$2 AND gateway_id=$3 AND state='active'`, org, site, gateway).Scan(&out.ID, &out.OrgID, &out.SiteID, &out.GatewayID, &out.Version, &out.State, &out.CreatedAt)
	if err == pgx.ErrNoRows {
		return out, apierr.NotFound("fqdn_resolver_config_not_found", "no server-managed resolver endpoint configuration exists for this Site/Gateway context")
	}
	if err != nil {
		return out, err
	}
	out.Endpoints, err = configEndpoints(ctx, q, out.ID, org)
	return out, err
}

// SetResolverConfig retires the preceding active revision and creates a new
// immutable active revision in the same transaction/audit boundary.
func (s *Service) SetResolverConfig(ctx context.Context, org, site, gateway, actor uuid.UUID, actorSystem, cause string, endpoints []ResolverEndpoint) (ResolverConfig, error) {
	if err := validateEndpoints(endpoints); err != nil {
		return ResolverConfig{}, err
	}
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Address != endpoints[j].Address {
			return endpoints[i].Address < endpoints[j].Address
		}
		if endpoints[i].Port != endpoints[j].Port {
			return endpoints[i].Port < endpoints[j].Port
		}
		return endpoints[i].Transport < endpoints[j].Transport
	})
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ResolverConfig{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := lockResolverOrg(ctx, tx, org); err != nil {
		return ResolverConfig{}, err
	}
	// Serialize a previously empty context as well as revision replacement.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text || ':' || $2::text || ':' || $3::text, 0))`, org, site, gateway); err != nil {
		return ResolverConfig{}, err
	}
	var next int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version),0)+1 FROM fqdn_resolver_context_configs WHERE org_id=$1 AND site_id=$2 AND gateway_id=$3`, org, site, gateway).Scan(&next); err != nil {
		return ResolverConfig{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE fqdn_resolver_context_configs SET state='retired',retired_at=now() WHERE org_id=$1 AND site_id=$2 AND gateway_id=$3 AND state='active'`, org, site, gateway); err != nil {
		return ResolverConfig{}, err
	}
	var out ResolverConfig
	if err := tx.QueryRow(ctx, `INSERT INTO fqdn_resolver_context_configs (org_id,site_id,gateway_id,version,state,retired_at,created_by) VALUES ($1,$2,$3,$4,'retired',now(),$5) RETURNING id,created_at`, org, site, gateway, next, nullableActor(actor)).Scan(&out.ID, &out.CreatedAt); err != nil {
		return ResolverConfig{}, writeErr(err)
	}
	for ordinal, endpoint := range endpoints {
		if _, err := tx.Exec(ctx, `INSERT INTO fqdn_resolver_context_endpoints (config_id,org_id,ordinal,address,port,transport) VALUES ($1,$2,$3,$4::inet,$5,$6)`, out.ID, org, ordinal, endpoint.Address, endpoint.Port, endpoint.Transport); err != nil {
			return ResolverConfig{}, writeErr(err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE fqdn_resolver_context_configs SET state='active',retired_at=NULL WHERE id=$1 AND org_id=$2`, out.ID, org); err != nil {
		return ResolverConfig{}, writeErr(err)
	}
	if err := writeAudit(ctx, tx, org, actor, actorSystem, cause, "fqdn_resolver_context.configured", out.ID, map[string]any{"intent": "replace_resolver_configuration", "outcome": "succeeded", "site_id": site, "gateway_id": gateway, "version": next, "endpoint_count": len(endpoints)}); err != nil {
		return ResolverConfig{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ResolverConfig{}, err
	}
	out.OrgID, out.SiteID, out.GatewayID, out.Version, out.State, out.Endpoints = org, site, gateway, next, "active", endpoints
	return out, nil
}

func nullableActor(actor uuid.UUID) any {
	if actor == uuid.Nil {
		return nil
	}
	return actor
}

// DeleteResolverConfig retires the active revision rather than erasing its
// provenance. Bound resources therefore have no usable config and must fail
// closed until a new revision is explicitly configured.
func (s *Service) DeleteResolverConfig(ctx context.Context, org, site, gateway, actor uuid.UUID, actorSystem, cause string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := lockResolverOrg(ctx, tx, org); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text || ':' || $2::text || ':' || $3::text, 0))`, org, site, gateway); err != nil {
		return err
	}
	var id uuid.UUID
	err = tx.QueryRow(ctx, `UPDATE fqdn_resolver_context_configs SET state='retired',retired_at=now() WHERE org_id=$1 AND site_id=$2 AND gateway_id=$3 AND state='active' RETURNING id`, org, site, gateway).Scan(&id)
	if err == pgx.ErrNoRows {
		return apierr.NotFound("fqdn_resolver_config_not_found", "no active resolver configuration exists for this Site/Gateway context")
	}
	if err != nil {
		return err
	}
	if err := writeAudit(ctx, tx, org, actor, actorSystem, cause, "fqdn_resolver_context.unconfigured", id, map[string]any{"intent": "remove_resolver_configuration", "outcome": "succeeded", "site_id": site, "gateway_id": gateway}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
