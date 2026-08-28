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
	"github.com/tunnexio/tunnex/apps/api/internal/fqdn"
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
	ProviderHint                 *string
	Endpoints                    []ResolverEndpoint
	Profiles                     []ResolverProfile
	CreatedAt                    time.Time
}

// ResolverProfile is one DNS authority inside an immutable resolver-context
// revision. LegacyDefault exists only for migrated/legacy flat clients; new
// profile-native writes require explicit zone suffixes and fail closed when no
// suffix matches.
type ResolverProfile struct {
	ID            uuid.UUID
	Name          string
	ProviderHint  string
	ZoneSuffixes  []string
	Endpoints     []ResolverEndpoint
	LegacyDefault bool
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

func validateProviderHint(provider *string) error {
	if provider == nil {
		return nil
	}
	switch *provider {
	case "aws", "azure", "google_cloud", "on_premises":
		return nil
	default:
		return apierr.BadRequest("invalid_resolver_provider", "resolver provider must be aws, azure, google_cloud, or on_premises")
	}
}

func validateProfiles(in []ResolverProfile) error {
	if len(in) == 0 || len(in) > 16 {
		return apierr.BadRequest("invalid_resolver_profiles", "resolver configuration requires 1 to 16 named profiles")
	}
	seenSuffix := map[string]string{}
	for i := range in {
		in[i].Name = strings.TrimSpace(in[i].Name)
		if in[i].Name == "" || len(in[i].Name) > 80 {
			return apierr.BadRequest("invalid_resolver_profile", "resolver profile name must be 1 to 80 characters")
		}
		provider := in[i].ProviderHint
		if err := validateProviderHint(&provider); err != nil {
			return err
		}
		if !in[i].LegacyDefault && (len(in[i].ZoneSuffixes) == 0 || len(in[i].ZoneSuffixes) > 16) {
			return apierr.BadRequest("invalid_resolver_suffixes", "each resolver profile requires 1 to 16 DNS zone suffixes")
		}
		if in[i].LegacyDefault && len(in[i].ZoneSuffixes) != 0 {
			return apierr.BadRequest("invalid_resolver_suffixes", "a legacy default profile cannot also declare DNS suffixes")
		}
		if err := validateEndpoints(in[i].Endpoints); err != nil {
			return err
		}
		profileSeen := map[string]struct{}{}
		for suffixIndex, raw := range in[i].ZoneSuffixes {
			normalized, err := fqdn.Normalize(raw)
			if err != nil {
				return apierr.BadRequest("invalid_resolver_suffix", "DNS zone suffix must be an exact normalized hostname without a wildcard")
			}
			if owner, exists := seenSuffix[normalized]; exists {
				return apierr.BadRequest("duplicate_resolver_suffix", "DNS zone suffix "+normalized+" is already assigned to profile "+owner)
			}
			if _, exists := profileSeen[normalized]; exists {
				return apierr.BadRequest("duplicate_resolver_suffix", "DNS zone suffixes must be distinct")
			}
			in[i].ZoneSuffixes[suffixIndex] = normalized
			profileSeen[normalized] = struct{}{}
			seenSuffix[normalized] = in[i].Name
		}
		sort.Strings(in[i].ZoneSuffixes)
		sort.Slice(in[i].Endpoints, func(a, b int) bool {
			left, right := in[i].Endpoints[a], in[i].Endpoints[b]
			if left.Address != right.Address {
				return left.Address < right.Address
			}
			if left.Port != right.Port {
				return left.Port < right.Port
			}
			return left.Transport < right.Transport
		})
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
	err := q.QueryRow(ctx, `SELECT id,org_id,site_id,gateway_id,version,state,provider_hint,created_at FROM fqdn_resolver_context_configs WHERE org_id=$1 AND site_id=$2 AND gateway_id=$3 AND state='active'`, org, site, gateway).Scan(&out.ID, &out.OrgID, &out.SiteID, &out.GatewayID, &out.Version, &out.State, &out.ProviderHint, &out.CreatedAt)
	if err == pgx.ErrNoRows {
		return out, apierr.NotFound("fqdn_resolver_config_not_found", "no server-managed resolver endpoint configuration exists for this Site/Gateway context")
	}
	if err != nil {
		return out, err
	}
	out.Profiles, err = configProfiles(ctx, q, out.ID, org)
	if err != nil {
		return out, err
	}
	if len(out.Profiles) == 0 {
		// Compatibility for historical fixtures and a schema-0117 writer. The
		// migration creates this row in production; this fallback is read-only.
		out.Endpoints, err = configEndpoints(ctx, q, out.ID, org)
		if err != nil {
			return out, err
		}
		provider := "on_premises"
		if out.ProviderHint != nil {
			provider = *out.ProviderHint
		}
		out.Profiles = []ResolverProfile{{ID: out.ID, Name: "Legacy resolver", ProviderHint: provider, Endpoints: append([]ResolverEndpoint(nil), out.Endpoints...), LegacyDefault: true}}
	} else {
		out.Endpoints = append([]ResolverEndpoint(nil), out.Profiles[0].Endpoints...)
		provider := out.Profiles[0].ProviderHint
		out.ProviderHint = &provider
	}
	return out, err
}

func configProfiles(ctx context.Context, q resolverConfigQuerier, configID, org uuid.UUID) ([]ResolverProfile, error) {
	rows, err := q.Query(ctx, `SELECT id,name,provider_hint,legacy_default FROM fqdn_resolver_context_profiles WHERE config_id=$1 AND org_id=$2 ORDER BY ordinal`, configID, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ResolverProfile
	for rows.Next() {
		var profile ResolverProfile
		if err := rows.Scan(&profile.ID, &profile.Name, &profile.ProviderHint, &profile.LegacyDefault); err != nil {
			return nil, err
		}
		out = append(out, profile)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		suffixRows, err := q.Query(ctx, `SELECT suffix FROM fqdn_resolver_context_profile_suffixes WHERE profile_id=$1 AND org_id=$2 ORDER BY suffix`, out[i].ID, org)
		if err != nil {
			return nil, err
		}
		for suffixRows.Next() {
			var suffix string
			if err := suffixRows.Scan(&suffix); err != nil {
				suffixRows.Close()
				return nil, err
			}
			out[i].ZoneSuffixes = append(out[i].ZoneSuffixes, suffix)
		}
		if err := suffixRows.Err(); err != nil {
			suffixRows.Close()
			return nil, err
		}
		suffixRows.Close()
		endpointRows, err := q.Query(ctx, `SELECT host(address)::text,port,transport FROM fqdn_resolver_context_profile_endpoints WHERE profile_id=$1 AND org_id=$2 ORDER BY ordinal`, out[i].ID, org)
		if err != nil {
			return nil, err
		}
		for endpointRows.Next() {
			var endpoint ResolverEndpoint
			if err := endpointRows.Scan(&endpoint.Address, &endpoint.Port, &endpoint.Transport); err != nil {
				endpointRows.Close()
				return nil, err
			}
			out[i].Endpoints = append(out[i].Endpoints, endpoint)
		}
		if err := endpointRows.Err(); err != nil {
			endpointRows.Close()
			return nil, err
		}
		endpointRows.Close()
	}
	return out, nil
}

// SetResolverConfig retires the preceding active revision and creates a new
// immutable active revision in the same transaction/audit boundary.
func (s *Service) SetResolverConfig(ctx context.Context, org, site, gateway, actor uuid.UUID, actorSystem, cause string, providerHint *string, endpoints []ResolverEndpoint) (ResolverConfig, error) {
	var profileNative bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM fqdn_resolver_context_configs c JOIN fqdn_resolver_context_profiles p ON p.config_id=c.id AND p.org_id=c.org_id WHERE c.org_id=$1 AND c.site_id=$2 AND c.gateway_id=$3 AND c.state='active' AND NOT p.legacy_default)`, org, site, gateway).Scan(&profileNative); err != nil {
		return ResolverConfig{}, err
	}
	if profileNative {
		return ResolverConfig{}, apierr.Conflict("resolver_profiles_required", "this resolver uses named profiles; update it with the profiles contract to avoid losing DNS authority routing")
	}
	provider := "on_premises"
	if providerHint != nil {
		provider = *providerHint
	}
	return s.SetResolverProfiles(ctx, org, site, gateway, actor, actorSystem, cause, []ResolverProfile{{Name: "Legacy resolver", ProviderHint: provider, Endpoints: endpoints, LegacyDefault: true}})
}

// SetResolverProfiles retires the previous revision and activates one complete,
// immutable profile set. A profile-native revision has no cross-profile or
// catch-all fallback; legacy flat clients retain one explicit legacy default.
func (s *Service) SetResolverProfiles(ctx context.Context, org, site, gateway, actor uuid.UUID, actorSystem, cause string, profiles []ResolverProfile) (ResolverConfig, error) {
	if err := validateProfiles(profiles); err != nil {
		return ResolverConfig{}, err
	}
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
	rootProvider := profiles[0].ProviderHint
	if err := tx.QueryRow(ctx, `INSERT INTO fqdn_resolver_context_configs (org_id,site_id,gateway_id,version,state,retired_at,created_by,provider_hint) VALUES ($1,$2,$3,$4,'retired',now(),$5,$6) RETURNING id,created_at`, org, site, gateway, next, nullableActor(actor), rootProvider).Scan(&out.ID, &out.CreatedAt); err != nil {
		return ResolverConfig{}, writeErr(err)
	}
	// Preserve the first profile as the legacy response projection. Runtime DNS
	// selection never reads this compatibility table for profile-native configs.
	for ordinal, endpoint := range profiles[0].Endpoints {
		if _, err := tx.Exec(ctx, `INSERT INTO fqdn_resolver_context_endpoints (config_id,org_id,ordinal,address,port,transport) VALUES ($1,$2,$3,$4::inet,$5,$6)`, out.ID, org, ordinal, endpoint.Address, endpoint.Port, endpoint.Transport); err != nil {
			return ResolverConfig{}, writeErr(err)
		}
	}
	for ordinal := range profiles {
		profile := &profiles[ordinal]
		if profile.LegacyDefault {
			profile.ID = out.ID
		} else {
			profile.ID = uuid.New()
		}
		if _, err := tx.Exec(ctx, `INSERT INTO fqdn_resolver_context_profiles(id,config_id,org_id,ordinal,name,provider_hint,legacy_default) VALUES($1,$2,$3,$4,$5,$6,$7)`, profile.ID, out.ID, org, ordinal, profile.Name, profile.ProviderHint, profile.LegacyDefault); err != nil {
			return ResolverConfig{}, writeErr(err)
		}
		for _, suffix := range profile.ZoneSuffixes {
			if _, err := tx.Exec(ctx, `INSERT INTO fqdn_resolver_context_profile_suffixes(profile_id,config_id,org_id,suffix) VALUES($1,$2,$3,$4)`, profile.ID, out.ID, org, suffix); err != nil {
				return ResolverConfig{}, writeErr(err)
			}
		}
		for endpointOrdinal, endpoint := range profile.Endpoints {
			if _, err := tx.Exec(ctx, `INSERT INTO fqdn_resolver_context_profile_endpoints(profile_id,org_id,ordinal,address,port,transport) VALUES($1,$2,$3,$4::inet,$5,$6)`, profile.ID, org, endpointOrdinal, endpoint.Address, endpoint.Port, endpoint.Transport); err != nil {
				return ResolverConfig{}, writeErr(err)
			}
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE fqdn_resolver_context_configs SET state='active',retired_at=NULL WHERE id=$1 AND org_id=$2`, out.ID, org); err != nil {
		return ResolverConfig{}, writeErr(err)
	}
	suffixCount, endpointCount := 0, 0
	for _, profile := range profiles {
		suffixCount += len(profile.ZoneSuffixes)
		endpointCount += len(profile.Endpoints)
	}
	if err := writeAudit(ctx, tx, org, actor, actorSystem, cause, "fqdn_resolver_context.configured", out.ID, map[string]any{"intent": "replace_resolver_configuration", "outcome": "succeeded", "site_id": site, "gateway_id": gateway, "version": next, "provider_hint": rootProvider, "profile_count": len(profiles), "suffix_count": suffixCount, "endpoint_count": endpointCount}); err != nil {
		return ResolverConfig{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ResolverConfig{}, err
	}
	out.OrgID, out.SiteID, out.GatewayID, out.Version, out.State, out.ProviderHint, out.Endpoints, out.Profiles = org, site, gateway, next, "active", &rootProvider, append([]ResolverEndpoint(nil), profiles[0].Endpoints...), profiles
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
