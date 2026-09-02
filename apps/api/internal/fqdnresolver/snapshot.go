package fqdnresolver

// This file is the narrow Lane 2 -> Lane 3 seam.  It exposes only durable,
// active selected-context generations; resolver observations, pending rows,
// withdrawn rows, and diagnostic last-good data are deliberately not compiler
// input.  The compiler owns entitlement and organization opt-in decisions.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// ActiveGeneration is an immutable, database-backed answer snapshot suitable
// for a later policy compiler adapter. Sequence is historical ordering only;
// the compiler derives its content identity from this selected-context answer
// set so a timestamp or retry cannot masquerade as a policy change.
type ActiveGeneration struct {
	OrgID, ResourceID  uuid.UUID
	Hostname, Protocol string
	PortLow, PortHigh  *int32
	Sequence           int64
	Context            Context
	// ResolverConfig is the immutable direct-endpoint revision that produced
	// this generation. Compiler consumers must reject an active row when its
	// current context no longer has this exact active revision.
	ResolverConfig ResolverConfig
	TTL            time.Duration
	ResolvedAt     time.Time
	Addresses      []netip.Addr
}

// ActiveGenerationReader is the read-only dependency Lane 3 consumes when it
// constructs a policy snapshot. Implementations must never return pending,
// retired, withdrawn, draft, or context-mismatched rows as active.
type ActiveGenerationReader interface {
	ActiveGenerations(context.Context, uuid.UUID) ([]ActiveGeneration, error)
}

// ActiveGenerations returns the current immutable generation for each FQDN
// resource in an organization. The selected Site/Gateway pair is joined back
// to the current resource row so an old generation cannot compile after a
// resolver-context edit, even before a scheduler tick records its withdrawal.
func (s *PostgresStore) ActiveGenerations(ctx context.Context, orgID uuid.UUID) ([]ActiveGeneration, error) {
	rows, err := s.pool.Query(ctx, `
SELECT g.org_id,g.resource_id,r.fqdn,r.protocol,r.port_low,r.port_high,
       g.generation,g.resolver_site_id,g.resolver_node_id,g.effective_ttl,g.resolved_at,
       cfg.id,cfg.version,profile.id,profile.name,profile.provider_hint,COALESCE(g.resolver_match_suffix,''),
       (SELECT COALESCE(jsonb_agg(jsonb_build_object('address',host(e.address),'port',e.port,'transport',e.transport) ORDER BY e.ordinal),'[]'::jsonb)
          FROM fqdn_resolver_context_profile_endpoints e
         WHERE e.profile_id=profile.id AND e.org_id=profile.org_id),
       ARRAY(SELECT host(a.address)
               FROM fqdn_resource_generation_answers a
              WHERE a.generation_id=g.id AND a.org_id=g.org_id
              ORDER BY a.address)
FROM fqdn_resource_answer_generations g
JOIN fqdn_resources r
  ON r.id=g.resource_id AND r.org_id=g.org_id
 AND r.resolver_site_id=g.resolver_site_id AND r.resolver_node_id=g.resolver_node_id
JOIN nodes n
  ON n.id=g.resolver_node_id AND n.org_id=g.org_id
 AND n.site_id=g.resolver_site_id AND n.status='active' AND n.revoked_at IS NULL
JOIN fqdn_resolver_context_configs cfg
 ON cfg.id=g.resolver_config_id AND cfg.org_id=g.org_id
 AND cfg.site_id=g.resolver_site_id AND cfg.gateway_id=g.resolver_node_id
 AND cfg.state='active'
JOIN fqdn_resolver_context_profiles profile
  ON profile.config_id=cfg.id AND profile.org_id=cfg.org_id
 AND profile.id=COALESCE(g.resolver_profile_id,cfg.id)
WHERE g.org_id=$1 AND g.state='active'
  AND (
    (profile.legacy_default AND COALESCE(g.resolver_match_suffix,'')=''
      AND NOT EXISTS (
        SELECT 1
          FROM fqdn_resolver_context_profiles candidate_profile
          JOIN fqdn_resolver_context_profile_suffixes candidate
            ON candidate.profile_id=candidate_profile.id
           AND candidate.config_id=candidate_profile.config_id
           AND candidate.org_id=candidate_profile.org_id
         WHERE candidate_profile.config_id=cfg.id
           AND candidate_profile.org_id=cfg.org_id
           AND (lower(r.fqdn)=candidate.suffix OR lower(r.fqdn) LIKE '%.'||candidate.suffix)
      )
    )
    OR (
      NOT profile.legacy_default
      AND EXISTS (
        SELECT 1
          FROM fqdn_resolver_context_profile_suffixes suffix
         WHERE suffix.profile_id=profile.id
           AND suffix.config_id=profile.config_id
           AND suffix.org_id=profile.org_id
           AND suffix.suffix=g.resolver_match_suffix
           AND (lower(r.fqdn)=suffix.suffix OR lower(r.fqdn) LIKE '%.'||suffix.suffix)
      )
      AND NOT EXISTS (
        SELECT 1
          FROM fqdn_resolver_context_profiles candidate_profile
          JOIN fqdn_resolver_context_profile_suffixes candidate
            ON candidate.profile_id=candidate_profile.id
           AND candidate.config_id=candidate_profile.config_id
           AND candidate.org_id=candidate_profile.org_id
         WHERE candidate_profile.config_id=cfg.id
           AND candidate_profile.org_id=cfg.org_id
           AND length(candidate.suffix)>length(g.resolver_match_suffix)
           AND (lower(r.fqdn)=candidate.suffix OR lower(r.fqdn) LIKE '%.'||candidate.suffix)
      )
    )
  )
ORDER BY g.resource_id`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ActiveGeneration{}
	for rows.Next() {
		var g ActiveGeneration
		var site, gateway uuid.UUID
		var config uuid.UUID
		var profile uuid.UUID
		var configVersion int64
		var profileName, profileProvider, matchedSuffix string
		var endpointJSON []byte
		var raw []string
		if err := rows.Scan(&g.OrgID, &g.ResourceID, &g.Hostname, &g.Protocol, &g.PortLow, &g.PortHigh,
			&g.Sequence, &site, &gateway, &g.TTL, &g.ResolvedAt, &config, &configVersion,
			&profile, &profileName, &profileProvider, &matchedSuffix, &endpointJSON, &raw); err != nil {
			return nil, err
		}
		g.Context = Context{ResolverID: site.String(), GatewayID: gateway.String()}
		g.ResolverConfig = ResolverConfig{
			ID: config.String(), Version: configVersion, ProfileID: profile.String(),
			ProfileName: profileName, ProfileProvider: profileProvider, MatchedSuffix: matchedSuffix,
		}
		if err := json.Unmarshal(endpointJSON, &g.ResolverConfig.Endpoints); err != nil || !g.Context.valid() || !g.ResolverConfig.valid() || len(raw) == 0 || len(raw) > MaxAnswers {
			return nil, fmt.Errorf("invalid active FQDN generation %s", g.ResourceID)
		}
		g.Addresses = make([]netip.Addr, 0, len(raw))
		for _, value := range raw {
			address, err := netip.ParseAddr(value)
			if err != nil || !address.IsValid() {
				return nil, fmt.Errorf("invalid active FQDN answer for %s", g.ResourceID)
			}
			g.Addresses = append(g.Addresses, address)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
