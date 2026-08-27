package fqdnresolver

// This file is the narrow Lane 2 -> Lane 3 seam.  It exposes only durable,
// active selected-context generations; resolver observations, pending rows,
// withdrawn rows, and diagnostic last-good data are deliberately not compiler
// input.  The compiler owns entitlement and organization opt-in decisions.

import (
	"context"
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
	TTL                time.Duration
	ResolvedAt         time.Time
	Addresses          []netip.Addr
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
       array_agg(host(a.address) ORDER BY a.address)
FROM fqdn_resource_answer_generations g
JOIN fqdn_resources r
  ON r.id=g.resource_id AND r.org_id=g.org_id
 AND r.resolver_site_id=g.resolver_site_id AND r.resolver_node_id=g.resolver_node_id
JOIN fqdn_resolver_context_configs c
  ON c.id=g.resolver_config_id AND c.org_id=g.org_id AND c.state='active'
 AND c.site_id=r.resolver_site_id AND c.gateway_id=r.resolver_node_id
JOIN fqdn_resource_generation_answers a
  ON a.generation_id=g.id AND a.org_id=g.org_id
WHERE g.org_id=$1 AND g.state='active'
GROUP BY g.org_id,g.resource_id,r.fqdn,r.protocol,r.port_low,r.port_high,
         g.generation,g.resolver_site_id,g.resolver_node_id,g.effective_ttl,g.resolved_at
ORDER BY g.resource_id`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ActiveGeneration{}
	for rows.Next() {
		var g ActiveGeneration
		var site, gateway uuid.UUID
		var raw []string
		if err := rows.Scan(&g.OrgID, &g.ResourceID, &g.Hostname, &g.Protocol, &g.PortLow, &g.PortHigh,
			&g.Sequence, &site, &gateway, &g.TTL, &g.ResolvedAt, &raw); err != nil {
			return nil, err
		}
		g.Context = Context{ResolverID: site.String(), GatewayID: gateway.String()}
		if !g.Context.valid() || len(raw) == 0 || len(raw) > MaxAnswers {
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
