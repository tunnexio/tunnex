package sites

import (
	"context"
	"errors"
	"net/netip"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// ListRoutedRanges returns the org's DECLARED routed LAN ranges for split-tunnel device AllowedIPs
// (S8.5) — the org's APPROVED site subnets (D1: a routed range IS an approved site subnet, so PENDING
// subnets never appear — routing-before-approval is the inverse of the routed≠permitted thesis).
// RANGES ONLY: no keys, no endpoints, no pool, no policy — so the client's never-re-fetch IDENTITY
// invariant survives (routes were never identity). Canonical (masked prefix) + sorted + deduped so the
// client's churn-free merge (2c) can byte-compare + two calls return an identical body. Empty is a
// first-class answer: a no-ranges org returns [].
func (s *Service) ListRoutedRanges(ctx context.Context, orgID uuid.UUID) ([]string, error) {
	subs, err := s.q.ListSiteSubnetsForOrg(ctx, orgID) // approved-only (the query filters status='approved')
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(subs))
	for _, ss := range subs {
		c := ss.Cidr.Masked().String() // canonical masked form (deterministic)
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	// S10.3 fork-1: the org's K8s VIP ranges join the device's routed set — the CLIENT half of the exposed-
	// Service feature. A synthetic VIP range is just another CIDR class in AllowedIPs: routing it delivers
	// both the Service VIPs (DNAT'd at the gateway) AND the reserved DNS VIP (a /32 inside the range). Without
	// this the gateway DNATs a VIP no client ever routes to it (the producer-without-consumer gap fork-1
	// closed). Empty for a non-cluster org → the routed set is byte-identical (the zero-config golden).
	vipRanges, err := s.q.ListVIPRangesForOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	for _, vr := range vipRanges {
		if p, e := netip.ParsePrefix(vr); e == nil {
			c := p.Masked().String()
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// ListRoutedForwards returns the DNS forwards REACHABLE by a split-tunnel device given its routed ranges
// (S8.5 Slice 3, D4). GATED: a forward is included ONLY if its resolver_ip falls inside one of the passed
// `ranges` — a resolver the device cannot route to is a SERVFAIL generator wearing a feature's face, so it is
// never handed over (the DNS walk's split-horizon honesty, extended to the client tier). In practice the
// device routes ALL approved subnets (2c) and every forward's resolver lives in an approved subnet (S8.4
// dns_resolver_not_in_site_subnet), so the set is normally "all org forwards" — but the gate is computed by
// CONSTRUCTION, never assumed: a range the device does not route silently drops that range's forwards.
// `ranges` are the canonical CIDRs already produced by ListRoutedRanges (no re-query, no drift between the
// two halves of the one poll). Domain-deduped + sorted so the client's churn-free compare (2c) byte-matches.
func (s *Service) ListRoutedForwards(ctx context.Context, orgID uuid.UUID, ranges []string) ([]DNSForward, error) {
	prefixes := make([]netip.Prefix, 0, len(ranges))
	for _, r := range ranges {
		if p, err := netip.ParsePrefix(r); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	rows, err := s.q.ListSitesByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]DNSForward, 0)
	seen := map[string]bool{}
	for _, site := range rows {
		for _, fwd := range decodeDNS(site.DnsForwarding) {
			ip, err := netip.ParseAddr(fwd.ResolverIP)
			if err != nil {
				continue
			}
			reachable := false
			for _, p := range prefixes {
				if p.Contains(ip) {
					reachable = true
					break
				}
			}
			if !reachable {
				continue // GATE: a resolver the device cannot route to is never handed over
			}
			nd, ok := NormalizeDomain(fwd.Domain)
			if !ok {
				continue
			}
			if seen[nd] {
				continue
			}
			seen[nd] = true
			out = append(out, DNSForward{Domain: nd, ResolverIP: ip.String()})
		}
	}
	// S10.3 fork-1: the K8s cluster-zone → reserved-DNS-VIP resolver mapping rides THIS SAME channel (one
	// delivery path, one cadence, one fail-static impl — no third client channel, the D-WFA-6 principle). A
	// client resolves <service>.<namespace>.svc.<cluster>.<zone> by sending the query to the cluster's DNS VIP,
	// which the gateway answers (H1). The SAME reachability gate applies: the DNS VIP must fall inside a routed
	// range — it does, because ListRoutedRanges now returns the VIP range that contains it (computed by
	// construction, never assumed).
	// L2: only zones the gateway ACTUALLY answers — a cluster with >=1 LIVE exposed Service. This is the SAME
	// live-service set the agent's K8sDNSZones is built from, so the client resolver and the gateway's answer
	// set agree by construction (never install a client resolver for a zone the gateway would REFUSE because no
	// Service is exposed yet — the consumer-without-producer inverse of this epic's earlier findings).
	czones, err := s.q.ListK8sServedZonesForOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	for _, z := range czones {
		if z.DnsVip == "" {
			continue // no reserved DNS VIP (older cluster row) → no resolver to hand over
		}
		ip, err := netip.ParseAddr(z.DnsVip)
		if err != nil {
			continue
		}
		reachable := false
		for _, p := range prefixes {
			if p.Contains(ip) {
				reachable = true
				break
			}
		}
		if !reachable {
			continue // GATE: a DNS VIP the device does not route to is never handed over
		}
		nd, ok := NormalizeDomain(z.Name + "." + z.DnsZone)
		if !ok || seen[nd] {
			continue
		}
		seen[nd] = true
		out = append(out, DNSForward{Domain: nd, ResolverIP: ip.String()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out, nil
}

// RouteLAN is the S8.5 D1 ONE-SCREEN affordance's backend: it routes a LAN CIDR through a gateway in a
// single call by COMPOSING the four existing service methods — RegisterSite → BindNode → AddSubnet →
// ApproveSubnet. It is deliberately a COMPOSITE OF THE SAME CODE, not a new bespoke flow: so the DB state
// (site row, node.site_id, the approved subnet) AND the audit trail (the FOUR constituent events, by
// construction) are BYTE-IDENTICAL to an admin performing the four steps by hand — the short path is
// exactly as auditable as the long one, and never emits a single composite event. If the disjointness
// validator REFUSES the approval (the range collides), the site + bind + PENDING subnet persist — again
// byte-identical to the long path's advertise-then-refused state — and the typed refusal (with its S8.5
// teaching text) is returned. name is optional: blank derives a sensible default from the CIDR.
func (s *Service) RouteLAN(ctx context.Context, actor, orgID, nodeID uuid.UUID, name string, cidr netip.Prefix) (sqlc.Site, sqlc.SiteSubnet, error) {
	// RETRY-SAFE by RESUME, not re-create (S8.5 #2). If this gateway already carries a half-built site from
	// a prior attempt (a refusal left it site+bound+pending), advance THAT site — never register a second
	// (which, with the old unconditional BindNode, silently re-homed the gateway and orphaned the first
	// site). GetNodeSiteBinding tells us the gateway's current binding.
	cur, err := s.q.GetNodeSiteBinding(ctx, sqlc.GetNodeSiteBindingParams{ID: nodeID, OrgID: orgID})
	if err == pgx.ErrNoRows {
		return sqlc.Site{}, sqlc.SiteSubnet{}, apierr.NotFound("node_or_site_not_found", "no such node in this organization")
	}
	if err != nil {
		return sqlc.Site{}, sqlc.SiteSubnet{}, err
	}

	var site sqlc.Site
	if cur.Valid {
		// RESUME the gateway's existing site — advertise THIS CIDR and mutate NOTHING else. A prior pending
		// subnet (a long-path advertisement awaiting review, or the abandoned CIDR of a failed attempt) is
		// SOMEONE'S awaited work, not residue to sweep — RouteLAN never hard-deletes existing site state
		// (the pre-fold invariant; deleting it silently is a data-loss class). If the resume leaves two
		// pendings, that is the true state: two advertisements await review, both visible + approvable via
		// the normal surfaces. The only guard is additive (below): a same-CIDR resume reuses, never dups.
		site, err = s.GetSite(ctx, orgID, cur.Bytes)
		if err != nil {
			return sqlc.Site{}, sqlc.SiteSubnet{}, err
		}
	} else {
		// FRESH: register + bind. name is optional; blank derives a sensible default from the CIDR.
		if name == "" {
			name = "LAN " + cidr.Masked().String()
		}
		site, err = s.RegisterSite(ctx, orgID, name)
		if err != nil {
			return sqlc.Site{}, sqlc.SiteSubnet{}, err
		}
		if err := s.BindNode(ctx, orgID, site.ID, nodeID); err != nil {
			return site, sqlc.SiteSubnet{}, err
		}
	}

	// Advertise + approve the target CIDR. A same-CIDR resume finds the surviving pending subnet (subnet_exists)
	// and approves THAT rather than erroring — idempotent.
	sub, err := s.AddSubnet(ctx, orgID, site.ID, cidr)
	if err != nil {
		var ae *apierr.Error
		if errors.As(err, &ae) && ae.Code == "subnet_exists" {
			existing, e := s.q.ListSiteSubnets(ctx, site.ID)
			if e != nil {
				return site, sqlc.SiteSubnet{}, e
			}
			found := false
			for _, ss := range existing {
				if ss.Cidr.Masked() == cidr.Masked() {
					sub, found = ss, true
					break
				}
			}
			if !found {
				return site, sqlc.SiteSubnet{}, err
			}
		} else {
			return site, sqlc.SiteSubnet{}, err
		}
	}
	if err := s.ApproveSubnet(ctx, actor, orgID, sub.ID); err != nil {
		return site, sub, err // refusal: site+bind+pending persist (byte-identical to advertise-then-refused)
	}
	return site, sub, nil
}
