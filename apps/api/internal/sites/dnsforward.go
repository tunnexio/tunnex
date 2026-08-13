package sites

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// DNSForward is the on-the-wire/on-disk shape of one dns_forwarding element (the sites.dns_forwarding JSONB).
type DNSForward struct {
	Domain     string `json:"domain"`
	ResolverIP string `json:"resolver_ip"`
}

// SetDNSForward adds or updates a forwarded zone on a site (S8.4 D7). Validates the domain + resolver_ip,
// refuses a resolver NOT inside one of the site's APPROVED subnets (one-truth — the resolver must live on
// the LAN the site fronts), and refuses a domain already forwarded by ANOTHER site (the D1-addition overlap
// rule — one org-domain → one resolver). Same-domain on THIS site = update. Audited in-tx.
func (s *Service) SetDNSForward(ctx context.Context, actor, orgID, siteID uuid.UUID, domain, resolverIP string) error {
	nd, ok := NormalizeDomain(domain)
	if !ok {
		return apierr.New(400, "dns_domain_invalid", "the domain is not a valid DNS name")
	}
	ip, err := netip.ParseAddr(resolverIP)
	if err != nil || !ip.IsValid() {
		return apierr.New(400, "dns_resolver_invalid", "the resolver IP is not a valid address")
	}
	return s.withTx(ctx, func(q *sqlc.Queries) error {
		site, e := q.GetSite(ctx, sqlc.GetSiteParams{ID: siteID, OrgID: orgID})
		if e != nil {
			if e == pgx.ErrNoRows {
				return apierr.NotFound("site_not_found", "no such site in this organization")
			}
			return e
		}
		// Resolver must be inside one of THIS site's APPROVED subnets (it lives on the LAN the site fronts).
		subs, e := q.ListSiteSubnets(ctx, siteID)
		if e != nil {
			return e
		}
		inSubnet := false
		for _, ss := range subs {
			if ss.Status == "approved" && ss.Cidr.Contains(ip) {
				inSubnet = true
				break
			}
		}
		if !inSubnet {
			return apierr.New(409, "dns_resolver_not_in_site_subnet",
				"the resolver "+ip.String()+" must be inside one of this site's approved subnets")
		}
		// Overlap: another site already forwards this domain → refuse (D1-addition, one zone → one resolver).
		// The ONE validator is DNSDomainConflict (F8 — the inline re-implementation that used to live here
		// was tested-but-never-shipped; now the CRUD calls the same function the test exercises). Gather the
		// OTHER sites' forwarded domains as its input; self is excluded (same-domain on this site = update).
		all, e := q.ListSitesByOrg(ctx, orgID)
		if e != nil {
			return e
		}
		var others []string
		for _, other := range all {
			if other.ID == siteID {
				continue
			}
			for _, en := range decodeDNS(other.DnsForwarding) {
				others = append(others, en.Domain)
			}
		}
		if DNSDomainConflict(others, domain) {
			return apierr.Conflict("dns_domain_conflict", nd+" is already forwarded by another site; a domain forwards to one resolver")
		}
		// Cross-mechanism (S10.3 (A)): the forwarded domain must not collide with a K8s cluster's DNS zone
		// (<cluster>.<dns_zone>) — one zone, one resolver, across BOTH the site-forward and cluster paths.
		czones, e := q.ListK8sClusterZonesForOrg(ctx, orgID)
		if e != nil {
			return e
		}
		var k8sZones []string
		for _, z := range czones {
			if z.DnsZone != "" {
				k8sZones = append(k8sZones, z.Name+"."+z.DnsZone)
			}
		}
		if DNSDomainConflict(k8sZones, domain) {
			return apierr.Conflict("dns_domain_conflict", nd+" collides with a Kubernetes cluster DNS zone; a domain resolves one way")
		}
		// Add or update on THIS site.
		mine := decodeDNS(site.DnsForwarding)
		found := false
		for i := range mine {
			if n, ok := NormalizeDomain(mine[i].Domain); ok && n == nd {
				mine[i] = DNSForward{Domain: nd, ResolverIP: ip.String()}
				found = true
				break
			}
		}
		if !found {
			mine = append(mine, DNSForward{Domain: nd, ResolverIP: ip.String()})
		}
		raw, e := json.Marshal(mine)
		if e != nil {
			return e
		}
		if e := q.SetSiteDNSForwarding(ctx, sqlc.SetSiteDNSForwardingParams{ID: siteID, DnsForwarding: raw}); e != nil {
			return e
		}
		return s.auditSite(ctx, q, orgID, actor, siteID, "site.dns_forwarding_set", map[string]any{"domain": nd, "resolver_ip": ip.String()})
	})
}

// RemoveDNSForward drops a forwarded zone from a site (S8.4 D7). Full-sweep: the artifact recompiles on the
// next reconcile and the forward is withdrawn from every gateway. Audited in-tx.
func (s *Service) RemoveDNSForward(ctx context.Context, actor, orgID, siteID uuid.UUID, domain string) error {
	nd, ok := NormalizeDomain(domain)
	if !ok {
		return apierr.New(400, "dns_domain_invalid", "the domain is not a valid DNS name")
	}
	return s.withTx(ctx, func(q *sqlc.Queries) error {
		site, e := q.GetSite(ctx, sqlc.GetSiteParams{ID: siteID, OrgID: orgID})
		if e != nil {
			if e == pgx.ErrNoRows {
				return apierr.NotFound("site_not_found", "no such site in this organization")
			}
			return e
		}
		kept := make([]DNSForward, 0)
		for _, en := range decodeDNS(site.DnsForwarding) {
			if n, ok := NormalizeDomain(en.Domain); ok && n == nd {
				continue // drop it
			}
			kept = append(kept, en)
		}
		raw, e := json.Marshal(kept)
		if e != nil {
			return e
		}
		if e := q.SetSiteDNSForwarding(ctx, sqlc.SetSiteDNSForwardingParams{ID: siteID, DnsForwarding: raw}); e != nil {
			return e
		}
		return s.auditSite(ctx, q, orgID, actor, siteID, "site.dns_forwarding_removed", map[string]any{"domain": nd})
	})
}

// decodeDNS unmarshals a dns_forwarding JSONB blob, tolerating an empty/null column (a fresh site).
func decodeDNS(raw []byte) []DNSForward {
	if len(raw) == 0 {
		return nil
	}
	var out []DNSForward
	_ = json.Unmarshal(raw, &out)
	return out
}

// S8.4 D1-addition — the disjointness law's DNS cousin: within an org, a forwarded DOMAIN maps to exactly
// ONE resolver. Two sites both claiming `corp.local` is a conflict (which resolver wins is undefined), so it
// is REFUSED at write time — decided here in Slice 1, wired into the CRUD in Slice 2 (never discovered in
// the walk). NormalizeDomain must agree with the agent forwarder's normalizer on what a domain IS.

// NormalizeDomain lowercases + strips a trailing dot; ok=false for empty / space-bearing / empty-label input.
func NormalizeDomain(d string) (string, bool) {
	d = strings.TrimSpace(strings.ToLower(d))
	d = strings.TrimSuffix(d, ".")
	if d == "" || strings.Contains(d, " ") {
		return "", false
	}
	for _, lbl := range strings.Split(d, ".") {
		if lbl == "" {
			return "", false
		}
	}
	return d, true
}

// DNSDomainConflict reports whether candidate's normalized domain already exists in the org's set of
// forwarded domains (one zone → one resolver). A malformed candidate is treated as a conflict=false here
// (the caller rejects malformed separately with a distinct error); comparison is on the normalized form so
// `Corp.Local.` and `corp.local` collide.
func DNSDomainConflict(existing []string, candidate string) bool {
	cand, ok := NormalizeDomain(candidate)
	if !ok {
		return false
	}
	for _, e := range existing {
		if n, ok := NormalizeDomain(e); ok && n == cand {
			return true
		}
	}
	return false
}

// ForwardedDomainsForOrg returns every normalized forwarded domain across the org's sites (union). It is the
// K8s cluster registrar's input for cross-mechanism one-zone-one-resolver (S10.3 (A)): a new cluster zone
// must not collide with an already-forwarded domain. Takes a caller's tx Queries so it runs in the same tx.
func ForwardedDomainsForOrg(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID) ([]string, error) {
	all, err := q.ListSitesByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, s := range all {
		for _, en := range decodeDNS(s.DnsForwarding) {
			out = append(out, en.Domain)
		}
	}
	return out, nil
}

// ListDNSForwards returns a site's forwarded zones (org-checked) for the config UI.
func (s *Service) ListDNSForwards(ctx context.Context, orgID, siteID uuid.UUID) ([]DNSForward, error) {
	site, err := s.q.GetSite(ctx, sqlc.GetSiteParams{ID: siteID, OrgID: orgID})
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, apierr.NotFound("site_not_found", "no such site in this organization")
		}
		return nil, err
	}
	return decodeDNS(site.DnsForwarding), nil
}
