import type { DNSForward, Loaded, Site } from "./api";

// S14.5 D1 — CROSS-SITE DNS FORWARDING, ORG-WIDE.
//
// ⛔ WHY THIS IS ORG-WIDE AND NOT PER-SITE, WHICH IS THE ONLY SHAPE THE API SERVES.
//
// The invariant the server enforces is ORG-SCOPED: one zone maps to ONE resolver ACROSS THE ORG
// (`409 dns_domain_conflict`). A per-site list cannot show a conflict, because a conflict is by definition
// two sites disagreeing — each site's own list looks perfectly fine. **A view of a rule's inputs that cannot
// show the rule being broken is a view of something else.**
//
// The cost is an N+1: one `listSiteDNSForwards` per site. Founder-ruled, accepted, bounded by site count.

export interface OrgForward {
  domain: string;
  resolverIp: string;
  siteId: string;
  siteName: string;
}

export interface OrgForwardsView {
  /** Every zone across every site, sorted by domain then site so the render order is stable. */
  rows: OrgForward[];
  /**
   * Sites whose fetch FAILED, by name.
   *
   * ⛔ THE LOAD-BEARING FIELD. A failed per-site fetch shortens `rows`, and a shortened list on THIS view
   * reads as "no conflict" — the reassuring-empty defect aimed at exactly the thing the view exists to show.
   * So a partial load is never rendered as a complete one.
   */
  failedSites: string[];
  /**
   * Domains served by MORE THAN ONE distinct resolver. The org-wide invariant, violated.
   *
   * Detected from what we can see; see `conflictsAreComplete`.
   */
  conflicts: string[];
  /**
   * FALSE when any site failed to load.
   *
   * ⛔ "No conflicts found" and "no conflicts exist" are different claims, and only the second is reassuring.
   * With a site missing we cannot make the second one — the missing site is precisely where the other half
   * of a conflicting pair would live. The UI must not print a clean verdict while this is false.
   */
  conflictsAreComplete: boolean;
}

export function mergeOrgForwards(
  per: { site: Site; res: Loaded<DNSForward[]> }[],
): OrgForwardsView {
  const rows: OrgForward[] = [];
  const failedSites: string[] = [];

  for (const { site, res } of per) {
    if (!res.ok) {
      failedSites.push(site.name);
      continue;
    }
    for (const f of res.data) {
      rows.push({
        domain: f.domain,
        resolverIp: f.resolver_ip,
        siteId: site.id,
        siteName: site.name,
      });
    }
  }

  rows.sort(
    (a, b) =>
      a.domain.localeCompare(b.domain) || a.siteName.localeCompare(b.siteName),
  );

  // A conflict is one domain with two or more DISTINCT resolvers. Two sites forwarding a zone to the SAME
  // resolver is not a conflict — it is duplication, which the server permits.
  const byDomain = new Map<string, Set<string>>();
  for (const r of rows) {
    const set = byDomain.get(r.domain) ?? new Set<string>();
    set.add(r.resolverIp);
    byDomain.set(r.domain, set);
  }
  const conflicts = [...byDomain.entries()]
    .filter(([, resolvers]) => resolvers.size > 1)
    .map(([domain]) => domain)
    .sort();

  return {
    rows,
    failedSites,
    conflicts,
    conflictsAreComplete: failedSites.length === 0,
  };
}
