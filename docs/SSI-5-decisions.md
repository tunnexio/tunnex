# SSI-5 — every site mutation is audited

Epic: [EPIC-site-to-site-improvements.md](EPIC-site-to-site-improvements.md). Finding F5.

## What was wrong

Only subnet approval, subnet removal and site deletion wrote an audit row. Creating a site,
advertising a range, binding a gateway and unbinding one wrote nothing, although the one-screen
route's own comment promised "four constituent audit events". A gateway could be moved off a site
with no record of who did it.

## Decisions

| Item | Decision |
| --- | --- |
| Actions | `site.created`, `site.subnet_advertised`, `site.gateway_bound`, `site.gateway_unbound`. |
| Targets | The site, except `site.subnet_advertised`, which targets the subnet like the existing approval rows. |
| Atomicity | Each row is written in the same transaction as its mutation and its error is returned, so a refused or failed mutation is never audited and an audit failure rolls the mutation back. |
| No-ops | An idempotent re-bind to the same site changes nothing and writes no row. |
| Actor | The service methods take the actor explicitly, like `ApproveSubnet`. A nil actor is stored as no user rather than a dangling reference. |
| One-screen route | `RouteLAN` passes its actor through, so it now really emits the four constituent events the long path emits. |
| Unbind by node | Reads the binding in the same transaction so the row names the site the gateway left. |

## Tests

| Test | Proves |
| --- | --- |
| `sites.TestSiteMutationsAreAudited` | One row per mutation with the actor; a refused duplicate create and a no-op re-bind write none; both unbind paths name the site. |
| `sites.TestRouteLANByteIdentical` (existing) | The short and long paths still produce the same audit actions. |

Red before the fix: on main none of the four actions exists.
