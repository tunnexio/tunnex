# SSI-2 — a port-scoped site rule works end to end

Epic: [EPIC-site-to-site-improvements.md](EPIC-site-to-site-improvements.md). Finding F3.

## What was wrong

A rule with a site or in-site CIDR source and a **resource** destination was compiled onto the source
gateway only. When the resource lives in another site the flow also crosses the transit hub and the
destination site's gateway. Both are default-deny under enforcement and never received the grant,
so the rule read as active while the traffic was dropped. The code comment said a site → resource
source "egresses via its own gateway, never the hub", which is true only for a resource outside
every site.

Reproduced by `TestSiteSourceResourceInOtherSiteFarPlacement`: on main the destination gateway's
allow list for the rule is empty.

## Decisions

| Item | Decision |
| --- | --- |
| Placement | When the resource's CIDR lies in an approved subnet of a site other than the source site, the grant is also placed on that site's gateway and on the active hub. Same rule as the device path (`devGrantNodes`). |
| Scope of the entry | Unchanged on every node: the resource's own protocol and ports. No node receives a whole-site entry for a resource rule. |
| Resource in no site | Source gateway only, as before. |
| Resource in the source site | Source gateway only; the flow never crosses a link. |
| IPsec sources | Unchanged; they already resolve their own gateway. |
| Policy version | No bump. The entries use the existing CIDR-source shape. |

## Tests

| Test | Proves |
| --- | --- |
| `TestSiteSourceResourceInOtherSiteFarPlacement` | Source gateway, destination gateway and hub hold the grant; it stays port-scoped; the two non-crossing cases keep source-only placement. |
| `TestCIDRSourceResourceInOtherSiteFarPlacement` | The same for a CIDR source, with the hub being the source gateway. |

Wire proof: SSI-10 (one allowed port and one denied port across two real sites).
