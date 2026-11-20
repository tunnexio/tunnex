# SSI-7b — a site with more than one gateway

Epic: [EPIC-site-to-site-improvements.md](EPIC-site-to-site-improvements.md). Finding F9.
The named health kind listed under SSI-7b in the SSI-7 paper is built with SSI-9, whose preflight
shows it.

## What was wrong

The one-gateway-per-site index was lifted for hub HA, so any site can hold several gateways. Two
places still assumed one.

- **Policy.** The compiler kept one gateway per site in a last-write-wins map. A site rule was
  granted on whichever gateway was listed last; the other, default-deny, dropped the same flow.
- **Data plane.** The hub peered with every gateway of a remote site and gave each the site's
  ranges. WireGuard keeps an allowed range on one peer, so which gateway received the site's
  traffic was whatever was configured last.

## Ruling

Put to the Founder on 2026-11-20 with three options (one carrier and the rest warm; refuse a second
bind; leave it to SCX-5). **Chosen: one carrier, the rest warm, and rules on every gateway of the
site.**

## Decisions

| Item | Decision |
| --- | --- |
| Policy placement | A site-source or site-destination grant, and a device grant to a site, is placed on every gateway of the site. More enforcement points hold the same allow; none holds a wider one. |
| Carrier | For each remote site the hub gives the ranges to one gateway: the site's earliest member of the active hub order when it has one, otherwise its lowest gateway id. Independent of list order. |
| Other gateways | Kept as peers with an endpoint and keepalive and **no** allowed ranges, the shape a spoke already gives a standby hub. |
| Same-site hub pair | Unchanged. Members of the hub's own site are excluded from its peer set as before. |
| Not in this story | Moving the carrier when it fails. A spoke site's gateways are not observed for liveness, and the cloud's return route points at one of them. That is cloud-fabric HA and stays with SCX-5. A two-gateway spoke site is therefore consistent, not highly available. |
| `site_has_gateway` | The refusal in `BindNode` is dead code since the index was lifted; left in place, harmless. |

## Tests

| Test | Proves |
| --- | --- |
| `policy.TestSiteGrantsReachEveryGatewayOfASite` | Site → site, site → resource and device → site grants reach every gateway of both sites, whatever the listing order. Red on main: one gateway held nothing. |
| `nodes.TestHubGivesARemoteSiteOneCarrier` | Exactly one hub peer carries a two-gateway site's range, the other is warm and empty, and the choice does not follow list order. Red on main: both peers carried it. |
| `nodes.TestSiteLinkGraphHA` (existing) | The same-site hub pair and the single-carrier invariant on the spoke side still hold. |

Wire proof: SSI-10, with a second gateway bound to the spoke site.
