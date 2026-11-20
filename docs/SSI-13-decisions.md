# SSI-13 — Site-to-site: one row of tabs, one way in, one name for each thing

Status: built on `story/site-to-site-improvements`. Local only. Dashboard only: no API, schema or
gateway change.

## What confused people

1. **Two levels of navigation for one job.** "Networks" and "Connections" sat above a second row of
   tabs. WireGuard links lived under one, cloud VPN tunnels under the other, and "Connections" also
   had a WireGuard mode.
2. **"Create connection" that creates nothing.** For Tunnex-to-Tunnex it opened a review of two
   networks; links are automatic. Only a cloud VPN is a stored object.
3. **The same ranges in two places.** "Routed ranges" in the sidebar is a read-only projection of the
   ranges approved under Site-to-site.
4. **A standby drawn apart from its network.** The list showed one gateway per network; the role of a
   second one was only on the Failover tab.
5. **Several words per thing.** Site / network / location; range / subnet; gateway / hub.

## Decisions

**D1. One row of tabs:** Networks · Map · Ranges · Failover · DNS forwarding · Cloud VPN. The
Networks/Connections switch is gone. Existing URLs keep working (`/sites?section=…`,
`/site-to-site`); `section=approvals` opens Ranges.

**D2. Cloud VPN is its own tab and is also shown on the network it belongs to.** The tab is the
existing IPsec workspace, unchanged: provider cards with their marks, profiles, file import,
eligibility, tunnel and BGP status, key rotation. Its WireGuard mode is no longer offered there (the
pair review stays reachable at `?method=wireguard`). A network that has a cloud VPN shows it under
"Linked by" in the list and inside its box on the map.

**D3. One way in: "Add a network".** It asks what is on the other side. A machine that can run a
Tunnex gateway opens the existing network setup; a cloud VPN gateway opens the existing provider
step. No wizard content changes.

**D4. Ranges is one tab.** Approvals queue, then every range of every network with its status. The
sidebar entry "Routed ranges" is removed; its page stays at `/routed-ranges` and is linked from the
tab as "What connected devices receive".

**D5. Gateways and their roles are shown where the network is.** The Networks list lists every
active gateway of a network with PRIMARY / STANDBY / NOT ANSWERING from the served hub set, and a
plain status. The map draws a network as a box with its gateways inside.

**D6. The map scales by changing form, not by shrinking.** Up to 12 networks: boxes and links.
Above that: a grid of tiles, problems first, paged. No grouping by cloud: the product does not
record where a network runs, and inventing it from names would be a guess.

**D7. Failover stays a tab.** The mock folded it into the network. The hub set is organisation-wide
(pins can span networks), so the control that orders it does not belong inside one network. The
network shows the roles; the tab orders them.

**D8. Words:** Network, Gateway (primary / standby), Range, Link. Applied to what this story touches;
a product-wide rename is not attempted here.

## Not in this story

- "How a range is reached" (direct, through a peering, over a cloud VPN): not recorded today.
- "Test this link": needs the probe from SSI-9 slice 3.
- Live tunnel status in the Networks list: it would be one status call per connection per page load.
  The list shows the connection's configuration state; the Cloud VPN tab shows tunnels.
