# SSI-7 — the gateway checks site routes against its own host

Epic: [EPIC-site-to-site-improvements.md](EPIC-site-to-site-improvements.md). Findings F8 and F10.
F9 moves to SSI-7b (below).

## What was wrong

The agent programmed and judged site routes without looking at the host it runs on.

- **F8.** A remote range that overlaps a network the host is attached to was installed as a `wg0`
  route anyway. The control plane cannot catch it: it knows the organization's ranges, not the
  bridges and container networks on a gateway host.
- **F10.** A local range counted as reachable only when a host address sat inside it. A range the
  gateway reaches through its LAN without being in it raised `site_subnet_unreachable` for a path
  that worked. On the AWS demo gateway both published ranges (`172.31.37.55/32`, a host elsewhere
  in the VPC, and `10.50.1.0/24`, a peered network) are of this kind.

## Decisions

| Item | Decision |
| --- | --- |
| One snapshot | `planSiteRoutes` takes the host's connected IPv4 networks and decides routes, source hint and health together, as the single host-address snapshot did before. |
| Remote range | Refused when it overlaps a connected non-tunnel network: same range, more specific, or wider. It never reaches the backend. |
| Local range | Deliverable when a LAN address of the host is inside it, or the kernel routes it out of a non-tunnel interface. Undeliverable when the kernel would send it into a tunnel or has no route. |
| Per range | Each local range is judged on its own. Before, one deliverable range hid every undeliverable one. |
| Tunnel devices | The agent's WireGuard interface by name, plus WireGuard, TUN/TAP and IPsec virtual devices recognised from sysfs. Checked on the AWS gateway host: `wg0` reports `DEVTYPE=wireguard`. |
| Health | A refused route or an undeliverable local range raises the existing `site_subnet_unreachable` signal and logs `site_route_refused_host_network` or `site_local_range_undeliverable`, once per onset, naming the range and interface. |
| Where it runs | Only with the kernel WireGuard backend on Linux. Other backends keep the address-containment behaviour. |

## A local range on a container network is not refused

The collision seen on 2026-11-20 was a **local** range: the gateway advertised `172.19.0.0/16`
and its host had a Compose bridge on the same range, so the kernel delivered that traffic to
containers. The agent cannot tell that from an operator who means to publish the container network.
It is therefore not refused here. Telling the operator is the job of the preflight in SSI-9, which
shows the interface a local range resolves to. Recorded so the gap is not mistaken for closed.

## Deferred

| Item | To | Trigger |
| --- | --- | --- |
| A named health kind `site_route_conflict` with its own dashboard copy | SSI-7b | Before SSI-9, whose preflight shows it. |
| F9: a second gateway bound to one site doubles the hub's peer | SSI-7b | Before SSI-8, which renders per-site rules on each gateway. |

## Tests

| Test | Proves |
| --- | --- |
| `TestPlanRefusesRemoteRangeOnAConnectedNetwork` | Exact, more-specific and wider remote ranges are refused against the AWS host's real interface list; a disjoint one is kept. |
| `TestPlanIgnoresTunnelNetworks` | A route on the tunnel network is not a host collision. |
| `TestPlanLocalRangeReachableThroughTheLAN` | The two demo ranges are deliverable and no source hint is guessed. |
| `TestPlanLocalRangeSourceHint` | The LAN address is the source hint; a tunnel address never is. |
| `TestPlanLocalRangeUndeliverable` | Into-the-tunnel and no-route cases are reported, per range. |
| `TestRunOncePlansRoutesAgainstTheHost` | The refused range never reaches the backend; the signal rises and clears. |
| `TestParseRouteGetDev` | Kernel route output, including a line with no interface. |

These are substitutes. Wire proof: SSI-10, with a colliding range on a real gateway host.
