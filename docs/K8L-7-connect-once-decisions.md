# K8L-7 — connect once, reach everything the rules allow

Story branch: `story/kubernetes-launch-fixes`. Founder requirement, 2026-11-22: a company has one
VPN. An employee connects once and reaches the private web apps and databases on cloud machines and
the Services in managed and on-prem Kubernetes that their access rules allow. They never pick a
gateway and never reconnect to a different one.

## What was true before

It worked only when the device happened to sit on the hub gateway.

- With no pinned priorities the organisation has exactly one hub member (`electSiteHubSet`).
- The desktop client enrols a new device on the first active gateway in the list
  (`tunnex-desktop/apps/client/src/main/httpdeviceapi.ts`, `activeNodeId`); in the dashboard the
  administrator picks any gateway. Neither prefers the hub.
- A device on a non-hub gateway is sent every network's routes and DNS zones, and its gateway
  forwards the traffic to the hub. The hub then drops it: its peer for that gateway carries the
  gateway's site ranges, not the device's address, so the WireGuard source check fails. Replies have
  no way back either. Nothing reports it.

Live, 2026-11-22, laptop moved to the non-hub (GKE) gateway, enforcement off:

    own network's cluster (GKE orders)        200
    own network (10.70.0.2:22)                open
    other network's cluster (on-prem orders)  000 by address and by name
    other network (10.80.0.2:22)              blocked

## What already existed

Migration 0166 added an opt-in organisation setting, "Cross-gateway client connectivity". When it is
on, the control plane builds a client graph (`gatewaymesh`): the hub primary holds each device's
exact address on the peer of the gateway that owns it, and every other gateway reaches remote
devices through the hub. Exact /32s only, never the pool on two peers, so the single-valued
AllowedIPs invariant holds. Enforcement placement already covers the source gateway, the hub and the
destination gateway. It shipped with unit, database and real-traffic tests for device-to-device
flows (`docs/S-cross-gateway-client-connectivity-decisions.md`).

That is the missing half of the site path: once the hub knows which gateway owns the device, the
existing site link carries the rest. Turning the setting on, with no code change, on the same
laptop and the same connection:

    enforcement off                    both clusters 200 by address and by name; both networks open
    enforcement on, no matching rule   blocked
    rule: admin -> GKE orders          200
    rule: admin -> on-prem orders      200 (the cluster in the OTHER network), by address and name
    on-prem orders on port 443         blocked (not granted)
    10.80.0.2:22                       blocked (no rule)

The hub's peer for the GKE gateway went from `10.70.0.0/24 100.65.0.2/32 100.65.0.3/32` to the same
plus the device's `10.99.0.2/32`.

## Decision

1. The setting is on by default (migration 0237), and existing organisations are switched on. It
   stays a setting: an administrator who wants each gateway's devices confined to that gateway's
   network can turn it off, with the existing audit event.
2. No change to rules or to what "enforcing" means. In enforcing mode only granted flows pass, on
   every gateway on the path. In open-mesh mode devices on different gateways can now reach each
   other, which is what open mesh already means for devices on one gateway.
3. No new mechanism. This reverses a default; the graph, its invariants and its tests are those of
   0166. The registered residual in `siteLinkGraphFrom` ("devices-on-SPOKES cross-site") is closed
   by this graph, not by putting the pool on more than one peer.
4. The earlier rulings stand: no NAT at the hub (device addresses are preserved end to end) and no
   per-grant AllowedIPs churn on far gateways (D-A3b-1). What changes on a device connect, revoke or
   move is the hub's peer list, which is the cost 0166 already accepted.

## What it is not

It gives the experience of a mesh — one connection, everything reachable, no gateway to choose —
but traffic still travels gateway to gateway through the hub. A device does not open a direct tunnel
to every network. Throughput and latency follow the hub path; pin a second hub for redundancy.

## Still open

- A device that an administrator moves to another gateway must reconnect by hand (the client holds
  the old gateway's endpoint). After this change there is no reason to move a device for reach.
- New devices still land on "the first active gateway". Harmless for reach now; worth changing to
  "nearest" or "the hub" later for latency.
- A gateway with no reachable WireGuard endpoint cannot be a carrier; the dashboard already says so.

## Proof

- Live walk above, both directions of the rule matrix, from a device on the non-hub gateway.
- Database: `TestCrossGateway…` in `internal/tenancy` now asserts the default is enabled.
- Full API suite (open edition, all shards) against an isolated PostgreSQL 16 with 0237 applied:
  83 packages pass. The only test that needed a change was the one that pinned the old default and
  assumed an untouched organization is off.
