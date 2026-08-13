# SCX-1 — Role-aware logical-site network map (commit-one, decision-first)

**Status:** commit-one. Local review preview is authorized; no production Sites-page wiring,
control-plane mutation, gateway action, or cloud-fabric change is in scope for this slice.

## Outcome

An operator can understand the site-to-site infrastructure in seconds: which logical sites exist,
their approved ranges and behind-host side, which gateways serve each site, which gateway is active
or standby, and whether overlay, local cloud route, DNS and end-to-end traffic have separately
measured evidence.

## D1 — logical sites are the primary objects (LOCKED)

AWS VPC, Azure VNet, on-prem LAN, or equivalent logical sites render as bounded site containers.
Gateways render inside their owning site and are annotations of that site; a gateway may not appear
again as a separate central hub node. This removes the current overlap where the same AWS gateway
reads as both the transit hub and a second infrastructure object.

## D2 — the map describes the data path, not a generic graph (LOCKED)

Each site container shows CIDR, behind-host side, and its local gateway members. A direct,
site-to-site edge describes the encrypted path. The edge carries separate evidence for overlay
handshake, cloud-fabric route target, DNS forwarding and end-to-end traffic; one green-looking
line cannot imply all four. Gateway roles read as primary, standby, active-on-standby, or unknown.

No decorative telemetry animation is permitted. Motion may only identify an observed transition
(for example a failover timeline) and never claim packets are flowing without a measured probe.

## D3 — visual language is compact and accessible (LOCKED)

Solid green means a verified source-to-destination proof. Blue means the encrypted overlay is
fresh but is not a traffic claim. Amber dashed means attention, transition, or a required cloud
action. Unknown is visibly distinct from healthy. Color is redundant with text/icon labels and
every site, edge and state is keyboard reachable with an explicit accessible name.

## D4 — interaction opens one operational detail, not another topology (LOCKED)

Selecting a site opens its detail pane: gateway pair, routed ranges, cloud-route truth, DNS state,
validation history and a copyable manual runbook when automation is not armed. Hover/focus on an
edge explains the exact meaning and evidence timestamp. The map does not expose raw pin/unpin
controls; role changes remain guided actions owned by SCX-1b.

## D5 — local preview is fixture-backed and reviewable (LOCKED)

The first deliverable is a browser-only local preview using production-shaped deterministic data:
a healthy AWS/Azure pair, same-cloud primary/standby, an active failover, cloud-route unknown,
DNS unavailable, long names/CIDRs and a one-gateway site. It exercises site select and edge detail
only. The preview makes no API call and cannot mutate CP, gateways, cloud routes or DNS.

## Non-goals

- No hub-election, route, DNS-forwarding, policy or gateway lifecycle behavior changes.
- No provider connector, live packet probe, background polling, topology canvas, or synthetic
  throughput visualization.
- No product deployment until the local proof is reviewed and accepted.

## Proof and stop condition

The preview is accepted only if each fixture state has visible, non-fabricated evidence labels;
the overlap case cannot be reproduced; a keyboard-only reviewer can inspect site and edge details;
and long values do not obscure the active path. Stop after the preview plus focused view-model tests.
Any need for a new API field, real-time telemetry, or a map action not already named above halts
this slice for a Founder decision rather than expanding it silently.
