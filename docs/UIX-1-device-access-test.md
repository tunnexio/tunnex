# UIX-1 — "can this device reach that?" for people's devices

Story branch: `platform-ui-improvement`. Founder request, 2026-11-23: the dashboard's "Test access"
must work for employees' devices, not only for AI agents.

## What is true today

`GET /organizations/{orgId}/agents/{deviceId}/test-access` explains one managed agent's path to a
destination, protocol and port. It reads lifecycle, runtime, gateway and the exact compiled policy;
it never sends traffic or resolves DNS. The dashboard exposes it on Access Policies as "Test access",
and the picker lists agents only.

The policy half is not agent-specific. `nodes.Service.EvaluateAgentAccess` takes a device id, its
tunnel address and its home gateway, finalises that gateway's compiled artifact and calls
`policyspec.EvaluateAccess`, the same five-field match the gateway enforces. Nothing in it depends on
the device being an agent.

An administrator asked why one person's laptop cannot open one service has no answer in the
product. They read rules by eye.

## Decision

Add a second read-only endpoint for ordinary devices that reuses the same evaluation:

    GET /api/v1/organizations/{orgId}/devices/{deviceId}/test-access
        ?destination=<ip or hostname>&protocol=tcp|udp&port=1..65535

It returns `DeviceAccessDiagnostic`: `overall` (`allowed`, `denied`, `inconclusive`), `first_blocker`
and an ordered list of checks, each `pass`, `fail` or `inconclusive` with a short code, a sentence
and facts. The check item reuses the existing `AgentAccessCheck` schema.

Checks, in order:

1. **Device** — active with a tunnel address (`device_active` / `device_not_active`).
2. **Posture** — not blocked by device posture (`posture_not_blocking` / `posture_blocked`).
3. **Gateway** — the device's home gateway is active and was seen recently
   (`gateway_reporting` / `gateway_not_reporting`), using the freshness rule the gateway list uses.
4. **Destination** — a literal address, or a hostname the compiled policy holds answers for
   (`destination_ip` / `fqdn_generation_active` / `device_dns_not_observed`).
5. **Route** — the destination is reachable from the home gateway: inside the organisation's device
   pool, inside one of the home gateway's own approved site ranges, or covered by a compiled route
   (`route_configured`, with a fact naming which / `route_not_configured` /
   `route_destination_unresolved`). Compiled routes alone hold only remote ranges, so reading only
   them would deny every local destination. For a full-tunnel device an uncovered destination is
   `inconclusive`, not a failure: the gateway's default route is not evaluated here.
6. **Rule** — the compiled policy permits the tuple, naming the rule
   (`matching_grant` / `policy_not_enforcing` / `no_matching_grant`).
7. **Applied** — the gateway reports the current compiled policy in force
   (`applied_policy_current` / `applied_policy_mismatch` / `applied_policy_not_observed` /
   `applied_policy_not_required`).

The agent endpoint's runtime and managed-route-intent checks are dropped: a person's device has no
managed runtime, and its client routes are whatever the gateway's compiled routes yield.

When the home gateway's compiled policy cannot be evaluated at all, one `compiled_policy_unavailable`
check (inconclusive) stands in for the route and rule checks. A hostname with no compiled answers
omits the rule check, so a result holds six or seven checks.

### Authorisation

`policy:view` on the organisation, the permission that already gates reading the rules being
explained. The device must belong to the organisation; an agent device id is refused with 404 so
the two endpoints do not overlap. The response carries no key, configuration or credential.

### What it does not claim

It evaluates the compiled policy of the device's **home gateway**. With cross-gateway client
connectivity a packet may also cross the hub and the destination's gateway; those apply the same
compiled rules, but their applied state is not read here. The route check's sentence says "home
gateway" so the limit is on the screen, not only in this paper. It never probes: `allowed` means the
rules and routes permit the flow, not that the service answered.

## Dashboard

"Test access" on Access Policies gains a subject choice: a device (people) or an agent. Devices are
listed with their owner. The result renders with the existing check list.

## Tests

- Unit: check ordering and `overall` for active/blocked/revoked device, missing gateway report,
  literal and hostname destinations, enforcing and off modes.
- Database-backed handler test: allowed by a rule, denied without one, 404 for another
  organisation's device and for an agent id, 403 without `policy:view`.
- Dashboard: subject picker, request path, result rendering.

## Rollback

Additive endpoint and UI. Removing them changes no stored data.
