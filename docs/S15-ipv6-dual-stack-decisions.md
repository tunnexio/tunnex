# IPv4/IPv6 dual-stack gateway decisions

## Goal

Clients and gateways should support IPv4 and IPv6 without silently losing internet
connectivity when a gateway has no usable IPv6 egress.

## Decisions

- **Capability gate:** A gateway reports IPv4 egress and IPv6 egress independently.
- **Full-tunnel routes:** Emit `0.0.0.0/0` only when IPv4 egress is available; emit `::/0`
  only when IPv6 egress is available.
- **Safe fallback:** An IPv4-only gateway gets an explicitly labelled IPv4-only full tunnel;
  the control plane must not claim dual-stack coverage it cannot prove.
- **IPv6 egress:** Prefer routed IPv6 connectivity from the provider; NAT66 is a fallback,
  not the default architecture.
- **Stale capability:** A stale or missing IPv6 report disables IPv6 routes for new profiles
  and is surfaced as an actionable gateway health condition; it does not block IPv4-only use.
- **Verification:** Test IPv4-only, IPv6-only capability loss, and fully dual-stack gateways
  in both open and enterprise builds before release.

## Delivery sequence

- **Slice 1 (this branch):** report IPv6 egress independently and add the guarded NAT66
  ruleset path. This is telemetry-only for existing device enrollment; no existing profile
  or full-tunnel gate changes until IPv6 address allocation and client kill-switch behavior
  are landed together.
- **Slice 2:** add persistent IPv6 pool/device allocation and dual-address WireGuard config.
- **Slice 3:** gate `::/0` on verified dual-stack capability. When IPv6 is unavailable, mint
  an explicit IPv4-only full-tunnel profile whose client kill-switch blocks non-tunnel IPv6;
  never silently leak IPv6 or require customers to enable IPv6.

## Addressing decision

- Use a deployment-configured ULA `/48` as the IPv6 source pool. Allocate one non-overlapping
  `/64` to each organization and one `/128` per device; the gateway owns the org `/64` on
  its WireGuard interface. The pool is not guessed from the IPv4 pool and is never a public
  provider prefix.
- Existing organizations remain IPv4-only until an IPv6 `/64` is assigned. This makes the
  migration additive and gives operators an explicit rollback: remove the IPv6 pool setting,
  keep the existing IPv4 profiles, and no existing peer is rewritten.
- A missing, malformed, overlapping, or exhausted IPv6 pool is a configuration error surfaced
  before dual-stack enrollment; it must not fall back to a fabricated address.

## Deferred

- Provider-specific IPv6 provisioning walkthroughs (AWS, GCP, Azure) are documentation work
  after the core capability and route-gating slice.
