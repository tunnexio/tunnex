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
- **Stale capability:** A stale or missing IPv6 report blocks new dual-stack enrollment and
  is surfaced as an actionable gateway health condition.
- **Verification:** Test IPv4-only, IPv6-only capability loss, and fully dual-stack gateways
  in both open and enterprise builds before release.

## Deferred

- Provider-specific IPv6 provisioning walkthroughs (AWS, GCP, Azure) are documentation work
  after the core capability and route-gating slice.
