# F08 deny-to-allow live evidence

Disposable agent `f08-live-20260816T0805Z` was enrolled through `aws-gw-1` and reached active lifecycle with runtime desired/applied/attempted revisions `1/1/1`. The Ubuntu service was active with zero restarts, its managed files were `root:root 0600`, the `runtime` WireGuard interface had a non-zero handshake, and route intent contained `10.99.0.0/24`.

Tuple: source agent above, destination `10.99.0.200`, TCP port `18080`.

## Before the grant

The released Access Policies route returned `denied` and first blocker `no_matching_grant`. The ordered checks independently proved:

- `agent_active`, address `10.99.0.7`;
- `runtime_ready`, desired/applied `1/1`;
- `gateway_reporting`, gateway `aws-gw-1`;
- `destination_ip`;
- `route_configured`, agent prefix `10.99.0.0/24`;
- `no_matching_grant`, enforcing mode, compiled policy hash `e7d790ab4da9`, version 6;
- `applied_policy_current` with the same hash.

## Disposable grant

The owner created resource `f08-target-20260816` (`10.99.0.200/32`, TCP `18080`) and one agent-source rule through the released UI. The same tuple then returned `allowed` with:

- exact rule ID `01a009cf-0c1f-79ad-9a6b-39f6d900e1c8`;
- compiled and applied policy hash `95b678aca708`;
- policy version 6;
- the same agent, gateway, route and runtime revision facts.

The diagnostic surface offered no probe, apply, fix or policy-mutation action. No packet or DNS request was sent by Test Access.
