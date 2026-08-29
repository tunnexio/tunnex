# S22 route-readback hotfix — decisions

## Observed failure

On a host-network Kubernetes connector, `wg0` has the kernel-created connected
route for the device pool alongside Tunnex's static, metric-tagged route. The
node agent enumerates routes with `ip route show ... proto static metric 8021`.
On the live AKS node, `iproute2` renders the matching connected route as
`10.99.0.0/24 scope link`, omitting the filter attributes. `parseOwnedRoute`
then rejects the line and aborts desired-state reconciliation before it applies
the WireGuard peer roster.

## Decisions

1. **Enumerate broadly, classify narrowly — locked.** Read all routes on the
   Tunnex interface and retain only routes that carry both existing ownership
   attributes (`proto static`, metric `8021`). Kernel-managed connected routes
   are unrelated state and must be ignored, not treated as a reconcile error.
2. **Keep the ownership marker unchanged — locked.** The static protocol and
   metric remain the sole deletion authority; this hotfix neither changes route
   ownership nor broadens pruning.
3. **Prove the live rendering — locked.** Add a regression covering the
   `scope link` line beside a valid owned route, then run the focused node-agent
   tests before any deployment.

## Non-goals

No changes to Kubernetes VIP/DNAT, policy evaluation, client routes, gateway
selection, or the existing ownership metric are in scope.
