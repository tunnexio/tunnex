# K8L-1 — the host-posture manager must recognise the gateway the chart actually ships

Story branch: `story/kubernetes-launch-fixes`. Found on 2026-11-22 while installing release v0.1.44
on a one-node k3s cluster (Flannel, Kubernetes 1.37) with `tunnex k8s install`.

## What happened

`tunnex k8s install` waited the full Helm timeout (10 minutes) and failed with
`release gw-a failed ... context deadline exceeded`. The gateway pod never left `Init:0/1`:

- init container: `{"status":"blocked","reason":"wait for live host-posture CNI ownership: context deadline exceeded"}`
- host-posture manager: `k8s_host_posture_candidate_ignored ... reason="gateway NET_ADMIN security contract is missing"`

## Cause

Two parts of the product disagree about the gateway container's capability set.

- The gateway chart adds `NET_RAW` when `aiVPN.enabled` is true, and that value has defaulted to
  true since 2026-10-02 (commit 4a5cdbbd). The chart contract test pins this set.
- The host-posture manager (`apps/node/internal/hostposture/kubernetes.go`) accepts a pod as a
  gateway owner only when the added set is exactly `NET_ADMIN`, `NET_BIND_SERVICE`. That check has
  not changed since S20.5 (2026-09-06).

So with chart defaults the manager ignores every gateway pod, on every cluster type. The CLI has no
flag to turn `aiVPN` off, so the CLI install path cannot succeed at all.

## Decision

1. The manager accepts exactly two capability sets for the `gateway` container:
   - `NET_ADMIN`, `NET_BIND_SERVICE` — only when `TUNNEX_AI_VPN_AUTO` is not the literal `"true"`;
   - `NET_ADMIN`, `NET_BIND_SERVICE`, `NET_RAW` — only when `TUNNEX_AI_VPN_AUTO` is the literal `"true"`.
   Anything else (for example `SYS_ADMIN`, or `NET_RAW` without the AI VPN switch) is still ignored.
   This keeps the check exact: the capability set must match what the chart renders for that mode.
2. No chart change. `NET_RAW` is needed by VPN inference to bind its socket to the WireGuard
   interface; removing it would break that feature.
3. Tests on both sides pin the same two sets: the chart contract test
   (`deploy/k8s-gateway-chart-contract_test.sh`, already present) and new manager unit tests that
   feed the manager the default-chart pod shape.

## Not in this story

- CNI coverage for Flannel/Calico/Cilium (`no_registered_adapter`) — K8L-2, expected to be the next
  blocker once the pod starts.
- The install failure message hiding the reason — K8L-3.

## Proof

- Unit: default-chart pod (with `NET_RAW` + `TUNNEX_AI_VPN_AUTO=true`) is accepted; `NET_RAW`
  without the switch is ignored; `SYS_ADMIN` is still ignored.
- Live (2026-11-22, k3s 1.37, Flannel): with the rebuilt agent image the init container reports
  `{"status":"ready"}`, the gateway container starts and enrols. It then stops at the next blocker,
  `unknown NAT POSTROUTING rule coverage` (K8L-2), so the install as a whole still does not finish
  on Flannel.
