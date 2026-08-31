# S20.5 Leg 7a — supported-abort pre-fix reconciliation

- Snapshot: `2026-08-31T19:25Z`–`2026-08-31T19:29Z`
- Context: `tunnex-aks-ha-walk-admin`
- Namespace: `tunnex-s205`
- Release: `s205-fail-abort`
- Lifecycle claim: `4fd62d46-9904-40a2-bf13-303c561db99d`

This was a read-only reconciliation. No Kubernetes, control-plane, cloud, or
repository object was changed while the snapshot was collected. No Secret data,
token, key, certificate, kubeconfig, or service-account credential was read or
recorded.

## Exact interrupted-install state

- Helm release `s205-fail-abort` was absent.
- Canonical Job `s205-fail-abort-tunnex-gateway-preflight` remained active with
  UID prefix `4b708cee`, resourceVersion `882078`, and the prior canonical hook
  policy `before-hook-creation,hook-succeeded`.
- Its controller-owned Pod (UID prefix `62999f30`) remained Pending because the
  controlled failure used a syntactically valid node selector that no node has.
- Immutable lifecycle anchor `s205-fail-abort-lifecycle` had UID prefix
  `b8608c9b`, resourceVersion `883911`, state `aborting`, request prefix
  `50ab333c`, install-operation prefix `ba71b553`, and epoch `2`.
- Immutable Secret `s205-fail-abort-bootstrap` had UID prefix `af85b505` and an
  exact owner reference to that lifecycle anchor. Only metadata was inspected.
- The exact control-plane install operation was `taken_over`; `aborted_at` was
  absent. The token-blind lifecycle claim was generation `1`, acknowledged,
  unconsumed, and not yet aborted. Its sealed response was absent.

Disposition: this is the crash-after-successful-Helm-uninstall replay shape.
The supported `tunnex k8s abort-install` path must validate and delete only the
canonical failed hook Job/Pod, re-prove release/workload absence, finalize the
claim abort, and then remove the owned Secret and anchor. A manual `kubectl
delete`, chart patch, or database edit is disqualifying and was not used.

## A/B health guard

- Host-posture status was desired `2`, Ready `2`, unavailable `0`.
- Both A and B Helm releases were deployed at revision `1` with the exact
  a229 candidate chart and digest-pinned node image.
- Both gateway Deployments were `1/1` Ready and Available; their control-plane
  identities were active with recent heartbeats and no policy-desync marker.
- A endpoint: `20.115.124.74:51820`; node-ID prefix `01a058cf`; PVC UID prefix
  `399149a2`; current Pod UID prefix `af355f1a`.
- B endpoint: `20.85.230.33:51820`; node-ID prefix `01a058d9`; PVC UID prefix
  `5ed83811`; current Pod UID prefix `12de816a`.
- Both current Pods were Ready. Their most recent terminated container states
  were `Completed` with exit code `0`.

Namespace inventory contained only the expected A/B release resources and the
exact stranded Leg 7a Job, Pod, anchor, and Secret. Events showed the controlled
failure, the deliberate sequential A/B reschedules, and the two bounded
`rp_filter` fixtures; no unrelated namespace mutation was observed. This is a
namespace-scoped statement, not a cluster-wide or Azure activity-log audit.
