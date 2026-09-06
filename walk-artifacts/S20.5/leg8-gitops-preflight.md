# S20.5 Leg 8 — isolated GitOps preflight

- Snapshot: `2026-08-31T19:57:36Z`
- Azure subscription: `Azure subscription 1`
- GitOps cluster: `tunnex-aks-livewalk` / `tunnex-aks-livewalk-20260829`
- HA guard cluster: `tunnex-aks-ha-walk` / `tunnex-aks-ha-walk-eastus`

The read-only queries were issued through the control-plane VM's system-assigned
Azure identity with `az aks command invoke`. No token, kubeconfig, Secret data,
private key, certificate, or registry credential was read or recorded.

## South India clean baseline

The `tunnex-system` namespace was Active with UID prefix `606a966a` and
resourceVersion `34103`. Its namespace-scoped inventory contained only the
default ServiceAccount. The following exact scoped checks returned no Tunnex
objects:

- cluster-wide resources selected by `app.kubernetes.io/part-of=tunnex`;
- CRD names containing `tunnex.io`;
- Helm releases matching `tunnex` in any namespace; and
- Deployments, Jobs, Secrets, Roles, and RoleBindings in `tunnex-system`.

This is a fresh Leg 8 start point. Later refusal fixtures must restore this
baseline before the next case because Helm uninstall does not delete retained
cluster-scoped CRDs.

## East US HA isolation guard

The separate HA cluster remained untouched while the South India baseline was
collected:

- `s205-gw-a-tunnex-gateway`: UID prefix `cb182f81`, `1/1` Ready;
- `s205-gw-b-tunnex-gateway`: UID prefix `085e180b`, `1/1` Ready;
- both Deployments used
  `tunnex-node-agent@sha256:777638c6fbd79caae173a7a603d335adb814165e6e0b80e0af6bb5f1afaa217e`;
- A and B Helm releases were deployed at revision `1` from candidate
  `0.0.0-walk.shaa229b0ebcd5b3dc9571bebd170380e17`.

The East US namespace also still contained the deliberately stranded Leg 7a
failed-hook fixture recorded in `leg7a-supported-abort-prefixed-state.md`. It is
not a GitOps fixture and must not be used for cluster-scoped CRD adoption or
refusal tests.

## Candidate boundary

The a229 candidate above is only the preserved HA baseline. Leg 8 final success
must use a new private candidate built from the eventual clean committed story
head. Reusing a229 after the pending lifecycle and desktop corrections would
violate the same-candidate provenance rule.
