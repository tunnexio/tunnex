# S20.5 live AKS walk session

- Started (UTC): `2026-08-31T04:45:34Z`
- Local branch: `story/route-readback-hotfix`
- Session-start HEAD: `074ddfaa`
- Target subscription: `Azure subscription 1` (`a9a140db-bb16-4113-a5c5-2108c61aca3f`)
- HA candidate cluster: `tunnex-aks-ha-walk` / `tunnex-aks-ha-walk-eastus`
  (East US, Kubernetes `1.35.7`, two Ready Linux nodes)
- GitOps candidate cluster: `tunnex-aks-livewalk` /
  `tunnex-aks-livewalk-20260829` (South India, Kubernetes `1.35.7`, one
  Ready Linux node)
- Evidence policy: redact tokens, credentials, private keys, certificates, kubeconfigs, and service-account tokens.

## Session status

Read-only live inventory completed. No AKS, control-plane, database, container,
Kubernetes, credential, or Azure mutation has occurred in this session yet.

## Read-only baseline disposition

- Control plane host: `tunnex-cp` (`20.219.77.240`). Its internal API readiness
  returned `200 ok leader`; all seven Compose containers were running with zero
  restarts during the snapshot.
- The live database is migration `129` with `dirty=false`. S20.5 migrations
  `130` and `131`, their tables, and lifecycle HTTP routes are absent; lifecycle
  route probes returned `404`. A matching candidate control-plane deployment is
  therefore a prerequisite for Legs 1, 2, 3, and 7a.
- The running API, web, and node containers are custom walk images and do not
  match the signed `v0.1.15` release descriptor. No candidate provenance has
  been claimed.
- East US currently has two legacy gateway Helm releases, four retained PVCs,
  and two reusable static gateway public IPs: `20.115.124.74` and
  `20.85.230.33`. The regional public-IP quota is `3/3`, including the AKS
  outbound IP, so the clean walk must retain and reuse the two gateway IPs
  rather than allocate new ones.
- South India contains a manually assembled gateway/operator baseline rather
  than a Helm-owned zero-touch baseline. A completed privileged debug Pod also
  remains.
- Credential material was found in last-applied Secret annotations for the
  South India bootstrap and operator Secrets. No value is recorded here. The
  consumed join token cannot replay, but the operator credential remains live;
  it must be rotated and revoked before that cluster is reused.

## Current gate

Leg 0 is not yet eligible to pass. It requires one immutable source identity
whose CLI, API, node, operator, and four chart artifacts all agree, followed by
an explicitly reviewed clean-baseline teardown and credential rotation.

## Proposed clean-baseline targets (review only; not executed)

East US HA cluster (`tunnex-ha`):

- Helm releases `tunnex-gw-a` (revision 12) and `tunnex-gw-b` (revision 9),
  including their Deployments, Services, Pods, ReplicaSets, Helm history
  Secrets, and legacy join Secrets `gw-a-join` and `gw-b-join`;
- PVCs `tunnex-gw-a-tunnex-gateway-state`,
  `tunnex-gw-a-tunnex-gateway-state-v2`,
  `tunnex-gw-b-tunnex-gateway-state`, and
  `tunnex-gw-b-tunnex-gateway-state-v2`;
- the four backing Azure disks have reclaim policy `Delete`, so PVC removal is
  destructive and not recoverable unless snapshots are created first;
- retain `acr-pull`, the AKS cluster, its two nodes, and static public IPs
  `20.115.124.74` and `20.85.230.33` for the clean reinstall.

South India GitOps cluster (`tunnex-system`):

- rotate Deployment `tunnex-operator` to a newly named immutable credential
  Secret, prove authenticated readiness, then revoke the old control-plane
  machine credential before removing Secret `tunnex-operator-credential`;
- deregister/finalize `TunnexCluster/aks-gitops-walk` after clearing any
  referenced scopes or access requests, which also removes its owned
  `TunnexExposedService/gitops-demo` and `TunnexGrant/gitops-pawan-to-demo`
  state through the supported product lifecycle;
- remove the manually assembled gateway Deployment/Service, consumed bootstrap
  Secret, completed preflight/debug Pods, and review its retained PVC
  `tunnex-gateway-tunnex-gateway-state` separately because its backing disk also
  has reclaim policy `Delete`;
- retain the AKS cluster and public IP `20.219.91.16` for the GitOps walk.

No target in this section has been changed or removed.
