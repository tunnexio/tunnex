# Kubernetes: what is planned after the launch fixes

Written 2026-11-22, after the K8L-1 to K8L-10 stories on `story/kubernetes-launch-fixes`. The founder's
ruling: plan these four and do them later; none of them blocks the launch.

Nothing here is started. Each needs its own decisions paper before code, and a live walk on a real
cluster before it is called done.

## What works today, and for whom

In-cluster gateway on Amazon EKS, Azure AKS, Google GKE Standard, and self-managed clusters using
Flannel with kube-proxy; exposing Services by address and name with per-port access rules; one
connection reaching every cluster and network; management from the dashboard or from Git; surviving
a 60-second Kubernetes API outage; restarting cleanly.

Walked live in this work: GKE Standard and k3s. EKS was walked in S20.5. AKS has never been walked
live.

## The four, in the order recommended

### 1. Calico and Cilium (was #4) — about 3 to 5 days

- **Gives the customer:** the gateway runs on clusters using these two network plugins, including
  GKE Dataplane V2 and EKS/AKS with Cilium.
- **Without it:** the gateway reports not-ready on such a cluster, naming the NAT chain it could not
  read. It no longer fails silently.
- **Who is stopped today:** anyone running their own cluster on Calico or Cilium. This is the
  largest group, which is why it is first.
- **Shape of the work:** `apps/node/internal/k8snetprep/observed.go` already proves "no rule can
  source-NAT traffic bound for the tunnel range". Calico masquerades behind ipset matches
  (`cali40masq-ipam-pools`), which the walk treats as unreadable; it needs to read set membership.
  Cilium in eBPF masquerade mode has no nft rules to read and needs a different proof (its own
  configuration). Each needs a real cluster and a live walk.

### 2. High availability that can be trusted (was #5) — a week or more

- **Gives the customer:** a second gateway for one cluster, so access continues when a gateway or
  its node fails.
- **Without it:** one cluster has one gateway. If it goes down, that cluster's Services are
  unreachable until the pod is back, usually one to two minutes.
- **Shape of the work:** the feature exists behind a setting, but the 2026-11-22 review found five
  serious problems (findings 4, 5, 6, 7 and 10): one organization's bad pool stops lease renewal for
  every organization; a handoff has no timeout; a leader flag can latch false until restart; a
  handoff cannot start once the old lease has expired; one Service with no ready pods withdraws the
  whole pool. Needs a walk with two pool gateways plus a separate edge gateway. Until then, describe
  it as a preview.

### 3. Lower privileges for the gateway (was #3) — one to two weeks

- **Gives the customer:** a security team can approve it without an exception; it runs on GKE
  Autopilot and in namespaces under the restricted Pod Security Standard.
- **Without it:** every node runs a privileged helper (the host-posture DaemonSet) and the gateway
  uses the host network with NET_ADMIN. Clusters that forbid privileged pods cannot use it.
- **Shape of the work:** the largest of the four. Today's design depends on host networking and on
  changing node sysctls and firewall chains. A lower-privilege gateway probably means a pod-network
  WireGuard with a userspace datapath, or a split where only a small, audited part is privileged.
  Start with a design paper comparing the options.

### 4. kubectl and cluster API access through Tunnex (was #6) — a week or more

- **Gives the customer:** developers reach the cluster's API server through Tunnex (`kubectl get
  pods`) without a separate VPN or a public API endpoint, with access rules and an audit trail.
- **Without it:** nothing is blocked; today Tunnex reaches Services inside a cluster, not the
  cluster's control API.
- **Shape of the work:** a new feature. Exposing the `kubernetes` Service like any other Service is
  the cheap version but gives no identity to the API server; the full version is an authenticating
  proxy that maps a Tunnex user to Kubernetes RBAC.

## Smaller items left open by the launch fixes

- Publish the `tunnex-cp` chart with releases. The release workflow lists charts in six places, and
  a new registry package starts private, which fails the workflow's own anonymous-pull check until
  an owner makes it public (K8L-10).
- A way to recover a lost first-administrator password (K8L-10).
- Readiness can drop for one pass with "CNI rules changed across semantic observation" when
  kube-proxy rewrites its chains between two reads (K8L-2, K8L-9).
- The operator should reject immutable edits at admission, not only report them (K8L-8).
- A release-time test of the charts and CLI on Helm 4 (K8L-3).
- The CLI checksum file names its entries `cli-artifacts/…`, so `sha256sum -c` fails for a user.
- Walk AKS live.
- The desktop client cannot recover when the control plane or the signed-in user changes
  (`managed_device_owner_mismatch`); it needed a manual state reset.
