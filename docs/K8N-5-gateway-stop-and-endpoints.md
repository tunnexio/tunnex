# K8N-5 — what a stopped gateway leaves on its node, and Service endpoints inside the device range

Story branch: `k8n/egress-stop-endpoints` (from `story/kubernetes-next`). Written 2026-11-24.
Two items in the in-cluster gateway (`apps/node/internal/egress`). Facts about Tunnex come from the
code at this branch, from `origin/main` and from the `v0.1.44` tag where stated. Nothing here was run
on a cluster. The packet results come from privileged containers with their own network namespaces
and real `nft`. Anything else is marked **unconfirmed**.

## Item 1 — traffic dropped after a normal gateway stop

### The observation

A container test saw that after the gateway's shutdown the `ip tunnex` table still had its chains,
among them `forward` hooked with `policy drop` and no rules. A router that forwarded plain traffic
before the stop dropped it after.

### What the code does on each path (before the fix)

The table the gateway applies while it runs (`rulesetWith`) is `add table` + `flush table` + the
full table. In Kubernetes mode it has, per family:

| family | chain | hook | policy |
|---|---|---|---|
| ip | `tunnex_posture_owner` | none | (regular chain, one marker rule) |
| ip | `prerouting` (only while a VIP is mapped) | nat prerouting, -101 | accept |
| ip | `postrouting` | nat postrouting, srcnat - 1 | accept |
| ip | `forward` | filter forward, filter | **drop** |
| ip6 | `tunnex_posture_owner`, `postrouting`, `forward` | as above | forward **drop** |

While it runs, `forward` lets ordinary node traffic through with
`tunnex_native_forward_passthrough` (both interfaces outside the tunnel set). Only
`ct state invalid drop`, which comes first, also applies to native traffic.

The paths:

1. **Normal stop.** SIGTERM, or any `return` from `main` after the egress manager is built
   (`apps/node/cmd/agent/main.go`, `defer egressMgr.Teardown`). This includes
   `desired_state_startup_base_failed`, which is how a gateway exits when it cannot fetch its desired
   state at start. `Teardown` withdraws the CNI rules, then the Docker rules, then
   `reduceToHostPostureMarkers`. That function checks the marker chain in both families, then applies
   `hostPostureMarkerOnlyRuleset`: `add table` + `flush table` + the marker chain. **`flush table`
   removes rules and keeps chains.** What remains is every chain above, empty, with `forward` still
   hooked at `policy drop` in both families. Every packet the node forwards is dropped. Then the
   deferred `shutdownDataplane` drains `wg0` (keys, peers, addresses) and leaves the link to the
   manager.
2. **Kill.** SIGKILL, OOM, `os.Exit`, or a panic outside `main`'s goroutine. No `Teardown` runs. The
   full running table stays, the native passthrough with it. Native traffic is unaffected. `wg0` keeps
   its peers and the last policy keeps applying to tunnel traffic.
3. **`EmergencyWithdrawK8s`** (the ownership lease found no fresh baseline). This is not a stop: the
   process goes on. It flushes only `prerouting` (the DNAT rules) and checks the readback. The rest of
   the running table is untouched. Native traffic is unaffected. A separate finding is below.
4. **Ownership withdraw** (`withdrawalOrder` / `withdrawAll`). The process goes on. On the
   Kubernetes surface (`production_k8s_surface.go`, `ApplyStage`) the egress calls are:
   - `ReconcileOVPNTunnel`;
   - `SetPolicy` + `ResolveK8sVIPs` + `Reconcile`;
   - `SetPolicy` + `ReconcileDNSVIPsWithCandidates`.

   They re-render the ordinary table with the non-serving state. It is always the full table, with
   the passthrough. Native traffic is unaffected.
5. **The host-posture manager's last-owner cleanup** (`hostposture.RestoreAndCleanup`). This runs
   once the exact-node owner list is empty, meaning no gateway pod on the node without a
   `deletionTimestamp`. It checks the marker and runs `nft delete table` for both families. Nothing
   remains. It runs on the manager's 2-second tick. It does **not** run while the owner list cannot
   be read: "API ambiguity must never cause last-owner restoration".

### When it bites a customer

The marker-only table is kept as long as the manager still sees an owner on the node. Each pass, the
manager checks only the marker chain (`Enforce`). The cases:

- **The container restarts inside the same pod**, for example after a liveness failure, or after the
  agent exits on its own through a `return`. The pod is still an owner. From the old process's stop
  until the new process's first egress pass, the node drops every forwarded packet. Normally that is
  seconds. If the new process also exits through a `return`, the node keeps dropping while the
  container crash-loops. One example: the control plane is unreachable, so
  `desired_state_startup_base` fails on every attempt.
- **The gateway pod is deleted while the manager cannot read the owner list**, for example during a
  Kubernetes API outage. The manager keeps the last owners, so the marker-only table stays until the
  API answers.
- **A pod deletion with the API healthy** is short. The pod gets its `deletionTimestamp`, and the
  manager deletes the table within about 2 s, often before the gateway has finished stopping. This
  assumes no replacement gateway pod becomes an owner on the same node first. The chart's `Recreate`
  strategy makes that unlikely, but it is **unconfirmed**.

"Forwarded" means traffic the node routes, not traffic it originates or receives. On the node, that
is traffic from pods to other nodes, Service traffic that kube-proxy DNATs on this node, and traffic
from other nodes to pods here. With `br_netfilter`, bridged pod-to-pod traffic counts too. A CNI with
eBPF host routing can bypass the netfilter forward hook. **Unconfirmed** which CNIs and modes avoid
it.

**Is `main` affected?** Yes. `origin/main` (60aae74f) and the released tag `v0.1.44` have the same
`Teardown`, `reduceToHostPostureMarkers` and `hostPostureMarkerOnlyRuleset` text, byte for byte. In
v0.1.44 the gateway chart runs the agent with `hostNetwork: true` and sets `TUNNEX_K8S_MODE=true`.
`configureEndpointSource` reads that variable and the agent calls `SetKubernetesMode(true)`, so
`Teardown` takes the Kubernetes branch, as on this branch. The witness replays that released text
(`releasedStopRuleset`). It is the same string as main's template, with the marker substituted.

**How a customer on v0.1.44 would notice:** after the gateway container restarts, workloads on the
gateway's node lose their network. Their Services time out, and so do connections from other nodes
to pods there. This lasts until the gateway is ready again, or for as long as it crash-loops. On the
node, `nft list table ip tunnex` shows `chain forward { type filter hook forward priority filter;
policy drop; }` with no rules, and the same in `ip6 tunnex`. Deleting the gateway pod, with the API
healthy, should clear it (see the qualification above).

### Decision

On a stop, leave no hooked chain that can affect traffic outside the tunnel. Keep the tunnel itself
closed, and keep exactly what the manager relies on.

What the manager relies on, from the code: `tunnex_posture_owner` in `ip tunnex` and `ip6 tunnex`,
holding exactly one rule, `counter comment "tunnex_host_posture_v1"`
(`hostposture.ValidateNFTMarkerChain`, used by the manager's `Prepare`, `Enforce` and
`RestoreAndCleanup` and by the gateway's own stop). The AWS proof (`validateTunnexPostrouting`) reads
the same chain while a gateway runs. Nothing reads the other chains of the table, and nothing keeps a
table handle (`NFTTableReceipt` is family, name and comment).

The stop table, per family, in one `nft -f` transaction:

```
flush table ip tunnex
add chain ip tunnex prerouting
delete chain ip tunnex prerouting
add chain ip tunnex postrouting
delete chain ip tunnex postrouting
add chain ip tunnex forward
delete chain ip tunnex forward
add chain ip tunnex forward { type filter hook forward priority filter; policy accept; }
add rule ip tunnex forward iifname "wg0" counter drop comment "tunnex_stopped_tunnel_drop"
add rule ip tunnex forward oifname "wg0" counter drop comment "tunnex_stopped_tunnel_drop"
add chain ip tunnex tunnex_posture_owner
add rule ip tunnex tunnex_posture_owner counter comment "tunnex_host_posture_v1"
```

The interface match is the tunnel set at the time of the stop: `wg0`, plus the OpenVPN `tun` when
one is active, as a set.

Why this shape:

- **No `add table`.** The stop does not hold the manager's lock. The manager can delete the table
  between the gateway's marker check and its apply. `flush table` on a missing table fails the whole
  transaction. Before, `add table` would have recreated a table nobody owns any more, and the next
  epoch's `CaptureBaseline` refuses that as an "ambiguous pre-Tunnex nft table".
- **`add chain X` + `delete chain X`** removes a chain whether or not it exists (the `prerouting`
  chain exists only while a VIP is mapped). A plain `add chain` with no hook is accepted over an
  existing base chain. This is the idiom `ipsec/guard_render.go` already uses. It needs neither a
  readback of the table nor knowledge of the hook priority the previous process used.
- **The forward chain stays, under the same name and hook, with `policy accept`.** It drops only
  packets that enter or leave a tunnel interface. Deleting the forward chain outright would make the
  stop fail open: `wg0` is drained only after `Teardown`, and the drain can fail
  (`agent_backend_shutdown_blocked`). Keeping the name matters too. The next start flushes and
  re-declares `forward` with `policy drop`, which replaces the guard in place. A guard chain under
  another name would survive into the running table.
- Ordinary node traffic meets no Tunnex rule and no Tunnex drop policy after a stop. The kill path
  is unchanged, and it already passes native traffic.

The VM/site path (`delete table ip tunnex; delete table ip6 tunnex`) is unchanged. It deletes both
tables, so nothing is left. It fails as a whole only if one of the two tables is missing, and the
running table always creates both.

### As built and proved

- `egress_linux.go`: `hostPostureMarkerOnlyRuleset` is replaced by `hostPostureStoppedRuleset(tun)`
  (the text above). It refuses an empty tunnel set or an interface name outside `ifaceRE`, and
  `Teardown` then logs `k8s_host_posture_shutdown_blocked` and applies nothing. The marker check
  before it is unchanged.
- Unit tests (`stop_ruleset_linux_test.go`): the exact stop text, statement by statement:
  - no `add table` or `delete table`, no `policy drop`;
  - every drop is limited to the tunnel interface, and the only hook is the forward guard;
  - the marker is written back in both families;
  - with OpenVPN the guard matches the set `{ "wg0", "tun0" }`, and `Teardown` applies it;
  - unsafe names are refused.

  `TestKubernetesGatewayRolloutShutdownPreservesManagerOwnedNFTMarkers` now requires exactly the
  stop text. The shutdown phase of `TestK8sAPIReturnPathKernel` now also requires no `policy drop`
  and no `postrouting` chain.
- Kernel witness (`stop_state_kernel_linux_test.go`, opt in with
  `TUNNEX_TEST_STOP_STATE_KERNEL=1`, privileged container). The gateway's namespace routes between
  pod A (10.80.0.5), pod B (10.70.0.9, the Service's endpoint) and a device behind `wg0`. "Native"
  means pod A to pod B, arriving with pod A's own address. Run on 2026-11-24 in `golang:1.26.11-alpine`
  (nftables 1.1.x), Docker's Linux 6.8 kernel. All of the following held:

| state | native pod A → pod B | device → exposed Service | device → pod B, no rule |
|---|---|---|---|
| before any gateway (no table) | passes | no path | — |
| gateway running | passes | answers, device source kept | dropped (`tunnex_default_drop`) |
| after SIGKILL (full table left) | passes | — | — |
| after the **released** stop text | **dropped** (2 s timeout) | — | — |
| new process over the released state | passes | answers | — |
| after the **fixed** stop | passes | — | dropped by `tunnex_stopped_tunnel_drop` (counter > 0) |
| new process over the fixed state | passes, ready | answers | — |
| after `EmergencyWithdrawK8s` | passes | withdrawn | — |
| after the ownership withdraw's egress calls | passes | withdrawn | — |
| after the manager's table delete | passes | — | **open** (the control: it is the guard that closes it) |

  Kernel listings recorded by the witness, `ip tunnex` only:
  - after the released stop: `prerouting`, `postrouting` and `forward { ... policy drop; }`, all
    empty; the same `forward` in `ip6 tunnex`;
  - after the fixed stop: `tunnex_posture_owner` with its one rule, and `forward { ... policy
    accept; }` holding only the two tunnel drops. The marker passes
    `hostposture.ValidateNFTMarkerChain` in both families.

  The race with the manager was replayed as well: the tables are deleted between the marker check
  and the apply. The released text recreates both tables, orphaned. The fixed text fails with "No
  such file or directory", `Teardown` logs `k8s_host_posture_shutdown_blocked`, and no table is
  left.

### Separate finding, not fixed here — the emergency path re-opens the mesh

`EmergencyWithdrawK8s` calls `SetPolicy(nil)`. `SetPolicy` marks a policy as received. In
`forwardRules`, a received nil policy renders the legacy blanket mesh: tunnel-to-anything accepts.
If the egress loop runs a pass after the emergency withdraw, with no fresh desired state in between,
the forward chain opens to every tunnel peer still on `wg0`. The emergency path removes the fenced
peers and routes from `wg0` first. The kernel witness shows it. After `EmergencyWithdrawK8s` and one more `Reconcile` in the same
process, `forward` holds `iifname "wg0" oifname != "wg0" accept`, and the device reached pod B
directly with no rule granting it. Whether the real agent runs such a pass before fresh desired
state arrives is **unconfirmed**. This needs its own decision; it is
recorded, not changed.

## Item 2 — Service endpoints inside the device range

### Background

`docs/K8N-review-false-ready.md` finding 4: the walk assumes that traffic bound for the tunnel never
carries a Kubernetes mark (0x2000, 0x4000, 0x8000). That assumption does not hold everywhere. An
EndpointSlice can point a Service at a device address, and anyone who may write EndpointSlices can
create one, for example behind a Service with no selector. kube-proxy (or a CNI's Service
implementation) then DNATs pod traffic to the device, marks it and masquerades it. Refusing such an
address in Tunnex's own DNAT does not cover that path, because kube-proxy does the rewrite, not
Tunnex. The founder ruled: refuse it, do not leave it as an assumption.

### Decision (written before the code): (a), node-level not ready

**(a) is feasible with read-only access the gateway already has.** The gateway chart's ClusterRole
(`deploy/helm/tunnex-gateway/templates/rbac.yaml`) already grants `get`, `list` and `watch` on
`discovery.k8s.io/endpointslices` and on `services`, cluster wide. The watcher
(`k8swatch_linux.go`) already lists and watches `/apis/discovery.k8s.io/v1/endpointslices` with no
namespace and no selector, so every slice in the cluster passes through it. **No RBAC change, no
chart change.** The chart contract test is not touched.

What is checked:

- **Addresses:** every address of every endpoint in every EndpointSlice labelled
  `kubernetes.io/service-name`, whatever its `ready`, `serving` or `terminating` condition. kube-proxy
  treats a missing `ready` as ready and can send traffic to terminating endpoints, so the DNAT view's
  ready-only list is not enough here. Addresses that do not parse as an IP address are skipped; that
  is `addressType: FQDN`. IPv4 and IPv6 are both checked.
- **Slices without the service-name label are ignored.** kube-proxy attaches a slice to a Service
  only through that label, so an unlabelled slice programs nothing. A Service with no selector and a
  hand-written `Endpoints` object is mirrored by the EndpointSlice mirroring controller into labelled
  slices, so it is covered.
- **The device range:**
  - the observed IPv4 subnet of `wg0`, the range the mark proof protects and the one passed to
    `k8snetprep.Reconcile`;
  - the organisation's device pool `PoolCIDR` from the current policy, when set (IPv4 or IPv6);
  - the global IPv6 subnet of `wg0`, when present.
- **Coverage depends on the prefix of `wg0`.** The control plane gives an in-cluster gateway
  `InterfaceAddress = ipalloc.GatewayCIDR(org.PoolCidr)`: the pool's first address with **the
  pool's prefix length** (`apps/api/internal/nodes/service.go`). The default is `10.99.0.1/24`, and
  the IPv6 gateway address comes from the org's IPv6 pool. So the observed `wg0` subnet is the
  organisation's whole device pool, even where `PoolCIDR` is absent from the policy. It is
  `omitempty`, and it is filled in on the site artifact path (`finalizeSiteArtifact`). The K8N-3 fixture's `100.65.0.2/32` on `wg0`
  is a fixture shape, not what the control plane assigns. On such a gateway the check would cover
  only its own address, plus `PoolCIDR` if delivered.
- **Not checked:**
  - **The Service VIP range.** VIPs end on the gateway node (DNAT to a pod), so they are not
    tunnel-bound.
  - **Remote site subnets reached through the tunnel** (`Routes`). A Service with no selector that
    points at an on-premises host across site-to-site is a legitimate pattern, and those addresses
    are not device addresses. This is a stated limit: for such a Service the mark assumption is
    still an assumption.

Where it acts: `reconcileK8sNetPrep`. That function computes `K8sNetPrepReady`, which the gateway's
readiness probe requires in Kubernetes mode (`agentReady`). A hit makes it not ready on every pass,
next to the host and CNI checks, and puts the reason into the host status that the
`k8s_netprep_state` log line prints. The reason is not sent to the control plane today; neither is
any other netprep reason. While the EndpointSlice view is not live, readiness is already false
(`k8sSnapshotReady`), so the check adds no refusal of its own then. Within the 60-second API outage
grace it reads the last complete view.

The reason names the Service and is deterministic. The first hit is taken in sorted order (namespace,
Service, address), and a count is added when there are more:

```
Service team-a/db has endpoint 10.99.0.7, inside the Tunnex device range 10.99.0.0/24. Kubernetes marks and masquerades traffic to it, so this gateway is not ready. Remove that endpoint or Service. (2 Services in all)
```

A cluster with no such endpoint is unaffected: the check finds nothing and readiness is what it was.

Tunnex itself creates no EndpointSlice or Endpoints object. The chart's WireGuard Service selects
the gateway pods, whose addresses are node addresses (`hostNetwork`).

**Trade-off.** Anyone allowed to write EndpointSlices, or Endpoints in any namespace, can now take
every Tunnex gateway in the cluster out of service by pointing a Service at a device address. That
person can already redirect any Service in the namespaces they can write. **Unconfirmed, not re-read
today:** since Kubernetes 1.22 the default `edit` and `admin` roles no longer include writing
Endpoints (CVE-2021-25740), and they never included writing EndpointSlices.

Why not (b): (b) would leave a known way around the walk as a written limit, although the data to
refuse it is already on hand.

### As built

- `k8swatch_linux.go`: each EndpointSlice group also keeps `all`, every endpoint address whatever its
  conditions. The DNAT's `ready` list is unchanged. `EndpointsInRanges(ranges)` returns every hit
  sorted by Service, then address. It returns `ok=false` while the view is not live, and on a nil
  watcher.
- `egress_linux.go`: `deviceRanges` and `deviceRangeEndpointRefusal`. `reconcileK8sNetPrep` takes the
  refusal before it logs the status. On a hit the host component becomes `blocked` with the reason,
  appended after any earlier host reason, and the gateway is not ready. The check runs only when the
  endpoint source is the in-cluster watcher (an optional interface). A VM gateway and the test fakes
  are untouched.
- RBAC: unchanged. Chart: unchanged.
- Tests (`device_range_endpoints_linux_test.go`):
  - every address is kept (ready, not ready, no condition, terminating) while the DNAT view stays
    ready-only;
  - IPv4 and IPv6 hits are found in sorted order;
  - an FQDN slice, an unlabelled slice and a pod address are not hits;
  - a DELETED event removes a hit, and a view that is not live, or a nil watcher, gives no answer;
  - a clean cluster is ready and carries no refusal;
  - a device endpoint makes the gateway not ready, with the exact reason, also in the logged status;
  - two Services add "(2 Services in all)", and deleting both restores readiness;
  - an endpoint in the policy's device pool but outside the `wg0` subnet is refused;
  - an earlier host refusal is kept in front;
  - sources without the cluster view, and a view that is not live, add no refusal.

## Not confirmed

- No real cluster was used for either item. The stop state was proved on veth namespaces, not on a
  node with a CNI, kube-proxy and the host-posture manager process.
- Which CNI datapaths bypass the netfilter forward hook, and so never saw the released drop.
- Whether the real agent runs an egress pass between `EmergencyWithdrawK8s` and the next desired state
  (the mesh re-opening above).
- That kube-proxy and every supported CNI attach slices only through `kubernetes.io/service-name`,
  and the Kubernetes 1.22 default-role change. Both are from memory, not re-read today.
- Item 2 on a live cluster: a Service with no selector and a hand-written EndpointSlice at a device
  address, the gateway going not ready, and back.
