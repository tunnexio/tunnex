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

## Item 3 — the emergency withdraw and a nil policy open the tunnel (decision, 2026-11-24)

Branch `k8n/emergency-sitelan` (from `story/kubernetes-next`). This follows up the separate finding
in item 1, "the emergency path re-opens the mesh". Nothing here was run on a cluster.

### Can the real agent reach it?

`EmergencyWithdrawK8s` has one caller, `productionK8sSurface.EmergencyWithdraw`. That is reached only
from the two `!found` branches of the ownership coordinator:

- `Coordinator.ApplyAndReadback` (a lease start, a withdraw, an expiry);
- `Coordinator.VerifyCurrent` (the v3 delivery ACK replay).

`found` is false only while the projector has no ordinary base (`Projector.Snapshot`, `p.base == nil`).
`p.base` is written only by `UpdateBase` and `ReplaceBaseAndFences`, and nothing clears it.
`ensureLoaded` replaces only the fences. In the agent, the one writer is `OnDesired` →
`Coordinator.UpdateBaseAndSnapshot` → `UpdateBase` → `ReplaceBaseAndFences`.

The order in `apps/node/cmd/agent/main.go`:

1. `desired_state_startup_base` (`submitDesiredStateCommand`). `ApplyDesiredState` calls `onDesired`
   first and returns its error. If it fails, `main` logs `desired_state_startup_base_failed` and
   returns.
2. `ownership_startup_withdraw` (`Lifecycle.StartupReconcile`). This is the first ownership command.
3. Only then are `egressLoop`, `produceOwnershipCommands` and the lease watchdog started. The lane's
   lease guard (`LeaseDeadline`) is inert while `Lifecycle.current` is nil, which it is until step 2.

So when the first ownership call runs, the base is always present, and it stays present for the life
of the process. **The emergency branch cannot run in the shipped agent.** The fail-open is latent in
the primitive, not live. The comment in `StartupReconcile` ("Production starts fail closed before the
first ordinary base arrives") and the tests
`TestProductionStartupWithoutLeaseOrFenceStillRunsEmergencyK8sSweep` and
`TestProductionStartupWithdrawsUnexpiredLeaseBeforeFirstBase` describe an older order, in which the
lease was replayed before the base.

If the branch were reached, the fail-open would be real:

- The next `egress_reconcile` command renders the table from the stored policy. It runs on the same
  lane, on the 30-second ticker (`TUNNEX_AGENT_EGRESS_INTERVAL`) or at once on an endpoint-watch kick.
- `SetPolicy(nil)` has marked a policy as received, so `forwardRules` takes the mesh branch.
- Nothing waits for fresh desired state first. The desired-state producer runs every 60 s.

The kernel witness in item 1 shows the result.

`main` and `v0.1.44` have the same `EmergencyWithdrawK8s` (`SetPolicy(nil)`), the same `forwardRules`
branch and the same start order (`main.go` lines 646, 652 and 658 on both). Same conclusion there:
latent, not reachable. **How it would show if it ever were reached:** after the ownership log line of an
emergency withdrawal, and within 30 s, `nft list chain ip tunnex forward` holds
`iifname "wg0" oifname != "wg0" counter accept` with no `tunnex_default_drop`. Every connected device
then reaches every pod and node address the gateway node can route to, whatever its rules.

### The other ways a nil policy reaches the egress manager

| path | Kubernetes mode | what renders today |
|---|---|---|
| start, before the first delivery (`policyReceived` false) | yes | deny-all (`tunnex_default_drop`), fail closed |
| control-plane outage, fetch error | yes | no `SetPolicy` call; the last policy stays |
| unsupported artifact version | yes | deny-all (`refusedVersion`) |
| control plane serves `Policy: null` | yes | **open mesh** |
| ownership stages `SetPolicy(desired.Policy)` | yes | whatever the base carries; the projection never turns a non-nil policy into nil (`filterFencedBase`, `cloneDesiredState`) |
| `EmergencyWithdrawK8s` | the surface is built in both modes | **open mesh**; it also clears an unsupported-version refusal |

When does the control plane serve `Policy: null`? The policy compiler (`CompiledForNode`) returns an
artifact for every node in its node set, and a deny-all for any other node of an enforcing org. It
returns nil only for an org with Zero Trust off. `DesiredState` also leaves it nil on a policy-compile
error in an org confirmed off (`policy_compile_failed_org_off_serving_mesh`). `finalizeSiteArtifact` and
`finalizeArtifact` then wrap it in an explicit `Mode: "off", Mesh: true` artifact whenever the gateway
has site routes, exposed Services (VIP mappings, the API endpoint), DNS zones, resolver profiles or
client-graph peers. A gateway with devices, a site or a connector is in the compiler's node set. So an
in-cluster gateway receives nil only:

- when it is in an off org and has no devices, no site, no Service, no route and no client peer, so
  there is nothing to forward; or
- in an off org during a policy-compile error with none of the above to wrap it.

### Decision

1. **In Kubernetes mode a nil policy renders deny-all**, the same as the cold start: `ct
   established,related accept`, `ct state invalid drop`, the native passthrough (both interfaces outside
   the tunnel set, unchanged), then `counter comment "tunnex_default_drop"` under `policy drop`. No
   `iifname <tunnel>` accept of any kind, in either family. Tunnel to non-tunnel, tunnel to tunnel and
   non-tunnel to tunnel all fall to the drop. The change is in `forwardRules`, before the mesh branch.
2. **The open mesh in Kubernetes mode comes only from an explicit artifact with `Mesh: true`.** This is
   the documented Zero Trust off behaviour (K8N-3, "Open mesh": with enforcement off an enabled API
   endpoint is reachable by every device). The control plane sends that artifact to every in-cluster
   gateway that has anything to serve. Unchanged.
3. **Outside Kubernetes mode, nil stays the legacy mesh, unchanged.** That is where the open mesh from
   nil is intentional: a VM or site gateway of an org with Zero Trust off, or an open build without the
   policy subsystem (`s.policy == nil`), whose desired state carries `Policy: null`. "nil = legacy
   mesh" is the documented contract there (the `policyReceived` comment, `DesiredState`'s
   `policy_compile_failed_org_off_serving_mesh` branch).
4. **`EmergencyWithdrawK8s` no longer calls `SetPolicy(nil)`.** It returns the manager to the cold-start
   state: no stored policy, `policyReceived` false. That renders deny-all in every mode, because the
   ownership surface is composed in both modes (`NewProductionOwnerSurfaceWithOVPN` sits outside `if
   kubernetesMode`). It leaves an unsupported-version refusal in place. The next real delivery
   (`SetPolicy` from `OnPolicy` or an ownership stage) leaves that state, exactly as after a start.
   "No fresh baseline" is what the cold start means, so the two share one state.

**Trade.** In an org with Zero Trust off, an in-cluster gateway that receives nil now denies tunnel
traffic instead of opening the mesh. From the list above, that happens only to a gateway with nothing
to serve, or during an off org's policy-compile error. In the second case the gateway's devices lose
device-to-device and cluster access until the compile succeeds again, where today they keep the mesh.
For a gateway that sits in a cluster's host network namespace, that is the right side to fail on.

**Limit.** Flows established while the mesh was open survive through `ct state established,related
accept`. The decision closes new flows. It does not flush conntrack. That is the same as every other
policy narrowing here except a grant removal (`drainFlush`).

**Tests.**

- Renderer:
  - Kubernetes nil gives exactly the deny-all forward text, in both families;
  - VM nil gives the legacy mesh text, unchanged;
  - Kubernetes `Mesh: true` is still open.
- The emergency path followed by the egress pass's own render (`rulesetWith(subnet,
  m.policy.Load())`), in both modes. Then a delivery restores the policy, and the emergency leaves an
  unsupported-version refusal in place.
- Ownership: with the base seeded first, as `main` does, `StartupReconcile` never calls the emergency
  withdraw, with or without a durable lease.
- Kernel (`TestGatewayStopStateKernel`, opt in):
  - the released behaviour replayed (the mesh text that nil renders today) opens device → pod B;
  - after `EmergencyWithdrawK8s` and one real `Reconcile`, the device cannot reach pod B, the
    `tunnex_default_drop` counter rises and the chain holds no tunnel accept;
  - the same after a control-plane nil followed by a pass.

## Item 4 — the site-LAN masquerade stops an in-cluster gateway at startup (decision, 2026-11-24)

### What happens

SSI-8's `siteLANMasqueradeRules` renders, for a site with `lan_egress = gateway_address` and for every
distinct IPv4 route of the artifact:

```
ip saddr <route> oifname != <tunnel set> masquerade comment "tunnex_site_lan_masquerade"
```

into `ip tunnex postrouting`. `validateTunnexPostrouting` (`k8snetprep/aws_linux.go`) accepts only the
device-pool rule and the API return rule there. It refuses this one with `unknown Tunnex source-NAT
rule`. The validator runs inside every Kubernetes-mode `Reconcile` (`reconcileK8sNetPrep`) on every
CNI, because the `ip tunnex postrouting` hook is checked in `validateHookCoverage`. During
`ownership_startup_withdraw` the OpenVPN and DNAT stages call `Reconcile`, and the error is fatal there.
The process logs `ownership_startup_reconcile_failed` and exits on every start. While it runs, the
gateway is not ready.

**Does it apply to an in-cluster gateway?** Yes. `finalizeSiteArtifact` sets `SiteLANMasquerade` from
the gateway's site whenever the artifact has routes. An in-cluster connector belongs to the cluster's
site. Its routes are:

- other sites' subnets;
- handoff VIP `/32`s of other connectors (`k8sHandoffGraph`);
- once the flag is set, the `/32`s of devices on other gateways that `finalizeArtifact` appends from
  the client graph.

The API's guard on `gateway_address` asks only that every gateway of the site supports artifact v15,
and the in-cluster agent is the same binary. The option is also useful there: a remote site host
reaching a pod gets an answer only if the pod's node can route back to the remote range. Host posture
gives every node a return route to the tunnel range, not to remote site ranges.

**Is `main` affected?** Yes. `origin/main` (60aae74f) and `v0.1.44` both render the rule
(`egress_linux.go` line 1824 on both). Both validators accept only the device-pool shape (main line 870,
`unknown Tunnex source-NAT rule` at 880). Both call `Reconcile` from the DNAT stage and so run the check
at startup. A site that turns on `gateway_address` with an in-cluster gateway that has any route makes
that gateway crash-loop. **How it shows:** the gateway pod restarts repeatedly, its log ends with
`ownership_startup_reconcile_failed ... unknown Tunnex source-NAT rule`, and `nft list chain ip tunnex
postrouting` on the node shows the `tunnex_site_lan_masquerade` rules from the last attempt.

### Decision: teach the check the site-LAN shape; withhold the IPsec desktop exemption in Kubernetes mode

**The site-LAN masquerade: (a), the validator learns exactly one more shape.** It follows the API
return rule. The comment is exactly `tunnex_site_lan_masquerade` (one constant,
`k8snetprep.SiteLANMasqueradeRuleComment`, used by the renderer and the check). There are exactly three
statements:

1. `ip saddr ==` one IPv4 prefix in canonical masked form. nft lists a `/32` as a bare address, so both
   forms are accepted, as `nftAddressMatch` already does.
2. The same tunnel exclusion as the device-pool rule: `oifname !=` the WireGuard interface, or a set
   that contains it.
3. A bare `masquerade`.

Refused:

- the same prefix twice;
- `0.0.0.0/0`. An unconditional masquerade in disguise: it would translate every flow the node forwards
  out of a non-tunnel interface. The API refuses such a site range (`subnetguard.Admissible`), so the
  renderer never emits it.
- any other field (`ip daddr`, `ct original ...`);
- `!=`, a set, a range, an IPv6 address;
- a missing or different interface exclusion;
- `snat`, `masquerade` with flags or ports, any further statement;
- the shape without the marker or under another comment;
- the marker on any other shape.

*Not refused: a source inside the tunnel range.* The client-graph device `/32`s of other gateways lie
in the org's device pool, which is also this gateway's `wg0` range, and the renderer emits them under
this marker. Refusing them would bring the crash loop back. They are translated as they leave a
non-tunnel interface, which is what the device-pool rule already does for the same range.

*Why the invariant still holds.* "Tunnex never source-NATs traffic bound for the tunnel" rests on the
exclusion, and the check refuses the rule without it. As with the API return rule, the check binds the
shape and the marker, not the prefixes. It is not given the routes, and after a restart it runs before
the policy is known. The renderer binds the prefixes: the table is replaced from the current artifact
on every pass.

*Residual risk:* root on the node can write a marked rule for another prefix. The check accepts it
until the next pass replaces the table. It cannot touch tunnel-bound traffic.

*Adjacent, unchanged:* on a `gateway_address` site, devices of other gateways (client-graph `/32`s)
reach pods with the node's address, not their own. That is SSI-8's behaviour on a VM gateway too, and
it is recorded, not changed.

**The IPsec desktop exemption: (b), not rendered in Kubernetes mode, with a logged reason.** It is
`ip saddr <device> ip daddr <dest> counter return comment "tunnex_ipsec_desktop_no_snat"`. A `return`
cannot translate anything, so on the invariant alone the check could accept it. But on an in-cluster
gateway it can never do its job:

- The exemption exists only to keep a desktop's flow into an IPsec tunnel un-NATed. That flow needs the
  IPsec runtime's guard table, `inet tunnex_ipsec`, whose `postrouting_guard` (priority 90) and
  `postnat_guard` (priority 300) are postrouting hooks (`ipsec/guard_render.go`).
- `validateHookCoverage` refuses every IPv4 or inet postrouting hook it does not know, with `unknown
  IPv4 postrouting hook coverage`.
- So IPsec on an in-cluster gateway is already refused by the host-network proof, whatever the
  postrouting chain holds.
- Teaching the check the exemption would add a shape that can never take part in a working
  configuration.

Rendering it anyway is what is harmful: whenever the IPsec runtime has published an exemption but not
yet installed its guard, the exemption alone triggers the same fatal refusal.

So in Kubernetes mode `desktopNATRules` is not rendered. The egress manager logs
`k8s_ipsec_desktop_nat_withheld` (once per change of the withheld set) with the reason "IPsec is not
supported on an in-cluster gateway: its guard hooks are refused by the host network proof". The IPsec
runtime then sees its exemption as pending (`errDesktopNATPending`). `RuntimeController.Apply` fails
the whole connection on it, and the maintenance pass keeps the desktop grant pending. Both fail closed,
and both are paths the runtime already has. Outside Kubernetes mode, nothing changes.

**Tests.**

- Renderer:
  - the site-LAN rules render under the shared marker constant;
  - the desktop exemption is withheld in Kubernetes mode and kept on a VM.
- Validator:
  - accept table: prefix and `/32` forms, the set exclusion, next to the device-pool and API return
    rules;
  - near-miss refusal table, each after one and after two valid rules;
  - duplicate refusal;
  - an `inet tunnex_ipsec` postrouting hook is refused (the evidence for (b)).
- The restart/ownership path over the real kernel's listing of a table that holds the rule: a new
  check before anything is loaded, then the startup order. The fixture is saved next to the rendered
  text, with an egress test that fails if the rendering drifts from it.
- Kernel (opt in): with a remote-site host behind `wg0` and a pod that has no route back, the pod
  answers through the rule and sees the node's address. A second process starts over the leftover
  table. Near-misses written into the live chain are refused. Shutdown leaves no rule.

## Items 3 and 4 — as built and what was run (2026-11-24)

### Item 3 (emergency fail-open)

Changed functions, all in `apps/node/internal/egress`:

- `forwardRules` (`egress_linux.go`): in Kubernetes mode a nil policy returns the cold-start
  `dropCounter` in both families. The check sits before the mesh branch and after the cold-start and
  refused-version checks. `Mesh: true` is untouched, and so is nil outside Kubernetes mode.
- `withdrawPolicy` (new, `egress_linux.go`): it stores no policy and clears `policyReceived`. It does not
  touch `refusedVersion`.
- `EmergencyWithdrawK8s` (`dnat_linux.go`) calls `withdrawPolicy` in place of `SetPolicy(nil)`.
- Comments: `SetPolicy`, `policyReceived`, and the `forwardRules` header.

`rulesetWith` and `observeWGSubnet` keep their signatures and bodies.

Tests:

- `egress/nil_policy_k8s_linux_test.go`:
  - Kubernetes nil gives the exact deny-all forward chain in both families;
  - VM nil gives the legacy mesh;
  - a Kubernetes `Mesh: true` artifact stays open;
  - an emergency withdraw followed by the pass's own render is deny-all in both modes, and the next
    delivery leaves that state;
  - the emergency keeps an unsupported-version refusal.

  Run against the old `egress_linux.go` and `dnat_linux.go`, three of them fail:
  `TestKubernetesNilPolicyIsDenyAllNotMesh`, `TestEmergencyWithdrawThenEgressPassIsDenyAllInEveryMode`
  and `TestEmergencyWithdrawKeepsAnUnsupportedVersionRefusal` ("cleared the refusal: 0, want 16").
- `ownershiplease/production_k8s_surface_test.go`,
  `TestProductionStartupAfterTheBaseNeverTakesTheEmergencyWithdraw`: with the base seeded first, as
  `main` does, `StartupReconcile` calls the emergency withdraw zero times, with and without an
  unexpired durable lease.
- `TestGatewayStopStateKernel`, section 7:
  - `RELEASED_EMERGENCY_PASS_OPENS_TUNNEL`: the control. The released post-emergency forward chain
    (`iifname "wg0" oifname != "wg0" counter accept`) lets the device reach pod B.
  - `EMERGENCY_THEN_PASS_TUNNEL_CLOSED`: `EmergencyWithdrawK8s` and then a real `Reconcile`. The device
    cannot reach pod B, `counter packets 2 bytes 120 comment "tunnex_default_drop"`, and there is no
    tunnel accept.
  - `KUBERNETES_NIL_POLICY_PASS_TUNNEL_CLOSED`: the same after a control-plane nil and a pass.
  - Native traffic still passes after both.

**A pre-existing break in the witnesses, fixed here.** On `story/kubernetes-next` before this branch,
`TestGatewayStopStateKernel` stops at its first start with `startup egress pass: host-posture facts: no
host-posture facts source is configured`. That was re-run on a clean checkout of the branch tip.
`TestK8sAPIReturnPathKernel` has the same cause: since K8N review finding 5 a Kubernetes-mode gateway
needs a receipt that says whether the node has iptables-legacy tables. Both witnesses now pass
`kernelTestHostFacts`. It reads the namespace's `ip_tables_names` the way the manager does and marks the
nat and mangle rule text as not needed. The witness namespaces have no iptables-nft tables. This does
not change what either witness proves.

### Item 4 (site-LAN masquerade)

Changed functions:

- `k8snetprep/types.go`: `SiteLANMasqueradeRuleComment`.
- `k8snetprep/aws_linux.go`: `validateTunnexPostrouting` accepts the marker, duplicate check included,
  and the new `tunnexSiteLANRule` checks the exact shape.
- `egress/egress_linux.go`: `siteLANMasqueradeRules` writes the shared constant. Its text is otherwise
  byte for byte unchanged. A new `desktopNATWithheld` field.
- `egress/ipsec_desktop_nat_linux.go`: `desktopNATRules` returns nothing in Kubernetes mode, and the new
  `withholdDesktopNAT` logs `k8s_ipsec_desktop_nat_withheld` once per change.

Tests:

- `k8snetprep/site_lan_postrouting_linux_test.go`:
  - accept table: a range; a `/32` as nft lists it; a device `/32` inside the tunnel range; next to the
    API return rule; before the tunnel has an address; the OpenVPN set form;
  - 31 near-misses, each after one and after three valid rules;
  - duplicates in both `/32` spellings;
  - the IPsec guard's two postrouting hooks are refused with `unknown IPv4 postrouting hook coverage`;
  - a restart over the kernel fixture.

  Before the validator changed, the accept table failed with `unknown Tunnex source-NAT rule`.
- The fixture `k8snetprep/testdata/k8n5-site-lan.{rendered.nft,nft-ruleset.json}` is the real kernel's
  listing (nft 1.1.6) of the renderer's output, written by the kernel witness.
- `egress/site_lan_k8s_linux_test.go`:
  - the marker and the exact NAT chain, both interface forms;
  - drift against the fixture;
  - `nft -c` syntax;
  - the desktop exemption withheld in Kubernetes mode, logged once per change, and still rendered on
    a VM.
- In `TestTunnexPostroutingRefusesEveryNearMissOfTheAPIReturnRule`, the case that expected the
  site-LAN rule to be refused now uses the IPsec desktop exemption, which is still refused.
- `TestSiteLANMasqueradeKernel` (new, opt in with `TUNNEX_TEST_SITE_LAN_KERNEL=1`). A remote-site host
  (10.50.0.5) sits on `wg0`. The pod (10.70.0.9) has only the host-posture route to the device range.
  The results:
  - `WITHOUT_THE_RULE_THE_POD_CANNOT_ANSWER`;
  - `FIRST_START_ACCEPTED`, through the startup order that crash-looped: egress pass, then the OpenVPN
    stage, then the DNAT stage;
  - `POD_ANSWERS_THE_REMOTE_SITE_VIA_NODE_ADDRESS` (`ANSWER from=10.70.0.6`);
  - `RESTART_OVER_LEFTOVER_RULE_ACCEPTED`: the check passes on the leftover table before anything is
    loaded;
  - `POD_ANSWERS_AFTER_RESTART`;
  - `NEAR_MISSES_STILL_REFUSED`: six rules written into the live chain, each refused with its reason,
    each removed by the next pass;
  - `OPENVPN_SET_FORM_ACCEPTED` and `POD_ANSWERS_WITH_OPENVPN_SET`;
  - `RULE_GONE_WITH_PRESERVE_SOURCE` and `POD_CANNOT_ANSWER_WITH_PRESERVE_SOURCE`;
  - `NO_RULE_LEFT_AFTER_SHUTDOWN`.

### Verification

All runs were in `golang:1.26.11-alpine` on Docker's Linux kernel, with nftables 1.1.6 from apk.

- In `apps/node`, with `--cap-add=NET_ADMIN`:
  - `gofmt -l .`: empty;
  - `go vet ./...` and `GOOS=linux go vet ./internal/egress/`: clean;
  - `go build ./...`: clean;
  - `go test ./internal/egress/... ./internal/k8snetprep/... ./internal/hostposture/... ./cmd/agent/...
    -count=1`: all `ok`;
  - `./internal/ownershiplease/...`: `ok`.
- With `--privileged`, one container per witness, because they share namespace names:
  - `TestGatewayStopStateKernel` PASS;
  - `TestK8sAPIReturnPathKernel` PASS;
  - `TestSiteLANMasqueradeKernel` PASS.

### Still not confirmed

- No cluster. The emergency branch's unreachability is shown from the code and the ownership test, not
  from a running agent that was forced into it.
- The off-org trade, where a nil policy now denies on an in-cluster gateway during a compile error, has
  not been watched on a live control plane.
- The site-LAN rule on a real cluster: a remote site reaching a pod through an in-cluster gateway on a
  `gateway_address` site.
- IPsec on an in-cluster gateway was not attempted. Its refusal is read from `validateHookCoverage` and
  the guard's hook shapes, and shown on the JSON model, not on a running IPsec runtime.
- `cilium_service_reach_kernel_linux_test.go` (K8N-6) says "Never nil: nil is the legacy mesh". In
  Kubernetes mode nil is now deny-all. The test passes an explicit enforcing policy and is unaffected.

*Correction, same day.* The decision text first said that a withheld exemption leaves "the desktop grant
pending". `RuntimeController.Apply` (`ipsec/runtime_controller.go`) treats the pending exemption as an
error and fails the connection's apply. Only the maintenance pass keeps the grant pending. The wording
above is corrected, and the code comment on `withholdDesktopNAT` says the same. The decision does not
change: IPsec is refused on an in-cluster gateway anyway.
