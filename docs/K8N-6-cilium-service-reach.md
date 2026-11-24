# K8N-6 — a device reaches Services past Tunnex on a Cilium node (finding 10)

Story branch: `story/kubernetes-next`, work branch `k8n/cilium-finding10`. This paper answers item 10
of `docs/K8N-review-false-ready.md`, which was a question raised by reading the code: on a Cilium node
with kube-proxy replacement, can a device connected to the Tunnex gateway reach Kubernetes Services
**without any Tunnex access rule**, because Cilium's eBPF programs on the WireGuard interface run
before Tunnex's nft forward chain? It was run on a local `kind` node on 2026-11-24. Nothing in this
paper changes code. The mitigations at the end are proposals for the founder to decide.

## Answer

**Confirmed, and the gap is wider than finding 10 said.** The setup is the one K8N-2 captured:
Cilium 1.20.5, kube-proxy replacement, native routing, eBPF masquerade, and ip-masq-agent listing
the tunnel range. The gateway's own table is in force, rendered by the real `Manager` for an
enforcing policy with no access rule. From a WireGuard peer, with no rule:

- **Reached:** NodePort on the gateway's `wg0` address; NodePort on the node's primary address;
  the LoadBalancer IP; and **the pod IP directly** (HTTP 200 each time; the backend saw the
  device's own address, `10.99.0.2`).
- **Not reached:** the ClusterIP. Cilium itself drops it on `wg0` with `Is a ClusterIP`. Tunnex
  plays no part in that drop.
- **Netfilter never sees the packets that get through.** The evidence: zero `nft monitor trace`
  events from a prerouting chain at priority -350; Tunnex's `tunnex_default_drop` counter does not
  move; netfilter conntrack has no entry; Cilium's own CT table has the flow, from source identity
  `world` (2); and a drop rule in an nft `netdev` ingress chain on `wg0` (priority -500) matched
  **0 packets** while NodePort and pod-IP requests still answered.

So Tunnex's forward chain is not the only gate on such a node. On this kernel no nftables rule can
be: every netfilter hook runs after the `tcx` ingress program Cilium attaches to `wg0`.

Two more results go beyond what finding 10 asked:

- **The other direction is open too.** A pod on the gateway node opened a TCP connection to the
  device (`agnhost connect 10.99.0.2:8000` exited 0). The forward chain saw nothing. This
  contradicts the "Scale" note of the review ("Tunnex's forward chain drops flows opened towards a
  tunnel"), which holds only with legacy host routing.
- **The cause is Cilium's BPF host routing, not the NodePort translation by itself.** With the same
  Cilium attached to `wg0` and doing the same translation, but with legacy host routing, every path
  reached Tunnex's forward chain and was dropped there (configurations D and F below).

## Setup

- **Cluster.** `kind` v0.31.0, one node, `kindest/node:v1.35.0` (Kubernetes v1.35.0), Docker Desktop
  kernel `6.8.0-117-generic` arm64, no default CNI, no kube-proxy. Config files and scripts are in
  `walk-artifacts/k8n6-cilium-service-reach-20261124/`.
- **Cilium 1.20.5 by Helm** (`cilium-values.yaml`): `kubeProxyReplacement=true`,
  `routingMode=native`, `ipv4NativeRoutingCIDR=10.244.0.0/16`, `autoDirectNodeRoutes=true`,
  `ipam.mode=kubernetes`, `bpf.masquerade=true`, and `ipMasqAgent.enabled=true` with
  `nonMasqueradeCIDRs: [10.99.0.0/24]`. This is K8N-2's configuration B with this paper's tunnel
  range, the one K8N-2 "As built" reports ready (`tunnel range is inside Cilium ip-masq-agent
  range`). The agent reported `Routing: Network: Native Host: BPF` and
  `Masquerading: BPF (ip-masq-agent) [eth0, wg0]`. `cilium-dbg bpf ipmasq list` showed exactly
  `10.99.0.0/24`.
- **App.** `agnhost:2.53 netexec` on port 8080, one replica (pod `10.244.0.35`), behind:
  - a ClusterIP Service `10.96.229.86:80`;
  - a NodePort Service on `30080`;
  - a LoadBalancer Service. kind has no load balancer of its own (it needs the separate
    `cloud-provider-kind`). Cilium's built-in LB-IPAM did the job instead, with one
    `CiliumLoadBalancerIPPool` (`172.31.250.0/28`). The Service got `172.31.250.0`; no other
    component was added.
- **WireGuard, not a substitute.** The `wireguard` module is present in this kernel.
  - **Gateway side:** `wg0` (type `wireguard`, `10.99.0.1/24`) in the node's network namespace.
    Its one peer has `allowed-ips 10.99.0.2/32`.
  - **Device side:** a second WireGuard interface, created in the node's namespace and then moved
    into a separate namespace `tnxdev` (`10.99.0.2/32`, peer `allowed-ips 0.0.0.0/0`, default
    route through it). Its UDP socket therefore stays in the node's namespace, and the two talk
    over `127.0.0.1` (`wg-setup.sh`). The handshake completed.
  - So packets arrive on a real WireGuard `wg0` exactly as from a client. Keys were generated in
    the throwaway container and are not kept.
- **Tools.** Everything ran from one privileged Alpine 3.24.4 container sharing the node's network
  namespace: `nft` 1.1.6, `bpftool` v7.8.0, `wireguard-tools` v1.0.20260223, `tcpdump`,
  `conntrack`, `curl`, `socat`.

### Cilium attaches to `wg0`, as K8N-2 recorded

A few seconds after `wg0` came up, the agent logged `Node addresses updated
addresses="10.99.0.1 (primary, nodeport)" device=wg0`, and `Program attached to device using tcx`
for `cil_from_netdev` and `cil_to_netdev` on `wg0`. `bpftool net show dev wg0`:

    wg0(16) tcx/ingress cil_from_netdev prog_id 7762 link_id 174
    wg0(16) tcx/egress cil_to_netdev prog_id 7759 link_id 175

`tc filter show dev wg0 ingress` prints nothing for `tcx` attachments. Only `bpftool` (or the agent
log) shows them.

Two members of the status at `/v1/healthz` say the same thing (`healthz-A-excerpt.txt`):
`kube-proxy-replacement.devices: ["eth0","wg0"]` and
`routing.intra-host-routing-mode: "BPF"`. `host-firewall.devices` also lists `wg0`.

### The Tunnex table: the real `Manager` rendering

A new opt-in test, `apps/node/internal/egress/cilium_service_reach_kernel_linux_test.go`,
modelled on `k8s_api_return_kernel_linux_test.go`, was cross-compiled (`go test -c`, linux/arm64,
Go 1.26.11) and run in the node's namespace. What it does:

- builds `New("wg0")` in Kubernetes mode, with the same authority stub as the K8N-3 kernel test;
- calls `SetPolicy(&nodepolicy.Compiled{Version: 7, Mode: "enforcing", Mesh: false})`, i.e. **no
  access rule**. It is not `nil`, which would be the legacy mesh.
- calls `Reconcile`, which loads the table through `nft -f` exactly as the agent does;
- asserts that the kernel's forward chain is the default-deny chain and holds no accept for traffic
  from `wg0`.

The forward chain in force (`tunnex-table-final.txt`; rendered text and full JSON listing in
`k8n6-cilium-service-reach.{rendered.nft,nft-ruleset.json}`):

    type filter hook forward priority filter; policy drop;
    ct state established,related accept
    ct state invalid counter drop comment "tunnex_ct_invalid_drop"
    iifname != "wg0" oifname != "wg0" counter accept comment "tunnex_native_forward_passthrough"
    iifname "wg0" oifname "wg0" tcp flags syn tcp option maxseg size set rt mtu
    counter comment "tunnex_default_drop"

**Readiness, as far as this harness can take it.** The first run was refused for
`net/ipv4/conf/wg0/rp_filter` = 1, which the host-posture manager sets to 0 on a real node. With it
set to 0, the host check and the NAT rule walk passed. The run was then refused at the Cilium step
only because the harness has no host-posture receipt: `Cilium masquerade on this node is not
verified: no host-posture facts source is configured`. The real manager would have supplied that
receipt: status `mode: BPF`, `ip-masq-agent: true`, and the map entry `10.99.0.0/24` read above.
Under K8N-2 "As built" this node is then **ready**. That end-to-end readiness was not run here. The
table is applied before the check runs, so the probes were against the table either way.

**Positive control first.** The device dialled the Docker network gateway `172.21.0.1:80`: the
connection timed out, the trace showed the packet in netfilter, and `tunnex_default_drop` went from
0 to 3. The table was live and dropping.

## Results

How each probe was read (`probe.sh`, one `curl -m 3` from `tnxdev`):

- Tunnex forward counters before and after.
- `nft monitor trace` from a separate table `ip f10trace`: a prerouting chain at priority -350 that
  sets `nftrace` for `iifname "wg0" ip saddr 10.99.0.2`.
- `tcpdump` on `wg0`, which sees the packet before tc ingress, and on the pod's `lxc` device.
- Netfilter conntrack for `10.99.0.2`.
- For the main configuration, Cilium's `bpf ct list global` and `monitor --type drop`.

"Pod → device" is `agnhost connect 10.99.0.2:8000` from the web pod to a `socat` listener in
`tnxdev`.

Configurations (each followed by `helm upgrade` and a restart of the Cilium DaemonSet; attachment
and service frontends were checked again before probing):

- **A**: the setup above. Run twice; the repeat came after all the other configurations.
- **B**: A plus `nodePort.addresses={172.21.0.2/32}`.
- **C**: A plus `devices={eth0}`. `wg0` was then no longer attached (`bpftool` showed no `tcx` on
  it) and no longer in the status.
- **D**: `bpf.masquerade=false`, ip-masq-agent off (K8N-2's C). The agent reported `Host: Legacy`.
  Cilium was still attached to `wg0`.
- **E**: `kubeProxyReplacement=false` with kube-proxy installed (kubeadm's addon, iptables mode),
  iptables masquerade. The agent reported `Host: Legacy`; `cil_from_netdev` was still on `wg0`.
- **F**: A plus `bpf.hostLegacyRouting=true`. eBPF masquerade and ip-masq-agent stayed on, and the
  agent reported `Host: Legacy`.

| Path, no access rule | A (paper setup, BPF host routing) | B `nodePort.addresses` | C `devices=eth0` | D iptables masq | E kube-proxy | F `hostLegacyRouting` |
| --- | --- | --- | --- | --- | --- | --- |
| NodePort on `wg0` address `10.99.0.1:30080` | **reached** — Cilium tc | refused by host (RST) | refused by host (RST) | dropped by Tunnex | dropped by Tunnex | dropped by Tunnex |
| NodePort on node address `172.21.0.2:30080` | **reached** — Cilium tc | **reached** — Cilium tc | refused by host (RST) | dropped by Tunnex | dropped by Tunnex | dropped by Tunnex |
| ClusterIP `10.96.229.86:80` | dropped by Cilium | dropped by Cilium | dropped by Tunnex | dropped by Cilium | dropped by Tunnex | dropped by Cilium |
| Pod IP `10.244.0.35:8080` | **reached** — Cilium tc | **reached** — Cilium tc | dropped by Tunnex | dropped by Tunnex | dropped by Tunnex | dropped by Tunnex |
| LoadBalancer IP `172.31.250.0:80` | **reached** — Cilium tc | **reached** — Cilium tc | dropped by Tunnex | dropped by Tunnex | dropped by Tunnex | dropped by Tunnex |
| Pod → device `10.99.0.2:8000` | **connects** — no netfilter | not run | SYN reaches device; reply dropped by Tunnex as `ct invalid` | dropped by Tunnex | dropped by Tunnex | dropped by Tunnex |

How each entry was decided, from the evidence files (`probe-<config>-paths.txt`,
`probe-<config>-pod-to-device.txt`):

- **"reached — Cilium tc"**:
  - HTTP 200, and `/clientip` answered `10.99.0.2:<port>`.
  - `tcpdump` on `wg0` shows the SYN to the original address. `tcpdump` on the pod's `lxc` shows
    the pod answering `10.99.0.2` directly.
  - Zero trace events; `tunnex_default_drop` unchanged; no netfilter conntrack entry.
  - Cilium's CT table (`probe-A-cilium-ct.txt`) has the service entries and the endpoint entries
    `IN 10.99.0.2:<port> -> 10.244.0.35:8080 ... SourceSecurityID=2`, for example:
    - `SVC 10.99.0.2:47672 -> 10.99.0.1:30080`
    - `SVC 10.99.0.2:35638 -> 172.21.0.2:30080`
    - `SVC 10.99.0.2:36338 -> 172.31.250.0:80`
  - The pod-IP flow has no service entry: Cilium delivered it straight to the local endpoint from
    `wg0`.
- **"dropped by Cilium"** (ClusterIP): `cilium-dbg monitor --type drop` printed `drop (Is a
  ClusterIP) ... ifindex 16, file bpf_host.c:995 ... identity world->unknown: 10.99.0.2:38890 ->
  10.96.229.86:80 tcp SYN` (ifindex 16 is `wg0`). There were zero trace events and no Tunnex
  counter change. Exposing ClusterIPs to outside traffic (`bpf.lbExternalClusterIP=true`) was not
  tested; it would presumably move this row to "reached".
- **"dropped by Tunnex"**: `tunnex_default_drop` rose by the three retransmitted SYNs, and the trace
  ends in `ip tunnex forward policy drop`. In D, E and F the trace shows the packet already
  translated by the time it reaches that chain: `iif "wg0" oif "cilium_host" ip saddr 10.99.0.2
  ip daddr 10.244.0.35 ... tcp dport 8080` (in E with kube-proxy's mark `0x00004000`). The
  translation happened, but the packet was handed to the stack instead of redirected.
- **"refused by host (RST)"**: the node itself answers RST. The trace shows the SYN reaching
  `ip filter INPUT`, because with `wg0` not a NodePort address (B), or not a Cilium device at all
  (C), nothing on the node listens on 30080. Tunnex has no input chain, so it did not decide this
  either.
- **Pod → device under C**: the pod's SYN still left through `wg0` without a trace event. BPF host
  routing redirects from the pod's own program, which `devices` does not change. The device's
  SYN-ACK came back into netfilter, which had never seen the SYN, and was dropped as `ct invalid`
  (`tunnex_ct_invalid_drop` 0 → 7). The device still received an unsolicited SYN.

**No nftables rule can close this.** With A in force, a `table netdev f10ingress` chain on `hook
ingress device "wg0" priority -500` with `ip saddr 10.99.0.2 counter drop` counted 0 packets. In
the same run, NodePort on `10.99.0.1` and the pod IP still answered 200
(`probe-A-netdev-ingress-drop.txt`). Cilium's `tcx` ingress program redirects the packet before
the netfilter ingress hook runs.

## What this means

- **On a Cilium node with BPF host routing and the tunnel interface among Cilium's devices, every
  connected device can open TCP connections to:**
  - every NodePort, through any node address;
  - every LoadBalancer IP served by that node;
  - every pod on the gateway's node, by pod IP.

  No access rule is needed. The device's own address is preserved, so a pod sees a source in the
  device pool.
- **Devices choose their own destinations.** The gateway's peer entry filters only the source
  (`allowed-ips 10.99.0.2/32`), and a device owner can set any route on their side. The `wg0`
  address is in the tunnel range and is always routed through the tunnel.
- **Pods on the gateway's node can open connections to devices.**
- **Tunnex reports this node ready, or would with the real receipt** (see "Readiness"). The
  K8N-2 proof is about source NAT and says nothing about this.
- **What the harness could not show.** This node exposes pods on the gateway's own node. For other
  nodes' pods, and for NodePorts whose backends sit on other nodes, the same `cil_from_netdev`
  program on `wg0` is in the path. Whether it forwards those past the forward chain too was not
  shown (single node).
- **Finding 10 should be updated** from "Unverified" to confirmed, with the wider scope above. The
  review's "Scale" paragraph should say that its premise (the forward chain drops flows opened
  towards a tunnel) does not hold under Cilium BPF host routing. This paper does not edit the
  review.

## Mitigations (proposals; nothing implemented)

Ordered by what was shown here.

1. **Tunnex refuses readiness on this condition (recommended, smallest Tunnex change).**
   - **Data already in hand.** The host-posture manager already reads `GET /v1/healthz` on a
     Cilium node and keeps only the `masquerading` member in the receipt. Two more members of that
     same response are enough:
     - `routing.intra-host-routing-mode`;
     - `kube-proxy-replacement.devices`.

     Their shapes are captured in `healthz-A-excerpt.txt`.
   - **Rule.** Refuse when the mode is `BPF` and any tunnel interface is in `devices`. A stricter
     variant refuses on `BPF` alone, because configuration C shows a pod's SYN still reaches the
     device when `wg0` is excluded.
   - **Message.** Customer-actionable, for example: `Cilium routes traffic on the tunnel interface
     wg0 ahead of Tunnex's rules (BPF host routing). Set bpf.hostLegacyRouting=true, or set
     devices to exclude wg0, then restart the Cilium agents`.
   - **Timing.** Cilium selects `wg0` about three seconds after it appears, and re-selects when
     devices change. The check must be re-read each interval with the receipt (as the masquerade
     proof already is), and an unreadable status stays a refusal.
   - **Not covered.** This does not cover eBPF dataplanes without Cilium's names (GKE Dataplane V2,
     finding 6).
2. **Customer setting, documented: `bpf.hostLegacyRouting=true`. Tested: closes every path,
   including pod → device (F).**
   - eBPF masquerade and the ip-masq-agent stay on, so the K8N-2 proof is unchanged.
   - Cost: host-side routing goes through the kernel stack for all pods. It is a cluster-wide
     agent option; a per-node override (CiliumNodeConfig) was not tested.
   - On managed offerings the customer may not be allowed to change it (AKS, see K8N-2 [D3]).
3. **Customer setting, alternative: `devices` that excludes the tunnel interface. Tested (C).**
   - It closes device → NodePort / LoadBalancer / pod.
   - It does not stop a pod's SYN from reaching a device; Tunnex then drops the reply as invalid,
     so the connection fails, but the device still receives an unsolicited SYN.
   - An explicit list also stops Cilium from picking up new interfaces by itself.
   - Not tested: whether a pattern such as `eth+` behaves the same.
4. **`nodePort.addresses` alone is not a fix. Tested (B).** Only the `wg0`-address NodePort
   closed; NodePort on the primary address, the LoadBalancer IP and the pod IP stayed reachable.
   NodePort translation happens on whichever selected device the packet enters, whatever address
   it targets.
5. **An ordering Tunnex controls: not nftables.** Any netfilter hook, `netdev` ingress included,
   runs after the `tcx` ingress program (shown above).
   - What would work in principle: Tunnex's own `tcx` ingress program on `wg0`, attached before
     Cilium's, returning `TCX_PASS` (hand the packet to the stack and skip the remaining `tcx`
     programs on that hook).
   - Untested. It would make Tunnex depend on link ordering against a CNI that re-attaches on every
     restart. It would not cover pod → device, which is decided in the pod's own program, not on
     `wg0`. Not recommended before 1 and 2.

Whichever is chosen, the legitimate path must be re-tested afterwards: a device with a grant,
through Tunnex's Service VIP DNAT, on each setting. That path was not exercised here (no control
plane, no VIP mapping).

## Side observation, outside this item

Tunnex's tables have no input chain. A device reached the kubelet on the gateway's `wg0` address
(`10.99.0.1:10250`): the TCP handshake completed and the TLS handshake returned the kubelet's certificate. The trace showed it
in `ip filter INPUT` only. Configurations B and C show the same path for NodePort: the SYN reached
INPUT and only the absence of a listener refused it. This does not depend on Cilium. Any
host-network listener on the gateway node is reachable from every device without a rule.

## What this setup cannot show

- **GKE Dataplane V2 and AKS (Azure CNI powered by Cilium).** Their device selection, host routing
  mode and whether a customer may change either are not confirmed. The K8N-3 GKE walk did not
  look at this.
- **Multi-node.** Pods on other nodes, NodePorts with remote backends, DSR or hybrid NodePort mode,
  and native routing towards other nodes were not exercised.
- **The real agent.** There was no control plane, no WireGuard management by the agent, no
  host-posture manager receipt, no Service VIP DNAT and no grants. Only the `Manager` rendering and
  `Reconcile` ran. End-to-end readiness was not run, and was inferred from K8N-2 "As built" plus the
  status and map read here.
- **Protocols and features not tried:** UDP, IPv6, `bpf.lbExternalClusterIP`, Cilium host firewall
  or network policies (a pod policy denying `world` might block these flows, and the Tunnex
  traffic a grant allows with them). Neither was tried.
- **Kernel and Cilium versions.** One kernel (6.8, arm64, Docker Desktop) and one Cilium release
  (1.20.5). Kernels or Cilium versions that cannot use BPF host routing fall back to legacy, which
  behaves like D.

## Reproduce

Files in `walk-artifacts/k8n6-cilium-service-reach-20261124/`:

- `kind.yaml`, `cilium-values.yaml`, `app.yaml`;
- `wg-setup.sh` (run in a privileged Alpine container started with `--network
  container:<kind node>`);
- `probe.sh`, `probe-all.sh`, `podtodev.sh` (the last two read `F10_DIR` for the kubeconfig and
  output directory).

The Tunnex table:

    TUNNEX_TEST_F10_KERNEL=1 TUNNEX_TEST_F10_OUT=<dir> ./egress.test -test.run '^TestCiliumServiceReachKernel$' -test.v

The test is skipped unless opted in. The `wg0` reverse-path filter must be 0, as the host-posture
manager sets it.
