# K8N review — ways the node check could report ready wrongly

Independent read-only review of `apps/node/internal/k8snetprep` on `story/kubernetes-next`,
2026-11-23/24, after K8N-1 (Calico) and K8N-2 (Cilium) widened what the proof accepts. Nothing here
was run on a cluster; packet-level claims come from reading code and the public Cilium v1.20.5
source. Each item is open until its fix and refusal test are merged.

Scale: Tunnex's forward chain drops flows opened towards a tunnel, and Cilium's eBPF program only
masquerades pod-sourced packets. Most items below therefore rewrite a pod-opened connection to a
device, the same effect the walk already accepts for Flannel. Item 10 is of a different kind.

## Findings

1. **High — Cilium, eBPF mode, ip-masq-agent on.** `cilium.go` accepts the status's
   `snat-exclusion-cidr-v4` before looking at `ip-masq-agent`. With the agent on, the datapath takes
   its exclusion only from the explicit `ipv4-native-routing-cidr` option; on Azure and Alibaba IPAM
   the status reports an auto-detected range the program does not apply. The gateway then says
   "inside Cilium's native-routing range" while nothing excludes the device range.
   Fix: accept the status exclusion only when ip-masq-agent is off; with it on, only a map entry
   proves. Refusal tests in `cilium_test.go` and `cilium_facts_test.go`. Needs a live capture with
   the agent on and no explicit native-routing range, and a check on Cilium 1.16–1.19.

2. **Medium — ipset proof ignores `netmask`/`bitmask` on `hash:ip`.** Such a set matches whole
   networks, but its members are read as /32. Confirmed with a scratch test. Calico uses `hash:net`,
   so this needs someone's own rule. Fix: refuse a `create` line carrying `netmask` other than 32 or
   `bitmask`; better, allow-list the header tokens.

3. **Medium/low — the exact-`oifname` exemption knows one tunnel interface.** The agent's tunnel set
   is `{wg0, tunnex-ovpn}`, and OpenVPN clients draw from the same device pool. A masquerade bound
   to exactly `tunnex-ovpn` is exempted today. Fix: pass every tunnel interface to the walk and
   exempt a rule only when its name is in none of them. Unknown: whether the control plane ever
   enables OpenVPN on an in-cluster gateway.

4. **Medium — "tunnel-bound traffic never carries a Kubernetes mark" is assumed, not enforced.**
   Only `ip mangle POSTROUTING` is proved unable to set 0x2000/0x4000/0x8000. Inside the NAT walk an
   `xt MARK` target and a native `mangle` statement are no-ops without reading the value, and a bare
   `ip saddr set` is read as "mangle". kube-proxy sets 0x4000 itself for NodePort traffic; someone
   who may write EndpointSlices can point a Service endpoint at a device address.
   Fix: in the NAT walk accept `mangle` only for `meta mark` with a value clear of the three bits and
   refuse `xt MARK` unless its saved value is read; and either refuse a Service endpoint inside the
   tunnel range or record the assumption as a stated limit. Needs a live capture.

5. **Medium, predates this branch — legacy iptables is invisible.** A node whose CNI or kube-proxy
   writes with `iptables-legacy` shows nothing in `nft`, so it is ready with no walk. The manager's
   `iptables-nft-save` already prints the "legacy tables present" warning. Fix: treat that warning,
   or a non-empty `/proc/net/ip_tables_names`, as a node-level refusal.

6. **Low — Cilium detection uses only the gateway's two signals** (`cilium_` device, `CILIUM_`
   chain). The manager may see the socket and pinned maps and publish a Cilium section the gateway
   never asks for. Fix: require the Cilium proof when either side saw a trace. GKE `anetd` and other
   eBPF dataplanes without those names are not covered by anything here.

7. **Low — set identity is not bound.** A set renamed or recreated between the rule save and the
   member read yields safe members for a name the rule no longer uses. Needs NET_ADMIN on the host.
   Fix, if wanted: read set names again after the members and compare.

8. **Low/info — the receipt.** Its digest is unkeyed: whoever can write the state directory (the
   manager, node root, a pod granted that hostPath) can forge it. The gateway mounts it read-only.
   Freshness is wall-clock, so a backward clock step extends a stale receipt.

9. **Info — charts and image.** `readOnly` on `/sys/fs/bpf` and `/var/run/cilium` blocks file writes
   only; the socket still accepts API calls from root. The manager is already privileged, so this
   adds reach, not authority; the NOTES wording "read-only" overstates it. `ipset`, `bpftool` and
   libLLVM are also in the gateway's image.

10. **Unverified, outside the source-NAT proof, possibly the most serious.** K8N-2 records that
    Cilium attaches its programs to `wg0` and serves NodePort on its address. With eBPF host routing
    that translation runs before Tunnex's forward chain, so a connected device may reach NodePort and
    LoadBalancer Services without a grant. Needs a live capture: device to the `wg0` address and a
    NodePort on a kube-proxy-replacement cluster.

## Found sound

- Positional pairing: text is bound by handle-bearing listings before and after; nft handles are
  not reused. A comment containing set-match text only breaks pairing, which refuses.
- The `oifname` exemption for one tunnel interface: `oif`, sets, wildcards, `!=`, an empty egress
  and `iifname` all prove nothing.
- The receipt against anyone without write access to the state directory: random boot ID per
  process, sequence tied to the heartbeat, no fallback in Kubernetes mode.
- Cilium's order of decisions (egress gateway, exclusion, map, pod source) matches v1.20.5;
  per-node overrides are covered because the local agent is asked; truncation is refused.

## Refusal tests still missing

`hash:ip` with netmask or bitmask; a second tunnel interface; a NAT-chain `MARK` or `mangle`
touching reserved bits and `ip saddr set`; a comment containing set-match text; ip-masq-agent on
with the tunnel inside the status exclusion; a receipt carrying a Cilium section when the gateway
saw no trace; a node with legacy tables; a set renamed between the save and the member read.

## Could not be determined

Whether GKE Dataplane V2 or AKS show the names the guard looks for; whether Cilium before 1.20.5
has the mismatch of item 1; whether an in-cluster gateway can have OpenVPN enabled; item 10.
