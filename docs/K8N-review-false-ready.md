# K8N review — ways the node check could report ready wrongly

Independent read-only review of `apps/node/internal/k8snetprep` on `story/kubernetes-next`,
2026-11-23/24, after K8N-1 (Calico) and K8N-2 (Cilium) widened what the proof accepts. Nothing here
was run on a cluster; packet-level claims come from reading code and the public Cilium v1.20.5
source. Each item is open until its fix and refusal test are merged.

The fixes are on branch `k8n/review-fixes`, one commit per finding; each item below says what was
done, with the commit subject and the refusal test. None of the fixes ran on a cluster.

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
   **Fixed** — `fix(k8s): accept Cilium's reported native-routing range only with ip-masq-agent
   off (K8N review 1)`. Tests: `TestProveCiliumReportedRangeProvesOnlyWithTheIPMasqAgentOff`,
   `TestCiliumFactsReportedRangeIsNotAProofWithTheIPMasqAgentOn`,
   `TestCiliumLiveNodeWithIPMasqAgentOnIsNotReadyOnTheReportedRange` (whole reconcile). The
   source reading was checked at tag v1.20.5 (`pkg/datapath/linux/config/config.go`,
   `pkg/status/status_collector.go`). One captured case changes verdict on purpose: node B
   (ip-masq-agent on) with a range inside the reported `10.244.0.0/16` and not in the map was
   ready and is now refused with the line to add; on that node the range was set explicitly, so
   the refusal is stricter than the datapath. See K8N-2, "After the review". Still owed: the
   live capture and Cilium 1.16–1.19.

2. **Medium — ipset proof ignores `netmask`/`bitmask` on `hash:ip`.** Such a set matches whole
   networks, but its members are read as /32. Confirmed with a scratch test. Calico uses `hash:net`,
   so this needs someone's own rule. Fix: refuse a `create` line carrying `netmask` other than 32 or
   `bitmask`; better, allow-list the header tokens.
   **Fixed** — `fix(k8s): read an ipset only when every header option is known (K8N review 2)`.
   The `create` line is now an allow-list (K8N-1, "After the review", has the table): `netmask`
   other than 32 and any `bitmask` refuse, and so does every option not decided on. Tests:
   `TestParseIPSetSaveRefusesASetThatMatchesMoreThanItLists`,
   `TestParseIPSetSaveHeaderIsAnAllowList`, the rows "source set that matches whole networks"
   and "source set with a bitmask" of `TestCalicoNodeRefusals` (whole reconcile) and "set that
   matches whole networks" of `TestGatewayRefusesHostFactsThatDoNotHold` (through the receipt).
   The captured Calico and Cilium sets read as before (`TestParseIPSetSaveReadsTheCapturedSets`).

3. **Medium/low — the exact-`oifname` exemption knows one tunnel interface.** The agent's tunnel set
   is `{wg0, tunnex-ovpn}`, and OpenVPN clients draw from the same device pool. A masquerade bound
   to exactly `tunnex-ovpn` is exempted today. Fix: pass every tunnel interface to the walk and
   exempt a rule only when its name is in none of them. Unknown: whether the control plane ever
   enables OpenVPN on an in-cluster gateway.
   **Fixed** — `fix(k8s): excuse no masquerade bound to any tunnel interface (K8N review 3)`.
   The gateway's reconciler now reads the agent's own tunnel set (`tunnelIfaces()`) at every
   observation, and a rule is excused only when its exact name is none of them. Tests:
   `TestObservedExcusesNoRuleBoundToAnyTunnelInterface`,
   `TestLiveCalicoNodeIsRefusedWhenAMasqueradeIsBoundToASecondTunnelInterface` (whole reconcile,
   direct and receipt path), `TestK8sCNIAuthorityWiringHandsTheProofTheLiveTunnelInterfaces`
   (the agent's wiring). On the unknown: the code can do it — the Kubernetes owner surface
   (`ownershiplease/production_k8s_surface.go`) reconciles an OpenVPN server and its tunnel
   interface when the desired state enables it; whether the control plane ever sends that to an
   in-cluster gateway was not checked. Not changed, and seen while fixing: the rules Tunnex owns
   in a registered mechanism (`ip daddr TUNNEL oifname wg0 return` in `IP-MASQ-AGENT` and
   `AWS-SNAT-CHAIN-0`) name the WireGuard interface only, so on GKE or EKS a pod's own connection
   to an OpenVPN client is still masqueraded by the node's rule, the same effect as the walk's
   pod-source exception. See K8N-1, "After the review".

4. **Medium — "tunnel-bound traffic never carries a Kubernetes mark" is assumed, not enforced.**
   Only `ip mangle POSTROUTING` is proved unable to set 0x2000/0x4000/0x8000. Inside the NAT walk an
   `xt MARK` target and a native `mangle` statement are no-ops without reading the value, and a bare
   `ip saddr set` is read as "mangle". kube-proxy sets 0x4000 itself for NodePort traffic; someone
   who may write EndpointSlices can point a Service endpoint at a device address.
   Fix: in the NAT walk accept `mangle` only for `meta mark` with a value clear of the three bits and
   refuse `xt MARK` unless its saved value is read; and either refuse a Service endpoint inside the
   tunnel range or record the assumption as a stated limit. Needs a live capture.
   **Fixed in the walk; the Service-endpoint part is recorded, not fixed** — `fix(k8s): prove
   marks set inside the NAT walk (K8N review 4)`. A native `mangle` statement is accepted only
   as `meta mark set` with a value that cannot turn a reserved bit on; `ip saddr set` and every
   other mangle statement refuse. An `xt MARK` that tunnel-bound traffic can reach is read from
   the saved rule, paired like a set match, and must leave the three bits alone; unread, it
   refuses. Tests: `TestObservedNATWalkReadsANativeMarkStatement`,
   `TestObservedNATWalkReadsAMarkTargetFromItsSavedRule`,
   `TestObservedNATWalkDoesNotReadAMarkItCannotReach`,
   `TestNodeIsRefusedWhenANATRuleSetsAKubernetesMark` (whole reconcile),
   `TestGatewayOnHostFactsRefusesANATMarkItCannotRead` (through the receipt). Limit: the
   manager carries NAT chains for their set matches only, so through the receipt a `MARK` in any
   other NAT chain is refused, never proved. No captured node has one on that path. The
   Service-endpoint scenario is **Assumption A1** in K8N-1, "After the review", with the
   options; it needs a ruling. Still owed: the live capture.
   Follow-up `test(k8s): refuse NAT marks on every reserved bit (K8N review 4)`: rows for the
   portmap (`0x2000`) and drop (`0x8000`) bits on both paths (`mark | 0x2000`, `mark | 0x8000`,
   `--set-xmark 0x8000/0x8000`, `--set-xmark 0x8000/0x0`) and `ip saddr set` behind a pod-source
   condition. Checked by narrowing the reserved bits to `0x4000`: those rows then fail.

5. **Medium, predates this branch — legacy iptables is invisible.** A node whose CNI or kube-proxy
   writes with `iptables-legacy` shows nothing in `nft`, so it is ready with no walk. The manager's
   `iptables-nft-save` already prints the "legacy tables present" warning. Fix: treat that warning,
   or a non-empty `/proc/net/ip_tables_names`, as a node-level refusal.
   **Fixed** — `fix(k8s): refuse a node with iptables-legacy tables (K8N review 5)`. The
   manager reads `/proc/net/ip_tables_names` and publishes it in the receipt
   (`legacy_iptables`); the gateway refuses before any proof when it lists a table, is
   unreadable or is absent. Chosen over the warning because the warning appears only where a
   save is read and its absence is silent. **Behaviour change**: the gateway now takes the
   receipt on every observation, so a node that needs no rule fact is no longer ready without
   one. Tests: `TestNodeWithLegacyTablesIsNotReady` and four more; every captured fixture is
   decided as before. Checked in a scratch namespace that a legacy `MASQUERADE` is invisible to
   `nft` and listed in the file. See K8N-1, "A node with iptables-legacy tables is not ready".
   Follow-up `fix(k8s): raise the host facts schema for the legacy fact (K8N review 5)`: a
   receipt from an older manager was refused as "damaged" (the missing field re-encodes empty,
   so the digest differs); the schema is now 2 and such a receipt is refused as an unknown
   schema. Test: `TestHostFactsFromAManagerBeforeTheLegacyFactAreRefused`.

6. **Low — Cilium detection uses only the gateway's two signals** (`cilium_` device, `CILIUM_`
   chain). The manager may see the socket and pinned maps and publish a Cilium section the gateway
   never asks for. Fix: require the Cilium proof when either side saw a trace. GKE `anetd` and other
   eBPF dataplanes without those names are not covered by anything here.
   **Fixed** — `fix(k8s): decide Cilium on the receipt's section alone (K8N review 6)`. With a
   facts source the gateway reads the `cilium` section on every observation and runs the
   Cilium decision when it is present, whatever it saw itself. Tests:
   `TestGatewayRunsTheCiliumDecisionOnAReceiptSectionAlone`, `TestCiliumGuardWithoutCilium`
   (changed: the source is now asked). GKE `anetd` and other unnamed eBPF dataplanes: still
   not covered. See K8N-2, "A `cilium` section in the receipt makes a Cilium node".

7. **Low — set identity is not bound.** A set renamed or recreated between the rule save and the
   member read yields safe members for a name the rule no longer uses. Needs NET_ADMIN on the host.
   Fix, if wanted: read set names again after the members and compare.
   **Fixed as far as `ipset` allows** — `fix(k8s): re-read set names after the members (K8N
   review 7)`. The manager lists the set names before and after the member reads and starts over
   when they differ; unreadable after three tries. Test:
   `TestHostFactsReaderRereadsSetNamesAfterTheMembers`. Checked on kernel 6.8 / ipset 7.24: the
   kernel refuses to rename or destroy a set a rule holds, so a held set keeps its name; `ipset
   swap` is allowed, keeps names, and changes the members unseen, like `ipset add`. `ipset` shows
   no set identity, so that cannot be bound; the receipt's freshness bounds it. See K8N-1,
   "Which set the members belong to". The test-only direct read is not changed.

8. **Low/info — the receipt.** Its digest is unkeyed: whoever can write the state directory (the
   manager, node root, a pod granted that hostPath) can forge it. The gateway mounts it read-only.
   Freshness is wall-clock, so a backward clock step extends a stale receipt.

9. **Info — charts and image.** `readOnly` on `/sys/fs/bpf` and `/var/run/cilium` blocks file writes
   only; the socket still accepts API calls from root. The manager is already privileged, so this
   adds reach, not authority; the NOTES wording "read-only" overstates it. `ipset`, `bpftool` and
   libLLVM are also in the gateway's image.
   **Wording fixed** — `docs(k8s): say what readOnly on the Cilium mounts prevents (K8N review 9)`.
   The host-posture NOTES, the `values.yaml` comment and the DaemonSet comment now say that
   `readOnly` stops file changes (create, replace, remove, pin) and not API calls on the socket
   or a map opened for writing with `BPF_OBJ_GET`; K8N-2, "What `readOnly` on the Cilium paths
   prevents", has the table. Chart contract test passes. No code test: wording only. The image
   contents are not changed.

10. **Unverified, outside the source-NAT proof, possibly the most serious.** K8N-2 records that
    Cilium attaches its programs to `wg0` and serves NodePort on its address. With eBPF host routing
    that translation runs before Tunnex's forward chain, so a connected device may reach NodePort and
    LoadBalancer Services without a grant. Needs a live capture: device to the `wg0` address and a
    NodePort on a kube-proxy-replacement cluster.

## Found sound

- Positional pairing: text is bound by handle-bearing listings before and after; nft handles are
  not reused. A comment containing set-match text only breaks pairing, which refuses.
  Now guarded by a test — `test(k8s): a comment holding set-match text only breaks pairing (K8N
  review)`, `TestObservedCommentWithSetMatchTextOnlyBreaksPairing`: a comment naming a safe set
  ahead of an overlapping real one, repeating the real matches or holding a negated match does
  not pair; one that ends inside a match is not understood; set-match text touching the quotes
  is not a match and the rule is read through its real sets. A regression guard, not a fix:
  with the set count dropped from the pairing, the first three rows are accepted.
- The `oifname` exemption for one tunnel interface: `oif`, sets, wildcards, `!=`, an empty egress
  and `iifname` all prove nothing.
- The receipt against anyone without write access to the state directory: random boot ID per
  process, sequence tied to the heartbeat, no fallback in Kubernetes mode.
- Cilium's order of decisions (egress gateway, exclusion, map, pod source) matches v1.20.5;
  per-node overrides are covered because the local agent is asked; truncation is refused.

## Refusal tests still missing

The review listed these; each now exists on `k8n/review-fixes`:

| Missing test | Now |
| --- | --- |
| `hash:ip` with netmask or bitmask | `TestParseIPSetSaveRefusesASetThatMatchesMoreThanItLists` and rows of `TestCalicoNodeRefusals` (item 2) |
| a second tunnel interface | `TestObservedExcusesNoRuleBoundToAnyTunnelInterface`, `TestLiveCalicoNodeIsRefusedWhenAMasqueradeIsBoundToASecondTunnelInterface` (item 3) |
| a NAT-chain `MARK` or `mangle` touching reserved bits, `ip saddr set` | `TestObservedNATWalkReadsANativeMarkStatement`, `TestObservedNATWalkReadsAMarkTargetFromItsSavedRule` (item 4; every reserved bit after the follow-up) |
| a comment containing set-match text | `TestObservedCommentWithSetMatchTextOnlyBreaksPairing` (a guard; no fix) |
| ip-masq-agent on with the tunnel inside the status exclusion | `TestProveCiliumReportedRangeProvesOnlyWithTheIPMasqAgentOff`, `TestCiliumLiveNodeWithIPMasqAgentOnIsNotReadyOnTheReportedRange` (item 1) |
| a receipt carrying a Cilium section when the gateway saw no trace | `TestGatewayRunsTheCiliumDecisionOnAReceiptSectionAlone` (item 6) |
| a node with legacy tables | `TestNodeWithLegacyTablesIsNotReady` (item 5) |
| a set renamed between the save and the member read | `TestHostFactsReaderRereadsSetNamesAfterTheMembers` (item 7) |

Not addressed on this branch: item 8 (the receipt's digest is unkeyed and its freshness is
wall-clock) and item 10 (needs a live cluster).

## Could not be determined

Whether GKE Dataplane V2 or AKS show the names the guard looks for; whether Cilium before 1.20.5
has the mismatch of item 1; whether an in-cluster gateway can have OpenVPN enabled; item 10.
