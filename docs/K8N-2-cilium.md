# K8N-2 — run the in-cluster gateway on Cilium

Story branch: `story/kubernetes-next`, work branch `k8n/cilium`. Second half of item 1 of
`docs/EPIC-kubernetes-next.md`. Calico is K8N-1; this paper shares none of its assumptions.

Facts about Cilium come from its documentation and from its source at tag `v1.20.5` (the release
the "stable" docs describe today); each carries a reference like [D1] or [S3], listed at the end.
One configuration was then run on a real node; what that confirmed is in "Live capture,
2026-11-23" and is marked [L]. Anything confirmed neither way is in "Not confirmed".

## What happens today

The host-posture check must prove, before the gateway carries traffic, that **no rule on the node
can rewrite the source address of a packet bound for the tunnel range**. `k8snetprep/observed.go`
does that by reading every rule reachable from `ip nat POSTROUTING`.

On a Cilium node, reading the code against Cilium's rule shapes [S5][S6], the expected result is:

- **Refused, without naming a NAT chain.** Cilium hooks its own `CILIUM_POST_mangle` chain into
  `mangle POSTROUTING` [S6]. `validateHookCoverage` refuses any postrouting hook it does not know
  with `unknown IPv4 postrouting hook coverage`, before the NAT walk starts.
- If that hook were accepted, **iptables masquerade mode would be refused by the walk**: Cilium's
  hairpin rule and, in tunnel mode, its host-to-cluster rule are `SNAT` rules limited by output
  interface (`-o cilium_host`), not by source [S5]. The walk does not read output interfaces.
- **One way to a false "ready".** With eBPF masquerade and Cilium told not to install its iptables
  rules (agent option `install-iptables-rules: "false"` [S11]), the node is expected to have no
  Cilium chain at all. The walk then passes and reports `observed_cni`, although it has read
  nothing about the eBPF masquerade. Today's check is not wrong about what it read; it does not
  know there is more to read.

## Why Cilium needs a second proof

In eBPF mode (`bpf.masquerade=true`) the masquerade is done by a program attached to network
devices, not by a NAT rule [D1]. Three facts decide the design:

1. **The program is likely attached to the WireGuard interface.** "Masquerading can take place only
   on those devices which run the eBPF masquerading program", and unless `devices` is set the
   program goes on every auto-detected device [D1]. Auto-detection selects any device that is up,
   is not a bridge or bond member, does not start with `cilium_`, `lo`, `lxc`, `cni` or `docker`,
   and has a route to a global unicast destination [S7]. `wg0` with its tunnel route qualifies.
2. **What the program does to a packet** [S1], in order: a packet from the node's own masquerade
   address keeps it; a pod's reply to a connection opened from outside is never rewritten; an
   **egress-gateway policy** match is rewritten "regardless" of any exclusion; a destination
   inside the **exclusion range** (`ipv4-native-routing-cidr` if set, otherwise the node's pod
   range) is not rewritten; with the ip-masq-agent enabled, a destination inside any entry of the
   **`cilium_ipmasq_v4` map** is not rewritten; otherwise a packet whose source is a pod on this
   node is rewritten.
3. **Both exclusions are documented settings** [D1]: destinations inside
   `ipv4-native-routing-cidr` "will not be masqueraded", and a packet "to a destination which
   belongs to any CIDR from the `nonMasqueradeCIDRs`" is not masqueraded.

So the provable statement for eBPF mode is by destination: **the tunnel range lies inside a range
Cilium never masquerades to.** That is stricter than what the walk accepts for Flannel (a
masquerade limited to pod sources). The reason is evidence: Flannel's source limit is written in a
rule the walk reads; Cilium's is behaviour inside a program, known only from one version's source.

## The cases

| Case | Where the masquerade is | Proof |
| --- | --- | --- |
| Cilium, IPv4 masquerade off | nowhere in Cilium | agent reports it off; the NAT walk covers whatever else the node runs |
| iptables masquerade, kube-proxy present or replaced | `CILIUM_POST_nat` [S5] | the NAT walk, once it can read Cilium's rules (wiring 1 and 2 below) |
| eBPF masquerade, kube-proxy replaced | program on devices [D1] | agent report + exclusion range / ip-masq-agent map |
| eBPF masquerade, kube-proxy still present | program on devices, plus one iptables hairpin `SNAT` rule Cilium keeps in this case [S5] | both: the Cilium proof and the NAT walk |
| GKE Dataplane V2 | Cilium-based `anetd`, no kube-proxy [D4]; customer sets ranges with the `ip-masq-agent` ConfigMap [D5] | same two proofs; which one carries it is **not confirmed** |
| AKS, Azure CNI powered by Cilium | Cilium, no kube-proxy; the customer may not change `cilium-config` [D3] | same two proofs; AKS's masquerade settings are **not confirmed** |

Kube-proxy replacement matters in two ways only: eBPF masquerade depends on it today [D1], and
without it Cilium keeps the hairpin rule and kube-proxy's own chains stay in the walk as today.

## Evidence on the node, evaluated

What the two Tunnex containers can reach today:

- **Host-posture manager** (`deploy/helm/tunnex-host-posture`): privileged, root, host network. It
  mounts only its state directory and `/proc/sys`; its service account may only read Pods. It has
  the capability to read BPF maps, but no path to Cilium's socket or pinned maps, and no `bpftool`.
- **Gateway**: host network, `NET_ADMIN` only, not privileged; reads Services and EndpointSlices;
  mounts the posture state directory read-only. It runs the NAT walk itself (`nft` is enough).

| Candidate | What it is | Verdict |
| --- | --- | --- |
| `cilium-config` ConfigMap | intended settings; the agent reads them at start | **Not a proof.** Intent, not what the running agent does. Needs new cluster-wide RBAC. Managed platforms own it [D3]. |
| `ip-masq-agent` ConfigMap | intended non-masquerade list | **Not a proof**, same reasons. It is where the customer makes the change. |
| `ipv4-native-routing-cidr` | a setting | Used, but read as the **effective** value the agent reports (`snat-exclusion-cidr-v4`), which is also right when the setting is absent [S2][S3]. |
| Files under `/var/run/cilium/state` | the agent's own working files | **Rejected.** Not a documented interface, and moving: in v1.20.5 the datapath takes some of these settings as header defines and others as per-program config values [S1]. |
| Agent API socket `/var/run/cilium/cilium.sock` [S8] | `GET /v1/healthz` returns the status, including a `masquerading` object: enabled, per protocol, mode `BPF` or `iptables`, `ip-masq-agent`, `snat-exclusion-cidr-v4` [S2][S3] | **Adopted.** A versioned API, and the running agent's own account. Needs the host path `/var/run/cilium` mounted; root can connect. The same socket also accepts writes, so the reader must be closed to that one request. |
| `cilium-dbg bpf ipmasq list` [D1] | prints the map | **Not usable by Tunnex**: it runs inside Cilium's pod, and Tunnex must not hold `pods/exec`. Kept as the command an operator runs to see what Tunnex saw. |
| Pinned map `/sys/fs/bpf/tc/globals/cilium_ipmasq_v4` [S4][S8] | the live non-masquerade list: an LPM map, key = 32-bit prefix length + IPv4 address, value unused | **Adopted** for the ip-masq-agent case. Needs the host's `/sys/fs/bpf` mounted (a container's own `/sys` does not show it) and `CAP_BPF`/`CAP_SYS_ADMIN`, which the privileged manager holds. The map alone is not enough: it can exist while the feature is off, so the agent report gates it. |
| "The program is not on `wg0`" | device list from the status, or tc/tcx attachments | **Not adopted.** Auto-detection will usually select `wg0` [S7], and it re-evaluates when devices change, so it would rarely pass and can stop being true. Revisit after the live walk. |

## Decision

1. **Two proofs on a Cilium node, and both must hold.** The NAT walk stays as it is for rules. A
   new Cilium proof covers what Cilium does itself. Neither replaces the other.
2. **Cilium is detected, never assumed absent.** Any trace — a `cilium_*` network device, a
   `CILIUM_*` NAT chain, a pinned `cilium_*` map — makes the Cilium proof mandatory. A node that
   shows Cilium but offers no readable agent report is refused. This closes the false "ready".
3. **The Cilium proof** (`proveCiliumNoTunnelMasquerade`), from the agent's report:
   - IPv4 masquerade off → proved.
   - mode `iptables` → nothing more to prove here; the walk decides.
   - mode `BPF` → proved only if the tunnel range lies wholly inside `snat-exclusion-cidr-v4`, or
     the ip-masq-agent is enabled and one entry of the live map contains the whole range.
   - mode `BPF` with an egress-gateway policy map pinned → refused (see "What stays refused").
   - Anything else — no report, a stale one, an unknown mode, an unknown field inside the
     `masquerading` object, fields that contradict each other, a map that was not read — is a
     refusal. Unknown fields elsewhere in the status are ignored; it has dozens and grows.
4. **Who reads.** The privileged manager reads the agent report and the map and publishes the
   facts, not a verdict, as a bounded receipt in the shared state directory, tied to its heartbeat
   like the existing CNI authority receipt. The gateway, which knows the tunnel range, decides.
   The gateway gets no new privilege and no access to Cilium's socket.
5. **How the map is read.** `bpftool --json map dump pinned <path>`: the pin path is the map's
   exact identity (a lookup by name can match more than one map, and then `bpftool` prints another
   shape, which the parser refuses), the tool opens the map read-only [S9], and an operator can run
   the same command. Adds `bpftool` to the image, verified at build like `iptables-nft-save -V`.
6. **Report.** A new adapter `cilium_masquerade` beside `observed_cni`. Its reason says what
   carried the proof, for example `tunnel range is inside Cilium ip-masq-agent range
   100.64.0.0/10`, or names the range to exclude when refusing.

### Tunnex only observes

Tunnex must not add the tunnel range to Cilium's map or configuration:

- Cilium owns the map. On every configuration change it deletes entries that are not in its
  configuration, and at start it adopts the map's content as its own state [S4b]. An entry written
  by Tunnex would be removed by Cilium.
- The map's value is one unused byte [S4]. There is nowhere to mark an entry as Tunnex's, so a
  clean withdrawal could not tell its entry from the customer's.
- Changing the ConfigMap needs write access in `kube-system`, and on AKS changes to
  `cilium-config` are not supported at all [D3].

### What the customer does

Nothing, when the tunnel range is already inside the exclusion range (common when
`ipv4-native-routing-cidr` is `10.0.0.0/8` and the device pool is inside it) or inside an
ip-masq-agent entry (the built-in list covers `10/8`, `172.16/12`, `192.168/16`, `100.64/10` [D1]).

Otherwise the refusal names the range, and the instruction is one of:

**Self-managed Cilium, ip-masq-agent already on.** Add the device range to the list in the
`ip-masq-agent` ConfigMap (namespace `kube-system`, key `config`). No restart: the agent watches
the file; allow about a minute [D1].

    nonMasqueradeCIDRs:
      - <the ranges already listed>
      - <device range>

If the file was empty until now, the built-in list was in effect, and it stops applying as soon as
the file has any content [D1][S4b]: list those ranges too if pods rely on them.

**Self-managed Cilium, ip-masq-agent off.** Turn it on with only the device range, and keep
link-local destinations masqueraded as before (without that line `169.254.0.0/16` also stops being
masqueraded [D1]). Then restart the agents.

    helm upgrade cilium cilium/cilium --namespace kube-system --reuse-values \
      --set ipMasqAgent.enabled=true \
      --set ipMasqAgent.config.nonMasqueradeCIDRs='{<device range>}' \
      --set ipMasqAgent.config.masqLinkLocal=true
    kubectl -n kube-system rollout restart daemonset/cilium

The three options are the documented ones [D1]; the command around them is ours and must be run
once in the live walk before it goes into customer documentation. The native-routing range stays
excluded with the ip-masq-agent on [S1].

**GKE Dataplane V2.** Add the device range to `nonMasqueradeCIDRs` in the `ip-masq-agent`
ConfigMap in `kube-system`; a custom list "must at least include the cluster's node and Pod IP
address range(s)" [D5].

**AKS, Azure CNI powered by Cilium.** No supported Cilium change exists [D3]. If the proof fails
there, the only fix is to choose a device pool inside a range the node already excludes.

**Any cluster.** Moving the organisation's device pool into an excluded range is always an
alternative to changing the cluster.

## What stays refused

- eBPF masquerade with the tunnel range outside every excluded range, until the customer acts.
- A tunnel range covered only by two or more entries together. One entry must contain it.
- **Egress gateway enabled** (an IPv4 egress policy map is pinned; the feature requires eBPF
  masquerade [D2]). Its policies are applied before either exclusion [S1], and v1.20.5 carries two
  policy maps with different layouts side by side [S10]. Reading them is a later step if a
  customer needs it.
- A Cilium node where the manager has no access to the socket or the pinned maps.
- A status whose `masquerading` object has a field this code does not know. A Cilium release that
  adds one turns gateways not-ready until Tunnex has read what the field means. That is the price
  of never guessing; see open question 5.
- Calico in eBPF mode, and any other eBPF dataplane: no proof exists for them yet.
- IPv6: the tunnel range is IPv4 only.

## Code in this change

New files only, pure functions, no I/O: `apps/node/internal/k8snetprep/cilium.go`, `cilium_test.go`.

- `parseCiliumStatus` — the agent's status JSON to mode, exclusion range, ip-masq-agent flag.
- `parseBPFToolMapDump`, `decodeCiliumIPMasqKeys`, `parseCiliumIPMasqDump` — a `bpftool` JSON dump
  of the map to the list of ranges.
- `ciliumPresent`, `ciliumEgressGatewayPinned` — detection from names.
- `proveCiliumNoTunnelMasquerade` — the decision, returning the reason or the refusal.

Nothing calls them yet.

## Wiring still to do (existing files, not touched here)

1. **Hook coverage** (`aws_linux.go`, `validateHookCoverage`): read Cilium's `mangle POSTROUTING`
   chain instead of refusing it, and accept it only if it cannot set a Kubernetes-reserved mark
   (`0x2000`, `0x4000`, `0x8000`) that the walk assumes tunnel traffic never carries. Fixtures first.
2. **Output interface in the walk** (`observed.go`): a rule limited to an output interface that is
   not the WireGuard interface cannot apply to tunnel traffic leaving through it. That needs the
   property restated as "bound for the tunnel range through the WireGuard interface", which is how
   the owned `IP-MASQ-AGENT` rule is already scoped. A wildcard (`cilium_+`) excludes only if it
   cannot match the WireGuard interface's name; a negated match proves nothing.
3. **Guard and adapter** (`aws_linux.go`, `reconcileWithAuthority`): after the snapshot, call
   `ciliumPresent` with the link names, the `ip nat` chain names and the pinned-map names from the
   receipt. If present, require a fresh receipt, run `proveCiliumNoTunnelMasquerade`, and append
   `cilium_masquerade` (ready, with the reason) or return `awsBlocked` with the refusal.
4. **Reader and receipt** (`hostposture`): each interval the manager performs exactly
   `GET /v1/healthz` on the socket (bounded read, no other request possible), lists
   `/sys/fs/bpf/tc/globals`, dumps `cilium_ipmasq_v4` when the report says the ip-masq-agent is on,
   and writes a receipt: schema version, manager identity and sequence, observed-at, the raw facts
   or the read error. The gateway refuses a receipt older than the heartbeat freshness window.
5. **Chart** (`tunnex-host-posture`): read-only host paths `/var/run/cilium` and `/sys/fs/bpf` on
   the manager only, behind a value (open question 2); chart contract test updated.
6. **Image** (`deploy/docker/node.Dockerfile`): add `bpftool`.

## Tests

- Unit, in this change: every accepted and refused shape of the status and of the map dump; the
  decision for each case in the table above; bounds. About a hundred cases; every statement of
  `cilium.go` is executed. The status fixtures are written from the API model [S2] and the map
  dumps from `bpftool`'s source [S9]; none is captured.
- From the live capture: `cilium_live_test.go` runs the captured status, device list, chain list,
  pinned-map list and `bpftool` output of one eBPF-masquerade node through the same functions, and
  `cilium_live_linux_test.go` runs today's hook check on the captured ruleset.
- With the wiring: fixtures captured on real nodes (below) replace the written ones; Flannel,
  kube-proxy, GKE, EKS and Calico fixtures must pass unchanged; a Flannel node must report no
  `cilium_masquerade` adapter.

## Live walk

`kind`, `helm` and `kubectl` are on the development machine, so steps 1 to 4 need no cloud account.

1. Cilium, iptables masquerade, kube-proxy present. Capture `nft -j list ruleset`,
   `iptables-nft-save -t nat` and `-t mangle`. Confirms "what happens today" and feeds wiring 1, 2.
2. Cilium, eBPF masquerade, kube-proxy replaced, native routing, device pool **inside** the
   native-routing range. Capture the status (`curl --unix-socket /var/run/cilium/cilium.sock
   http://localhost/v1/healthz`), `ls /sys/fs/bpf/tc/globals`, `bpftool net show dev wg0`. Expect
   ready, reason naming the native-routing range. Check whether Cilium attached to `wg0`.
3. Same, device pool **outside**. Expect the refusal naming the range. Then follow the customer
   instruction (ip-masq-agent with the range), capture `bpftool --json map dump pinned ...`, and
   watch the gateway become ready with no Tunnex restart. Remove the range; expect not-ready again.
4. In 2 and 3: from a device reach a Service by address and by name; from a pod open a connection
   to a device and read the source address on `wg0` with `tcpdump`, with and without the exclusion.
5. GKE Dataplane V2: which proof carries it, whether `anetd` exposes the same socket, status and
   map, default list in effect, then a custom ConfigMap.
6. AKS, Azure CNI powered by Cilium (overlay): what the agent reports; whether the existing
   `IP-MASQ-AGENT` adapter is what applies there. AKS has never been walked live at all.

## Not confirmed

Items settled by the live capture moved to "Live capture, 2026-11-23". Still open:

1. GKE Dataplane V2: whether masquerade is done in eBPF by `anetd` or by iptables rules from the
   `ip-masq-agent` DaemonSet (Google's page describes only the latter, in general terms [D5]);
   whether `anetd` uses the same socket path, status fields, map name and pin path.
2. AKS: which masquerade settings AKS chooses, and whether its own ip-masq-agent is present.
3. Cilium older than v1.20.5 (AKS ships 1.16 to 1.19 [D3]): same status fields, map name and layout.
4. The `cilium_ipmasq_v4` map itself: never dumped on a real node. Its pin path, the byte order of
   its key as `bpftool` prints it, and the status with `ip-masq-agent` true are still from source.
5. The status and rules in iptables masquerade mode, and the nft JSON form of Cilium's masquerade
   rules (interface wildcards, mark and conntrack matches). The capture has eBPF mode only, where
   `CILIUM_POST_nat` and `CILIUM_POST_mangle` are empty.
6. Whether Cilium removes a pinned map when its feature is turned off. Only the first half is
   known: on a node where the ip-masq-agent was never on, the map is not pinned [L].
7. A host whose Cilium uses legacy iptables: `nft` would not show those rules at all. This is a
   general gap in the walk, not specific to Cilium. (The kind node uses the nf_tables backend.)
8. The customer command for turning the ip-masq-agent on, which was not run.

## Open questions

1. Accept eBPF mode without a destination exclusion, on the strength of Cilium's code (replies are
   not rewritten; only pod-sourced packets are)? Recommended: no. It rests on one version's source.
2. The two new host paths: always mounted, or only when `tunnex k8s install` sees Cilium and sets a
   chart value? Recommended: a value. A Cilium node without the mounts is refused with a reason
   naming it. The manager is already privileged, so this adds reach, not authority.
3. `bpftool` in the image, or the same read through `bpf()` calls in Go (`golang.org/x/sys` is
   already a dependency)? Recommended: `bpftool`, for an operator-reproducible reading.
4. Egress gateway: keep refusing, or read the policy map?
5. An unknown field in the `masquerading` object: refuse (as written) or ignore?
6. A general guard for eBPF dataplanes Tunnex does not know: refuse when an unknown program is
   attached to the WireGuard interface's egress?

## Rollback

The pure functions are unused until wired. The wiring only adds a requirement on nodes that show
Cilium, which are refused today anyway, and one adapter name in the status. Removing it returns
Cilium clusters to "not ready". No stored data changes; the receipt file is ignored by old gateways.

## References

Documentation:

- [D1] Cilium, Masquerading — https://docs.cilium.io/en/stable/network/concepts/masquerading/
- [D2] Cilium, Egress Gateway — https://docs.cilium.io/en/stable/network/egress-gateway/egress-gateway/
- [D3] Microsoft, Azure CNI Powered by Cilium — https://learn.microsoft.com/en-us/azure/aks/azure-cni-powered-by-cilium
- [D4] Google, GKE Dataplane V2 — https://docs.cloud.google.com/kubernetes-engine/docs/concepts/dataplane-v2
- [D5] Google, IP masquerade agent — https://docs.cloud.google.com/kubernetes-engine/docs/concepts/ip-masquerade-agent
  and https://docs.cloud.google.com/kubernetes-engine/docs/how-to/ip-masquerade-agent

Cilium source, https://github.com/cilium/cilium at tag `v1.20.5`:

- [S1] `bpf/lib/nat.h`, `__snat_v4_needs_masquerade` — the order of checks.
- [S2] `api/v1/openapi.yaml`, definitions `StatusResponse` and `Masquerading`; path `/healthz`.
- [S3] `pkg/status/status_collector.go`, `getMasqueradingStatus` — how the fields are filled.
- [S4] `pkg/maps/ipmasq/ipmasq.go` and `cell.go` — map name, key and value, created only when the
  ip-masq-agent is enabled. [S4b] `pkg/ipmasq/ipmasq.go` — `update`, `restore`, empty-file defaults.
- [S5] `pkg/datapath/iptables/iptables.go` — `installMasqueradeRules`, `installHairpinRule`,
  `hairpinWithBPFMasquerade`, `allEgressMasqueradeCmds`.
- [S6] `pkg/datapath/iptables/custom_chain.go` — `CILIUM_POST_nat`, `CILIUM_POST_mangle` hooks.
- [S7] `pkg/datapath/linux/devices_controller.go`, `isSelectedDevice`; `pkg/defaults/node.go`,
  `ExcludedDevicePrefixes`.
- [S8] `pkg/defaults/defaults.go` — `/var/run/cilium/cilium.sock`, `/sys/fs/bpf`, `tc/globals`;
  `install/kubernetes/cilium/templates/cilium-agent/daemonset.yaml` — the agent's host paths.
- [S10] `pkg/maps/egressmap/policy.go` — `cilium_egress_gw_policy_v4` and `..._v4_v2`.
- [S11] `pkg/option/config.go` — `install-iptables-rules`.

Other:

- [S9] bpftool, https://github.com/libbpf/bpftool `src/map.c` (`do_dump`, `print_entry_json`) and
  `src/common.c` (`print_hex_data_json`), main branch.

## Founder ruling, 2026-11-23

"Do the recommended." Recorded against the open questions above:

1. eBPF mode without a destination exclusion is **not** accepted on the strength of Cilium's code. The
   device range must be inside an exclusion Tunnex can read, or the node is refused with the
   instruction to add it.
2. The pinned map is read with `bpftool` in the gateway image, not with hand-written `bpf()` calls.
3. The two extra read-only host paths are mounted only when the chart value for Cilium is set, which
   the installer sets when it sees Cilium. They are not mounted on other clusters.

Questions 4 to 6 keep the paper's written default: egress gateway stays refused, an unknown field in
the masquerade report is refused, and no general guard for unknown eBPF programs is added in this
item.

## Live capture, 2026-11-23

One node, one configuration. `kind` v0.31.0, node image `kindest/node:v1.35.0`, Docker Desktop
kernel `6.8.0-117-generic` (arm64), no default CNI, no kube-proxy. Cilium **1.20.5** by Helm:
`kubeProxyReplacement=true`, `routingMode=native`, `ipv4NativeRoutingCIDR=10.244.0.0/16`,
`autoDirectNodeRoutes=true`, `ipam.mode=kubernetes`, `bpf.masquerade=true`, ip-masq-agent off. eBPF
masquerade works on this kernel. Everything was read from a separate pod (Alpine 3.24.2, host
network, privileged, root, `RuntimeDefault` seccomp profile requested) with **read-only** host
mounts of `/var/run/cilium` and `/sys/fs/bpf`, using `curl`, `bpftool` v7.8.0, `nft` 1.1.6 and
`iptables-nft-save` 1.8.13. The files are in
`apps/node/internal/k8snetprep/testdata/cilium-1.20.5-kind-A-bpf.*`.

The run was stopped for lack of disk on the development machine before the ip-masq-agent
configuration and the iptables masquerade configuration were installed. Nothing below speaks for
them, for GKE Dataplane V2 or for AKS.

Confirmed [L]:

- **Status.** `GET /v1/healthz` returns the `masquerading` object exactly as modelled:
  `enabled`, `enabledProtocols.ipv4`, `mode` `"BPF"`, `snat-exclusion-cidr` and
  `snat-exclusion-cidr-v4` (both the native-routing range); `ip-masq-agent` is omitted when false;
  there is no `stale` member. `parseCiliumStatus` reads it unchanged. No change to `cilium.go` was
  needed.
- **Socket.** `/var/run/cilium/cilium.sock`, mode `0660 root:root`, directory `0755`. Root in
  another pod connects through a read-only host-path mount (HTTP 200); the mount refuses writes.
- **Seccomp.** A privileged container has no seccomp filter even when `RuntimeDefault` is asked
  for (`Seccomp: 0` in `/proc/self/status`), and `bpf()` works.
- **bpftool through a read-only mount of `/sys/fs/bpf`.** It opens and dumps a pinned map
  (`cilium_runtime_config` was dumped). Each entry is an object with `key` and `value` as arrays
  of `"0xNN"` strings plus `formatted`, the shape `parseBPFToolMapDump` expects. A path that is
  not pinned prints `{"error":"bpf obj get (<path>): No such file or directory"}` on standard
  output and exits 255; the parser refuses it (fixture `ipmasq-v4.bpftool.json`).
- **Kernel map names are cut to 15 characters**: `bpftool map show pinned
  .../cilium_snat_v4_external` reports the name `cilium_snat_v4_`. Only the pin path identifies a
  map.
- **The ip-masq-agent map is not pinned when the feature was never on.** Of 43 pins under
  `/sys/fs/bpf/tc/globals`, none is `cilium_ipmasq_v4`.
- **Egress gateway off: no `cilium_egress_gw_policy_v4*` pin.** A map named
  `cilium_egresscall_policy` is always pinned and is unrelated; the prefix test does not match it.
- **Today's refusal.** Cilium's feeder rule makes iptables create the base chain
  `ip mangle POSTROUTING` (type `filter`, priority -150). That base chain, not
  `CILIUM_POST_mangle`, is the hook `validateHookCoverage` does not know. Its only rule is an
  opaque `xt` comment match and a jump to `CILIUM_POST_mangle`, which is empty in eBPF mode.
  (Derived from the captured ruleset; the test for it compiles for Linux but has not been run.)
- **NAT in eBPF mode with kube-proxy replaced.** `ip nat POSTROUTING` has one Cilium rule, an
  `xt` comment match and a jump to an empty `CILIUM_POST_nat`. `CILIUM_PRE_nat` and
  `CILIUM_OUTPUT_nat` exist too. The other NAT rules on the node are kind's own DNS rules.
- **iptables backend** on the kind node is nf_tables (`iptables v1.8.9 (nf_tables)`); the legacy
  tables hold no rules.
- **Cilium attaches to the WireGuard interface.** Two seconds after a `wg0` of type `wireguard`
  with `100.96.0.1/24` came up, the agent logged `Devices changed ... [eth0 wg0]`, attached
  `cil_from_netdev` and `cil_to_netdev` to it with tcx, and listed it in the status. It also made
  the `wg0` address a NodePort address.
- **And it does rewrite.** A pod (`10.244.0.10`) pinging `100.96.0.5` was seen on `wg0` with
  source `100.96.0.1`. With the range outside the native-routing range and no ip-masq-agent, the
  refusal by `proveCiliumNoTunnelMasquerade` describes a real rewrite.

Refuted: nothing. No field name, encoding or shape seen differs from what `cilium.go` assumed.

## Wiring checklist, corrected by the live capture

The six steps of "Wiring still to do" stand. Corrections and additions:

1. **Hook coverage.** The chain to admit is the base chain `ip mangle POSTROUTING` (type
   `filter`, priority -150), then the `CILIUM_POST_mangle` it jumps to. Accept only: one rule in
   the base chain, an `xt` comment match plus that jump, and a target chain that is empty or
   proved not to set a reserved mark. Non-empty contents are not yet captured (iptables mode).
2. **The walk must read an `xt` comment match in front of a jump** in `ip nat POSTROUTING`
   (`cilium-feeder: CILIUM_POST_nat`), as it appears in nft JSON with no text. Whether today's
   walk accepts it was not run, because the hook check refuses first; run the captured ruleset
   through it once step 1 is in.
3. **Detection inputs.** Link names from `ip -o link` carry a peer suffix
   (`cilium_net@cilium_host`); the prefix test holds, but strip the suffix where names are
   compared exactly. The pinned-map list is `/sys/fs/bpf/tc/globals`; `/sys/fs/bpf/cilium/devices`
   also names every device with a program, including `wg0`.
4. **Reader.** Root, read-only mounts of `/var/run/cilium` and `/sys/fs/bpf`, nothing else. Treat
   `bpftool` exit status and output together: an `{"error":...}` object is a read error, to be
   carried in the receipt as such, never as an empty map. When the status says the ip-masq-agent
   is off, a missing pin is expected and is not an error.
5. **Egress detection** stays an exact prefix test on `cilium_egress_gw_policy_v4`; do not widen
   it to `cilium_egress`, which would match `cilium_egresscall_policy` on every node.
6. **Image.** Alpine 3.24's `bpftool` package (binary reports v7.8.0) reads the pins.
7. **Before wiring**, repeat the capture for the two configurations that did not run: ip-masq-agent
   on with the device range listed (dump of `cilium_ipmasq_v4`, status with `ip-masq-agent` true,
   then off again to see whether the pin stays), and iptables masquerade mode.
8. **Outside this item, to raise:** Cilium serves NodePort on the `wg0` address once it selects
   the device.
