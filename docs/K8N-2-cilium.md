# K8N-2 — run the in-cluster gateway on Cilium

Story branch: `story/kubernetes-next`, work branch `k8n/cilium`. Second half of item 1 of
`docs/EPIC-kubernetes-next.md`. Calico is K8N-1; this paper shares none of its assumptions.

Facts about Cilium come from its documentation and from its source at tag `v1.20.5` (the release
the "stable" docs describe today); each carries a reference like [D1] or [S3], listed at the end.
Three configurations were then run on a real node; what that confirmed is in "Live capture,
2026-11-23" and is marked [L]. Anything confirmed neither way is in "Not confirmed".

## What happens today

The host-posture check must prove, before the gateway carries traffic, that **no rule on the node
can rewrite the source address of a packet bound for the tunnel range**. `k8snetprep/observed.go`
does that by reading every rule reachable from `ip nat POSTROUTING`.

**Corrected by the live capture: on this branch a Cilium node is no longer refused. The rule
check reports all three captured nodes ready as `observed_cni`, including the eBPF-masquerade
node on which a pod's packet to the device range was seen rewritten [L]. The mangle hook is
accepted since K8N-1 taught the check to prove it sets no reserved mark, and Cilium's chains are
empty in eBPF mode. The "false ready" below was therefore the normal case, not a corner case.
It was first closed by the guard described in "The guard, built", which refused a node that shows
Cilium in every mode, and is now closed by the proof itself: see "As built" at the end. A node
that shows Cilium is ready exactly when that proof holds.** The original reading, kept for the
record:

On a Cilium node, reading the code against Cilium's rule shapes [S5][S6], the expected result was:

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
  pinned-map list and `bpftool` output of the three configurations through the same functions
  (A refused, B proved by the map entry, C deferring to the walk), and
  `cilium_live_linux_test.go` runs today's whole rule check on the captured rulesets.
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
4. Tunnel routing mode (the capture is native routing only), eBPF masquerade with kube-proxy still
   present, and a multi-node cluster.
5. A big-endian host. The key's prefix length is in host byte order; only arm64 was captured.
6. Whether a pin can outlive its feature in other ways (agent not restarted, agent crash, an
   egress-gateway map). Seen once: ip-masq-agent off plus an agent restart removes the pin [L].
7. A host whose Cilium uses legacy iptables: `nft` would not show those rules at all. This is a
   general gap in the walk, not specific to Cilium. (The kind node uses the nf_tables backend.)
8. The exact customer command of "What the customer does" (`--reuse-values --set ...`). The
   capture used a values file with the same three settings, which worked.
9. Traffic opened from a device towards a pod or Service, and the reply. Only a pod's own packet
   to the device range was observed.

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

One node, three configurations. `kind` v0.31.0, node image `kindest/node:v1.35.0`, Docker Desktop
kernel `6.8.0-117-generic` (arm64), no default CNI, no kube-proxy. Cilium **1.20.5** by Helm:
`kubeProxyReplacement=true`, `routingMode=native`, `ipv4NativeRoutingCIDR=10.244.0.0/16`,
`autoDirectNodeRoutes=true`, `ipam.mode=kubernetes`, and:

- **A** `bpf.masquerade=true`, ip-masq-agent off.
- **B** A plus `ipMasqAgent.enabled=true`, `nonMasqueradeCIDRs: [100.96.0.0/24]`,
  `masqLinkLocal: true`. Then the ip-masq-agent was turned off again and the agent restarted.
- **C** `bpf.masquerade=false` (iptables masquerade), ip-masq-agent off.

eBPF masquerade works on this kernel. Everything was read from a separate pod (Alpine 3.24.2, host
network, privileged, root, `RuntimeDefault` seccomp profile requested) with **read-only** host
mounts of `/var/run/cilium` and `/sys/fs/bpf`, using `curl`, `bpftool` v7.8.0, `nft` 1.1.6,
`iptables-nft-save` 1.8.13 and `ipset`. A `wg0` of type `wireguard` with `100.96.0.1/24` and no
peer stood in for the tunnel; a pod pinged `100.96.0.5` and `tcpdump` on `wg0` showed the source.
The files are in `apps/node/internal/k8snetprep/testdata/cilium-1.20.5-kind-*`. Nothing below
speaks for GKE Dataplane V2 or AKS.

| | Status `masquerading` | `cilium_ipmasq_v4` | Pod packet on `wg0` | Cilium proof, range `100.96.0.0/24` | Rule check today |
| --- | --- | --- | --- | --- | --- |
| A | `mode: BPF`, no `ip-masq-agent` | not pinned | source `100.96.0.1` (rewritten) | refused | **ready** |
| B | `mode: BPF`, `ip-masq-agent: true` | pinned, one entry | source is the pod's | proved by the map entry | ready |
| B, agent off again | as A | pin removed | rewritten again | refused | not run |
| C | `mode: iptables`, no `ip-masq-agent` | not pinned | source `100.96.0.1` (rewritten) | defers to the walk | ready |

Confirmed [L]:

- **Status.** `GET /v1/healthz` returns the `masquerading` object exactly as modelled:
  `enabled`, `enabledProtocols.ipv4`, `mode` (`"BPF"` or `"iptables"`), `ip-masq-agent` (present
  only when true), `snat-exclusion-cidr` and `snat-exclusion-cidr-v4` (both the native-routing
  range, in every configuration); there is no `stale` member. `parseCiliumStatus` reads all three.
- **Map dump.** `bpftool --json map dump pinned /sys/fs/bpf/tc/globals/cilium_ipmasq_v4` printed
  `[{"key":["0x18","0x00","0x00","0x00","0x64","0x60","0x00","0x00"],"value":["0x00"]}]`: the
  prefix length as a little-endian 32-bit number, then the address, and a one-byte value, as
  `decodeCiliumIPMasqKeys` assumed. This map has no `formatted` member. `bpftool map show` reports
  it as `lpm_trie`, key 8 bytes, value 1 byte, `max_entries` 16384, kernel name `cilium_ipmasq_v`.
  With `masqLinkLocal: true` the map holds only the listed range. `cilium-dbg bpf ipmasq list`
  inside the agent's pod showed the same single range.
- **The exclusion is real.** With the range in the map the pod's packet left `wg0` unchanged; with
  the map gone it was rewritten to the node's `wg0` address.
- **Turning the ip-masq-agent off removes the pin**, after the agent restart that the change needs.
  A map that was never enabled is not pinned either. `bpftool` then prints
  `{"error":"bpf obj get (<path>): No such file or directory"}` on standard output and exits 255;
  the parser refuses that as a map.
- **Socket.** `/var/run/cilium/cilium.sock`, mode `0660 root:root`, directory `0755`. Root in
  another pod connects through a read-only host-path mount (HTTP 200); the mount refuses writes.
- **Seccomp.** A privileged container has no seccomp filter even when `RuntimeDefault` is asked
  for (`Seccomp: 0` in `/proc/self/status`), and `bpf()` works.
- **Kernel map names are cut to 15 characters** (`cilium_snat_v4_`, `cilium_ipmasq_v`). Only the
  pin path identifies a map.
- **Egress gateway off: no `cilium_egress_gw_policy_v4*` pin.** A map named
  `cilium_egresscall_policy` is always pinned and is unrelated; the prefix test does not match it.
- **Hooks.** Cilium's feeder rule makes iptables create the base chain `ip mangle POSTROUTING`
  (type `filter`, priority -150) with one rule: an opaque `xt` comment match and a jump to
  `CILIUM_POST_mangle`. That chain is **empty in all three configurations**, so the mangle mark
  proof passes without reading any saved text.
- **eBPF mode rules.** `ip nat POSTROUTING` has one Cilium rule, an `xt` comment match and a jump
  to an empty `CILIUM_POST_nat`. The walk reads it and finds nothing.
- **iptables mode rules** (`CILIUM_POST_nat`, as saved):

      -s 10.244.0.0/24 -m set --match-set cilium_node_set_v4 dst -j ACCEPT
      -s 10.244.0.0/24 ! -d 10.244.0.0/16 ! -o cilium_+ -j MASQUERADE
      -m mark --mark 0xa00/0xe00 -j ACCEPT
      -s 127.0.0.1/32 -o cilium_host -j SNAT --to-source <cilium_host address>
      -o cilium_host -m mark --mark 0xf00/0xf00 -m conntrack --ctstate DNAT -j SNAT --to-source <same>

  In nft JSON: `oifname != "cilium_*"` for the wildcard, `oifname == "cilium_host"`, the marks as
  `meta mark & mask == value`, and `set`, `conntrack`, `comment`, `MASQUERADE`, `SNAT` as opaque
  `xt` descriptors. **Today's walk accepts this node** for `100.96.0.0/24` with `wg0` as the
  tunnel interface: the masquerade is limited to the node's pod range as its source, and both
  `SNAT` rules are bound to the exact interface `cilium_host`. It reads no set (the set match is
  on an `ACCEPT`). It refuses when the tunnel interface is unknown or is `cilium_host`, and when
  the tunnel range contains the node's pod range and reaches outside `10.244.0.0/16`.
- **The accepted masquerade is not idle.** In C the pod's packet to `100.96.0.5` left `wg0`
  rewritten, by the pod-source rule the walk accepts. That is the same exception the walk grants
  Flannel, and the opposite of the by-destination rule this paper sets for eBPF mode: a device
  sees the node's address, not the pod's, for connections a pod opens. Whether that asymmetry is
  wanted is a question for the founder, not settled here.
- **iptables backend** on the kind node is nf_tables (`iptables v1.8.9 (nf_tables)`); the legacy
  tables hold no rules.
- **Cilium attaches to the WireGuard interface**, in every configuration including iptables
  masquerade. Two seconds after `wg0` came up the agent logged `Devices changed ... [eth0 wg0]`,
  attached `cil_from_netdev` and `cil_to_netdev` to it with tcx, and listed it in the status. It
  also made the `wg0` address a NodePort address.

Refuted:

- **"A Cilium node is refused today."** True when the paper was written; no longer true on this
  branch. See the correction under "What happens today".
- **"iptables masquerade mode would be refused by the walk"** (output interface not read). The
  walk now reads exact `oifname` conditions and accepts the real rules.
- Nothing in `cilium.go`: no field name, key encoding or JSON shape seen differs from what it
  assumed, and it is unchanged.

## The guard, built

**Replaced.** This section describes the refuse-only guard as it stood before the reader existed.
Its detection is kept unchanged; its refusal is now the decision of "As built". Kept for the
record.

`apps/node/internal/k8snetprep/cilium_guard_linux.go`, called once in `reconcileWithAuthority`
right after the first rule check and before anything is written.

- **What it does.** If the node shows Cilium, the reconcile is refused: every component is
  blocked, no `observed_cni` adapter is reported, nothing is written. The reason is bounded and
  names what was found, for example: `Cilium runs on this node and its eBPF masquerade cannot be
  verified yet (K8N-2); the gateway is not ready on Cilium nodes (found iptables chain
  CILIUM_OUTPUT_nat)`.
- **Signals read**, both with what the gateway already has (no socket, no `bpftool`, no new mount,
  privilege, chart or image change):
  1. the names of the network devices in the gateway's (the host's) network namespace, from the
     kernel's device list: any name starting with `cilium_` (`cilium_host`, `cilium_net`);
  2. the names of every IPv4 iptables chain in the nft listing the rule check has just read, in
     any table: any name starting with `CILIUM_`.
- **Signal not read:** Cilium's pinned maps. The gateway container does not see the host's
  `/sys/fs/bpf`. The device names cover the case the maps were meant for, a Cilium told to
  install no iptables rules.
- **When detection cannot be done** (the device list cannot be read, or is empty) the node is
  refused with a reason starting `Cilium detection`; it is never taken as "no Cilium".
- **All modes are refused, iptables masquerade included.** The live capture shows today's walk
  would accept the real iptables-mode rules, and it is right about them; the node is refused
  anyway because the gateway cannot yet read which mode the agent is in, and the same chains
  exist in eBPF mode. This lasts **only until the reader exists** (checklist steps 2 and 3): then
  mode `iptables` hands the decision back to the walk, and mode `BPF` needs the Cilium proof.
- **Other nodes are unaffected.** The Flannel, kube-proxy/GKE, EKS and Calico fixtures and tests
  pass unchanged.
- Tests (`cilium_live_linux_test.go`): the whole reconcile on the real A, B and C captures is
  refused with this reason; device names alone are enough; a node without Cilium stays ready;
  unreadable or empty device lists are refused.

Not covered: a Cilium-derived dataplane that uses neither a `cilium_` device nor a `CILIUM_`
chain. Whether GKE Dataplane V2 or AKS show these names has not been checked on those platforms.

## Wiring checklist, corrected by the live capture

Of the six steps in "Wiring still to do", steps 1 and 2 are already done on this branch by K8N-1
(mangle mark proof, exact `oifname`) and hold on the real Cilium rules. What remains, in order:

1. **Guard: done**, refuse-only (see "The guard, built"). When the reader exists, the guard's
   refusal becomes "Cilium is present and there is no fresh receipt", and a fresh receipt lets
   step 3 decide.
2. **Reader and receipt** (`hostposture`). Root, read-only mounts of `/var/run/cilium` and
   `/sys/fs/bpf`, nothing else. One `GET /v1/healthz`; list `/sys/fs/bpf/tc/globals`; dump
   `cilium_ipmasq_v4` only when the status says `ip-masq-agent` is true. Treat `bpftool`'s exit
   status and output together: an `{"error":...}` object is a read error, carried in the receipt
   as such, never as an empty map. With the ip-masq-agent off a missing pin is expected.
3. **Decision in the gateway.** `proveCiliumNoTunnelMasquerade`, then: mode `iptables` → the rule
   walk's result stands (it accepts the real rules); mode `BPF` → both must hold, and the walk
   always holds there because Cilium's chains are empty.
4. **Egress detection** stays an exact prefix test on `cilium_egress_gw_policy_v4`; do not widen
   it to `cilium_egress`, which would match `cilium_egresscall_policy` on every node.
5. **Detection inputs.** Link names from `ip -o link` carry a peer suffix
   (`cilium_net@cilium_host`); the prefix test holds, but strip the suffix where names are
   compared exactly.
6. **Chart and image** as planned. Alpine 3.24's `bpftool` package (binary reports v7.8.0) reads
   the pins; a privileged container needs no seccomp exception.
7. **Freshness.** The map changes without an agent restart when the ConfigMap changes, and the pin
   disappears when the feature is turned off; in both cases traffic was rewritten again at once.
   The receipt must be re-read every interval and a stale one refused, as planned.
8. **To raise outside this item:** Cilium serves NodePort on the `wg0` address once it selects the
   device; and in iptables mode a pod's own connection to a device is masqueraded, which the walk
   accepts (see "The accepted masquerade is not idle").

## As built, 2026-11-23

Branch `k8n/cilium-wiring`. Checklist steps 1 to 7 above are done; step 8 is still to be raised.

### Who reads what

- **The manager** (`k8snetprep/cilium_reader_linux.go`, wired in `cmd/agent/k8s_host_posture.go`).
  Each pass, after its netfilter read, on a node that shows a trace of Cilium (a `cilium_` network
  device, a `cilium_` pinned map, or the agent's socket):
  1. `GET /v1/healthz` on `/var/run/cilium/cilium.sock`. The runner takes no argument: not the
     method, not the path, not the socket. No redirect is followed, the body is bounded (4 MiB).
  2. the names under `/sys/fs/bpf/tc/globals` (a directory listing, at most 16384 names; nothing
     inside is opened);
  3. only when the status says `ip-masq-agent` is on:
     `bpftool --json map dump pinned /sys/fs/bpf/tc/globals/cilium_ipmasq_v4`. The runner accepts
     no other argument vector. Exit status and output are read together: a failed run, an
     `{"error":...}` object or anything that is not a JSON array is a read error.

  One read is bounded to 2 s. On a node with no trace of Cilium nothing is read past the device
  list, the directory listing and one `lstat` of the socket, and nothing is published.
- **The receipt.** The facts go into the existing `host-facts.json` as a `cilium` member beside
  `netfilter`, under the same node, manager, boot, sequence, `observed_at` and digest:

      cilium:
        status       state read | unreadable, reason, text
        pinned_maps  state read | unreadable, reason, total, egress_gateway [names]
        ip_masq_map  state read | not_needed | unreadable, reason, text

  `status.text` is not the whole status (11 to 14 KiB, dozens of members): it is one JSON object
  with the `masquerading` member and, when the agent sent one, the `stale` member, byte for byte
  compacted. `parseCiliumStatus` reads it exactly as it reads the full status. `ip_masq_map.text`
  is what `bpftool` printed. `egress_gateway` lists the pinned names that start with
  `cilium_egress_gw_policy_v4`. Bounds: 8 KiB for the status text, 32 KiB for the map dump (about
  390 ranges), 8 egress-gateway names, 240 bytes per reason. What does not fit is published as
  `unreadable` with the reason, never cut; if the whole receipt would not fit, both sections are
  replaced by that statement. Nothing in it is a verdict, and the tunnel range is not in it.
  **A node without Cilium publishes the receipt exactly as before**: the member is absent, so an
  older gateway beside a newer manager is unaffected there.
- **The gateway** (`cilium_guard_linux.go`, `cilium_facts.go`). After the rule check has passed
  and before anything is written: detection as before (device names, chain names). If the node
  shows Cilium, the gateway takes the `cilium` section through the same store, under the same
  rules as the netfilter facts, and runs the unchanged parsers and `proveCiliumNoTunnelMasquerade`:
  - masquerade off, or mode `iptables`: ready; in `iptables` mode the reason says the rule walk
    decides, and that walk has just passed on the live rules;
  - mode `BPF`: ready only if the tunnel range is inside the native-routing range or inside one
    entry of the dumped map; the pinned-map listing is required (egress gateway), and the map dump
    is required when the agent reports the ip-masq-agent on;
  - anything else is a refusal, and nothing is written.

  A ready node reports the adapter `cilium_masquerade` after `observed_cni`. A node without
  Cilium reports no such adapter and its facts source is never asked.

### What the customer reads

Ready (`cilium_masquerade`):

- `tunnel range is inside Cilium's native-routing range 10.244.0.0/16`
- `tunnel range is inside Cilium ip-masq-agent range 100.96.0.0/24`
- `Cilium masquerades with iptables rules; the NAT rule walk decides`
- `Cilium does not masquerade IPv4 traffic`

Not ready, and the customer can lift it (both fit the 240-byte bound for any range):

- ip-masq-agent off: `Cilium eBPF masquerade would rewrite traffic to the tunnel range
  100.96.0.0/24. Enable Cilium's ip-masq-agent (Helm ipMasqAgent.enabled=true) with 100.96.0.0/24
  in nonMasqueradeCIDRs, then restart the Cilium agents`
- ip-masq-agent on: `Cilium eBPF masquerade would rewrite traffic to the tunnel range
  100.96.0.0/24. Add 100.96.0.0/24 to nonMasqueradeCIDRs in the ip-masq-agent ConfigMap (namespace
  kube-system, key config); no restart is needed, allow about a minute`

Not ready, something could not be read or was not understood. Each starts with `Cilium masquerade
on this node is not verified: ` and, where it fits, ends with what made this a Cilium node, for
example `(found network device cilium_host)`:

- `no host-posture facts source is configured`
- `host facts receipt is missing` / `... is stale or from the future` / `... is from another node`
  / `... does not belong to the live heartbeat` / `... is damaged: its digest does not match` /
  `host-posture heartbeat is stale`
- `the host-posture manager published no Cilium facts` (a manager from before this change)
- `the host-posture manager could not read the Cilium agent status: /var/run/cilium is not mounted
  in the host-posture manager; set cilium.enabled=true on the tunnex-host-posture chart`
- `the host-posture manager could not read the Cilium agent status: no agent socket at
  /var/run/cilium/cilium.sock; the Cilium agent is not running or is restarting`
- `the host-posture manager could not list Cilium's pinned maps: ...`
- `the host-posture manager could not read the ip-masq-agent map: bpftool: bpf obj get (...): No
  such file or directory`
- `Cilium masquerading status is not understood` (an unknown field), `... mode is not understood`,
  `... is stale`, `... is inconsistent`

Not ready, by ruling: `Cilium egress gateway is enabled; its policies are applied before any
masquerade exclusion and are not read`.

### Chart, installer, image

- **Chart** `tunnex-host-posture`: value `cilium.enabled`, default `false`. With it the manager
  gets two more `hostPath` volumes, type `Directory`, both mounted `readOnly: true`:
  `/var/run/cilium` and `/sys/fs/bpf` (the latter with `mountPropagation: HostToContainer`, as
  Cilium's own agent mounts it, so a BPF filesystem mounted after the pod started is still seen).
  Nothing else in the rendered release changes; the contract test compares the two renders line
  by line. The gateway chart is unchanged and its contract test now refuses any Cilium path in it.
- **Installer** (`tunnex k8s plan` / `install`): looks for the DaemonSet `cilium` in `kube-system`
  (`kubectl get daemonset cilium --namespace kube-system --ignore-not-found=true --output name`).
  If it is there the plan says `"cilium_host_paths": true`, names the two mounts in its
  operations, and sets `cilium.enabled=true`. A manager whose mounts do not match what the cluster
  needs is upgraded, not reused; the value is set to `false` only where the mounts have to be
  taken away. The fixed-shape check of the live DaemonSet accepts exactly none or both of the
  paths, read-only, with these host paths and types. `tunnex k8s upgrade` upgrades a gateway and
  has never changed the shared manager; it does not set the value.
  GKE's `anetd` is deliberately not matched: nothing is known about its paths.
- **Image** (`deploy/docker/node.Dockerfile`): see "Found while building the image" below.

### Found while building the image

Alpine 3.24's `bpftool` package (7.1.5-r0, binary reports v7.8.0) cannot simply be added:

- it depends on `perf`, `cpupower`, `linux-tools-gpio` and `linux-tools-iio`, and through `perf` on
  `python3`. The image's own runtime check (`deploy/ipsec/verify_runtime.sh`) refuses `python3` as a
  build tool, so the build fails;
- the binary is linked against `libLLVM.so.22.1`. `llvm22-libs` is 167 MiB installed.

Measured on the pinned base with today's runtime packages: 31 MB of files; with `llvm22-libs`
203 MB; with the whole `bpftool` package 264 MB.

As built, the Dockerfile takes the one binary `/usr/sbin/bpftool` from a stage of the same pinned
Alpine release and installs the libraries it is linked against by name (`libelf`, `libcap2`,
`zlib`, `llvm22-libs`); `bpftool version` runs in the build and fails it if a library is missing.
That keeps every byte from Alpine's signed packages and passes the runtime check. The whole
Dockerfile was built this way (arm64): the build passes, `bpftool version` prints v7.8.0 in the
image, and neither `python3` nor the `bpftool` or `perf` packages are in it. The image is 433 MB
as Docker reports it, against 182 MB for the last image built on this machine without it (an
earlier build of another branch, so not an exact before and after); `libLLVM.so.22.1` alone is
168 MB of it. **This cost was not known when the founder ruled
for `bpftool`; it needs a second look.** The alternatives: build `bpftool` from its upstream
source without LLVM (under 1 MB; a new pinned source, as the FRR observer already is; not tried
here), or read the one map with `bpf()` calls in Go (ruled out on 2026-11-23, before this was
known).

### Tests

- `k8snetprep/cilium_facts_test.go`: the section's shape and bounds; the decision on the real
  captures (A refused with the instruction, B proved by the map entry, B then off refused, C
  deferring to the walk); every refusal by name; both instructions within the reason bound.
- `k8snetprep/cilium_reader_linux_test.go`: the reader builds exactly that section from the
  captured node; publishes nothing without Cilium; states what it could not read (no socket, no
  mount, agent down, oversized, not JSON, unlisted pins, `bpftool`'s error object, a map over the
  bound); the real status runner against a real unix socket sends exactly `GET /v1/healthz`,
  follows no redirect and bounds the body; the real runners refuse every other argument vector.
- `k8snetprep/cilium_live_linux_test.go`: the whole `Reconcile` on the real captures with those
  sections; refused without a source, without a receipt, without the section; an iptables-mode
  range the walk refuses stays refused by the walk; a Flannel node reports no `cilium_masquerade`
  and its facts source is never asked.
- `k8snetprep/cilium_e2e_linux_test.go`: the real manager with both real readers and a real
  gateway reconciler over one state directory, the captured node between them: A, then B, then the
  range removed, the pin gone, the ip-masq-agent off, an egress-gateway pin, an unknown field;
  and a missing, earlier, truncated, edited, oversized and foreign-node receipt, and a manager
  that publishes no section.
- `hostposture/host_facts_cilium_test.go`: the section under the receipt's identity, freshness
  and digest; an edit of the section after sealing is refused for both kinds of facts.
- `apps/cli/internal/cli/k8s_host_posture_cilium_test.go`: the installer's six cases, the plan
  text, the shape drift refusals. `deploy/k8s-host-posture-chart-contract_test.sh`: the value off
  and on.
- The Flannel, kube-proxy, GKE, EKS and Calico fixtures and tests, including the Calico receipt
  path, pass unchanged.

## Live check of the wiring, 2026-11-23

One-node `kind` v0.31.0, Kubernetes v1.35.0, kernel 6.8.0-117-generic (arm64), containerd 2.2.0,
no default CNI, no kube-proxy; Cilium **1.20.5** by Helm with the values of the capture above.
Tools in the pods: bpftool v7.8.0, nft 1.1.6, iptables-nft-save 1.8.13, ipset 7.24 (Alpine
3.24.2). The package's test binary ran in two `hostNetwork` pods sharing
`/var/lib/tunnex/host-posture/v1`:

- **the manager's pod was the chart itself**: `helm template` of `tunnex-host-posture` with
  `cilium.enabled=true`, with only the image and the command replaced. Privileged, root,
  read-only root filesystem, 128Mi limit, the two Cilium paths read-only (`touch` in either:
  `Read-only file system`). In it ran the real manager loop with the real netfilter reader and
  the real Cilium reader with their real, closed runners. Only the Kubernetes API read and the
  kernel mutations were replaced, so nothing on the node changed but the state directory.
- **the gateway's pod** had the gateway container's security context (root, drop ALL, add
  `NET_ADMIN` and `NET_BIND_SERVICE`; effective capabilities `0x1400`; seccomp filter active), the
  state directory read-only, and no path to `/var/run/cilium` or the host's `/sys/fs/bpf`. In it
  ran the real reconciler with the real authority guard and both real facts sources, once a
  second, for 100.96.0.0/24 and 10.244.200.0/24.

Neither Tunnex pod was restarted between the first three rows (0 restarts, same start time).

| Cilium | 100.96.0.0/24 | 10.244.200.0/24 |
| --- | --- | --- |
| A: eBPF masquerade, ip-masq-agent off | not ready, "Enable Cilium's ip-masq-agent ..." | ready, native-routing range |
| ip-masq-agent on, list `[100.64.99.0/24]` | not ready, "Add 100.96.0.0/24 to nonMasqueradeCIDRs ..." | ready, native-routing range |
| B: `100.96.0.0/24` added to the ConfigMap | **ready**, `tunnel range is inside Cilium ip-masq-agent range 100.96.0.0/24` | ready |
| the range removed from the ConfigMap | not ready, "Add ..." | ready |
| ip-masq-agent off again, agent restarted | not ready, "Enable ..."; no `cilium_ipmasq_v4` pin | ready |
| C: iptables masquerade | **ready**, `Cilium masquerades with iptables rules; the NAT rule walk decides` | ready, same |
| C, manager without `cilium.enabled` | not ready, "/var/run/cilium is not mounted ... set cilium.enabled=true ..." | not ready, same |

Timings, by the node's clock:

- **A ConfigMap change took 49 s to be seen, both ways** (added 09:15:46.4, ready 09:16:35.6;
  removed 09:16:48.2, not ready 09:17:36.9). Almost all of it is before Cilium changes its map
  (the kubelet's ConfigMap sync and the agent's watch): the manager's pass that first carried the
  new map was at 09:16:35.0 and the gateway was ready 0.6 s later. Tunnex's own share is at most
  one manager interval (2 s) plus one gateway pass (2 s in the agent, 1 s in this check). Because
  the manager reads the live map, the gateway turns not ready when Cilium starts to masquerade
  again, not when the ConfigMap is edited.
- **Every restart of the Cilium agent makes the gateway not ready for its duration**, 8 to 10 s
  here: the socket is gone, the reason says `no agent socket ...; the Cilium agent is not running
  or is restarting`, for every range including those inside the native-routing range. Cilium's
  programs keep forwarding while the agent restarts; Tunnex has no fresh report to stand on and
  does not keep the last one. See "Decisions to confirm".
- One manager pass took 15 to 110 ms (225 to 280 ms in the pass right after an agent restart);
  the receipt was 1.5 to 2.5 KiB; each of the two processes used about 15 MB.

Not part of this check: packets (the capture above saw them; this check did not look again), the
real images and both charts installed by `tunnex k8s install`, the real manager's Kubernetes and
kernel work, a `wg0` on the node (the `rp_filter` read-back was pointed at a file).

## Still not confirmed

Nothing here speaks for them; on each the gateway stays not ready unless the proof holds:

1. **GKE Dataplane V2.** Whether `anetd` shows `cilium_` devices or `CILIUM_` chains, whether it
   serves the same socket and status, and whether its map has this name and pin. The installer
   does not set `cilium.enabled` there (it looks for `kube-system/cilium`).
2. **AKS, Azure CNI powered by Cilium.** Whether its DaemonSet is `kube-system/cilium` with the
   usual host paths (then the installer mounts them), and what its agent reports.
3. **Cilium older than 1.20.5.** Status fields, map name, key layout. An unknown field in the
   masquerading report refuses.
4. Tunnel routing mode, eBPF masquerade with kube-proxy still present, a multi-node cluster, a
   big-endian host, legacy iptables: as in "Not confirmed" above, unchanged.
5. A node whose `/var/run/cilium` does not exist yet when the manager pod starts (the volume is
   `type: Directory`): the kubelet is expected to retry the mount until Cilium has created it;
   not exercised.
6. The egress gateway refusal on a real cluster with the feature on; an ip-masq-agent list longer
   than about 390 ranges (refused as too large, by the receipt bound).
7. Whether a real device sees the pod's address through a gateway that is ready by the map
   entry: the capture saw it on a stand-in `wg0`, no real gateway has carried it.

## Decisions to confirm

1. **`bpftool` costs about 170 MB of image** because Alpine links it against LLVM; see "Found
   while building the image". Keep it, build it from source without LLVM, or reopen the `bpf()`
   read.
2. **Not ready during every Cilium agent restart** (8 to 10 s here). The alternative is a short
   grace on the last good report, as `apiFaultGrace` does for the Kubernetes API; not built,
   because it would be the first place the gateway stands on a report it cannot refresh.
3. **Detection by `kube-system/cilium` only.** Cilium installed in another namespace, or under
   another name, gets no mounts from the installer; the gateway then says which chart value to
   set. Matching the label `k8s-app=cilium` in every namespace would also match GKE's `anetd`.
4. **`hostPath` type `Directory` for `/var/run/cilium`.** Nothing is created on the host, and a
   manager pod waits where the directory does not exist. `DirectoryOrCreate` (what Cilium's own
   chart uses) would never wait but creates the directory on such a node.
5. **The ip-masq-agent list is carried as `bpftool` printed it**, bounded to 32 KiB. A list
   longer than about 390 ranges is refused rather than carried in a denser form.
6. **In iptables mode a pod's own connection to a device is still masqueraded** (the walk's
   pod-source exception; checklist step 8). Unchanged by this work, and still to be ruled on.
