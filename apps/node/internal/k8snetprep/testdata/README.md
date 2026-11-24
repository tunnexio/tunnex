# CNI formatter fixtures

The worker snapshots below are byte-identical copies of the complete, redacted
[read-only evidence](../../../../../walk-artifacts/S20.5/aws-20260905/) at the repository root.
Package-local copies keep `make test-node` hermetic when it mounts only the node
module. Never replace the originals or construct foreign operational semantics
from an excerpt. Worker tools: nft 1.0.4 and iptables-nft-save 1.8.8.

SHA-256:

```text
50b7ee921e03be250b99bbf7a42fd79515a276aef7e0404783514141206ede2c  native-nft-ruleset.json
94b3c24573e053f8f95f2b94bef5c0b31178f96e77b843e258edef08186574b6  native-iptables-nft-save.txt
72b51b90498608d97b46ab20ac32adf219622b1c137065246a2aff776a050c54  runtime-alpine-baseline.iptables.txt
b4e1fe6f85cae6466bc67d9185aba6fe81fe00d428dae4d61385f057c68a04a8  runtime-alpine-baseline.nft.json
8579c36f09525e1c7b10f77e894f65fa8b880863addda77c0aa3068a65e1127b  runtime-alpine-owned.iptables.txt
ff88ba871ff827ae1e0b4323b42749bd39cfc37cac91af6b6416302901b3e6dc  runtime-alpine-owned.nft.json
```

The `runtime-alpine-*` snapshots are also byte-identical copies from that evidence
directory: an isolated Alpine 3.20 container using nft 1.0.9 and explicit
iptables-nft-save 1.8.10, before and after the exact native owned return. The
container had a representative KUBE/AWS NAT fixture, not the AWS worker's
network namespace. These prove runtime formatter interoperability, not AWS
packet delivery. Tests consume both complete before/after snapshots directly.

The additional typed-formatter unit transformation changes only the exact
witnessed xt descriptors at compat-proven positions in the larger worker
snapshot. All foreign packet semantics remain checked against the unchanged
explicit save output. Negative tests alter each of those nine positions to
reject unknown types/names, misplaced known descriptors, and extra fields.

## Cilium 1.20.5, live capture

`cilium-1.20.5-kind-*` are captures from one kind node (kind v0.31.0,
kindest/node v1.35.0, kernel 6.8.0-117-generic, arm64) running Cilium 1.20.5
with kube-proxy replacement and native routing, taken on 2026-11-23 from a
privileged pod with read-only host mounts (bpftool v7.8.0, nft 1.1.6,
iptables-nft-save 1.8.13). They are stored as read, except that the `#` comment
lines of `iptables-nft-save` (version and date) were dropped.

- `A-bpf`: eBPF masquerade, ip-masq-agent off. `bpftool-net.json` was taken
  before the test `wg0` existed; the other A files likewise.
- `B-bpf-ipmasq`: eBPF masquerade, ip-masq-agent on with
  `nonMasqueradeCIDRs: [100.96.0.0/24]`. `B-then-ipmasq-off.pinned-maps.txt` is
  the pin list after the ip-masq-agent was turned off and the agent restarted.
- `C-iptables`: iptables masquerade.

`healthz.json` is `GET /v1/healthz` on the agent socket; `ipmasq-v4.bpftool.json`
is what `bpftool --json map dump pinned .../cilium_ipmasq_v4` printed (an error
object in A, where the map is not pinned). See `docs/K8N-2-cilium.md`, "Live
capture".

### Host routing captures, 2026-11-24

`cilium-1.20.5-kind-hostlegacy-ipmasq.*` and `cilium-1.20.5-kind-hostbpf-ipmasq.*` come from the
same kind, node image and kernel, with Cilium 1.20.5 and the values of K8N-6. Those values are
eBPF masquerade, and the ip-masq-agent on with `nonMasqueradeCIDRs: [10.99.0.0/24]` and
`masqLinkLocal: true`.

- `hostlegacy-ipmasq`: `bpf.hostLegacyRouting=true`. The agent reports `Host: Legacy`.
  - The files were read before the test `wg0` existed, as for A.
  - They are the status, the pin list, the map dump, `nft -j list ruleset`, the two
    `iptables-nft-save` tables (with the `#` lines dropped), the device names (`ip -o link`,
    second field) and `bpftool --json net show`.
- `hostbpf-ipmasq`: the same with `bpf.hostLegacyRouting=false`, after the agents restarted. The
  agent reports `Host: BPF`, and `wg0` is up and among its devices.
  - Only the status, the pin list and the map dump were taken.

Read from a privileged `hostNetwork` pod with read-only host mounts (Alpine 3.24.4: bpftool
v7.8.0, nft 1.1.6, iptables-nft-save 1.8.13).

`calico-v3.31.2-kind-ebpf.*` come from the same kind and kernel with Calico v3.31.2.

- The setup: the unchanged `calico.yaml`, pool `192.168.0.0/16`, switched to the eBPF dataplane
  (`bpfEnabled: true`).
- Connect-time load balancing was turned off, because Felix could not attach it on this kernel.
- What was taken: the device names, `nft -j list ruleset` and `iptables-nft-save` (`#` lines
  dropped).
- Felix's tc programs did not load on this kernel, so nothing was attached.

See `docs/K8N-2-cilium.md`, "Host routing — decision, 2026-11-24".
