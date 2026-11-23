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

`cilium-1.20.5-kind-A-bpf.*` are unedited captures from one kind node
(kindest/node v1.35.0, kernel 6.8.0-117-generic, arm64) running Cilium 1.20.5
with kube-proxy replacement, native routing and eBPF masquerade, ip-masq-agent
off, taken on 2026-11-23 from a privileged pod with read-only host mounts
(bpftool v7.8.0, nft 1.1.6, iptables-nft-save 1.8.13). `healthz.json` is
`GET /v1/healthz` on the agent socket; `ipmasq-v4.bpftool.json` is what
`bpftool --json map dump pinned` prints for the map that is not pinned in this
configuration. `bpftool-net.json` was taken before the test `wg0` existed. See
`docs/K8N-2-cilium.md`, "Live capture".
