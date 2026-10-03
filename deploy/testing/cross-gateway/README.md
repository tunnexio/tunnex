# Cross-gateway qualification

Run from the repository root with Go (per the modules' toolchain declarations), Python 3, and a local Docker Unix socket. The Linux Docker host must support WireGuard, nftables, conntrack and `/dev/net/tun`. The scripts support `arm64` and `amd64` Docker hosts. They compile the current checkout on each invocation.

## Database

```sh
docker pull postgres:16-alpine
docker pull alpine:3.23
python3 deploy/testing/cross-gateway/database.py
```

This runs the feature's migration/audit, lifecycle, and health integration tests against disposable databases in a fresh PostgreSQL container. It checks explicit test PASS output and the test container exit code, so skipped tests cannot count as qualification. Every DB-capable operation verifies and prints the unique project, container and network. Do not supply a production DSN: the harness supplies its own fixture DSN.

## Real packet delivery

```sh
docker build -t tunnex-gateway-qualification:local deploy/testing/cross-gateway
python3 deploy/testing/cross-gateway/qualify.py --topology both --transport wireguard
python3 deploy/testing/cross-gateway/qualify.py --topology two_gateway --transport openvpn
python3 deploy/testing/cross-gateway/qualify.py --topology two_gateway --transport mixed
python3 deploy/testing/cross-gateway/qualify.py --topology two_gateway --transport mixed_reverse
```

`mixed` means OpenVPN source → WireGuard destination; `mixed_reverse` reverses them. These commands run 20 cases across human → human, human → agent, agent → human, and agent → agent. WireGuard uses IPv4 and IPv6; OpenVPN and mixed flows use IPv4.

The fixture exports desired states through the real control-plane graph, policy compiler and artifact finalizer. A persistent test adapter uses the production node WireGuard, OpenVPN and firewall managers. Synthetic endpoints exchange payloads through kernel tunnels. Assertions cover default-off, default-deny, scoped allowance, a forbidden port with a real listener, reverse-direction denial, established TCP withdrawal, disable/re-enable, device revocation and missing-carrier refusal. WireGuard also checks moving a client away and back.

`nat_spokes_relay` is the historical argument name for an unadvertised-spoke topology: only the relay has an advertised endpoint, and spokes establish outbound sessions. There is no NAT translation appliance in this fixture. Native client UX, production enrollment, internet reachability, and stopped-agent conntrack recovery are outside its proof.

## Isolation and results

Each run creates a unique labelled internal Docker network and captures the IDs it owns. Packet fixtures use read-only container filesystems, tmpfs, only NET_ADMIN/NET_RAW capabilities, and `/dev/net/tun`. They have no host networking, exposed ports, host mounts or persistent volumes. The DB runner mounts only local test binaries read-only. Synthetic private keys stay inside container tmpfs and are not printed or written into evidence.

Cleanup verifies ownership and removes only captured fixture IDs. Other Docker workloads are untouched. A failed ownership check stops cleanup for inspection rather than deleting a resource whose identity no longer matches.

Results are under ignored `.gateway-update-proof/`: per-packet-run `result.json`, adapter/OpenVPN logs, public handshakes and projections; DB test output is saved as `<project>-<suite>.log`. A command must exit zero and contain every expected PASS case before its run is accepted. These fixtures are local qualification, not deployment.
