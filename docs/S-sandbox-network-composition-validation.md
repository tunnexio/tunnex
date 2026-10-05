# Network/SSH composition checkpoint — Oct3

Same isolated story/sandbox-foundation worktree; original checkout/pilot intact.
Concrete helper/Unix-FD control transport, gateway-route pinned SSH probe,
lease-bound initial launch, current sandbox physical-peer roster gates, durable
withdrawal receipt/lost-stop recovery, explicit task TLS CA, standalone scoped
worker and host unit source are implemented. No external Go dependency added.
The existing qualified workload image's absolute sshd argv[0] fix is aligned;
separate host bootstrap client carries the new CA support, so no image rebuild.
Provider uses immutable local image config ID, distinct from OCI manifest.

Full affected PostgreSQL/loopback race suites pass48.730s and2.254s. Earlier
focused composed enrollment/SSH-pending/Ready/lost-stop recovery tests4.673s.
Node helper portable race suite, Linux build/vet, generated private CA TLS tests
and three Python entrypoint wiring tests pass. Network/provider composition uses
fake adapters; real authenticated nodes.ReportStatus feeds handshake evidence.
Linux parser/socket fixtures passed under network-disabled/capless Docker;
these do not establish real rootless isolation or privileged network setup.

First full rerun exposed an outdated downgrade fixture: it omitted new migration
0173, so launch-table drop failed on the withdrawal FK. Fixture now includes
0173; its down migration refuses nonempty receipts. Full rerun passes.

Worker initial launch is limited to one fixture org, generation1 and one retained
sandbox. Public availability stays closed. Resume epochs, connection UI, real
Linux/provider/network supervision and latency qualification remain incomplete.
The approved bounded target setup must pass before any production-ready claim.

Oct3 read-only dev CP prerequisite inspection: exact pinned package simulation
still0upgrades/8additions/0removals; UID/GID1101 and subordinate200000:65536 are
unused; runc1.5.1 present; Docker active;982MiB MemAvailable/no swap;13,285MiB
free root disk. Existing CP services remain running. Existing host8443 conflicts
with a fixture host binding, so fixture HTTPS8443 uses its private container IP
without publishing any host port. This preserves the approved private-bridge
scope and does not change the existing CP listener.
