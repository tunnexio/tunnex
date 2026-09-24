# S2S-2 — Engine and client qualification

Status: local qualification proposal, 2026-09-24. This records the concrete runtime candidate and gates for the complete S2S-2 implementation. It does not authorize production capability, migration, deployment or shared host routing changes.

## Engine and package selection

Select a dedicated **strongSwan 6.1.0 `charon` process**, controlled exclusively through a restricted Unix VICI socket. Do not use an existing host daemon or start distribution OpenRC services. The initially considered Alpine 3.22 package `5.9.14-r1` is **rejected pending verified security backports**, not selected because a matching base image is cached. The current upstream release is 6.1.0. Its September 7 advisories fix authentication-state and rekey-collision issues; disabling EAP/multiple-KE reduces specific exposure but is not a substitute for selecting a patched release. [Upstream release and signing key](https://strongswan.org/download.html), [pre-authentication CHILD_SA advisory](https://strongswan.org/blog/2026/09/07/strongswan-vulnerability-(cve-2026-78135).html), [rekey collision advisory](https://strongswan.org/blog/2026/09/07/strongswan-vulnerability-(cve-2026-78133).html).

The qualification build uses the upstream 6.1.0 source archive and detached signature verified against the official release key `DF42C170B34DBA77`; record the full fingerprint, archive SHA-256, configure arguments, builder image digest, installed package manifest and resulting immutable image digest before daemon startup. The qualification run resolved Alpine 3.22 for native ARM64 from `sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce`. Packaging review corrected this digest identity: it is the official multi-platform index, with ARM64 child `sha256:2c9d26f410d032d5b1525aa8a873e238b05b90c4ae8618743d4311f0cc827e37`; see [packaging provenance](../deploy/ipsec/PROVENANCE.json). That is a build candidate, not evidence of a patched engine or production platform qualification. No mutable latest tag qualifies a binary. A supported distribution package may replace source build only after its exact signed-index revision and security patches are verified.

Enable only the required modules: `charon`, IKEv2, VICI, kernel-netlink, socket-default, OpenSSL crypto, nonce/random and required PRF/KDF support as proven by `list-algs`/loaded-plugin inventory. Disable automatic plugin-directory loading and unused EAP, X.509, PKCS containers, SQL, HA, stroke/starter, updown and bypass-lan integrations. The final build must actually enumerate the required IKE AES256/SHA2-256/DH14 and ESP AES256/SHA2-256/PFS14 transforms. Missing algorithms/plugins refuse readiness.

Run with an explicit nonsecret configuration: a dedicated `0700` runtime directory, restricted node-owned Unix VICI socket, `install_routes = no` and XFRM route auto-installation disabled. The controller owns routes and refusal enforcement separately. No wildcard PSK identity owners, opportunistic authentication, remote scripts or automatic activation. Each tunnel is a distinct IKE configuration with exact local/remote identities, fixed IPv4 traffic selectors and allocated `if_id_in`/`if_id_out`. The existing static profile fixes IKE/ESP lifetimes at 28800/3600 seconds. Refuse transformations outside that profile.

## Client and adapter boundary

Reviewed and rejected without hardening: **`github.com/strongswan/govici v0.8.2`**, upstream-linked pure Go MIT implementation. Its `clientConn.read` allocates the peer-supplied32-bit frame length before imposing a bound. Select an internal bounded VICI codec/transport from the documented protocol instead: no new Go dependency, C linkage or cryptographic implementation. No module import is added. The reviewed source confirmed that context cancellation alone does not supply allocation bounds; the internal transport implements and tests those limits directly. The current upstream API provides context `Call`/`CallStreaming` and a custom dialer. [Official VICI documentation](https://docs.strongswan.org/docs/latest/plugins/vici.html), [client release tags](https://github.com/strongswan/govici/tags).

The Tunnex adapter exports typed operations only, never a generic arbitrary daemon call. Its Unix dialer accepts the dedicated socket only, verifies socket/parent ownership and mode, and enforces a finite deadline. Maximum VICI segment is512KiB (upstream transport bound); impose aggregate inventory/count bounds and bounded nesting/duplicate rejection. Close the connection on framing, cancellation or response ambiguity. Never subscribe to control-log or diagnostic-log events. Convert daemon errors into fixed codes without exposing response text.

Required typed operations:

- `Inspect`: version, loaded plugins/algorithms, complete connection/credential identifier inventory and streamed IKE/CHILD_SA observations. Keep daemon-instance unique SA IDs distinct from reusable configuration names. Reject unexpected owned-name collisions and incomplete enumeration.
- `Stage`: load one uniquely named shared PSK using `load-shared`, then one exact connection via `load-conn`. PSK bytes travel in memory through VICI, never argv, environment, files, URLs, logs or returned state. The daemon operation is not proof of durable control-plane delivery or activation.
- `Initiate`: requires the independent refusal guard receipt for the exact assignment/revisions and explicit initiator intent. Bound both command timeout and transport context; command acceptance never means connected.
- `Terminate`: address exact observed daemon-instance IKE/CHILD IDs. Unload the matching connection and shared-secret IDs only. Re-enumerate daemon and owned kernel state; no global credential clear, wildcard terminate or premature cleanup acknowledgment.

The adapter cannot mint assignment ownership or a guard receipt. Control-plane delivery obligations, durable local ownership journal, current policy, route readback and fencing remain separate required inputs. [VICI operations and wire protocol](https://github.com/strongswan/strongswan/blob/master/src/libcharon/plugins/vici/README.md).

## Distribution obligations

strongSwan publishes GPLv2 licensing and a commercial option. Alpine identifies its package as GPL-2.0-or-later with OpenSSL exception. The daemon's notices, corresponding source/build scripts and actual linked dependency licences belong in the distribution inventory; the reviewed but unused govici client is not redistributed by this implementation. This is a recorded packaging requirement, not a claim that a commercial licence was acquired or a legal compliance decision completed. Production packaging must not silently copy only the executable. [Upstream licence](https://strongswan.org/license.html), [Alpine package metadata](https://pkgs.alpinelinux.org/package/v3.22/main/x86_64/strongswan).

## Isolated qualification and acceptance matrix

Root reviews the concrete guard script before package acquisition or daemon startup. Builder/runtime resources have a fresh explicit non-default project label, immutable base image, no host mounts/sockets/devices, no host network/PID namespace and no published ports. Package downloads use a separate owned builder network; the actual traffic lab uses internal-only owned networks with no cloud endpoints. Runtime capabilities are restricted to what the lab requires (NET_ADMIN/NET_RAW); secrets are synthetic and memory-only. Cleanup removes only newly created resources whose labels and identities match.

| Gate | Required evidence |
| --- | --- |
| Binary provenance | Verified upstream signature/hash or patched signed APK; daemon version; image digest; complete plugin/algorithm inventory |
| Wire safety | Truncation, oversize, wrong packet/event, duplicate fields, nesting, cancellation, timeout and socket-permission tests; no secret/error echo |
| Daemon lifecycle | Real stage/readback/initiate/targeted terminate/unload; another owned tunnel unaffected; daemon restart drops readiness |
| Encrypted traffic | Two explicit tunnel identities; protected payload reaches the remote destination with ESP/UDP4500 underlay evidence, no cleartext protected payload |
| Refusal | Before activation, missing SA/interface/route, stale revision, daemon loss, revoked policy and established flows all blocked for forwarded and host-originated traffic |
| Isolation | WireGuard/unrelated routes/marks and unrelated daemon objects preserved; collisions refused |
| Failover/cleanup | Single selected path, bounded failover after qualified evidence, rekey overlap refused until supported, disable/delete acknowledged only after exact negative enumeration |

Pure fixtures, daemon command success or an empty kernel dump cannot satisfy real traffic gates. Results and unresolved package/download constraints must be appended with exact artifacts; do not mark S2S-2 complete from this proposal alone.


## Recorded build evidence

The reviewed `/private/tmp/s2s-engine-build.py` successfully built the source in a new label-scoped capability-free container and removed only its captured builder/network IDs. It did not start a daemon. Artifact directory: `/private/tmp/s2s-engine-source-n_6kle6n/`; log: `/private/tmp/s2s-engine-build.log`.

- Verified detached signature signer: `948F158A4E76A27BF3D07532DF42C170B34DBA77`.
- Recorded archive SHA-256: `d9484eea319481bda86f992fa69cbdbdd9c0d6f8b9a4bd793a7df45c0760d963`. This is a hash of the signature-verified archive, not an assertion of a separately published upstream SHA comparison.
- Qualification-only image: `sha256:8e7153d3bcfa7f2f0215881806132bc7c02c9ceade13a8bc71a05e725d35e73a` (ARM64). Builder tools/source remain in this image; production slim packaging is not yet qualified.
- Live downloaded Alpine3.22 aarch64 index still listed5.9.14-r1 with a2025 build date, confirming why that package was not selected.
- Internal codec bounds:512KiB/frame before allocation;4MiB/command;1024 events;4096 message elements; nesting16; finite30-second maximum command deadline. Individual typed operations may use shorter deadlines. Stage/initiate/cleanup remain package-private and require the refusal controller before production integration.

## Typed adapter qualification and remaining ownership boundary

The dedicated native daemon smoke passed against the recorded image: actual version 6.1.0, required plugin/algorithm inventory, and empty configuration/credential/SA inventory (`/private/tmp/s2s-engine-smoke.log`). The owned network-none container was removed. This is daemon/API evidence, not encrypted traffic evidence.

Focused VICI/daemon race regressions passed after proving failures first (`/private/tmp/s2s-daemon-review-red.log`, `/private/tmp/s2s-daemon-review-green.log`). Enumeration accepts only the documented empty terminal `list-sas` response. CHILD observations require AES-CBC256/SHA2-256. Cleanup checks all matching live IKE endpoints and child names, XFRM IDs and selector sets before its first mutation. Peer transport addresses inside remote protected prefixes are refused; a local private NAT interface may legitimately be inside a local prefix.

Upstream 6.1.0 `list-conns` does not expose configured XFRM IDs. Consequently daemon names alone cannot prove ownership of a staged configuration with no live SA. The private cleanup entry point requires a durable previously recorded stage intent and an exclusively managed dedicated daemon; the future controller must fence uncertain or foreign state. Adapter success is not a cleanup acknowledgment, and kernel negative enumeration is a separate requirement.

## Native traffic qualification in progress

The reviewed isolated two-container internal-network run established two real IKEv2/CHILD pairs and verified exact timed guard readback, required transforms, XFRM IDs and selectors on both endpoints. It correctly refused protected traffic before activation. The first permitted ping did **not** deliver: native counters showed the protected packet traversing postrouting again on the physical interface before encryption, where the conservative final refusal rule dropped it. No encrypted-delivery claim is made. Evidence: `/private/tmp/s2s-engine-traffic-diagnose.log`; all captured owned containers/network were removed.

This exposed a required narrow encrypted-egress qualification, not grounds for a generic IPsec bypass. A future permitted second traversal must bind current SA reqid, outer peer, physical interface, assignment and expiring lease; route-loss fallback must still be proven silent. Separately, the external peer fixture now uses a test-only ICMP request/reply ACL on its independently observed XFRM interfaces. That peer ACL does not qualify Tunnex gateway host-inbound permissions; the gateway continues using the actual production renderer/readback.

### Host-origin traffic evidence

After adding exact observed reqid/outer-peer/physical-interface encrypted-egress guards, the complete host-origin lab passed (`/private/tmp/s2s-engine-traffic-final.log`). Both separately selected XFRM paths delivered protected ping; an underlay observer saw ESP/NAT-T headers, and each daemon reported positive encrypted bytes in/out. Removing the owned route refused traffic despite a configured ordinary underlay fallback: the observer reported zero packets captured, received or dropped. Targeted removal preserved the second tunnel; final removal produced empty connection, secret-ID and SA inventory. All owned resources were removed. Path selection was explicit test orchestration, not automatic failover qualification.

The keyless XFRM fixtures were captured only with `ip xfrm state list nokeys` and `ip xfrm policy list nosock`; raw key-bearing state was never dumped. Peer test ACLs emulate an external VPN and do not expand Tunnex host-inbound policy. The adapter and lab still do not enable production capability. Forwarded TCP/UDP, established-flow revocation, normal permit expiry and wider lifecycle/coexistence acceptance remain separate gates.

### Forwarded traffic and revocation evidence

The four-container, three-internal-network lab passed (`/private/tmp/s2s-engine-forwarded-final.log`) on native Linux `6.8.0-117-generic`; `/proc/uptime` is recorded in that artifact. Separate client/server LAN endpoints exchanged actual TCP/18080 and UDP/18081 payloads through both explicitly selected tunnels. The gateway used the production renderer and exact readback; each permit matched real daemon CHILD identities against independently read keyless kernel SPI/reqid/if_id/outer endpoints and all three global policy directions before and after installation.

The lab also proved pre-activation denial, a viable ordinary-route fallback with zero cleartext after owned-route removal, refusal of fresh TCP/UDP after a two-second kernel permit expired with no applier process remaining, and refusal of the same previously established TCP socket after policy denial. Final targeted cleanup removed the exact owned daemon objects; all four containers and three networks were removed. This qualifies normal-operation expiry, not VM/host suspend behavior. It does not qualify an automatic failover controller, NAT traversal, rekey or production activation.

### Negative packet gates

The remaining isolated qualification-image scenarios passed, each with fresh captured resources removed afterward:

- `/private/tmp/s2s-engine-negative-faults-final.log`: missing server return route refused TCP/UDP; explicit restoration recovered both. Taking the selected XFRM interface down refused traffic with zero cleartext captured or capture loss. Linux withdrew its route on interface-down; interface-up alone does not recreate that route. No automatic recovery is claimed.
- `/private/tmp/s2s-engine-negative-sa-loss.log`: after positive traffic and a fresh 30-second permit, deleting only the independently verified outbound ESP state by exact source/destination/SPI refused payload with zero cleartext. Cleanup targeted owned daemon objects.
- `/private/tmp/s2s-engine-negative-wrong-psk.log`: mismatched synthetic PSKs refused both initiations, left zero kernel SAs/global tunnel policies and delivered no payload. Credentials were supplied only on stdin, never logged.
- `/private/tmp/s2s-engine-negative-daemon-loss.log`: SIGKILL targeted only the captured daemon PID after confirming its executable. The two-second kernel lease expired and refused TCP/UDP with zero cleartext. This proves bounded independent expiry, not instantaneous daemon-loss detection by an integrated controller.

These runs used the earlier qualification image. The separately built production candidate requires its own actual packet and coexistence gates; package-content smoke is insufficient.

### Exact production-candidate packet gate

The core forwarded suite also passed on candidate image `sha256:7e29f9e72a30513b486afd68aca925c757d436081c1bfe0808db248033a949ef` for both gateway and peer (`/private/tmp/s2s-engine-final-image.log`). The reviewed harness asserted each captured endpoint's immutable image ID before operations. Python client/server containers used the earlier tools image; a separate read-only, NET_RAW-only observer shared only the captured gateway network namespace, checked by inode, with no host mounts or published ports. No tools were installed into the candidate.

This run repeated real TCP/UDP and ESP evidence on both explicit paths, daemon-to-kernel tuple verification, route-loss silence, normal two-second permit expiry, established TCP revocation and targeted cleanup. All five containers and three internal networks were removed. The executed harness, test binary and log hashes are recorded in `/private/tmp/s2s-engine-final-image-evidence.json`. This gate does not replace WireGuard/OpenVPN coexistence or integrated controller acceptance.

## Dedicated process supervisor

`daemon_process_linux.go` starts only the pinned absolute charon binary with a static nonsecret configuration, minimal environment and discarded daemon logs. It holds an exclusive lock in the private compiled PID directory `/run/tunnex-ipsec`; unexplained artifacts refuse startup. It never reads a PID file as authority to signal a process. Shutdown targets only the captured child, retains ownership when process death is uncertain, and removes only captured matching-inode artifacts. Child exit/parent loss never proves kernel cleanup. The fixed PID directory was checked against the pinned 6.1.0 source archive `src/charon/charon.c` and packaging configure flags.

`/private/tmp/s2s-daemon-process-native.log` passed the actual private socket/version/plugin inspection, rejection of a second supervisor, owned stop and clean restart against the pinned candidate in a fresh disconnected container. Test temporaries used its private tmpfs; no host daemon or default namespace was touched. Crash-left artifacts and orphan kernel SAs remain refusal/pending until independent ownership recovery proves cleanup; they are never silently adopted.
