# Gateway engine packaging (local candidate)

This patch adds an authenticated strongSwan source stage and ships the actual
source/build inputs alongside its runtime. It does not start charon or raise the
node's IPsec capability. The existing Go build/version, node entrypoint, health
check and WG/OpenVPN/iptables executables are preserved. The Alpine runtime
upgrade is part of this candidate and must pass compatibility gates before use.

The pinned Alpine digest is the official multi-platform index, not the arm64
child digest. `PROVENANCE.json` records both child manifests and its official
source. That index contains Alpine 3.22.5; authenticated APK installation resolves
current packages on the supported 3.22 branch and records the resulting versions.
This pins the base and engine source, not every APK repository byte.

`verify_source.py` bounds the download, checks the exact archive hash, verifies the
bundled release signature using a private non-autostart keyring and the full pinned
fingerprint, and refuses archive traversal, links, devices, duplicate paths and
oversized expansion before extraction. Build output carries the archive,
signature/key, verifier, build script, Dockerfile, provenance and upstream COPYING.
No source patch is applied. Runtime packaging omits the installed example config,
headers and static archives. The supervisor must supply private config/socket
paths; this image does not provide a default launch wrapper or startup service.

## Checks already possible without Docker

```
PYTHONDONTWRITEBYTECODE=1 python3 deploy/ipsec/test_verify_source.py
sh -n deploy/ipsec/build.sh
sh -n deploy/ipsec/verify_runtime.sh
```

Actual cached release bytes also pass hash, pinned-signature and archive-layout
verification locally. This is source provenance proof, not a successful image
build or runtime compatibility result.

## Main-agent build and smoke plan — review before execution

Use the explicit `colima-f10-dev` context and a new non-default project such as
`tunnexs2spackage0924`. Inspect the context, builder and architecture first; refuse
an unexpected host or reused project resources. Build from a staged context
containing only `apps/node`, this directory and `deploy/docker/node.Dockerfile`,
excluding local credentials, .git, caches and unrelated application files. The
existing root .dockerignore intentionally does not exclude those files.

Planned build (with that staged context as working directory):

```
COMPOSE_PROJECT_NAME=tunnexs2spackage0924 docker --context colima-f10-dev build \
  --platform linux/arm64 --network=default \
  --label com.docker.compose.project=tunnexs2spackage0924 \
  --build-arg VERSION=s2s-local \
  -f deploy/docker/node.Dockerfile \
  -t tunnexs2spackage0924:node-arm64 .
```

This build can fetch only public base images, Go modules, APKs and the pinned
engine source. No host network, privilege or persistent host mounts are needed.
Capture image ID and source/runtime manifests. Inspect final entrypoint/health,
architecture and image contents; run `verify_runtime.sh` in a new labelled
container with network none, all capabilities dropped, no host mounts or ports,
and no daemon started. Verify no compiler, Python or GPG remains in the final
image. Inspect ELF dependency closure and strongSwan plugin list in the final
image, not just the builder.

Then let the main agent run its separately reviewed packet harness using this
exact final image: a new labelled internal bridge/network and new captured
container IDs, no host-network or default project/data. Use only bounded NET_ADMIN
inside the disposable lab namespaces. Verify WG handshake + payload, OpenVPN
handshake + payload, nft/iptables-nft inspection, node health with IPsec disabled,
private charon process/plugin inspection, both IPsec tunnels, real allowed and
denied packets, permit expiry, route/SA loss without plaintext, and exact cleanup.
Retain results; remove only newly created IDs after label/network revalidation.
No pruning, volume cleanup, control-plane restart or publishing belongs here.

Repeat build/content checks on AMD64. Emulated execution is labelled emulated;
native AMD64 runtime and packet qualification remains a distinct required gate.
Run existing gateway/host-posture chart contracts. Dependency licence/source
review described in NOTICE is a distribution gate; this local patch is not a
claim that it is completed.

The executable implementation of the bounded ARM64 build/content step is
`PYTHONDONTWRITEBYTECODE=1 python3 deploy/ipsec/qualify_image.py`. Review it before
running. It refuses a reused tag/container name, verifies the explicit Colima
endpoint and native daemon architecture, stages only production Go source plus
explicit packaging inputs, records SHA-256s, captures complete build diagnostics,
and validates the captured container identity/isolation before cleanup. It does
not execute the subsequent packet/compatibility matrix or publish an image.

The first native build exposed two packaging-check details: upstream configure
forces an extra counters plugin whenever VICI is enabled; the runtime stage
explicitly omits that unused plugin to retain the qualified seven-plugin set.
Dynamic plugins resolve daemon-exported symbols, so their dependency check
preloads the exact bundled libstrongswan/libcharon libraries; executable/core
library checks remain ordinary ldd. No missing-library error is suppressed, and
actual private-daemon plugin loading remains a separate runtime gate.

## Native ARM64 content result

The reviewed build/content orchestrator passed for immutable local image
`sha256:7e29f9e72a30513b486afd68aca925c757d436081c1bfe0808db248033a949ef`,
tag `tunnexs2spackage0924:node-arm64`. Full staged-input hashes, image metadata,
build log and network-none content log are retained at
`/private/tmp/s2s-packaging-build-b7l5le5i/`. Required binaries, exact plugin set,
core/plugin dynamic closure, absent build tools and bundled source hash passed.
The sole newly created content container was removed after revalidation.
No daemon or packet was exercised by this check; coexistence/runtime and native
AMD64 qualification remain pending. Future code changes require a new image
identity and another bounded build, not relabelling this result as current.

## Native ARM64 WireGuard/OpenVPN compatibility result

`qualify_legacy_vpn.py` passed with the exact candidate image on both disposable
endpoints. Evidence: `/private/tmp/s2s-vpn-compat-evidence-pnicvrgk/`. WireGuard
reported both kernel handshakes, transferred exact synthetic HTTP bytes on the
verified WG route, and refused the same transfer when the interface was down.
OpenVPN completed mutually authenticated TLS, transferred the same payload on
its verified TUN route, and refused it after stopping the verified owned daemon.
The WG transfer still passed while OpenVPN was running.

The fixture uses only bundled BusyBox nc (minimal BusyBox omits httpd), and
OpenVPN's temporary directory points into its existing private tmpfs because
the container root is read-only. These were test-harness fixes, not runtime
package changes. Synthetic PKI was generated in a new private temporary directory,
transferred only on stdin and deleted; endpoint key files lived only on tmpfs.
Only the captured, labelled endpoints/internal network were removed.

This historical check proves native ARM64 base compatibility for these two VPN
protocols. Subsequent native ARM64 simultaneous IPsec/WireGuard/OpenVPN controller
qualification is recorded in docs/S-S2S-2-completion.md. The complete product
OpenVPN authentication flow and native AMD64 behavior are separate checks.

The feature-branch IPsec native qualification workflow builds the candidate and
observer tools on Ubuntu 24.04 AMD64, verifies native architecture, and retains
packet/status/restart/cleanup/coexistence evidence. Until that run passes, AMD64
qualification remains pending.

### Controlled container-stop evidence

`runtime_stop_proof.py` is a root-only observer for a Linux Docker host with
cgroup v2 and a dedicated `/docker/<container-id>` cgroup. It does not stop,
start, or reconfigure a container. Use it around an independently authorized,
controlled gateway stop:

```sh
sudo python3 runtime_stop_proof.py snapshot \
  --container GATEWAY_CONTAINER \
  --journal /exact/state/mount/ipsec/journal.json \
  --output /private/evidence/before.json
# The authorized supervisor stops that exact container here.
sudo python3 runtime_stop_proof.py prove \
  --snapshot /private/evidence/before.json \
  --output /private/evidence/stopped.json
```

The snapshot binds the container's exact state mount, current namespace and
kernel boot, and every journal entry. The proof requires the same runtime to be
stopped, its cgroup to be empty, no old namespace holders in host threads, file
descriptors or namespace mounts, and a retained matching Docker termination
event. Entries cannot change between snapshot and proof; guard metadata may
advance during graceful shutdown. The stopped journal's exact byte digest is
included for the separate Go receipt assembler.

Outputs are private nonsecret lifecycle evidence, not controller permission.
Missing historical events, an unsupported host layout, surviving namespace
references, or changed journal entries refuse. Run the observer on the actual
Docker host, never inside an ordinary container. This supervised container test
does not prove unattended VM/host reboot recovery. Keep evidence and the current
journal; never roll back ownership by restoring an old journal snapshot.

`runtime_restore_runner.py` automates that controlled lifecycle without manual
mid-test receipt assembly. It requires explicit container, journal, helper,
evidence directory, daemon paths, and bounded timeouts:

```sh
sudo python3 runtime_restore_runner.py \
  --container GATEWAY_CONTAINER \
  --journal /exact/state/mount/ipsec/journal.json \
  --receipt-helper /root/private/ipsec-restoration-receipt \
  --evidence-dir /root/private/restoration-evidence \
  --swanctl /opt/tunnex-ipsec/sbin/swanctl \
  --strongswan-conf /run/tunnex-ipsec/strongswan.conf \
  --vici unix:///run/tunnex-ipsec/charon.vici \
  --stop-timeout 10 --timeout 180
```

The evidence directory must already be root-owned mode 0700. Docker restart
policy must be `no`. The runner captures a snapshot, stops the exact container,
proves termination, starts the same container, assembles an exact-entry receipt,
and installs it atomically. An existing receipt is archived and replaced only
when its digest is already recorded by the current restoration epoch. Unknown
receipts refuse. Receipt installation still grants no traffic authority: the
controller must acquire its fresh CP lease and pass its own ownership checks.

Acceptance requires the next epoch, a new allocation,
preserved route duty, exact current kernel interface ownership, and both named
IKE/CHILD sessions established/installed. The result records measured stop-to-
session-recovery time; client traffic remains a separate verification. A private startup gate is created before stop and retained through fresh receipt
installation. The controller must support this gate and require valid termination
evidence before restoring even if Linux recycles the same namespace inode. The
runner removes only its own unchanged gate after the receipt is durable. On
errors the gate remains and restoration refuses until explicit recovery.

On a caught stop/proof error the runner attempts to start the same container,
keeps the journal and evidence, and does not fabricate a receipt or toggle CP
configuration. A runner kill, host failure, or unexpected Docker restart is not
covered by this workflow: automatic crash detection/resumption remains
unqualified. This is automated **controlled supervisor restoration**, not a claim
of unattended recovery from every container, VM, or host failure.

### Accelerated scheduled IKE renewal (lab only)

`qualify_scheduled_ike.py` qualifies the IKE scheduler at shortened intervals;
it does not claim an eight-hour soak. Run on the Docker host as root with explicit
container, state journal, evidence directory, and daemon paths (same named
arguments as the restoration runner, excluding its receipt helper/timeouts).
The directory must be private root-owned. Both baseline tunnels must already be
established, and the daemon must contain exactly the two scoped connections.

The runner renders the existing nonsecret Engine profile, changing IKE rekey
intervals to 120/150 seconds and jitter to zero. It preserves the original
2880-second grace explicitly and leaves CHILD lifetimes, proposals, selectors,
identities, interface IDs, request IDs, and PSKs unchanged. It never reads PSKs
or calls credential-loading operations.

Pinned strongSwan 6.1.0 inherits the old peer configuration during IKE rekey.
Therefore each connection is bootstrapped with an exact terminate/initiate
operation and a verified short countdown. These maintenance operations are
excluded from the scheduled observation window. During observation no initiate,
terminate, or rekey command is issued: passing requires a matching VICI
`ike-rekey` event linking the baseline and replacement IKE serials at the expected
time, with both replacement sessions and their CHILD SAs installed.

A finally handler and a detached six-minute watchdog restore the original
configuration and create fresh sessions whose long countdowns are verified.
The runner refuses restoration if the container identity or CP-owned Engine
configuration changed. Original settings alone do not update existing SA timers,
so the restore phase also involves brief per-tunnel maintenance. Client SSH/TCP
continuity is recorded separately from the scheduler evidence.

The runner checks exact loaded connection inventory before every `--load-conns`:
strongSwan unloads connection names missing from that file, so this qualification
must never be used against a shared daemon containing other connections.
