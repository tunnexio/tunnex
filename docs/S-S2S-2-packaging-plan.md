# S2S-2 — Bounded production packaging proposal

Status: local candidate implementation, 2026-09-24. `deploy/docker/node.Dockerfile` and new `deploy/ipsec/` source/build assets implement this proposal. Native ARM64 build/content qualification passed under `qualify_image.py`; exact-candidate simultaneous IPsec, WireGuard and OpenVPN payload also passed under `qualify_coexistence.py`. Native AMD64 qualification remains pending. No image is published. Qualified LinuxARM64 controllers now advertise capability1 only after actual supported-package/runtime probes; other platforms remain0. Packaging cannot grant authority merely by installing a daemon.

## Verified inputs and current gap

The baseline gateway image used Go1.25.13 and Alpine3.20. The local candidate keeps that Go build, version stamp, health check, node entrypoint and existing ca-certificates/wireguard-tools/iproute2/nftables/iptables/openvpn packages, and moves the source builder and runtime together to the pinned Alpine3.22 index. The reviewed qualification builder `/private/tmp/s2s-engine-build.py` built strongSwan6.1.0 on Alpine3.22 ARM64 and retained compiler tools in its output image. Do not transplant that binary tree into Alpine3.20 or claim AMD64 qualification from it.

Recorded verified source: `strongswan-6.1.0.tar.gz`, SHA-256 `d9484eea319481bda86f992fa69cbdbdd9c0d6f8b9a4bd793a7df45c0760d963`, detached-signature fingerprint `948F158A4E76A27BF3D07532DF42C170B34DBA77`. Provenance is in [engine qualification](S-S2S-2-engine-qualification.md) and `/private/tmp/s2s-engine-source-n_6kle6n/result.json`. The qualification script verifies the signature and records the resulting hash; production build must also compare the archive against the fixed expected SHA before extraction. Archive path/type checks and download bounds remain required.

Alpine's official lifecycle lists3.20 standard support ending2026-04-01, now on-request support;3.22 main remains supported until2027-05-01. This is a concrete production packaging concern, not authorization for a standalone base upgrade. Select a supported runtime branch and immutable multi-platform manifest deliberately, then use the same base family/digest for the C source builder and final runtime and qualify all existing binaries. Official Docker image metadata now verifies cached digest `sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce` is a multi-platform OCI index, not an ARM64-only child as the initial audit assumed. It resolves to Alpine3.22.5, with ARM64 child `2c9d26f410d032d5b1525aa8a873e238b05b90c4ae8618743d4311f0cc827e37` and AMD64 child `7c8cb692ae09657cbc4a3f3cbd0e8d5a2690ba38386aaaf252dbb060bf5eb2e6`. [Official image metadata](https://github.com/docker-library/repo-info/blob/master/repos/alpine/remote/3.22.md). [Official release lifecycle](https://alpinelinux.org/releases/).

## Minimal patch boundary

1. Add a separate strongSwan source-build stage to `deploy/docker/node.Dockerfile`; leave the Go agent build path, version stamp, entrypoint and health check intact. Use an explicit fixed version/hash/signature fingerprint. No `latest`, package-version guess, `curl|sh`, unverified archive or runtime download.
2. Add a small reviewed build script and provenance manifest under `deploy/ipsec/`. Acquire only the named archive/signature/release key, validate size and exact SHA, import the key into an ephemeral isolated keyring, check full signer fingerprint, then safely extract. Cache the authenticated archive through the build system; source hash remains authoritative even if transport changes. Record exact configure flags and dependency/package manifests.
3. Build under `/opt/tunnex-ipsec`, configuration root `/etc/tunnex-ipsec`, PID/runtime root `/run/tunnex-ipsec`. Preserve qualified `--disable-defaults --enable-charon --enable-ikev2 --enable-vici --enable-kernel-netlink --enable-socket-default --enable-openssl --enable-nonce --enable-random --enable-kdf`. The qualification build also enables swanctl; keep it only if the final diagnostic contract needs it, otherwise omit the CLI after separately proving the adapter uses no dependency it supplies. Do not remove required libraries based solely on names.
4. Stage an explicit runtime file manifest: charon, its exact required shared libraries and plugin `.so` closure, necessary version/config metadata and notices. Determine dynamic dependencies with ELF inspection in the target architecture stage and verify resolution again in the final image. Install the matching runtime crypto libraries through the selected distribution's authenticated package system. No compiler, headers, static archives, libtool `.la` files, build caches or qualification Python/tcpdump tools in the final runtime.
5. Keep strongSwan isolated from existing host services: no OpenRC/systemd startup in package build, no host charon adoption, no TCP VICI endpoint, no default swanctl config/credential loading, and no daemon route installation. The node supervisor—not Docker ENTRYPOINT replacement—will later create the private0700 runtime directory and supervise the daemon only under qualified authority. Merely shipping binaries must not start IPsec or advertise capability1.
6. Add component provenance/notice assets and packaging contract tests. Update only gateway image consumers where needed to carry the resulting release/digest; no change to the separate managed-client runtime artifact.

A supported-base update is integral to this patch only after the complete coexistence matrix passes. If the base cannot be qualified, keep the current production Dockerfile unchanged and report packaging incomplete; do not paper over the gap with the local lab image.

## Source and notice delivery

Ship upstream `COPYING`, relevant component copyright/exception notices and actual linked dependency notices. A simple concrete source-delivery strategy is to include the exact corresponding strongSwan archive, detached signature, pinned key/fingerprint, build script/configure arguments and any patch files under a documented `/usr/share/tunnex-ipsec/source/` location, or produce a versioned accompanying source artifact with an immutable image-to-source mapping. Prefer actual source delivery over inventing a written source offer whose fulfilment process does not exist. If a written offer is chosen, its scope, duration and fulfilment owner must be reviewed before distribution.

Inventory OpenSSL/musl and other actual linked dependencies separately; do not copy the APK's licence label as proof for an independently configured source build. The internal VICI codec does not redistribute the rejected govici dependency. This plan records required distribution artifacts; it does not assert completion of a licensing review. [Upstream licensing](https://strongswan.org/license.html).

## Existing distribution paths

- `docker-compose.yml` builds `deploy/docker/node.Dockerfile` for development; `.github/workflows/ci.yml` already includes that image in the Docker build matrix.
- `deploy/tunnex.yml` consumes `TUNNEX_NODE_AGENT_IMAGE`. `deploy/install.sh` installs the control-plane/optional co-located gateway stack and directs separate Linux gateway enrollment. No host charon installation belongs in that CP installer.
- `apps/api/internal/config/config.go` and the meta endpoint expose the gateway image reference used by dashboard enrollment. Keep release/digest provenance consistent; do not add another hidden image default.
- `deploy/helm/tunnex-gateway` and `deploy/helm/tunnex-host-posture` consume the same node image; CP chart has `nodeAgentImage`. Their existing chart contract tests pin image/version and admission behavior.
- `deploy/docker/agent-runtime.Dockerfile` and `deploy/systemd/tunnex-agent-runtime.service` are the separate managed-client artifact. They are not the gateway daemon packaging path and are out of scope.

Keep current volumes/identities, network modes and capabilities unless the separate supervisor/journal contract proves a narrowly required change. Never add privileged mode or SYS_ADMIN merely to make the engine start.

## Required build and runtime matrix

| Gate | Linux ARM64 | Linux AMD64 |
| --- | --- | --- |
| Source provenance | Exact archive hash, signature fingerprint, configure flags and build/runtime base digest recorded | Same independently verified inputs |
| Final ELF closure | Correct machine architecture; every needed library resolves in final slim image | Same, with native AMD64 execution |
| Existing executables | `tunnex-node`, `wg`, `wg-quick`, `ip`, `nft`, `iptables-nft-save`, OpenVPN and CA bundle present and runnable | Same |
| Existing behavior | Isolated real WG handshake/traffic, OpenVPN startup/handshake smoke, nft and iptables-nft inspection, unchanged node health/startup with IPsec off | Same |
| IPsec process | Exact charon6.1.0 identity, required plugin and algorithm inventory, dedicated private socket, no unsolicited config/SA/credential/route | Same |
| Enforcement | Actual guard readback, expiring permits, crash/refresh failure, established-flow revocation and plaintext-leak refusal | Same |
| Crypto traffic | Real engine negotiation/allowed packet + denied packet, both tunnels, safe failover/rekey and exact cleanup | Same |
| Image contents | No build tools/default secrets, notices and corresponding-source mapping, SBOM/artifact digests | Same |

Cross-compiling Go or inspecting a manifest does not replace native C/plugin execution and packet tests on the second architecture. Emulation can supplement build validation but must be labelled distinctly from native packet qualification. Run existing gateway/host-posture chart contracts after the image change; a packaging regression must not be mistaken for IPsec-only failure. No image publication or installer rollout until explicitly requested.

## Candidate verification record

Source-verifier regressions were written before implementation. Changed archive hash, archive traversal/links/devices/duplicate paths, and wrong/ambiguous signature status refuse. Three Python tests and shell syntax checks pass. Actual cached upstream bytes pass exact SHA, pinned GPG signature and bounded archive layout; a mutated detached signature is rejected. GPG uses a temporary isolated keyring with `--no-autostart --no-auto-key-retrieve`.

The reviewed executable stages only non-test node Go files, go.mod/go.sum and explicit packaging inputs; excludes .git, .env, caches and unrelated files; records input digests; verifies the Colima endpoint and native ARM64 daemon; refuses resource/tag reuse; and runs final content checks with network none, read-only root, no capabilities/mounts/ports. The first real build failed on a standalone plugin dependency check; investigation found daemon-exported symbols require the exact parent libraries and upstream auto-builds an unused counters plugin whenever VICI is enabled. Runtime staging now omits that extra plugin and checks plugin dependencies with exact libstrongswan/libcharon preloads, while retaining all unresolved-symbol failures. The final image build and network-none, read-only, capdropALL content smoke passed. Final ARM64 image: `sha256:7e29f9e72a30513b486afd68aca925c757d436081c1bfe0808db248033a949ef` (`tunnexs2spackage0924:node-arm64`). Evidence and complete input hashes: `/private/tmp/s2s-packaging-build-b7l5le5i/`. Required existing binaries are runnable, exact seven plugins and their library closure pass, compiler/Python/GPG binaries are absent, and the bundled source hash passes. The captured smoke container was removed after identity/isolation revalidation. No daemon was started by this content test. No image-build result substitutes for WG/OpenVPN or native AMD64 packet proof.

The exact final ARM64 candidate also passed the independent WG/OpenVPN fixture:
`/private/tmp/s2s-vpn-compat-evidence-pnicvrgk/result.json`. Both endpoints used
the final image with no package installs. WG kernel handshakes and exact HTTP
payload passed, including interface-down refusal. OpenVPN mutual TLS and exact
payload passed, including daemon-stop refusal after checking the executable
identity; WG remained functional while OpenVPN ran. Synthetic credentials stayed
in fresh private host/tmpfs directories and stdin, then were removed with the
newly captured labelled resources. This is protocol/base compatibility proof,
not full product authorization or simultaneous IPsec-controller qualification.


## Existing local architecture discovery, 2026-09-24

Read-only `docker context ls` and bounded `docker --context ... info` checks found two reachable existing contexts: `colima-f10-dev` and `colima-tunnex-sso-review`, both `aarch64`, Ubuntu24.04.4 LTS/kernel6.8.0-117-generic. Other configured contexts were unreachable; none was started. No reachable native AMD64 runner was found. Evidence: `/private/tmp/s2s-existing-docker-architectures.json`. This is an environment limitation, not permission to provision a host or to count emulation as native proof.

The tested candidate is ARM64. The current Dockerfile changes the runtime base and adds the C build for every target architecture, so setting IPsec capability0 on AMD64 alone would not preserve the previous AMD64 image contents. Concrete choices before publication are: qualify the shared candidate on native AMD64; or explicitly separate the ARM64 IPsec runtime target from an unchanged legacy image target for unqualified architectures, preserving their prior base/package graph and capability0. The latter needs explicit build/manifest selection and contract tests; it cannot be achieved only with a conditional package copy. No Dockerfile change or architecture-support claim is made by this note.
