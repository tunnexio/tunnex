# Alpine lightweight candidates — not selectable

Completed local work is preserved pending the parent's platform recommendation.
Three shared-layer recipes were built on linux/arm64 and linux/amd64: Minimal,
Python and Node.js/npm. No template registration, live gate or deployment changed.
Ubuntu's recipe and its Python entrypoint remain unchanged. The provider now uses
an approved immutable image's CMD; this is necessary for Python-free images.

Minimal includes Bash, OpenSSH/SFTP, coreutils, WireGuard, iproute2, nftables,
openresolv, setpriv, CA certificates and a static Go bootstrap. Python adds
Python 3.12.15; Node adds Node.js 24.18.1 and npm 11.11.0. All exclude git.
Minimal excludes Python, Node and npm. Full package inventories, exact immutable
platform/config/index digests, image source commit and measurements are in
`manifest.json`. Packages resolve from official signed Alpine repositories at
build time only; recorded versions do not guarantee byte-identical future builds.
Qualify and register immutable final images. Arbitrary glibc binaries are unsupported.

| Profile | Arch | Compressed layer bytes | Unpacked allocated bytes | Idle cgroup bytes |
| --- | --- | ---: | ---: | ---: |
| Minimal | arm64 | 12,070,210 | 32,006,144 | 2,629,632 |
| Minimal | amd64 | 11,908,177 | 28,381,184 | 8,998,912 |
| Python | arm64 | 26,869,491 | 78,516,224 | 2,416,640 |
| Python | amd64 | 26,784,114 | 72,007,680 | 8,908,800 |
| Node.js/npm | arm64 | 40,344,461 | 111,865,856 | 3,088,384 |
| Node.js/npm | amd64 | 40,841,266 | 112,029,696 | 9,170,944 |

**amd64 ran under Docker Desktop emulation on arm64.** Its RAM includes emulator
overhead and does not predict native amd64/rootless memory. arm64 Docker samples
also do not qualify native rootless RAM. Each is one idle sample after SSH restart,
not a capacity claim. The 10–50 MB compressed range was a target; these builds fit it.

Reproduce from a clean committed tree (not needed until approach is reconciled):

```
./deploy/sandbox/alpine/build-image.sh arm64 tunnex-sandbox-alpine-task3-minimal-arm64 minimal
python3 deploy/sandbox/alpine/verify.py tunnex-sandbox-alpine-task3-minimal-arm64
```

The build target can be minimal, python or node. Builds ran sequentially with Go
compilation limited to two jobs. Docker BuildKit package steps use the existing
Docker VM bounds; no task-specific build-memory limit was enforced. Runtime
fixtures enforce 1 CPU, 128 MiB RAM, 64 PIDs, read-only root, dropped capabilities,
no-new-privileges, 4 MiB /run and /tmp and 8 MiB workspace tmpfs. These are test
caps and are not published as configured production caps.

The verifier generates disposable keys, uses the existing API SSH configuration,
pins the host key, checks uid1001 and exit status 37, roundtrips Unicode plus
1 MiB binary bytes via SFTP, rejects a mismatched host key and verifies identity
after restart. It checks entrypoint rejection for root, symlink SSH directory,
world-writable SSH directory and extra arguments; verifies bootstrap --help,
installed tool execution and omitted tools. Only task-owned fixtures are removed.
Loopback publication/Docker bridge are synthetic test transport.

Compressed download is the sum of gzip OCI layers in the exported final image,
excluding small manifest/config/attestation overhead; no registry download ran.
Unpacked allocation is `du -sx -B1 /` in a separate offline root inspection
container, excluding virtual proc/sys/dev. Docker's reported Size is separately
labeled because this backend reports compressed content size.

Source API metadata definitions are in `apps/api/internal/sandboxes/image_profiles.go`;
`generate-catalog.py` projects this manifest into the embedded measured catalog.
They do not register templates. Shared OpenAPI, handler and UI integration is
held for ownership coordination; see `metadata-proposal.md`. No Ubuntu image or
native measurements are inferred. See `native-verification-plan.md` for the
bounded remaining native qualification, which cannot run on this Mac environment.
