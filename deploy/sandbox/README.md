# Quarantined sandbox image layer

`build-image.sh <approved-base@sha256:digest> <amd64|arm64> <tunnex-sandbox-task-tag>` builds the bootstrap client from committed source and adds it to an approved preloaded Ubuntu base. The final Podman layer has pull=never/network=none and performs no package installation. Its fixed Python entrypoint prepares the private tmpfs SSH directory and execs foreground sshd as uid1001; no service manager, DBus or host socket is started. Provider creation supplies network=none, read-only filesystem, resource bounds and the namespace-local unprivileged-port setting. Trusted read-only SSH mounts must exist; starting this image alone cannot claim connectivity or Ready. Actual nonroot sshd/AppArmor behavior remains to be qualified.

The separate [Ubuntu dependency/archive producer](ubuntu-base/README.md) supplies
real official Ubuntu26 base pins, a complete signed-snapshot AMD64 package lock,
verified dependency fetching and a finished Docker archive with public catalog
pins. Its [local build validation](../../docs/S-sandbox-ubuntu-base-delivery-validation.md)
records an actual offline image build and measured sizes. Building/exporting an
image does not qualify native AppArmor, SSH, WireGuard, deadlines or cleanup on
a newly enrolled host. No manual pilot image/container is read or reused. The
image includes WireGuard, iproute/coreutils, SSH/SFTP, Python stdlib/SSL,
resolvconf, setpriv and nft, and provides uid1001. Context copies only public
recipes, verified packages and a committed-source binary, never repository
credential/config files. Go module resolution is build-time, checksummed and
readonly; no launch installs/downloads are introduced.

Public sandbox bootstrap requires qualified provisioning and uses HTTPS. The one-time token is supplied to `tunnex-sandbox-bootstrap` through stdin; flags are server URL, expected sandbox UUID/generation and a new private handoff directory. Files are0600 inside a newly reserved0700 directory. Existing destinations refuse without redeeming. Networking/workload startup, policy acknowledgements, private SSH health and skill/workspace delivery still belong to the coordinator and cannot be inferred from this bootstrap layer.

Historical AMD64 image/runtime evidence and its exact scope are summarized in
[the validation record](../../docs/S-sandbox-pr-validation.md). The source uses
the absolute sshd argv[0] fix. Historical enrollment used a separate SHA-pinned
host worker; its result does not qualify a new image or installation. Current
image delivery uses the dependency producer/package lock and separate archive
release artifact; selection still requires explicit native qualification on the
selected host. Provider template image identity is the immutable image config
digest derived from the archive, and archive verification separately checks its
SHA256 and each uncompressed layer's config-bound diff ID.

## Alpine option (candidate, unavailable for selection)

`alpine/build-image.sh <amd64|arm64> <tunnex-sandbox-task-tag>` creates a prebuilt
musl Alpine candidate alongside the unchanged Ubuntu recipe. See
`alpine/manifest.json` for measured size and compatibility and
`alpine/README.md` for qualification limits. No creation gate or template is changed.
