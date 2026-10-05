# Quarantined sandbox image layer

`build-image.sh <approved-base@sha256:digest> <amd64|arm64> <tunnex-sandbox-task-tag>` builds the bootstrap client from committed source and adds it to an approved preloaded Ubuntu base. The final Podman layer has pull=never/network=none and performs no package installation. Its fixed Python entrypoint prepares the private tmpfs SSH directory and execs foreground sshd as uid1001; no service manager, DBus or host socket is started. Provider creation supplies network=none, read-only filesystem, resource bounds and the namespace-local unprivileged-port setting. Trusted read-only SSH mounts must exist; starting this image alone cannot claim connectivity or Ready. Actual nonroot sshd/AppArmor behavior remains to be qualified.

This is a source recipe, not a built or qualified image. No base digest is invented or selected automatically; no manual pilot image/container is read or reused. The approved base must have WireGuard, iproute/coreutils, SSH/SFTP, Python stdlib, the resolvconf CLI, setpriv and nft, and a free uid1001. Base construction/package locking, AppArmor-compatible setup, exact size/dependency inventory and runtime underlay isolation are pending qualification. Image context copies only this recipe and a locally compiled binary, never repository credential/config files. Go module resolution is build-time, checksummed and readonly; no launch installs/downloads are introduced.

Public sandbox bootstrap requires qualified provisioning and uses HTTPS. The one-time token is supplied to `tunnex-sandbox-bootstrap` through stdin; flags are server URL, expected sandbox UUID/generation and a new private handoff directory. Files are0600 inside a newly reserved0700 directory. Existing destinations refuse without redeeming. Networking/workload startup, policy acknowledgements, private SSH health and skill/workspace delivery still belong to the coordinator and cannot be inferred from this bootstrap layer.

Historical AMD64 image/runtime evidence and its exact scope are summarized in
[the validation record](../../docs/S-sandbox-pr-validation.md). The source uses
the absolute sshd argv[0] fix. Historical enrollment used a separate SHA-pinned
host worker; its result does not qualify a new image or installation. Current
image delivery requires an approved dependency-preloaded Ubuntu base/archive,
a reproducible producer/package lock and CI input, offline final-layer assembly,
and native qualification on the selected host. Provider template image identity
is the immutable local config digest; archive verification separately pins its
OCI manifest.

## Alpine option (candidate, unavailable for selection)

`alpine/build-image.sh <amd64|arm64> <tunnex-sandbox-task-tag>` creates a prebuilt
musl Alpine candidate alongside the unchanged Ubuntu recipe. See
`alpine/manifest.json` for measured size and compatibility and
`alpine/README.md` for qualification limits. No creation gate or template is changed.
