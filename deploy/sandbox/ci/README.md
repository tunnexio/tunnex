# Sandbox source artifact bundle

CI compiles the dedicated Linux sandbox actor, SSH probe and offline enrollment
tool in both API editions, plus the namespace helper and bootstrap client, for
AMD64 and ARM64. The package target also compiles the entire API module in both
editions for ARM64; existing API gates build/test both editions on AMD64.
The bundles contain these binaries, explicitly listed public
image recipes, the portable installer and its public configuration example,
a source/architecture manifest and checksums. No credentials, actual operator
configuration, qualification receipts, fixed-host units or runtime state
are included. CI never executes these binaries or starts a provider.

From a clean source checkout with pinned Go 1.26.8, `make test-sandbox-package`
builds `dist/sandbox/{amd64,arm64}/tunnex-sandbox-linux-<arch>.tar.gz`. The normal
main/tag release job publishes these bundles using the existing source-ledger
guard and artifact provenance. Downloaded bundle checksums use bare filenames;
the internal `SHA256SUMS` covers the manifest and every included file.

Compilation is separate from native runtime qualification. Existing native
sandbox evidence applies to its exact approved AMD64 image, provider and host
configuration. An ARM64 binary build does not qualify ARM64 Podman, AppArmor,
WireGuard, SSH, cgroup deadlines or cleanup. Bundle manifests therefore mark
native runtime qualification false for both architectures.

Workload images are **not built or published by this binary packaging lane**.
The Ubuntu recipe needs an independently approved, preloaded base digest; CI
does not invent one. Minimal/Python/Node Alpine recipes remain candidates until
their exact final image and host placement pass native qualification. Recipes
require their source checkout and build tools; package installs occur only at
image build time. Launch never installs dependencies or downloads an image.

The included stdlib-only installer provides offline plan/check/install operations
for the supported Linux prerequisites. It accepts explicit operator-selected
identities, bounded state/storage placement, source/image/trust pins and verified
local artifacts. Its installation leaves services stopped and disabled and
never downloads dependencies or generates credentials. An example is not a live
configuration. Existing qualification units and their fixed research-host paths
are excluded from the bundle.

Portable deployment still requires separately provisioned rootless Podman,
native overlay, namespace/cgroup controls and an exact local gateway binding.
Source checks and synthetic installer fixtures do not qualify a newly activated
deployment or ARM64 hosting. Bundling binaries does not enable creation, register
templates, widen policy, enroll a runner or enable services. The legacy DB
fixture worker and fixture setup command compile in the existing API gates and
are not release operations.
