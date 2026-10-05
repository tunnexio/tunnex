# Sandbox source artifact bundle

CI compiles the dedicated Linux sandbox actor, SSH probe and offline enrollment
tool in both API editions, plus the namespace helper and bootstrap client, for
AMD64 and ARM64. The package target also compiles the entire API module in both
editions for ARM64; existing API gates build/test both editions on AMD64.
The bundles contain these binaries, explicitly listed public
image recipes, the portable installer, the enrollment launcher and its public configuration example,
a source/architecture manifest and checksums. No credentials, actual operator
configuration, qualification receipts, fixed-host units or runtime state
are included. CI never executes these binaries or starts a provider.

From a clean source checkout with pinned Go 1.26.8, `make test-sandbox-package`
builds `dist/sandbox/{amd64,arm64}/tunnex-sandbox-linux-<arch>.tar.gz`. The normal
main/tag release job publishes these bundles using the existing source-ledger
guard and artifact provenance. Downloaded bundle checksums use bare filenames;
the internal `SHA256SUMS` covers the manifest and every included file.

The guarded release job also publishes `Tunnex-Sandbox-Enroll.py`, its bare-name
SHA256 sidecar, and `Tunnex-Sandbox-Distribution.json` plus its SHA256 sidecar.
The launcher is extracted from both verified architecture bundles; disagreement
is refused. It is the exact committed `deploy/sandbox/install/enroll.py`, with
no separately maintained installer copy. The distribution manifest records
the same source SHA, the actual repository/release tag and public HTTPS URLs
and hashes for the launcher and both bundles. It contains no organization,
gateway, controller, host placement or private credential configuration.
When the separately verified Ubuntu image delivery is present, its
`workload_image_delivery:{url,sha256}` points to the exact release descriptor
bytes and `workload_images_built` is true. Without that pointer the flag is false.
Internal binary bundle manifests keep their image-build flag false. Every
distribution keeps `native_runtime_qualification` false; image delivery supplies
an artifact pin for the reviewed catalog/qualification flow.

The API's supported distribution loader selects the AMD64 bundle and supplies
these public pins to the runner enrollment profile. The operator still supplies
the reviewed organization/gateway/controller/image authority and dedicated
runtime identities. A browser cannot invent a source URL or enable a host from
artifact metadata. The copied install command prompts for its one-time token;
the token does not appear in the public manifest, shell arguments or URLs.
ARM64 remains a compilation artifact and is refused by the installer.

For local source-only fixture validation, distribution staging takes an existing
verified bundle directory and a new absolute output directory:

```sh
python3 -B deploy/sandbox/ci/package.py distribution \
  --directory /absolute/bundles --source "$SOURCE_SHA" \
  --repository tunnexio/tunnex --tag "tunnex-build-$SOURCE_SHA" \
  --output /absolute/new-distribution
```

Staging performs no download, enrollment or service operation. The real release
job validates the release's source ledger and draft state before attachment and
includes the public launcher and manifest in artifact provenance. A local
fixture's generated URLs do not claim that its release exists or was published.

Compilation is separate from native runtime qualification. Existing native
sandbox evidence applies to its exact approved AMD64 image, provider and host
configuration. An ARM64 binary build does not qualify ARM64 Podman, AppArmor,
WireGuard, SSH, cgroup deadlines or cleanup. Bundle manifests therefore mark
native runtime qualification false for both architectures.

The binary bundles include the six public Ubuntu producer/input/lock files.
The required `test-sandbox-image` entry in the existing tooling matrix produces
the AMD64 Ubuntu workload archive separately. It uses pinned Go 1.26.8 and a
readonly build-time module cache, fetches the committed package closure and
preloads the immutable official Ubuntu base with anonymous registry settings.
Final image assembly uses no network or pull and includes only verified locked
dependencies and committed source. Downloaded package archives are mounted
during assembly so they do not add a retained image layer.

The existing release job verifies the exact source, AMD64 platform, dependency
lock, base/config digests, archive bytes, image labels, unprivileged user and
checksums before attaching the archive, `workload-image.json` and `SHA256SUMS`
and recording their provenance. These public artifacts start no service,
register no template and supply no host qualification proof. ARM64 workload
image production and hosting remain unqualified. Minimal/Python/Node Alpine
recipes remain candidates until their exact image and host placement pass
native qualification. Launch never installs dependencies or downloads an image.

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
