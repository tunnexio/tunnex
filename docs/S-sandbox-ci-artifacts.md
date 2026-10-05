# Sandbox CI and release coverage

This ledger covers the combined sandbox and upstream App Access source, including
the portable Linux story decided in `S-sandbox-portable-runtime-decisions.md`.
It describes source wiring and local verification, not a remote CI run or a new
native deployment. No workflow, publication, enrollment or service was triggered
while preparing this change.

## Job to component to artifact

| CI job/target | Components | Build/test scope | Artifact and authority |
| --- | --- | --- | --- |
| `codegen` / `make generate-check` | Combined OpenAPI, Go API/CLI, TS client, RBAC and sqlc | Generated drift check against the integrated schema | Tracked generated source; does not activate a feature |
| `api` / `make test-edition` | API, policy, sandbox lifecycle/admission/delegation, runtime libraries and all API commands | Full build in open and enterprise editions; package tests partitioned over isolated DB shards | Normal API image is built separately; fixture setup/legacy DB worker compile but are deliberately excluded from release bundles |
| `tooling` / `test-node` | Gateway reconciliation/ACK reporting and namespace helper | The actual Unix worker boundary runs as `nobody` before the privileged Linux Go suite, including sandbox network ownership contracts | Normal node image contains the gateway agent and AI relay; the privileged sandbox namespace helper remains a separate artifact |
| `tooling` / `test-cli` and `cli-release` | Normal CLI, managed-agent runtime, sandbox bootstrap/lifecycle client | Module build/vet/tests; CLI and managed-agent binaries cross-built for Linux AMD64/ARM64 | Existing CLI/managed-agent distribution remains unchanged; sandbox bootstrap is included in the sandbox bundle |
| `tooling` / `test-sandbox-package` | Sandbox actor, private SSH probe, offline enrollment, namespace helper and bootstrap | Actor/probe/enrollment in both API editions, eight binaries per Linux architecture; full API module compile-only in both editions on ARM64; committed-source archive, readonly modules, pinned Go | Two public `tunnex-sandbox-linux-<arch>.tar.gz` bundles plus external checksums; strict public asset allowlist and internal source manifest/checksums |
| `contracts` | SSH entrypoint, supervisor layout, image assembly, artifact integrity and portable installer | Python stdlib/synthetic fixtures; no provider, host, SSH, cloud or systemd action | No raw fixture/host logs or credentials uploaded |
| `web` | Sandbox creation/Skills/Setup/saved-key/local connection/deployment gates plus App Access | TS types, Vitest and Vite build | Normal dashboard image; no mandatory hosted AI/MCP runtime introduced |
| `node-native` / existing `publish` matrix | Normal API/node/web/migrate and other release services | Existing architecture/image/source-ledger checks | Existing signed release/image publication path; no sandbox image is silently substituted for a qualified template |
| Existing `release-assets` | Public sandbox binary/installer/recipe bundles | Same-run artifact download, source/architecture/ELF/inventory/checksum verification, exact source-ledger/draft checks | Existing release job attaches only the two bundles and sidecars, then records artifact provenance; no installer or service executes |

The new packaging matrix entry is already part of required `tooling` and `gates`.
A package failure blocks the existing aggregate. It has no advisory/skip fallback.
Sandbox asset edits select the Go/tooling lane. Main/tag retention uploads exactly
four named public files; PR checks build them without publication. Bundle manifests
declare `native_runtime_qualification=false` and `workload_images_built=false`.

## Public bundle inventory

For each architecture, actor/probe/enrollment binaries have distinct `open` and
`enterprise` names. Helper and bootstrap are edition independent. Public assets
are the Ubuntu final-layer recipe/entrypoint/build script, Alpine candidate
recipes/entrypoint/build script, network-plan contract, packaging README, and
portable `install.py`, installer README and `example.json`.

The example contains public placeholders, not an operator configuration. Existing
fixed qualification units, host receipts, private keys, working directories,
runtime credentials, private logs and credential files are not allowlisted.
Bundling the offline enrollment executable does not execute it or mint keys.

## Required workload image build path and exact remaining gap

`deploy/sandbox/build-image.sh <approved-preloaded-Ubuntu-base@sha256:digest>
<amd64|arm64> <tunnex-sandbox-tag>` is the existing offline Ubuntu final-layer
path. It compiles the bootstrap from committed source, passes the exact source
SHA into the label, and assembles a context containing only that binary and two
public source files. Podman uses `--pull=never --network=none`. The base must
already supply WG tools, ip/coreutils, OpenSSH/SFTP, Python stdlib, resolvconf,
setpriv and nft. It is not a plain official Ubuntu base.

The repository does not currently provide the corresponding reproducible,
dependency-preloaded Ubuntu **base producer/package lock and approved CI image
input**. Historical qualification digests describe their exact historical images;
they are not invented current release inputs. Consequently ordinary CI cannot
honestly produce a new complete Ubuntu workload image from these tracked recipes
alone. The image gate needs an approved immutable preloaded base/archive whose
architecture, prerequisite inventory and checksum have been verified, followed
by offline final-layer assembly and native runtime qualification before template
registration. This is a concrete image release-readiness prerequisite, not a
claim that binary packaging satisfies image delivery.

`deploy/sandbox/alpine/Containerfile` separately builds Minimal/Python/Node
candidate images from its pinned Alpine base. It is not an Ubuntu dependency
layer and cannot satisfy the Ubuntu prerequisite. Its recipe uses build-time
package installation; nothing installs or pulls per sandbox launch. Building a
candidate image alone does not qualify the previously failed policy path or
publish an enabled template. No Alpine substitution, new base choice or package
version selection was made during this PR preparation.

## Architecture and qualification boundaries

Existing native sandbox evidence is AMD64 and applies to its exact original
image/provider/host/control-plane scope. Both Linux architectures are compiled;
ARM64 hosting/activation remains unavailable without native qualification.
Source and installer synthetic checks cannot claim a newly portable deployment
has passed Podman, AppArmor, WireGuard, SSH, cgroup expiry or full cleanup.
Windows/macOS runner hosting and First-Ready-relative usable lifetime remain
outside this implementation. The original Create-relative absolute TTL stays.

## Local validation checkpoint

- PASS: OpenAPI YAML/duplicate-key parsing, all local references and unique
  operation IDs; sandbox and App Access contract additions retained.
- PASS: artifact integrity/source/architecture/public-inventory tests (11), SSH
  entrypoint tests (3), supervisor source fixtures (28), CI/gate wiring tests (57),
  native release publication contracts (5) and draft permission contracts (5).
- PASS: Ubuntu offline image assembly fixtures (3), including both architectural
  contexts, invalid/mutable input refusal, source pins, no pull/network flags and
  context/cleanup boundaries. Synthetic tools compiled or activated no image.
- PASS: API command census tests in both editions with cached Go 1.26.8 and
  module networking disabled; CI/security classifier copies match, and the
  existing content-only embed exemption retains its deletion guard.
- PASS: portable installer synthetic host fixtures (14). Package-format
  interoperability verifies its exact public asset/command inventory, accepts
  the AMD64 bundle and refuses ARM64 activation. Render/preload interfaces were
  checked without invoking host installation or runtime commands.
- PASS: `make -n test-node` and its CI wiring assertion require unprivileged Unix
  fixture execution before the privileged full suite, retaining `NET_ADMIN`.
- PASS: actual AMD64 and ARM64 bundles from clean preparation source
  `c3fd55e2954610076fa6345519609a9756fd2cae`, built with cached Go 1.26.8 and
  module networking disabled. Full API `./...` compiled for ARM64 in both
  editions. Source/ELF/inventory/inner and outer checksums verified; the real
  AMD64 archive passed installer acceptance and the ARM64 archive was refused
  for native activation. Bundles are 19,841,396 and 17,964,210 bytes respectively.
  A publication candidate with a different source SHA requires its own rebuild
  and verification; preparation evidence does not substitute for final provenance.
- PASS: actual bundles rebuilt from clean publication content checkpoint
  `4c8452e1dad6244d4d19ec11551299039cf41289`, with the same source/ELF/inventory
  and inner/outer checksum verification. AMD64 is 19,841,380 bytes and ARM64
  is 17,964,255 bytes. Full API ARM64 compilation passed in both editions; the
  installer accepted AMD64 and refused ARM64 without activation. A later
  documentation checkpoint must be rebuilt again before handoff; its bundle
  manifest and accompanying verification record carry its exact source SHA.
- Remote CI, complete workload-image builds and new portable native qualification
  were not run. The missing approved Ubuntu base/image input remains explicit.
