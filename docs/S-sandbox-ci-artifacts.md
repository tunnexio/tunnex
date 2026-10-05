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
| `tooling` / `test-sandbox-package` | Sandbox actor, private SSH probe, offline/online enrollment, namespace helper and bootstrap | Actor/probe/enrollment in both API editions, eight binaries per Linux architecture; full API module compile-only in both editions on ARM64; committed-source archive, readonly modules, pinned Go | Two public `tunnex-sandbox-linux-<arch>.tar.gz` bundles plus external checksums; strict public asset allowlist and internal source manifest/checksums |
| `tooling` / `test-sandbox-image` | Ubuntu AMD64 dependency producer and workload bootstrap | Pinned Go, committed signed-metadata/package lock, anonymous immutable base preload, offline final assembly; source/lock/base/config/layer/architecture verification | Exact Docker archive, `workload-image.json` and `SHA256SUMS`; delivery remains unqualified and enables no template |
| `contracts` | SSH entrypoint, supervisor layout, image producer/assembly, artifact integrity and enrollment/portable installer | Python stdlib/synthetic fixtures, including actual archive-format verification without an engine; no provider, host, SSH, cloud or systemd action | No raw fixture/host logs or credentials uploaded |
| `web` | Sandbox creation/Skills/Setup/saved-key/local connection/deployment gates plus App Access | TS types, Vitest and Vite build | Normal dashboard image; no mandatory hosted AI/MCP runtime introduced |
| `node-native` / existing `publish` matrix | Normal API/node/web/migrate and other release services | Existing architecture/image/source-ledger checks | Existing signed release/image publication path; no sandbox image is silently substituted for a qualified template |
| Existing `release-assets` | Public sandbox binary/installer/recipe bundles, enrollment launcher/distribution and Ubuntu workload delivery | Same-run artifact download; source/architecture/ELF/inventory/lock/config/layer/checksum verification; exact source-ledger/draft checks | Existing release job attaches both bundles, exact launcher, public distribution, image archive/descriptor and checksums, then records artifact provenance; no installer or service executes |

Both sandbox targets are required entries in the existing `tooling` matrix and
`gates` aggregate. Failures have no advisory/skip fallback. Sandbox asset edits
select the Go/tooling lane. Main/tag retention uploads exactly four named binary
bundle files and three named image-delivery files; PR checks build them without
publication. Binary bundle manifests declare `native_runtime_qualification=false`
and `workload_images_built=false`.

The public distribution stages the exact committed enrollment launcher from both
verified bundles, refusing disagreement. Its HTTPS URLs identify the actual
source-bound draft release. `workload_image_delivery:{url,sha256}` is present only
when the exact separately verified descriptor is included;
`workload_images_built` is true if and only if that pointer is present.
`native_runtime_qualification` stays false. The API selects the supported AMD64
bundle from these public pins while organization, gateway, controller, image and
host authority remain explicitly reviewed configuration. Public artifacts carry
no enrollment token; the launcher prompts for it locally.

## Public bundle inventory

For each architecture, actor/probe/enrollment binaries have distinct `open` and
`enterprise` names. Helper and bootstrap are edition independent. Public assets
are the Ubuntu final-layer recipe/entrypoint/build script, Alpine candidate
recipes/entrypoint/build script, network-plan contract, packaging README, and
portable `install.py`, `enroll.py`, installer README and `example.json`. The six
Ubuntu producer assets are `delivery.py`, `archive.py`, `Containerfile`,
`public-inputs.json`, `ubuntu26-amd64.lock.json` and their README.

The example contains public placeholders, not an operator configuration. Existing
fixed qualification units, host receipts, private keys, working directories,
runtime credentials, private logs and credential files are not allowlisted.
Bundling the offline enrollment executable does not execute it or mint keys.

## Required workload image build path

`make test-sandbox-image` uses the tracked Ubuntu producer and AMD64 lock. Before
final assembly it populates the pinned readonly Go module cache, verifies the
locked signed Ubuntu metadata/package closure, and preloads the immutable public
Ubuntu base using an empty registry-auth configuration. The final image build
uses `--network=none` and Docker `--pull=false` (Podman producer support uses
`--pull=never`). Readonly context mounts keep downloaded `.deb` archives out of
retained image layers. There is no per-launch package installation or download.

The producer emits only
`tunnex-sandbox-ubuntu26-linux-amd64.docker.tar`, `workload-image.json` and
`SHA256SUMS`. The release guard matches the exact current source SHA and committed
lock hash, checks the official base pin and archive bytes, verifies the actual
config digest/platform/UID 1001/workspace/source labels, checks all uncompressed
layer diff IDs and their measured byte total, and verifies exact inventory and
checksums. Native qualification and services-started fields must remain false.
The release retains and attests this bounded public delivery separately from
binary bundles.

The tracked producer resolves the former missing preloaded-base/lock release
prerequisite. Its actual local build/export evidence belongs to the producer's
exact source checkpoint; the final integrated publication source still needs
its own complete bundle and image build/verification. Image delivery alone does
not qualify a new host or register an enabled template. Required native
Podman/AppArmor/WireGuard/SSH/cgroup-expiry/cleanup proof remains scoped to the
exact reviewed image/provider/host. ARM64 image production and activation remain
unqualified.

`deploy/sandbox/build-image.sh` retains its offline final-layer interface for an
already approved/preloaded Ubuntu dependency base. Alpine Minimal/Python/Node
recipes remain separate candidates and do not substitute for the Ubuntu image
or its native policy/host qualification.

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
- PASS: complete public package fixtures (16), including interoperability with
  the committed installer and enrollment launcher at
  `2937b6768277dde2db68387d8ee60964d90a348c`: all 18 public assets match,
  both accept AMD64 and refuse ARM64 activation. Enrollment distribution/source-pin
  fixtures (5) are included in that suite, covering exact launcher
  extraction, release URL encoding and verified unqualified image-descriptor pins;
  image CI wiring/archive-format fixtures (5), including measured-layer refusal;
  updated aggregate/release contracts (58) and `make -n test-sandbox-image`. These
  fixtures use synthetic archives and committed producer source, not host activation.
- PASS: the release guard independently verified the producer's actual three-file
  delivery from `4fd7c533bab3f091633fdeca96d6bff21e273d7f`, including committed
  lock/base/config/source identities, every layer diff ID and checksums. The
  archive is 71,403,520 bytes and measured uncompressed layers are 195,198,976
  bytes. Delivery retains false native qualification, services-started and
  per-launch-installation fields. This source export is not a native runtime test.
- The earlier binary checkpoints predate the expanded enrollment/Ubuntu producer
  inventory. Final integrated source requires a fresh exact-SHA build and
  verification. Remote CI and new portable native qualification were not run.
