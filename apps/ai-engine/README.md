# Private Bifrost runtime

`build.py` extends the Bifrost v2.0.0 release pinned by immutable Git object
`9537b2fadf42af90eb34ed47d3d4252e1beff4a0` (the annotated release tag resolving
to `e4a30d604`). The engine serves inference, authenticated model discovery and
provider connection tests. There is no LiteLLM bridge or Python runtime service.

The three administrator-only operations are:

- `POST /api/tunnex/test-connection` for transient draft credentials.
- `POST /api/tunnex/model-catalog` for live authenticated model discovery.
- `POST /api/providers/{provider}/keys/{key_id}/test-connection` for an owned
  credential resolved inside the engine.

Tests use the same pinned native provider transport as serving. Saved tests check
key identity, revision name and endpoint; they never return a key, change its
model allowlist or persist a draft credential. Results contain only status,
duration and bounded failure categories. The control plane additionally checks
organization ownership, revision, endpoint eligibility and admission limits.
Private probes bound upstream responses to 1 MiB; catalog responses to 4 MiB.
Native custom and Azure Foundry providers retain the authenticated Go CONNECT
egress boundary, certificate validation and installation endpoint policy.

The native SageMaker extension retains explicit installation alias/client scopes,
IAM environment references, optional STS role assumption, SigV4 requests and
streaming inside Bifrost's authorization and accounting pipeline. It never uses
ambient AWS credentials. Its only supported operations are authenticated alias
listing, chat and chat streaming. An existing managed OpenAI bridge configuration
can migrate to this provider only when the endpoint is explicitly registered as
SageMaker and its destination, security settings and owned keys remain unchanged.

Catalog/pricing files are baked into the image at build time with attribution.
Live endpoint discovery remains separate from these static estimates. Missing
prices stay unknown. Upstream source and dependencies retain their licenses;
`BIFROST-LICENSE` and upstream third-party notices are shipped in the image.
Tunnex extensions are Apache-2.0 code.

Build with `python3 apps/ai-engine/build.py SOURCE_GIT_DIRECTORY OUTPUT_BINARY`.
Add `--test` to run synthetic native provider/mode, Azure CONNECT, SageMaker and
actual engine authentication/scope tests before accepting the artifact. These
tests use local fake providers and no paid model calls. Python is a build/test
helper only. The source checkout remains untouched; builds use a fresh archive,
compile its extended core through an explicit local module replacement, and keep
other module dependencies read-only.

The upstream modules require at least Go 1.27.0. The image uses its independently
pinned Go 1.27.2 builder; Tunnex first-party modules keep their shared toolchain pin.
