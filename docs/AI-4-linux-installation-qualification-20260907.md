# AI gateway Linux image qualification — 2026-09-07

Local zero-spend qualification used Docker context `colima-tunnex-sso-review`,
project label `com.docker.compose.project=tunnexaiwalk0907`, and dedicated network
`tunnexaiwalk0907_engine`. No pre-existing containers, databases, volumes, or
networks were changed. All qualification containers were stopped; project volumes
and stopped containers remain available for inspection. No provider credentials
or paid requests were used.

## Artifact and fixture

Official image index:
`maximhq/bifrost:v2.0.0@sha256:cf71be9fad4e0749b6e26cbb774c687413dad9a0970b83f4e1dadb6f503ea208`.
The executed image was Linux arm64. Its `/app/main` binary SHA256 was
`85f21483ed660d8c50de5f4313a995cd8ba364de058d2d645966bf13d5ba9222`.
A stopped Linux amd64 artifact container separately yielded `/app/main` SHA256
`e3a59884140ed5ddb29f373c6c76f42de8d453dc150b996f8f834893b2bfed41`;
that binary was extracted, not executed in this walkthrough.

The fixture copied `deploy/ai-gateway/config.json`, changing only the OpenRouter
network destination to an instrumented HTTP provider on the dedicated network
and allowing that private synthetic destination. Provider responses contained
four prompt tokens and three completion tokens. Engine/admin/encryption secrets
were disposable fixture strings, with no real credentials inherited.

Separate named volumes held configuration, logs, and a stopped-engine snapshot
restored into independent configuration/log volumes. Source files entered Docker
through stdin tar archives; host bind mounts were not assumed. The image used
its standard entrypoint/CMD, UID/GID1000:1000, dropped capabilities,
no-new-privileges, a read-only root filesystem and writable `/tmp`. It had no
published host port and belonged only to the dedicated engine network.

## Observed results

- Linux startup and `/health` succeeded under that non-root configuration.
- A separate container on Docker’s unrelated default bridge could not reach the
  healthy engine by its inspected private IP (three-second connection timeout).
- Anonymous governance and inference requests returned401. Two exact scoped
  native keys were created through authenticated governance.
- Synthetic inference succeeded and native key-scoped stats retained seven
  tokens. Setting one key inactive returned403 on subsequent inference.
- After a stopped-engine snapshot, both SQLite logical records and raw log
  database/WAL bytes omitted the unique synthetic prompt and response markers.
- Restarting the same container preserved the revoked key's403 refusal, an
  independent healthy key's200 response and the revoked identity's seven tokens.
- Recreating the engine against the same state with a changed admin environment
  password rejected the old password401 and accepted the new password200.
  Revoked/healthy inference controls remained403/200.
- Starting the same image against the separate snapshot volumes preserved
  revoked/healthy controls and the original identity's seven-token history.

Native `total_requests` includes logged denied attempts: one completion followed
by two native denials produced three requests and seven tokens. Qualification
therefore asserted token preservation rather than incorrectly treating request
count as successful completions only.

## Evidence and limits

Local scripts, synthetic fixture state and the result log are retained at
`/private/tmp/tunnexaiwalk0907/`. `results.log` includes one superseded assertion
that expected request count1 after logged denials; the corrected token-preservation
assertion and subsequent checks passed. An earlier fixture invocation supplied
unnecessary CLI arguments and hit an upstream entrypoint argument loop; the
walkthrough then used the actual installer default invocation successfully.

This qualifies the pinned Linux image with synthetic inference, metadata omission,
state preservation, admin rotation and same-version stopped-snapshot restore.
It is not a full control-plane Compose installation, real-provider Linux test,
Helm cluster/CNI test, amd64 execution test, crash recovery test, or cross-version
upgrade/downgrade proof. The bootstrap configuration was copied into the dedicated
state volume rather than mounted at the production read-only config subpath.
The restored engine and provider ran only within this explicit test project.
