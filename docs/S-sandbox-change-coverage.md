# Sandbox change coverage for PR preparation

This ledger accounts for the completed sandbox work, its earlier story branches,
and preserved working changes. It records source coverage, not a new validation
pass or authorization to deploy. The isolated preparation branch is
`story/sandbox-pr-prep-20261005`.

The integration inventory checkpoint is `57c1655`: it follows supervisor integration
`2827c3a`, upstream-main/schema integration `162348a`, and optional-module
integration `0b6cd41`. Source work after this checkpoint requires its own
validation record. Organization-admission source was subsequently implemented at
`f30c378`. Original story branches, worktrees and qualification evidence
remain available unchanged; publication filtering does not alter those originals.

## Completed source and supporting material

“Included” means the named integrated commits are ancestors of the preparation
checkpoint. “Equivalent” means stable Git patch comparison or final file
comparison established the mapping; an earlier branch tip need not itself be an
ancestor after integration.

| Capability | Integrated source and tests | Earlier branch or mapping | Coverage |
| --- | --- | --- | --- |
| Independent sandbox lifecycle and policy-bound identity | `593544c`, `9442cbc`, `61d8361`; sandbox domain/store tests and policy subject/projection tests | `story/sandbox-foundation`, content tip `9b5d17d` | Included. Sandbox identities remain separate from ordinary human-device controls. |
| Provider boundary, generated lifecycle API and recoverable cleanup | `a49025f`, `3469ee6`, `e237664`, `bcd2496`; provider/store/cleanup/lease integration tests | Foundation | Included, together with OpenAPI, generated API/CLI/TS contracts and RBAC mirror. |
| Managed bootstrap, distinct runtime credential and durable launch handoff | `f6e3218`, `4cc442a`, `16f93f2`, `82e43ab`; bootstrap, enrollment and launch tests | Foundation | Included. No mandatory hosted agent or new enrollment protocol is introduced by this ledger. |
| Selectable skills, private versioned Skills library and inert workspace delivery | `126a2f1`, `455cc6f`, `ac68e8c`, `cbd03a7`; skill catalog/configuration, custom-skill, workspace and UI tests | Foundation | Included. Skill configuration and selection are part of the product scope. |
| Creation UI, private connection instructions and lifecycle controls | `9e3a57d`, `b573a9b`, `19dc861`, `822879f`, `c1da4ba`; creation, connection and private-skills UI tests | `ui/sandbox-experience`, original tip `811b9b4` | Included with the prior Stop/Delete availability repair retained. Original and integrated premium UI differ only in that repair and its added test. |
| Compact console, Setup and image/profile selection | `9e146c9`, `685bdff`, `4afd5da`; setup, image-profile and console tests | `ui/sandbox-compact-console`, tip `ab685dac`; integrated compact tip `a61a8ae` | Earlier compact branch patches are equivalent to foundation. Product assets include `apps/web/src/assets/sandbox/ubuntu.svg` and `ATTRIBUTION.md`. |
| Prebuilt lightweight image recipes and measured catalog candidates | `55ad590`, `1d4a3a9`, `4a53a0f`, `d07ff3c`; image assets/provider tests, recipe verification and catalog source | `sandbox/alpine-profile`, tip `cf3f70e` | All seven earlier branch patches are equivalent to foundation. Candidate recipe history does not establish that every image is supported on every host. |
| Retained runtime, workspace, host identity and bounded resume | `6fd44a8`, `65e638b`, `385bc13`, `7472e8b`, `c7a573d`, `5279770`, `82b3260`; persistence, resume, cleanup and qualification tests | `codex/persistent-sandbox-catalog`, tip `3329b38` | Earlier persistent/reservation patches are equivalent to foundation. Later admission, resume-quota, stopped-TTL cleanup and MTU fixes are also included. |
| Saved account public SSH keys and creation selection | `c0e82d9`, `f559510`; saved-key store, HTTP, picker and PostgreSQL tests | Original `422ed08` / `835841b` | Exact patch equivalents; all changed final blobs match their integrated counterparts. The missing decision paper from `2ab9d25` was recovered during integration `162348a`. |
| Explicit bounded machine delegation and withdrawal | `445681a`, `b7f1298`, `177bf90`; delegation store, revocation/race, HTTP/RBAC and generated-route tests | `story/sandbox-agent-delegation`, original tip `7959c6f` | Exact patch equivalents. Generated administration routes and the remote integration are included; no implicit broad privilege inheritance is authorized. |
| Remote runner, mTLS enrollment/renewal, scoped network and offline expiry | `78faf67`, `16804fa`, `c1b1a30`, `177bf90`, `400dba4`, `a91ea1f`, `d828361`, `0c34189`, `4164058`; runner, network, routing, health and remote-lifecycle tests | `story/sandbox-remote-runner`, tip `ea229743` | Included, including the latest remote-sequence test refinement. Runtime and helper commands, contracts and tests remain in scope. |
| Supervisor ownership across transport restart and independent bounded expiry | `4c63e6a`, `46ecee5`, `0622919`; actor socket, cgroup lease guard, provider and fixture tests | `story/sandbox-supervisor-layout` | Included through `2827c3a`. The generic fixture source and regression tests are distinct from host-specific execution receipts. |
| Bounded readiness diagnostics and prompt policy acknowledgement | `8133596`, `7821bec`, `e52b0ea`; readiness diagnostics/gates, report persistence/callback, node reporter/outcome and stale-endpoint tests | Supervisor tip `8133596`; `story/sandbox-readiness-diagnostic-live`, tip `4bd254e` | Both source variants and the ACK fix are included. Exact-hash, freshness, identity and readiness gates remain required. Historical live qualification is recorded separately from checks on the merged PR head. |
| Optional module and safe draining | Original `17a6caa`, integrated at `0b6cd41`; module configuration, HTTP/meta/policy and web-gate tests | `story/sandbox-optional-module` | Included after upstream-main integration. This commit added **no migration**; no migration renumbering is attributed to it. |
| Organization-member admission and immutable terminal selection | `f30c378`; eligibility, organization admission/binding/orchestrator, HTTP and terminal-picker/creation tests | Decisions at `57c1655` | Implemented in preparation. Explicit organization mode derives creator from authenticated authority, validates the selected owned terminal, preserves its immutable workload binding and retains one shared slot. Narrow validation is recorded below; combined gates remain pending. |

Source, regression tests, product assets, generic image/installation examples,
OpenAPI overlays, generated contracts and decision records are retained together.
The feature does not become complete by preserving backend code while dropping
its Skills, Setup, key-picker, connection or lifecycle surfaces.

## Preserved uncommitted working changes

The older persistent-catalog worktree, `2026-10-03/task-5/tunnex`, contained the
following names at inventory. It was neither reset nor copied wholesale. The
three reservation files match the committed foundation snapshot. A narrow source
comparison of the four UI files establishes that their behavior is represented
in the current committed versions; their literal working snapshots stay in the
original worktree.

| Preserved working path | Disposition in preparation |
| --- | --- |
| `apps/api/internal/sandboxes/dev_reservation.go` | Exact bytes match foundation `9b5d17d`; current source has subsequent integrated changes. |
| `apps/api/internal/sandboxes/dev_reservation_test.go` | Exact bytes match foundation and the inventory checkpoint. |
| `docs/S-sandbox-dev-reservation-decisions.md` | Exact bytes match foundation and the inventory checkpoint. |
| `apps/web/src/pages/Sandboxes.tsx` | Earlier connection/lifecycle behavior is represented in current source, which additionally contains the saved-key picker and newer resume eligibility. Superseded by committed source, not silently dropped. |
| `apps/web/test/sandboxes.test.tsx` | Earlier cases are represented in current tests; current tests additionally cover five resume/quota cases. Superseded by committed tests. |
| `apps/web/src/lib/sandboxConnection.ts` (untracked there) | Committed helper covers the same behavior. The observed difference is equivalent `printf` newline escaping. |
| `apps/web/test/sandbox-connection.test.ts` (untracked there) | Committed counterpart covers the same behavior, with corresponding equivalent newline escaping. |

The four task-2 source worktrees inspected—foundation, remote runner, supervisor
and diagnostic-live—were clean. Earlier Alpine, compact/premium UI, saved-key,
delegation and optional-module worktrees were also clean. This is a filesystem
inventory and source mapping, not an additional test result.

## Current authorized integration work and exclusions

The decisions introduced at `57c1655` authorize organization-based admission
and a portable Linux installation path. Admission was implemented at `f30c378`:
it follows the authorized organization/user policy and current lifecycle guards,
rather than a fixed human/Mac identity; capacity remains one workload. Its
creation UI includes explicit terminal selection. Portable installation and CI
source are implemented at `440034b` and `c3fd55e`. Historical qualification
evidence remains immutable in its original worktrees. The new source does not
establish a new live deployment or wire qualification.

First-Ready usable lifetime remains excluded from this integration. The current
creation-based expiry contract and independent absolute expiry bound are not
silently changed. No new live workload, deployment, policy/account mutation,
publication, push or PR merge follows from this source-coverage record.

## Publishable tree and validation record

The final PR tree keeps all sandbox source, tests, product assets, generic
installation/qualification source and decision documentation. Host-specific
operational walk scripts and raw execution receipts are excluded from the
publishable final tree. Originals remain on their existing branches/worktrees;
sanitized validation summaries preserve what passed, failed, skipped or remains
unrun, with source checkpoints and limitations.

Filtering must distinguish executable regression/fixture source from an operator
script tied to a particular live host. Filename-based inventory is only a review
aid; it is not permission to delete a source file, test or decision record. No
private key, credential file, raw live log or private host configuration is
needed to make this classification.

Historical qualification does not substitute for tests on the merged PR head.
The applicable generated-code drift, migration compatibility, both API edition,
Linux node, web type/test/build and installation checks belong in the final
preparation validation record. They were not rerun by this inventory worker.

The root relayed the following bounded worker results for `f30c378`; these are
distinct checks, with no aggregate count inferred from potentially overlapping
selection patterns. Final combined results are recorded in
[the validation summary](S-sandbox-pr-validation.md).

| Reported check | Result |
| --- | --- |
| Focused API admission/identity race selection, 13 top-level tests, fresh disposable PostgreSQL fixtures | Open passed in 24.227s; enterprise passed in 20.919s. |
| Focused policy lane | 23 test records in each edition; zero skips/failures. |
| Eligibility and cleanup lane | 12 test records in each edition; zero skips/failures. |
| Final Ready CAS/binding-authority races and existing resume selection | Open passed; no additional both-edition result is inferred. |
| Focused creation wizard and terminal picker | 28 tests passed: 25 wizard and three picker tests. |

These narrow results preceded the full API/web follow-up. An earlier fixture
initialized with an incorrect blank legacy binding is not a product failure or
a pass on the final combined head. The final validation summary reports the
completed suites, corrected migration-fixture rerun and remaining skips separately.

Portable runtime placement and the offline installer are implemented at `440034b`; both-architecture packaging and required fixture coverage are implemented at `c3fd55e`. The historical fixture source-validation manifest is preserved outside publication; its executable fixture and regression tests remain included and run in CI. Final combined checks are recorded in S-sandbox-pr-validation.md.

Final integration repair `691d56a` restores the pinned generated header and tests forward upgrade from published schema180 to195 without downgrading retained App Access authority. Original source/operational history remains on the integration branch; the separate candidate retains all 352 product/test/build paths unchanged.

Public image README correction `47a44ef` removes stale operator-only citations
and makes current image-release prerequisites explicit. After that reviewed
documentation change, all 352 product/test/build paths remain identical between
the integration branch and publishable candidate. No executable source changed
after the validation checkpoint.
