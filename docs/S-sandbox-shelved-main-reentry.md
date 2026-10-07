# Sandbox shelving on main

Sandbox development is paused at the user's request. This patch starts from
published main `e6b65cd9b60b96d05344fb2cec770a0dc45e28dd` and shelves the
sandbox implementation already present there. It does not import later local
runner, lifetime, enrollment or release development.

## Decisions before implementation

- Locked: use isolated branch `story/sandbox-shelved-main-20261007`; preserve
  the original development and shelving branches unchanged.
- Locked: make sandbox product availability a source-level off switch. Earlier
  environment settings, stored opt-ins and supplied dependencies must not
  reactivate UI, API, background work or dedicated executable entry points.
- Locked: retain implementation source, generated contracts, migrations and
  existing data. Shared VPN, gateway, site-to-site, SHIELD/browser access,
  identity restrictions and security checks remain active.
- Locked: remove only sandbox-specific work from ordinary CI and releases.
  Preserve shared compile dependencies, full source builds and ordinary check
  names. Historical sandbox matrix contexts may print explicit shelving
  notices without claiming qualification.
- Locked: keep this public checkpoint free of private host identifiers,
  machine access paths, credentials and enrollment/operational details.
- Locked: this work is local preparation only. No push, PR creation, workflow
  dispatch, deployment, live access change or infrastructure cleanup.

## Implementation stories and acceptance

1. **Product entry points.** Add explicit static gates and TODOs at existing
   web, API/server, node and CLI integration seams. Sandbox navigation/settings
   and direct routes cannot expose the product. HTTP refuses before sandbox
   authentication, body parsing or providers; server and executable guards
   refuse before dedicated configuration or credential loading.
2. **Ordinary CI and release paths.** Disable sandbox-only test discovery,
   fixtures, packaging/image producers and their artifact consumers together.
   Keep aggregate dependencies coherent, ordinary release verification and
   shared VPN/security coverage. Failed/invalid/empty package discovery cannot
   silently pass. Do not remove dependencies still required by retained source.
3. **Validation.** Exercise affected acceptance/contract tests, both API
   editions and ordinary UI/build checks as appropriate. Validate workflow
   syntax and the exact diff from the published baseline. Clearly record
   passed, failed and unrun checks; no native/live sandbox qualification.
4. **Re-entry.** Record final source pointers and restoration seams without
   importing private operations history. The final PLAN pointer names the
   content commit, followed by a documentation-only checkpoint commit.

Stories 1 and 2 can proceed independently after this decision record. Story 3
depends on both, and story 4 closes the local checkpoint.

## Shelving boundaries

| Integration | Main-based boundary |
| --- | --- |
| Web | `SANDBOX_PRODUCT_SHELVED` disables existing sandbox lazy pages, routes, navigation and effective metadata. Direct links show Not found before product providers. Existing Settings, SHIELD and App Access wiring remain. |
| API/server | `sandboxproduct.Shelved` bypasses only sandbox configuration validation and the lazy sandbox initializer. No retirement query, private runtime loader, sandbox worker or fixture transport is constructed. HTTP clears sandbox dependencies and returns 404 before authentication/body processing for sandbox and its saved-key endpoints. |
| CLI/node executables | CLI `SandboxProductAvailable = false` and node `sandboxproduct.Available = false` hide/refuse existing sandbox entry points before dedicated flags, files or network setup. Ordinary managed-agent and VPN commands remain. |
| CI/release | Sandbox Python contracts, bundle/image producers, downloads, distribution attachment and attestations are dormant. The two historical tooling matrix contexts print a shelving notice; aggregate needs and ordinary signing/managed-agent/source-ledger steps remain. |

Source is retained, including its underlying scope restrictions and existing
cleanup contracts. This local source change does not stop or clean up an
already deployed installation.

The checked package selector excludes the four existing API families
`sandboxes`, `sandboxrunner`, `sandboxruntime`, `sandboxscope`; node
`sandboxnetwork`; dedicated API/node `cmd/tunnex-sandbox-*` commands; and CLI's
exact `cmd/tunnex-sandbox-bootstrap` package. New ordinary
packages and the new static-gate acceptance code remain covered. Full source
builds and CLI vet remain active; App Access transport tests are unchanged.
Exactly ten existing sandbox-only Vitest suites and two historical publication
contract cases are archived, while shelving/shared acceptance remains active.

Review disposition: the unchanged `cli-release` job deliberately retains its
full CLI tests, including the bootstrap command's sole new shelving-refusal
test. That negative acceptance test performs no sandbox feature work. Keeping
it preserves ordinary release behavior and verifies the unavailable command;
it is not sandbox qualification.

No dependency manifest or lockfile changed. Shared Python/SQLite prerequisites
for native AI tests and node VPN tools/`NET_ADMIN` remain. Only sandbox-specific
CI installation, fixtures and artifact-generation requirements were disabled.
The existing native web-image build fix remains untouched.

## Preserved local development history

The earlier combined development/shelving branch remains local as
`story/sandbox-shelved-20261007`, checkpoint
`a316ac73607d71bcb7b8178a3034121585a2723c` (content
`30172195114a7a5fb872cecec28434025ca03425`). Its 30 commits include 24 later
implementation commits and six shelving commits. They are not imported into
this main-based patch. Detailed private operational and unfinished-work
checkpoints remain local; obtain that handoff deliberately before any restart.

## Re-entry procedure

1. Confirm an explicit restart instruction and select the intended integration
   base. Review this patch separately from the preserved local development
   branch; do not blindly cherry-pick the entire old history.
2. Review all static product gates together, then restore the existing route,
   server, executable and UI wiring deliberately.
3. Restore sandbox tests, fixtures and the complete CI/release artifact chain
   together. Keep ordinary shared gates and verified dependency requirements.
4. Review the original goals: policy-bound user sandboxes, direct terminal or
   existing local-agent access, selectable templates and configurable skills,
   and a lightweight preloaded runtime with measured startup/resource budgets.
   General multi-user runner architecture remains a re-entry direction, not
   authorization to resume it during this pause.
5. Requalify exact-source builds, generated drift, native operation, cleanup
   and release compatibility before separately authorized publication or use.

## Validation ledger

Decision record `39e90b7e` was committed before implementation. The final PLAN
pointer names content checkpoint `666d0c4c692ae9527f4739db2ea584dfe2bf8ce8`;
the subsequent checkpoint commit changes documentation only.

Passed locally:

- Web typecheck, lint and production build; 53 focused tests; 25 built-browser
  smoke checks with synthetic read-only fixtures. Seven direct sandbox links
  make no API calls; ordinary Settings, OpenVPN, Applications and SHIELD
  navigation remain usable. No sandbox page chunks or entry labels are emitted.
  Discovery retains 173 suites and excludes exactly ten dormant feature files.
- CI/script contracts: 84 passing, two explicit historical skips, zero failed.
  Real readonly/offline package discovery preserves shared/current packages;
  aggregate contexts and remaining artifact producers/consumers are consistent.
- All five workflows pass actionlint 1.7.12; the 21-job CI graph and 73 embedded
  shell scripts pass syntax checks without executing those scripts. Shellcheck
  and pyflakes are unavailable and disabled.
- Both API editions pass the Go embed/classifier census and focused ordinary
  release signing, manifest and bootstrap verifier checks (38 passing events
  per edition), using synthetic fixture keys only.
- Both API editions pass 17 focused product/shared HTTP tests, with seven
  explicit dormant/DB skips each. Coverage includes all 30 sandbox operations
  before authentication/body processing, the 433-operation sessionless census,
  shared terminal/auth transport, and inactive startup/configuration callbacks.
  Full API source builds pass for Linux AMD64 in both editions.
- Six focused node/CLI checks and dedicated node Linux AMD64 builds pass.
  Ordinary agent and CLI behavior remain preserved.
- Bounded independent source reviews cover product seams, shared behavior,
  package selection, CI/artifacts and public-document privacy. No blocking
  finding remains; the deliberate CLI refusal-test exception is recorded above.

The first API validation run exceeded its compilation timeout without producing
an assertion/build result; it is incomplete, not passing. A new metadata test
then injected an inert tenancy service with no database and failed in that
fixture. The fixture was corrected without a product-code change; both edition
reruns and full builds pass. Restricted browser and HTTP test listeners lacked
loopback permission; narrow approved local fixture runs subsequently passed,
and their servers/browser were closed. Full database/container gates, native Linux execution, full web
suite and generated-drift execution were not run locally. No migrations or
generated-contract inputs/outputs changed.

## Authorized draft publication and CI correction

[Draft PR #103](https://github.com/tunnexio/tunnex/pull/103) was published under
separate authorization after source review. Its initial head `9a3ab4f7` passed
Security and Dependency Review. The main CI run completed with two tooling
failures: node and CLI full-source compile steps could not obtain VCS status
inside their source-mounted containers, before tests ran.

The [scoped correction decisions](S-sandbox-shelved-ci-vcs-decisions.md) record
the real-Go reproduction and two-lane `GOFLAGS` change. Complete Linux AMD64
node/CLI builds, CLI vet and selected tests, 72 affected contract checks and
independent review pass locally. The updated exact-head remote results belong
to the PR checks; local validation does not establish their success. No release
flags, live resources or preserved sandbox development source changed.
