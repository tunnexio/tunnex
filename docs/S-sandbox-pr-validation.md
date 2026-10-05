# Sandbox PR validation

This summary preserves source and qualification evidence without publishing operator-specific configuration or raw walk receipts. Original story branches and evidence remain unchanged. Historical checks do not establish that the final integrated PR head passed.

## Source checkpoints

Completed foundation, UI, Skills, image/provider, persistence/cleanup, saved-key and bounded delegation work was integrated with the remote runner, retained supervisor and prompt policy-report ACK fix. Supervisor integration is 2827c3a; upstream-main/schema integration is 162348a; optional module integration is 0b6cd41. Organization admission and immutable terminal selection were implemented at f30c378 under decisions57c1655. The coverage ledger records earlier source mappings. The optional-module commit introduced no migration.

## Reported narrow results for f30c378

The focused API admission/identity race selection passed13 top-level tests in each edition: open24.227s and enterprise20.919s, using fresh disposable PostgreSQL fixtures. The policy lane passed23 test records per edition with no skips/failures; eligibility/cleanup passed12 per edition with no skips/failures. These selections can overlap and are not added into an aggregate. Final Ready CAS/binding-authority races and an existing resume selection passed in open; no further both-edition result is inferred. Creation wizard/terminal-picker coverage passed28 tests,25 wizard and3 picker. These are worker-reported bounded results, not a complete repository gate.

## Historical qualification

Earlier source checks included generated contracts, policy/authorization/lifecycle tests, both API editions, supported Linux builds, node report/gate regressions, and synthetic browser QA for Workspaces, Skills, Setup, profiles and saved keys. Earlier full API qualification disclosed IPsec fixture failures reproduced on its baseline; those records remain failures, not silently green gates. Source-specific validation documents retain the scope and limitations of individual checks.

One historical native Ubuntu 26 AMD64 trial of the ACK source measured29.092 seconds from canonical Create to Ready. One ordinary private SSH command using the user's existing key passed in2.629 seconds with unprivileged UID/GID1001. Original expiry, provider/network/credential/file retirement and owned-role shutdown were confirmed. This is one sample, not a startup benchmark or proof of newly implemented organization admission. No private identity, address, host key or raw receipt is needed to report it.

## Combined local checks

Executable source is integrated through `691d56a`; that checkpoint includes pinned oapi-codegenv2.4.1 metadata and the corrected forward-only main migration fixture. Public image documentation was corrected at `47a44ef`. The publishable tree preserves all 352 product/test/build paths byte-for-byte against that integration checkpoint. Candidate content checkpoint `4c8452e` precedes only the reviewed documentation corrections. Documentation and historical receipts are separately reviewed; source copies do not include private credentials.

| Check | Result and scope |
| --- | --- |
| Generated OpenAPI API/CLI/TS, App Access projection, SQL, RBAC and design tokens | Passed equivalent pinned cached generation on the clean candidate with no drift. Offline generator uses its supported version override to retain the normalv2.4.1 generated header. No generator source or public module files changed. |
| Fresh combined migrations | Both isolated databases reached195, clean. Corrected upgrade fixture starts at published180 and verifies the installation authority row and occupied predecessor data remain unchanged through195. Its earlier downgrade-based fixture failed honestly because App Access authority is forward-only. |
| Full API race suites, both editions | Enterprise completed with 4490 passed test records, 85 skipped, no failures, 83 passed packages and 19 without tests. Open completed with 4470 passed records, 84 skipped and one failure in the old downgrade-based migration fixture; all other packages passed. After its correction, the full affected sandbox package passed 285 records with no failures/skips. The entire open module was not rerun after that focused repair. Both runs used distinct disposable migrated databases. |
| Full Linux API builds | AMD64 and ARM64 compiled in both editions. ARM64 remains compile-only. |
| Linux runtime/lifecycle/runner tests | Unprivileged source run completed with 432 passed records, three skipped and the same old migration-fixture failure. All other tests/packages passed; the corrected migration test then passed on Linux in 1.980s. Two skipped native cgroup fixtures and a root-pinned helper-peer socket fixture remain unrun. Native provider qualification is not enabled. |
| Full CLI race suite | Passed 519 test records, no failures/skips. Focused selected-terminal JSON propagation also passed after the added assertion. Module vet and Linux AMD64 build passed. |
| Shared App Access transport/proxy | Full transport and proxy race suites passed; the contract projection test passed. This preserves the upstream integration boundary. |
| Linux node source tests | Passed1768 records with23 skipped native/tool-dependent checks. The actual unprivileged Unix worker socket fixture passed. Standard CI now requires that fixture as nobody before its privileged nft/full suite. Local NFT/OpenVPN parse checks remain unrun because those tools are absent. |
| Full web suite | Passed167 files/2105 tests; two expected failures. Typecheck and production build passed. |
| Local Chromium UI QA | Passed16 checks at1440×1000 and375×812: owned terminal selection, saved public keys, configurable Skills, Review/back/retry, empty/error states, legacy behavior, scrolling and pinned SSH/local-agent instructions. No uncaught page error or external request. |
| Installer/package/CI fixtures | Passed14 installer,14 package/image and57 CI contract tests. Public generic supervisor fixture suite passed28 tests. No host installation or runtime activation occurred. |
| Actual source artifact bundles | At candidate 4c8452e, both architecture bundles built and verified offline, 19,841,380 bytes AMD64 and 17,964,255 bytes ARM64. Source/ELF/inventory/inner and outer hashes passed; actual AMD64 installer verification and ARM64 activation refusal passed. Any later documentation checkpoint requires fresh bundles whose manifests record that exact source SHA before handoff. Workload images are not built by this lane. |

Skipped API tests require separate App Access/local-stack, PostgreSQL compatibility,
bootstrap/email, native AI binary, subprocess, paid or live fixtures; one skip
deliberately tests an unconfigured database endpoint and one retains a superseded
agent assertion. They are not passes. No opt-in native lab, live account, paid
model or blocked audit work was enabled. These local checks do not claim the
exact remote required CI gates or an all-platform client run have passed.

## Performance and remaining qualification

The initial proposed budgets are essential image≤250MB unpacked, idle≤32MiB and warm click-to-private-SSH p95≤10s on a preloaded host. They remain targets. The historical29.092s Create-to-Ready sample exceeds that latency target before the ordinary SSH connection; it does not establish a percentile. At least30 starts with admission/provider/enrollment/policy/SSH stage timing are still needed before accepting or revising it. No instant-start or measured p95 claim is made. Current runtime caps are128 MiB/1 CPU/64 PIDs per workload,224MiB/256tasks/zero-swap aggregate and at most900 seconds from Create.

A newly selected Linux host still needs native overlay, AppArmor-compatible networking, cgroup freeze/kill/late-child, SSH/SFTP, stop/resume, absolute TTL and confirmed provider/network/file retirement qualification. The signed Ubuntu dependency lock, offline image/archive producer, immutable public descriptor and existing CI artifact input are now supplied. Actual source archive verification measured 68.1 MiB compressed and 186.2 MiB of unpacked layers; this is build evidence, not native qualification. The final layer and launch remain offline; no Alpine substitution or host-protection change supplies that missing proof. ARM64 native activation is refused.

No new live deployment/trial was performed for organization admission or the installer. Capacity remains one shared retained workload slot within the pinned org/gateways/profiles; the current persistent profile admits empty outbound scope. Skills are optional inert instructions and do not add access. Private SSH keys remain local. First-Ready-relative lifetime is unimplemented; original Create-relative absolute expiry and independent execution fencing remain.


## Integrated dashboard enrollment qualification

Candidate `18254cb` integrates the real enrollment API, issuer/client wiring,
controlled trial, atomic ordinary admission and SQL generation through schema 197.
Subsequent `0eb4c15` adds only the final UI withdrawal-response fences. These
checks extend, rather than reinterpret, the historical results above.

| Gate | Current evidence |
| --- | --- |
| Generated API/CLI/TS, proxy contract, RBAC, tokens and SQL | Cached pinned generators completed with no generated drift. SQL generation used sqlc 1.31.1 offline. |
| Server off/draining module boundary | Both editions passed. Off exposes no enrollment/trial service and constructs no worker; draining keeps retirement authority while creation is unavailable. |
| Full Linux API builds | Both editions passed on AMD64 and ARM64. ARM64 remains compile-only. |
| CLI and shared transport | Full CLI race suite passed 519 records with no failures/skips; vet and Linux AMD64 build passed. Shared App Access transport/proxy race suites and contract projection passed. |
| Enrollment and trial races | Real PostgreSQL tests cover current ownership, atomic grant assignment/withdrawal, shared-slot quotas and fail-closed qualification. The actual Python report producer is exercised against the service using synthetic evidence. Final outcomes and the initial full-suite failures are recorded below. |
| Packaging/source contracts | Passed 39 package/image/SCP fixtures,51 installer/profile fixtures,17 Ubuntu producer fixtures,58 CI gate contracts and10 release contracts. All18 public assets align; no native installation or live SCP was executed. |
| Web | Full compatibility suite passed 169 files/2158 tests with two expected failures; typecheck/build passed. Final withdrawal fixes passed 69 affected tests across four files and typecheck. Final Chromium QA passed 39 checks at desktop and narrow widths, with 34 screenshots and no uncaught error, unmocked API or external request. The source manifest records unchanged web hashes and candidate `0eb4c15`. Legacy omitted/false enrollment requirements passed in the 13 Setup tests; Ready-transition dialog retention passed through both browser journeys. |

No native host was enrolled, installed, activated or qualified during these
checks. The source qualification path is implemented and fails closed until
actual observations, canonical lifecycle proof, confirmed retirement and explicit
human review satisfy its current grant. Runner-origin SSH evidence is labeled
accordingly; synthetic fixtures are not independent terminal-side proof.

Capacity remains one shared retained workload with one enrolled image profile,
128 MiB/1 CPU/64 PIDs and the original maximum900 seconds from Create. Workload
launch is offline with prebuilt dependencies. The first supported host is
Ubuntu 26.04 AMD64 with the documented rootless Podman, native overlay, cgroup
and existing gateway prerequisites. Host supervision supplies independent expiry;
workloads run without systemd or DBus. Other hosts/providers and additional
capacity require their own qualification. First-Ready-relative TTL remains
unimplemented. No new instant-start or percentile claim is made.


The initial combined API runs used separate migrated databases but shared one
disposable PostgreSQL server, with both editions running four packages at once.
Open recorded 4396 passes,84 skips and four failed test records; enterprise
recorded 4414 passes,85 skips and four failed records. Each had79 passed packages,
18 packages without tests and five failed packages. Both database and sandbox
packages hit the default ten-minute package timeout, leaving tests unfinished.
Other failures included disposable-database cleanup deadlines, a leadership-lock
precondition and one readiness sequence. These are retained failures, not passes.

A fresh, owned test server and sequential package execution produced full
database-package passes in118.352 seconds(open) and114.538 seconds(enterprise).
The open database/sandbox retake recorded 535 combined passed records and two
database compatibility skips. Its sandbox package completed in 411.642 seconds
with 332 passes and one concrete stale downgrade-fixture failure: its
manual dependency chain ended at195. Correction `175e423` adds the actual 196/197
down files while retaining occupied-state refusal and transaction rollback.
Production migrations and runtime behavior were unchanged by that correction.
The enterprise sequential retake passed all 203 database records and 333 sandbox
records, with the same two database compatibility skips and no failures or
unfinished tests. Its database/sandbox durations were 114.538/405.004 seconds.
The corrected downgrade case separately passed in both editions at `175e423`,
retaining both the occupied-state refusal and empty-state rolled-back proof.
All four initially failed completed-case tests passed in each edition in their
sequential retakes, including the private readiness sequence and leadership
precondition. No further product edits were needed for those cases. These
results complete affected verification; they do not turn the original failed
concurrent full runs into passing runs.

Final enterprise race retakes passed both initially failed qualification cases:
canonical lifecycle 61.750 seconds and bounded admission 2.510 seconds, package
66.171 seconds, with no failures/skips. The affected open race selection passed
87.732 seconds; the full runner transport race package passed in both editions
(3.763/4.463 seconds). Linux AMD64 test-binary compilation passed. These use
synthetic provider/network/SSH fixtures and do not constitute native proof.

The original 84/85 API skips include separate opt-in stack/AppAccess/browser
fixtures, native AI tool paths, database compatibility, paid/live fixtures and
CLI subprocess prerequisites. No additional opt-in, live account, paid model or
blocked audit was enabled. Native physical host qualification, performance
benchmarking and live SCP remain unrun. Exact-source artifact verification and
required remote CI results accompany the final handoff rather than being
inferred from local source tests.
