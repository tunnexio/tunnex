# Sandbox PR validation

This summary preserves source and qualification evidence without publishing operator-specific configuration or raw walk receipts. Original story branches and evidence remain unchanged. Historical checks do not establish that the final integrated PR head passed.

## Source checkpoints

Completed foundation, UI, Skills, image/provider, persistence/cleanup, saved-key and bounded delegation work was integrated with the remote runner, retained supervisor and prompt policy-report ACK fix. Supervisor integration is 2827c3a; upstream-main/schema integration is 162348a; optional module integration is 0b6cd41. Organization admission and immutable terminal selection were implemented at f30c378 under decisions57c1655. The coverage ledger records earlier source mappings. The optional-module commit introduced no migration.

## Reported narrow results for f30c378

The focused API admission/identity race selection passed13 top-level tests in each edition: open24.227s and enterprise20.919s, using fresh disposable PostgreSQL fixtures. The policy lane passed23 test records per edition with no skips/failures; eligibility/cleanup passed12 per edition with no skips/failures. These selections can overlap and are not added into an aggregate. Final Ready CAS/binding-authority races and an existing resume selection passed in open; no further both-edition result is inferred. Creation wizard/terminal-picker coverage passed28 tests,25 wizard and3 picker. These are worker-reported bounded results, not a complete repository gate.

## Historical qualification

Earlier source checks included generated contracts, policy/authorization/lifecycle tests, both API editions, supported Linux builds, node report/gate regressions, and synthetic browser QA for Workspaces, Skills, Setup, profiles and saved keys. Earlier full API qualification disclosed IPsec fixture failures reproduced on its baseline; those records remain failures, not silently green gates. Source-specific validation documents retain the scope and limitations of individual checks.

One historical native Ubuntu26 AMD64 trial of the ACK source measured29.092 seconds from canonical Create to Ready. One ordinary private SSH command using the user's existing key passed in2.629 seconds with unprivileged UID/GID1001. Original expiry, provider/network/credential/file retirement and owned-role shutdown were confirmed. This is one sample, not a startup benchmark or proof of newly implemented organization admission. No private identity, address, host key or raw receipt is needed to report it.

## Combined local checks

Product source is integrated through `691d56a`; that checkpoint includes pinned oapi-codegenv2.4.1 metadata and the corrected forward-only main migration fixture. The publishable tree preserves all352 product/test/build paths byte-for-byte. Documentation and historical receipts are separately reviewed; source copies do not include private credentials.

| Check | Result and scope |
| --- | --- |
| Generated OpenAPI API/CLI/TS, App Access projection, SQL, RBAC and design tokens | Passed equivalent pinned cached generation with no semantic drift. Offline generator uses its supported version override to retain the normalv2.4.1 generated header. No generator source or public module files changed. |
| Fresh combined migrations | Both isolated databases reached195, clean. Corrected upgrade fixture starts at published180 and verifies the installation authority row and occupied predecessor data remain unchanged through195. Its earlier downgrade-based fixture failed honestly because App Access authority is forward-only. |
| Full API race suites, both editions | Running on distinct disposable migrated databases. Final results must be recorded after completion; no complete pass is inferred from package progress. |
| Full Linux API builds | AMD64 and ARM64 compiled in both editions. ARM64 remains compile-only. |
| Linux runtime/lifecycle/runner tests | Running as an unprivileged user; native cgroup/provider qualification is not enabled. Corrected migration test is validated separately. |
| Full CLI race suite | Passed519 test records, no failures/skips. Focused selected-terminal JSON propagation also passed after the added assertion. Linux AMD64 module build passed. |
| Linux node source tests | Passed1768 records with23 skipped native/tool-dependent checks. The actual unprivileged Unix worker socket fixture passed. Standard CI now requires that fixture as nobody before its privileged nft/full suite. Local NFT/OpenVPN parse checks remain unrun because those tools are absent. |
| Full web suite | Passed167 files/2105 tests; two expected failures. Typecheck and production build passed. |
| Local Chromium UI QA | Passed16 checks at1440×1000 and375×812: owned terminal selection, saved public keys, configurable Skills, Review/back/retry, empty/error states, legacy behavior, scrolling and pinned SSH/local-agent instructions. No uncaught page error or external request. |
| Installer/package/CI fixtures | Passed14 installer,14 package/image and57 CI contract tests. Public generic supervisor fixture suite passed28 tests. No host installation or runtime activation occurred. |
| Actual source artifact bundles | Atc3fd55e, both architecture bundles built and verified offline; actual AMD64 installer verification passed, ARM64 activation refusal passed. Final publication-SHA bundles are a separate required provenance check. Workload images are not built by this lane. |

## Performance and remaining qualification

The initial proposed budgets are essential image≤250MB unpacked, idle≤32MiB and warm click-to-private-SSH p95≤10s on a preloaded host. They remain targets. The historical29.092s Create-to-Ready sample exceeds that latency target before the ordinary SSH connection; it does not establish a percentile. At least30 starts with admission/provider/enrollment/policy/SSH stage timing are still needed before accepting or revising it. No instant-start or measured p95 claim is made. Current runtime caps are128MiB/1CPU/64PIDs per workload,224MiB/256tasks/zero-swap aggregate and at most900seconds from Create.

A newly selected Linux host still needs native overlay, AppArmor-compatible networking, cgroup freeze/kill/late-child, SSH/SFTP, stop/resume, absolute TTL and confirmed provider/network/file retirement qualification. The approved immutable dependency-preloaded Ubuntu base/archive, reproducible producer/package lock and CI input are not yet supplied. The final layer and launch remain offline; no Alpine substitution or host-protection change supplies that missing proof. ARM64 native activation is refused.

No new live deployment/trial was performed for organization admission or the installer. Capacity remains one shared retained workload slot within the pinned org/gateways/profiles; the current persistent profile admits empty outbound scope. Skills are optional inert instructions and do not add access. Private SSH keys remain local. First-Ready-relative lifetime is unimplemented; original Create-relative absolute expiry and independent execution fencing remain.
