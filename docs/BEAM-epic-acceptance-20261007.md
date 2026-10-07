# Beam epic acceptance — 2026-10-07

## Result and scope

**11/11 stories are implemented. All checks runnable in this Mac/local/AWS environment passed. Full epic release acceptance remains open for the physical platform, Beam-specific login handoff, browser and deployment exercises listed below.** Test results do not imply that every manual acceptance criterion is closed.

Core: `/private/tmp/tunnex-beam-plan`, branch `extra-feature`, baseline `7ed12a91a2c4d4f9f0e7f30a3e6ae19eb5e219aa`. Desktop: `/private/tmp/tunnex-client-beam`, branch `extra-feature`. These include uncommitted feature sources: baseline HEAD alone does not identify the tested build. The snapshot is recorded in `/private/tmp/beam-epic-acceptance-20261007/source-manifest.json`. All recorded source file hashes remained unchanged during acceptance, before this documentation update.

Validation-only work: no product edits, commit, push, release, AWS deployment, CP restart, host-clock change or production rollback. The primary `/Users/pawangupta/tunnex` checkout on `fix/web-publish-native-build` remains clean and untouched. Historical evidence in [local qualification](BEAM-local-qualification.md) remains separately dated.

## Automated gates

| Gate | Result | Qualification boundary |
| --- | --- | --- |
| Complete console verify | 191 files; **2,378 passing tests**, plus 2 existing expected-failure cases; contract freshness, typecheck and production build passed | The expected failures are not counted as passing tests |
| Complete desktop renderer suite | 86 files; **1,147 passing tests**, plus 2 declared expected-failure cases | Renderer/main typechecks and builds, and **355 passing native desktop tests**, reused from the immediately preceding unchanged-source qualification |
| API Beam/readiness/HTTP/config, real PostgreSQL, race detector | Open: **162 passing test events** including subtests; enterprise: **130**, zero failures/skips | Affected packages and Beam/route test selection; not a claim that the entire API repository suite ran |
| Persistent CP → proxy → native connector authority | **All 31 distinct cases passed together in one complete run** | Real persistent authority and protocol streams; no physical laptop sleep or live infrastructure outage induced |
| Proxy, shared transport and CLI | Complete `go test -race -count=1 ./...` suites passed in each module | Go 1.26.8; readonly modules |
| Static checks | `go vet` passed for CLI, proxy, transport and affected API packages | Same affected scope as above |
| Optional Beam Compose | **6 security/rendering checks passed** | Confinement, defaults, ports, image rules and secret redaction |
| Additional native transport integrations | **6 tests passed without skips** | HTTP/SSE/WS; authority loss; strict HTTPS; frame/message/fragment bounds; actual Vite; backpressure |
| Exact-source unsigned packages | macOS ARM64 and Windows x64 directory builds verified | Content/cross-compilation proof; not signed release, installer or native Windows execution |

The 31 persistent cases cover stop, pause, expiry, grant removal, reviewer logout/membership/group/parent expiry/auth epoch, publisher group/credential/status/role/credential expiry, policy disable/MFA, fresh connector generation, restore barrier/supported restore, CP authority outage, installation disable/domain change, failed/expired readiness, session store outage, proxy restart, organization deletion, MFA freshness/future proof and authority clock skew in both directions. Clock cases vary the returned lease boundary; the host clock is unchanged.

Extra native transport measurements: Vite update 22 ms, HMR/SSE withdrawal 1,894 ms; slow-reader origin plateau 3,997,696 bytes, external-memory delta 7,699,125 bytes, withdrawal 1,546 ms, concurrent serving preserved. These are local fixture measurements, not production performance guarantees.

Local parent PostgreSQL schema, organization count, policies and stable operator settings were preserved. Normal CP readiness refresh changed only `readiness_checked_at`, `readiness_expires_at` and `updated_at`; full byte-for-byte row equality is not claimed. Disposable `tnx_test_%` databases remaining: **0**.

Each unsigned package contained the exact current **62 compiled JavaScript modules and 19 renderer resources**, including the notification inbox. Dashboard artifacts and development fixtures were excluded. Windows helper PE architecture and vendored Wintun digest were checked. Both `app.asar` SHA-256 digests: `926e1b5b1cd5c7aef788a4ccbf15d45857c4406cd89eeaf113abe01efb8d7086`.

## Live AWS and browser checks

Target: existing CP `16.170.207.192`, console `https://tunnex.app`. CP API, Beam proxy, gateway, PostgreSQL and Redis were healthy; web/nginx were running. Read-only inspection did not alter infrastructure. Standard TLS hostname validation succeeded for a newly generated `p-…tunnex.app` hostname; no certificate verification was disabled.

Actual Publisher member UI generated a command from named user/group selections with the server login command and automatic organization/reviewer identifiers. This was a draft only; the named Consumer/QA selections did not grant access.

A ten-minute disposable Vite share used the existing Publisher CLI credential and **only the Publisher as explicit reviewer**. No customer content, additional login credential or other user's share was used. The normal browser login/one-use launch/Continue path served the local app. Editing `main.js` changed rendered text from “version one” to “version two” **without browser reload**; captured browser error/warning logs were empty. This closes the previously missing authenticated browser Vite DOM-update proof.

The actual web Pause action withdrew app access. CLI Resume using the same source credential restored the **same share ID, URL and expiry**, and a fresh browser launch reached version two. Ctrl+C then stopped the task-owned share; the CP displayed Stopped and recorded successful pause/resume/stop history, public app access was denied, and Active inventory displayed **0/5 slots and no cards**. The task-owned CLI/Vite processes were stopped. Existing user credentials and the original native publisher process were preserved.

An earlier desktop-published share expired naturally during observation: its card disappeared without a manual refresh and the public URL denied access. Owner history retained actual allowed admission records. A cached admin header was resolved by reload to the actual Publisher identity; Access Events page denial for that member was correct and is not evidence of an admin role walkthrough.

A 390-pixel viewport override did not take effect (observed viewport remained 1,728 pixels) and was reset. **No new mobile/Safari/QR acceptance is claimed.**

## Story-by-story acceptance

| Story | Evidence completed or reused | Remaining acceptance |
| --- | --- | --- |
| BM-0 Feasibility | Previously accepted native desktop → browser journey; current transport suites and package contents confirm feasibility | Formal feasibility accepted; later platform checks belong to BM-10 |
| BM-1 Domain/policy | Readiness probes, migration/default/restricted/open-for-all policy and RBAC tests; actual public DNS/TLS | Live operator policy-impact confirmation, certificate rotation/disable/drain exercise |
| BM-2 Create share | Idempotency, concurrent quotas, named reviewer/expiry UI tests; actual member command draft and self-only CLI publish | Complete multi-user delegated publisher error/retry walkthrough |
| BM-3 Connector | Complete native transport and persistent matrix; exact source credential/generation/target tests | Live account/server/organization switch UI matrix |
| BM-4 Reviewer access | Actual authenticated browser launch and denial; nonce/replay/session/grant/MFA fixtures | Existing SSO provider login was previously tested (user confirmed); provider flow unchanged in the Beam diff. Remaining: Beam-link → SSO → original preview integration smoke, optional Beam MFA policy step-up, separate Consumer/denied reviewer walkthrough, physical mobile fresh-login QR and hostile-content browser isolation matrix |
| BM-5 Apps/HMR | HTTP/SSE/WS/strict HTTPS/bounds/backpressure; **actual authenticated browser HMR DOM update** | Wider supported application/browser compatibility matrix |
| BM-6 Management | Actual CLI publish, web pause, same-credential CLI resume, explicit stop and active-card removal; desktop management evidence reused; current UI suites | Full latest console access confirmation/extend/manage-all cross-user UI matrix |
| BM-7 Continuous authority | **One complete 31-case run**; real AWS expiry/stop denies access and removes cards | Complete live logout/switch UI and longer deployed cleanup observation; no multi-proxy HA qualification claimed |
| BM-8 Recovery/lifetime | Native CP/Redis/proxy/restore fences; prior Mac window/tray/quit evidence | Physical sleep/wake, laptop network outage/app restart, native Windows lifetime and installed compatibility |
| BM-9 Audit/limits | Actual owner allowed history and lifecycle records; quota/capacity/diagnostics/filters/tenant/RBAC tests | Further denied/multi-user browser evidence, multi-tenant load, operator rotation/drain |
| BM-10 Release | Fresh/rollback migration guards, DB preservation, Compose checks, exact-source unsigned packages and source manifest | Native Windows install/runtime, signed release/Intel Mac if supported, actual deployed upgrade/rollback, final customer acceptance |

User follow-up confirmed that existing SSO was already tested. Current diff inspection found no changes to SSO provider/start/callback, shared auth/session/CLI-auth modules, login UI, or desktop session/credential modules. Beam adds its own authenticated launch/session/grant checks and accepts the existing SSO parent session. Generic SSO retesting is not a new completion requirement; a narrow Beam-link → existing SSO → intended preview smoke remains distinct from earlier provider qualification. Optional Beam MFA policy checks likewise concern the new integration. No Windows machine was supplied, so native Windows install/runtime remains unverified; cross-compilation is not runtime evidence. Remaining operational tests need a planned disposable/staging exercise; migrations and restore fixtures do not establish a real AWS upgrade/rollback.

## Evidence files

Private output directory: `/private/tmp/beam-epic-acceptance-20261007`. No credentials were printed or stored in this report. Relevant artifacts:

- `open.jsonl`, `enterprise.jsonl`, `open-summary.json`, `enterprise-summary.json`: real PostgreSQL/race/native results.
- `parent-preserved.json`: stable parent state and normal readiness timestamp differences.
- `package-content.json`, `source-manifest.json`, `public-tls.json`: package/source/TLS evidence.
- `aws-cli-command.png`: member command generator with named reviewers.
- `aws-authenticated-vite-hmr.png`: browser rendered version two after a live file edit.
- `aws-active-expired-removed.png`, `aws-expired-link.png`: natural expiry inventory/denial.
- `aws-clean-active-inventory.png`, `aws-test-stopped-access-denied.png`: explicit test cleanup, no active cards and public denial.

The outputs live outside Git; their paths are local evidence, not published release artifacts. This report supersedes dated test counts and browser HMR gaps in the 2026-10-06 qualification without rewriting historical observations.
