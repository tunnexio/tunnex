# Provider onboarding validation — 2026-09-07

## Scope and provenance

Branch `ai-improvement`; baseline main `26a36afc9be657af94127c474e173783c91318c3`.
Decision paper `8e5af9e7`; generated OpenAPI contract `283c40c7`.
Provider engine is the already qualified Bifrost transports/v2.0.0 pin. No engine
replacement, provider secret in CP persistence, provider inference spend, push,
merge, release or external infrastructure operation occurred in this slice.

Implemented: authenticated Community provider connections, write-only OpenRouter
key setup/rotation, bounded model catalog, no-inference credential checks,
transactional revision/state and same-org ownership, explicit legacy ACL migration,
central disable and referenced-delete refusal, safe deletion recovery, provider
and team UI, and opt-in database-owned Compose/Helm configuration.

## Checks and their limits

- Full web: **117 files / 1,335 tests PASS**; TypeScript and production build PASS.
  Focused provider/policy/workspace selection set: 33 tests PASS.
- API open and enterprise builds PASS.
- Focused provider/policy PostgreSQL suites in both editions: **PASS**, sequential
  `-p 1 -race`; open 7.892s, enterprise 7.383s. Covers ownership/unknown keys,
  cross-org refusal, legacy snapshot and reserved-prefix collision, union models,
  concurrent CAS, disable at issuance/inference, pending/error eligibility,
  missing-native deletion and lost-delete recovery.
- HTTP owner/member/foreign/anonymous authorization-before-validation regression:
  observed red (member/foreign returned 400), then green with canonical permission
  checks before validation. Safe provider validation messages and human-only
  handler checks pass under race testing.
- Pinned native provider adapter tests PASS `-race` (6.666s): fresh provider
  initialization and retry, single-key CRUD, literal secret rotation, masked
  metadata edits, credential refusal despite HTTP 200, cached catalog projection,
  disabled-only deletion and absent-key retry, legacy and scoped virtual-key
  preservation, encrypted native storage, provider-stanza removal across restart.
  Synthetic auth fixtures; **zero inference requests**.
- CLI suite PASS after OpenAPI regeneration.
- Code generation: both full passes completed; **second-pass drift zero**, including
  SQL model and RBAC regeneration. No hand-edited generated contracts.
- Static Compose and Helm render/lint checks PASS in legacy and managed modes:
  private engine, matching state volumes, durable encryption reference, provider
  config stanza absent only in explicit managed mode, optional legacy env key.
- Full open API suite: **INCONCLUSIVE / infrastructure blocked**, not green.
  Docker `/dev/vdb1` was 7.8 GiB, 100% bytes (49% inodes), with PostgreSQL
  SQLSTATE 53100 and recovery/connection failures. The broad run's failures are
  not accepted product assertions or proof of correctness. Full both-edition gates
  must be rerun after capacity recovery; exact-head remote CI is not run.

## Capacity and preservation

The full run exhausted the 8 GiB `colima-tunnex-sso-review` VM. It temporarily
stopped the separate preview PostgreSQL service. No shared SSO project, cloud
resource or existing database was deleted or repaired. Two inactive preview API
builds were moved to private host backups with exact SHA256 verification before
removing their duplicate container files, recovering about 93 MB. Cleanup of
exactly three disposable `tnx_test_*` databases was then resumed from this run's
explicit failed-cleanup ownership log. No wildcard database/volume cleanup.
Preview database ledger was verified `140|false`, then normal migration 0141 ran
on API startup after database readiness. Focused sequential tests recovered to
196260 KiB free; this is not sufficient justification for another broad run.

The original build backups remain owner-only under
`/private/tmp/tunnex-ai-ui-wcb0_v5d/retained-preview-binaries`.
Any VM resize requires a separate approval because it restarts the same local VM
hosting `tunnexssoreview0906` PostgreSQL/Redis/Keycloak as well as this preview.
No resize or unrelated-container restart was performed.

## Actual local browser walk

Preview: `http://127.0.0.1:5180/agents/ai-gateway`.
Project `tunnexaiwalk0907repro4`, network `tunnexaiwalk0907repro4_engine`;
container labels/network were verified before every state-affecting command.
Native admin is private; the provider base URL remains the synthetic fixture.
The running Linux arm64 API binary SHA256 is
`8f79f95af594fae93cf9c8b9124754f97854af7a53176abad5cc999dfa430523`.

1. Existing `openrouter-primary` reference survived migration and the switch from
   file-owned to database-owned native providers. Original private engine config
   was backed up inside its existing volume; encryption and volumes retained.
2. In the actual browser, added **Engineering demo (fixture)** with a synthetic
   write-only key and selected `openrouter/openai/gpt-4o-mini` from live cached
   model suggestions. Connection became applied at revision 1.
3. Credential test returned success against the synthetic local provider. This
   preview fixture is not a real-provider entitlement or invalid-key proof; the
   independent native test above verifies real refusal handling with a strict fixture.
4. Selected the named connection in `installed-team` and saved policy revision 3.
   Deleting the referenced connection was refused with actionable guidance. Then
   restored the team's original key selection (policy revision 4), preserving its
   exact model and `0.000000000001` threshold.
5. Disabled/re-enabled the unassigned connection (revisions 2/3), then rotated its
   synthetic key (revision 4). The password field was empty on edit, cleared on
   save; the previous credential-check result reset to untested on rotation.
6. Restarted only the preview engine with the same volumes. The rotated connection
   remained applied, and its credential test succeeded afterward. Existing legacy
   reference remained visible. No real provider key was used for this walk.
7. Browser width 857 px equalled document width: no page horizontal overflow.
   Screenshots record actual rendered provider table and team picker. They are
   visual evidence, not user visual approval or native mobile qualification.

Screenshots: `walk-artifacts/ai-gateway-20260907/providers-local.png` and
`walk-artifacts/ai-gateway-20260907/provider-team-local.png`.
The local preview is intentionally left RUNNING for user review.

## Review dispositions

Two independent bounded reviewers covered CP/security and native/deployment.
Known P1 model-union defect was accepted for correction: removal checks now
intersect only removed models with referencing team policies. Metadata edits,
rotation and disable no longer incorrectly require one key to cover the team's
whole union. The corrected code re-earned independent review with no new finding.

A second recovery edge was corrected before final review: after a native delete
succeeds but CP acknowledgement is lost, confirmed native absence completes the
ownership tombstone without recreating the key. HTTP prevalidation permission
ordering was fixed with a red-to-green regression. No unresolved actionable
finding remains from these bounded reviews; this is not a full-epic security audit.

## Next action

Obtain approval to expand the local Docker VM from 8 to 16 GiB (preserve all
volumes, brief restart of its existing local services), then rerun required full
API gates in both editions. After visual approval, obtain push/PR authorization
and require exact-head CI before any separately approved merge/release.
NetBird-wide parity is not claimed; the verified gap register remains in the
provider onboarding decision paper (direct providers, request investigation,
broader policy limits and separate production NAT lifecycle work).
