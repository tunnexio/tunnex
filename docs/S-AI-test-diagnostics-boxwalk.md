# Test Connect diagnostics — local verification, 2026-09-08

Decision record: [S-AI-test-diagnostics-decisions.md](S-AI-test-diagnostics-decisions.md).
Paper commit: `e48fb066`. Branch: `ai-improvement`. No push, PR or merge.

## Result

Draft and saved-credential tests return a bounded diagnostic containing the
failure category, its source, and an HTTP status only when that source actually
responded. The form and Sonner toast use the same explanation. A successful test
still enables saving; failed, changed and expired tests do not.

The approved review fold covers outer gateway timeouts, interrupted/invalid
responses, and guidance specific to gateway failures. Provider HTTP rejections
remain authoritative even if their body is truncated. Successful calls omit the
failure object. Unknown or malformed metadata is discarded, never rendered raw.

## Browser and local wire

Preview: `http://127.0.0.1:5180/agents/ai-gateway`.
Project `tunnexaiwalk0907repro4`, network `tunnexaiwalk0907repro4_engine`;
container labels/network verified before all database-capable operations.

Using a separate browser tab and synthetic fixture credentials:

| Check | Observed result |
| --- | --- |
| Draft key through a refusing local CONNECT proxy | `Network proxy HTTP 403` in toast and form; saving disabled |
| Draft with an invalid synthetic key, after fixture routing recovery | `Provider HTTP 401` in toast and form; authentication guidance; saving disabled |
| Saved `Private proxy demo (fixture)`, new `private-demo-new`, chat | Test succeeded; Add Model enabled; key and endpoint inputs absent |
| Same saved credential/new model, embedding against the chat-only fixture | `Provider HTTP 404` in toast and form; endpoint/deployment guidance; saving disabled |
| Bridge unavailable while restoring the preview | `Tunnex HTTP 503` with gateway/bridge guidance |

Evidence is in [walk-artifacts/ai-test-diagnostics-20260908](../walk-artifacts/ai-test-diagnostics-20260908).
DOM captures include the actual notification region, successful test status and
button state. Screenshots captured during toast entry animation accompany them.
No models or credentials were saved or deleted. The synthetic draft was cleared.
Existing user tabs and actual Azure credentials were not inspected or submitted.

## Runtime update and recovery

Only the user-approved `tunnex-sso-review` Docker VM was restarted after disk-full
I/O errors. macOS was not restarted. Twelve local application containers were
restored. Manual preview API, bridge, fixture and relay processes were restored.
The restart changed the fixture IP; its existing bridge host mapping and exact
`/32` proxy destination were updated to that same local fixture. No Azure route,
firewall, public endpoint policy or credential changed. These manual preview
helpers/mappings require restoration after a future VM/container restart.

The updated API and private engine are running locally. Before replacing the
engine, its binary and stopped data were backed up privately. Provider-row
fingerprints were identical before/after the update and fixture recovery;
schema version 150 remained clean. The UI still reports five models and four
credentials. Application database/config/log volumes were retained.

| Artifact | SHA-256 |
| --- | --- |
| Local API | `a8a37a70f81d4f86117ffaa8b98fa4eaf9a30136fa3f5d4a7ad4b485dee89a86` |
| Local Linux ARM64 engine | `3beb0abf997c8c5061ce4d047758db384dedd966e9cd9ab18ce1f2969b2ff54d` |

Engine source remains pinned to Bifrost
`9537b2fadf42af90eb34ed47d3d4252e1beff4a0` plus the existing private extension.
The build used one CPU and readonly modules. Resource-limited attempts failed
before completion; the final compile disabled C debug symbols and the cached
link completed within a 704 MiB container limit. Four task-owned stopped compiler
containers, their compiler image and generated VM scratch files were removed.
Final free space: VM root 5.5 GB, Docker data 2.4 GB, host 16 GiB. Runtime engine
health and all twelve restored application containers were verified afterward.

## Checks and limits

- Full Python bridge suite: **145 passed**, including actual SDK calls through
  a CONNECT fixture and native private-engine probes. Covers provider
  401/403/404/429/503, proxy 403/502, socket failure, deadlines, truncated bodies,
  malformed JSON, unsupported encoding, invalid completions, metadata rejection
  and secret-marker exclusion.
- API focused diagnostics: both boundaries preserve/sanitize errors and strip
  success metadata; real delayed headers and partial bodies exercise timeouts.
- Full enterprise API suite: passed serially. Full open API run passed except
  two timing/session tests in `leader` and `nodes`; both packages passed on a
  serial rerun. The initial full run is not described as green.
- Full web suite: **1,460 passed across 121 files**; focused provider workspace
  suite **76 passed**; TypeScript and production build passed. Existing bundle
  size advisory remains.
- Full CLI suite passed with the generated API types.
- All seven pinned generators ran twice: **50 generated files, zero second-pass
  drift**. No migration or dependency change. `git diff --check` passed.
- Independent catalog/control-plane and protocol reviews completed. The three
  findings were approved before folding; final protocol review found no
  actionable regressions in the response-state simplification.

This is local fixture wire evidence, not proof of connectivity to the user's
private Foundry deployment. Actual Azure reachability and the user's visual
acceptance remain to be checked by their next Test Connect. A 403 does not prove
that a private route is absent. Node/helper/client platform gates and remote CI
were not run for this diagnostic slice; full composite gates are not claimed.
