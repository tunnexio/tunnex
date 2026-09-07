# AI-0 first qualification slice — 2026-09-07

Status: initial evidence below is historical. The continuation addendum records
completed fixes and stronger native/enrolled proof. No release or cloud change.

## Provenance

- Tunnex branch `ai-improvement`, rebased onto main
  `5199b62d15c5498bc8ede58703b9d5af5aa45c23`; decision paper `70741779`.
- Bifrost source tag `transports/v2.0.0` resolves through annotated tag
  `9537b2fadf42af90eb34ed47d3d4252e1beff4a0` to commit
  `e4a30d6041c0446603aea615bc5da340dac001b1`.
- Official darwin/arm64 binary SHA-256
  `31ac451d83706069e580dd1dedf099aa518d1bc47c3c481d20f97203f799275e`.
  `go version -m` reports that exact source commit and `vcs.modified=false`.
- Source root license is Apache-2.0. This does not qualify enterprise features
  or every transitive license. Tested admin/governance APIs run in this OSS binary.

## Executed evidence

| Boundary | Observed result | Limit |
| --- | --- | --- |
| Adapter rejection | Missing identity, cross-fixture tenant, denied model, admin path, query injection, duplicate model, invalid JSON, oversized body and provider override refused with zero instrumented arrivals | Synthetic authorization resolver |
| Trusted context | Caller identity/internal/provider credential headers removed; scoped server-side virtual key injected; upstream cookies/internal key headers not returned | Narrow experimental payload/header allowlist |
| Transport | Fixture flush flag and request cancellation tests pass; upstream redirect not followed; expired/invalid grants refused | Review found no incremental-delivery proof and incomplete end-to-end timeout; see findings |
| Native Bifrost policy | Missing/invalid virtual key and disallowed model returned errors with zero provider inference arrivals | Exact policy error contract not yet asserted; unrelated server errors could pass |
| Native compatibility | HTTP 200 with expected text on both requested streaming paths against an instrumented provider | Missing terminal-event validation; Anthropic route maps to Responses API |
| Native admin/revocation | Unauthenticated admin GET refuses; after authenticated virtual-key disable, new requests error before and after process restart using the same private SQLite store | Missing active-key control/readback means persisted revocation is not yet conclusively proven |
| Real OpenRouter | Two HTTP 200 responses to streaming requests through adapter → Bifrost → OpenRouter; expected tiny response received, no credential detected in response | Synthetic identity; terminal/incremental streaming assertions incomplete |

OpenRouter model: `openai/gpt-4o-mini`, checked against its live model catalog.
Each request requested at most 16 output tokens, with a fixed tiny smoke prompt.
User explicitly supplied a burner key and authorized its use. The key and raw
responses are excluded from this evidence. No exact billing claim is made.

The complete zero-spend suite passed with the race detector before the later
revocation extension. The native test including restart passed separately.
The paid smoke passed once; repeat execution is not a normal regression gate.
Final local validation and review status are recorded in the handoff below.

## Source findings and acceptance gaps

- `plugins/governance/tracker.go` updates usage from provider results, including
  streaming/terminal settlements. A strict pre-reserved monetary cap has not
  been proven. Qualification must measure concurrent overshoot and restart
  accounting before publishing budget semantics.
- Existing `agentruntime.Service.Authenticate` is a reusable enrollment/credential
  lifecycle boundary. It is not AI audience/model authorization. The harness
  does not silently reinterpret it as an AI grant.
- Native restart refusal was observed but needs the controls below. Accounting persistence,
  team/tenant usage attribution, secret rotation, aliases/fallback bypasses and
  active-stream behavior remain unqualified.
- Added CI workflow runs only deterministic adapter tests without provider
  credentials. It has not run remotely. Full required repository gates and
  exact-head CI remain prerequisites to merge.

## Independent review — ranked and held

Two independent reviewers completed the adapter and native/paid harness scopes.
The overlapping streaming findings are combined below. User disposition on
2026-09-07: continue through the entire epic without routine stops. All four
recommended fixes are ACCEPTED for implementation and re-review.

1. **P2 — End-to-end lifetime not bounded.** Inbound body reads precede the
   timeout context; downstream writes have no deadlines. Recommendation: enforce
   read/write deadlines on the serving connection and test slow upload/download
   over real sockets. Moving context creation alone is insufficient.
2. **P2 — Streaming acceptance too weak.** HTTP 200, expected text and recorder
   flush flag accept buffered JSON or truncated SSE. Recommendation: assert SSE
   content type, expected delta/terminal events, absence of protocol errors and
   receipt of first event before the fixture releases completion.
3. **P2 — Restart denial lacks a control.** Losing all configuration could pass.
   Recommendation: preserve an independent active key, require it to succeed
   after restart, and read back the revoked key with `is_active=false`.
4. **P2 — Denial accepts unrelated failures.** Any HTTP status >=400 passes.
   Recommendation: require the pinned authentication/model/inactive-key error
   contract alongside the zero-provider-arrival assertion.

These findings block qualification claims, not the observed fact that two live
provider requests returned HTTP 200 with the expected text. No paid repeat is
needed to develop the stronger deterministic assertions.

## Handoff

Implementation/evidence content tip: `5509c6ab`; decision paper: `70741779`.
Final local validation: complete current zero-spend suite with pinned native
binary passed under `go test -race -count=1 ./...` (9.355s); `go vet ./...` passed.
Paid smoke skipped in that final run; its earlier two-request run passed once.
Known proof gaps remain open despite these green test results. Full repository
gates and remote CI were not run; no push, PR, merge or release performed.

Next action: obtain disposition of the four held findings (recommend accepting
all fixes), implement their regression proofs, and re-review the changed scope.
Then wire the minimal qualification adapter to a real enrolled Tunnex agent
identity in an isolated CP fixture and complete accounting/engine-fit qualification.
Do not restart engine comparison or treat this partial result as AI-0 acceptance.

## Continuation evidence — 2026-09-07

The four original findings were accepted for fixes under the user's instruction
to continue the epic. All four fixes are implemented: real connection read/write
deadlines; incremental SSE delivery with delta/finish/terminal validation and
truncation refusal; persisted inactive-key readback with an independent active
control after restart; exact pinned denial contracts plus zero provider arrivals.
Short authorization expiry and blocked downstream cancellation have focused
real-socket regression coverage. These supersede the initial acceptance gaps,
not the record of what the earlier run proved.

The qualification transport now lives in `apps/api/internal/aigateway`; production
HTTP integration reuses it. No second proxy or provider SDK implementation was
introduced.

- Relocated transport/native/accounting race suite passed in 29.291 seconds.
- Real CP bootstrap enrollment and current runtime authentication were exercised
  against isolated PostgreSQL, including revoke-before-dispatch.
- An authorized enrolled-agent OpenRouter walk passed both streaming protocols
  in 5.14 seconds (package 5.833 seconds), with at most 16 output tokens each.
  These are two additional calls after the initial two-call smoke. No provider
  credential or raw prompt/response is included in committed evidence.
- Community bootstrap/current-auth proof passed while paid managed-runtime access
  remained unavailable. AI-1 adds independent default-off policy and scoped TTL.
- Native accounting qualification is recorded in
  [AI-0-budget-qualification.md](AI-0-budget-qualification.md): concurrent
  overshoot, exact post-charge refusal, per-key metadata and graceful restart.
- User approved honest **soft usage thresholds**. Unknown prices must refuse
  monetary-policy admission. This is not a hard cap or an exact invoice.
- Native admin client create/update/persistent-and-memory readback/disable passed
  against the pinned binary. Updates preserve native key/config identity.

Bifrost remains the selected engine. Production policy/team reconciliation,
complete customer walkthrough, final repository gates and exact-head remote CI
are still separate acceptance requirements. No push, PR, merge or release.
