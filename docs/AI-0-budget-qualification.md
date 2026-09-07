# AI-0 native accounting qualification

Date: 2026-09-07. This records a single-process native-engine qualification,
not a production financial cap or complete AI-3 acceptance.

## Candidate and isolation

Bifrost `transports/v2.0.0`, source
`e4a30d6041c0446603aea615bc5da340dac001b1`, standalone darwin/arm64 artifact
SHA-256 `31ac451d83706069e580dd1dedf099aa518d1bc47c3c481d20f97203f799275e`.
The test verifies this digest before executing the engine.

`TestBifrostBudgetQualification` uses a loopback instrumented OpenRouter-compatible
provider, five synthetic virtual keys and a fresh temporary SQLite config store.
It reads no real provider key and incurs no provider spend. The engine receives
only PATH and explicitly supplied test environment. Prompt/response logging is
disabled. Dedicated local pricing and model-parameter files avoid relying on a
changing public price catalog for the accounting assertions.

## Measured result

The final native race-enabled run passed in 22.06 seconds (24.336 seconds
including race-test process overhead). Rates were deliberately
synthetic: 1 unit per input/output token. A completion reports 4 input and 1
output token, hence 5 cost units. Each scoped virtual key has a 1-unit daily
threshold. These figures are test values, not OpenRouter prices or bills.

| Case | Observed native behavior |
| --- | --- |
| Concurrent priced completions | A provider barrier proves both requests were admitted before either completed. Both returned success. Native cost became 10 despite a 1-unit threshold. |
| New request after charge | Exact HTTP 402 budget refusal; instrumented provider arrival count unchanged. |
| Streaming completion with final usage | Successful SSE response charged 5 once. |
| Separate idle identity | Cost remained zero; no attribution to the unrelated virtual key. |
| Unknown model price | Two successful requests with reported tokens reached the provider; cost remained zero despite a configured monetary budget. |
| Provider rejection | HTTP 400 propagated, exactly one provider arrival with `max_retries: 0`, and no reported usage/cost charged. |
| Persisted request/token attribution | After restart: concurrent key 2 requests / 10 tokens; streamed key 1 / 5; unpriced key 2 / 10; idle and provider-error keys 0 / 0. Native request counters count successes, not every attempted request. |
| Restart | Graceful stop/restart retained 10 and 5 charged units and zero-cost identities in the same temporary SQLite store. Exhausted key still refused before provider arrival; a separate healthy key succeeded, ruling out general engine failure as the reason for denial. |

The admin virtual-key read is a persisted snapshot. An initial 8-second polling
bound was insufficient; the pinned tracker flushes on a 10-second cadence. The
qualification polls for the exact counter value for at most 15 seconds. This
is observed eventual persistence, not synchronous durable admission accounting.

## Source-supported limits and required product contract

At the pinned commit:

- `plugins/governance/main.go`, `PostLLMHook` launches asynchronous accounting;
  `postHookWorker` computes cost from response usage and the configured catalog.
- `plugins/governance/tracker.go` updates in-memory counters and uses a 10-second
  worker to dump budgets/rate limits. Native request counters count successful
  requests; failed requests without reported usage are skipped.
- Terminal accounting deduplicates request ID plus attempt number within the
  process. The deduplication map is process-local with a five-minute TTL. This
  does not establish durable caller-retry idempotency.
- Partial error/cancellation usage is charged when the provider adapter supplies
  `BilledUsage`; no usage report cannot be reconstructed as a real provider bill.
- `framework/modelcatalog/datasheet/cost.go` returns zero when cost cannot be
  resolved. Monetary limits alone therefore do not fail closed for an unpriced
  model; the test demonstrates this behavior directly.

Recommended production contract: retain Bifrost for execution and its native
usage ledger; expose **soft usage thresholds**, never a strict spending cap.
Require explicit verified pricing for every exact allowed model before enabling
a monetary policy. Otherwise report the model as **uncosted** and reject a
configuration claiming cost enforcement. Price/routing changes must revalidate
that condition. Restrict concurrency and requested output at the Tunnex boundary,
but do not describe these bounds as a prepaid reservation or exact maximum bill.

No second ledger or Bifrost fork is proposed. This is an engine-fit limitation to
carry into the shared decision paper, not permission to quietly claim stricter
semantics or switch engines.

## Still unproven

This fixture does not prove forced-crash persistence, multiple engine instances,
team/customer hierarchy rollups, retry-after-partial-usage behavior, cancellation
billing across each real provider, pricing-source failures after startup, or the
upper bound of token/cost overshoot under real model limits. The one measured
concurrency example is a counterexample to strict caps, not a universal overshoot
bound. Provider rejection with retries disabled does not qualify retry dedup.

Those conditions require focused AI-3 tests before their corresponding claims.
AI-0/AI-3 may not be declared fully accepted from this fixture alone.
