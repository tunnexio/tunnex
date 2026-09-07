# AI usage dashboard local validation

The user requested a usage/cost dashboard using their LiteLLM screenshot as a
reference. The public [LiteLLM usage source](https://github.com/BerriAI/litellm/blob/main/ui/litellm-dashboard/src/components/usage.tsx)
was inspected for its cards, daily spend and ranking arrangement. This is an
independent Tunnex implementation with no added UI dependency or copied source.

## Result

- Usage & cost is the default AI gateway view. Configuration retains organization
  opt-in, team policy, agent assignment, disable and reconciliation controls.
- User's follow-up configuration theme request is also implemented: scoped status
  and policy cards, responsive team/agent layout, compact selectors and explicit
  revision/membership/synchronization presentation. Shared Settings remain intact.
- Cards show estimated spend, requests, input/output token total, provider request
  outcomes and average cost for completely priced traffic. Missing cost is
  explicitly incomplete, and tiny nonzero amounts retain useful precision.
- One authenticated `dashboard=true` request adds UTC daily spend and historical
  team/agent/model rankings. Eight bounded native aggregate reads reuse retained
  key attribution; no secondary accounting database, prompt logs or migration.
- Today, seven-day, thirty-day, custom range, team and agent filters reload data.
  Failed/old/stale responses never become zero-spend or another scope's results.
  Gateway retention and soft-threshold limitations remain visible.
- Review P2s corrected: refreshing page-two agent inventory clears a now-missing
  selection and its editor; historical usage remains available with Agent Groups
  disabled and no policy-inventory dependency. Both have regression coverage.

## Evidence

- Both API editions build. Full API suites passed in both editions (62 tested
  packages each), including the affected HTTP and AI gateway packages.
- Scoped adapter/refusal tests and PostgreSQL historical attribution tests passed,
  including foreign selectors, empty scope without an engine call, malformed
  results, duplicate/foreign IDs, overflows and cancellation.
- Actual pinned Bifrost native race test passed in 13.089s: priced/uncosted/error
  outcomes, independent key isolation, zero-record key, midnight and inclusive
  end boundary, hourly/eight-hour/daily aggregation across 24h/72h/168h/744h.
  Fresh synthetic fixture only; provider content logging disabled; no paid calls.
- Full web suite: 116 files / 1,325 tests passed, typecheck and production build
  passed, rerun after configuration refinement. Focused usage/policy/placeholder
  tests also pass. Generated CLI tests passed with local test-server access.
- OpenAPI generators ran twice with zero second-run drift. The large generated Go
  diff is its embedded compressed OpenAPI schema, plus additive types/parameter.
- Real signed-in local CP dashboard: all teams show 8 requests / 56 tokens /
  $0.000170; team B filter shows 4 requests / 28 tokens / $0.000160. Native model,
  team and agent rankings agree with the fixture's retained usage. Daily chart
  focus displays the same values; configuration remains accessible.
- Actual rendered evidence: [local dashboard](walk-artifacts/ai-gateway-20260907/usage-dashboard-local.png).
  This screenshot is the real authenticated CP UI, using retained local test data.
  Desktop/narrow-panel rendering inspected; native mobile-device proof not claimed.
- Configuration preview: [local configuration](walk-artifacts/ai-gateway-20260907/configuration-local.png).
  DOM inspection verified selected team model/key IDs, applied agent revisions,
  membership and every save/disable/retry control. Both views fit the 857px
  preview viewport without horizontal page overflow.

## Running local preview

- UI: `http://127.0.0.1:5180/agents/ai-gateway`, normal demo-owner login.
- API loopback proxy: `127.0.0.1:5181`; engine/admin endpoints remain private.
- Docker context `colima-tunnex-sso-review`, project `tunnexaiwalk0907repro4`,
  network `tunnexaiwalk0907repro4_engine`. Exact project labels/network verified
  before replacing only the preview API process. Original API binary retained.
- Running API binary SHA-256:
  `723438eaee2cad06a4f8e49741b7731adbdb98bb00a9ffd0346fea5edde1397d`.
- CP, database, engine, fixture and UI intentionally remain running for user review.
  Local login credentials remain outside Git in a protected temporary file.

User visual approval and exact-head remote CI remain pending. No push, merge,
release, external infrastructure action or provider spending was performed.

## Threshold display correction

The retained installed-walk fixture deliberately sets its first team's daily
threshold to `0.000000000001` to prove priced refusal. JavaScript `toString()`
rendered this as `1e-12`. The configuration input now uses ungrouped decimal
formatting with sufficient significant digits and matches the API's positive
amount validation. Saving preserves the numerical value; no budget was changed.
Regression: tiny amounts failed before the fix; all 11 policy tests and TypeScript
pass afterward. Live form reads `0.000000000001` without range-underflow.
Provider/key onboarding remains private engine configuration, as described in
`AI-gateway-setup.md`; the UI references key IDs and does not yet add provider
secrets. This is distinct from the implemented authenticated inference proxy.
