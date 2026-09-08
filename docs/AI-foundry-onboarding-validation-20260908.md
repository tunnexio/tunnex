# Foundry onboarding correction evidence — September 8, 2026

Branch `ai-improvement`; paper `cf691248`. No push or merge.

## Reproduction and change

The supplied Azure URL was a complete deployment request with `api-version`.
The editor's generic base validator rejected its query, so Test Connect remained
disabled despite a selected model and API key. Regression tests failed for both
Add Model and Add Credentials before the change. Four catalog regressions also
failed: Llama, DeepSeek, Phi and Mistral were absent from the GPT/o-series-only
reference filter.

Onboarding now recognizes resource roots, v1 bases/operation URLs and complete
deployment-operation URLs on the existing three Azure resource suffixes. It
imports these into the existing canonical `/openai` base; both serving and
preflight append `/v1/<operation>`. The form explicitly displays the actual
request URL and replacement of the legacy API version with v1 implicit versioning.
Deployment and mode conflicts disable test with actionable explanations. Extra
query parameters, unexpected paths/protocols, userinfo, fragments and encoded
path tricks are refused. The server contract and immutable saved endpoint do
not change.

The provider is named Azure AI Foundry. Its reference snapshot now contains 351
original `azure` and `azure_ai` rows from the same pinned LiteLLM catalog. Runtime
suggestions remain mode-filtered and deduplicated. Claude Messages-only names
are excluded and the form states that this adapter is not implemented.
Non-OpenAI preflight keeps `max_tokens`; identifiable GPT-5/o-series names use
`max_completion_tokens`. Token/time/no-retry limits remain unchanged.

## Checks

- Final focused web suite: **100 passing** (64 editor cases and 36 URL parser
  cases), including both forms, canonical test/save payload, mismatched target,
  existing-key reuse, key clearing and stale proof invalidation.
- Full web suite: **1431 passing /119 files** before the final added empty-userinfo
  refusal case; that case and the final parser run passed in the focused suite.
  TypeScript and production build pass on final source. Existing bundle size
  warning remains.
- API: affected Foundry/reference/catalog tests pass in open edition; enterprise
  cases pass with race detection. `TestAIFoundryProvidersPostgres` uses the
  verified `tunnexai0907-postgres-1` test database/network. Both full API editions
  compile. No API schema, migration or generated type change.
- LiteLLM bridge: **103 passing**. Actual SDK subprocess, authenticated CONNECT
  and TLS fixture prove GPT-5, Llama and DeepSeek requests to
  `/openai/v1/chat/completions`, raw deployment names, Bearer auth and appropriate
  token limit fields across all three resource host suffixes. No Azure DNS/network
  or paid inference in these fixtures.
- Pinned Bifrost native `TestEngineNativeCustomProxy/FoundryOpenAIV1` passes with
  an actual engine process: saved catalog and streaming/nonstreaming inference
  use the canonical resource path through the proxy; stopped proxy refuses.
- Self-review: URL normalization is onboarding-only; no global relaxation of
  server/proxy URL validation; no stale success can authorize a changed key,
  endpoint, model or mode. No independent/story-end review claimed.

## Local preview

Updated CP and SDK on `http://127.0.0.1:5180/agents/ai-gateway`. Before refresh,
verified Docker context `colima-tunnex-sso-review`, project
`tunnexaiwalk0907repro4`, labelled CP/Postgres containers, network
`tunnexaiwalk0907repro4_engine` and volume `tunnexaiwalk0907repro4_pg`. Schema148
remained clean; complete provider metadata fingerprint stayed identical:
**3 credentials /4 models**. Auto migration stayed disabled. New CP binary:
`/private/tmp/tunnex-ai-ui-wcb0_v5d/api-foundry-correction`; old binary retained
as `api-modes-final`. SDK listener remains local port18200 with private env files.

Separate browser tab inspected with synthetic inputs: typing Llama automatically
returned 9 models; pasting the screenshot's deployment URL structure for `gpt-5`
enabled Test Connect and displayed the canonical request. Synthetic key cleared
and form cancelled afterward. Existing user forms/keys were not read or submitted.

- [Expanded Llama search](walk-artifacts/ai-gateway-20260908/foundry-llama-search.png)
- [Enabled test and canonical request](walk-artifacts/ai-gateway-20260908/foundry-portal-url-test-enabled.png)

This is not literal legacy-version execution or full LiteLLM provider parity.
Anthropic Messages and legacy `/models` transports remain outstanding. Actual
Azure deployment inference, user visual sign-off, full composite gates and remote
CI remain unproven; live provider proof requires the user's selected deployment
and key entered in the updated UI.
