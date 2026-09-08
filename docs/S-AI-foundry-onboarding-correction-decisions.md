# Foundry endpoint and catalog correction — 2026-09-08

User evidence: a complete Azure portal deployment URL ending
`/openai/deployments/gpt-5/chat/completions?api-version=2025-01-01-preview`
is rejected by the base-only form, disabling Test Connect. The Foundry reference
catalog also incorrectly excludes every non-GPT/o-series family.

## Dispositions before code

- **Locked — accept portal URL input in onboarding.** For the three existing
  Azure resource host suffixes, accept resource roots, canonical v1 bases, v1
  operation URLs and recognized deployment operation URLs with one optional
  date-form `api-version`. Resolve these to the existing resource `/openai` wire
  contract. Display that requests use `/openai/v1` (implicit version), and that
  the legacy query is not forwarded. A deployment/operation conflict with the
  chosen model/mode is actionable, never silently directed to another model.
  Canonical API persistence, existing endpoint immutability and egress validation
  remain unchanged. Unknown paths, extra queries, credentials, encoding tricks,
  non-Azure hosts and fragments remain invalid. Do not convert `/models` or
  `/anthropic` protocols into v1.
- **Locked — vendor-neutral Foundry model suggestions.** Extend the same pinned
  LiteLLM source extraction to `azure_ai` as well as `azure`. Preserve model/mode
  filtering, exact deployment names, deduplication and paging. Remove the GPT
  family allowlist. Exclude known Anthropic Messages-only Claude suggestions
  from this v1 form and explain that actual deployment and operation support
  must be checked; do not label the entire provider OpenAI-only.
- **Locked — bounded non-OpenAI preflight.** Use `max_tokens` for ordinary
  Foundry chat deployments; use `max_completion_tokens` for identifiable GPT-5
  and o-series reasoning model names, following LiteLLM's model-specific
  parameter handling. Existing no-retry and token/time bounds remain.
- **Deferred to the provider protocol slice — literal legacy API-version
  routing, Anthropic Messages and serverless `/models` endpoint adapters.** This
  correction imports a portal URL into the existing v1 route; it does not claim
  to execute the literal legacy URL or every LiteLLM adapter. No schema or engine
  configuration change is needed for this onboarding correction.

## Source inspection

Read installed LiteLLM1.100.0 `llms/azure/azure.py` (separate resource endpoint,
deployment and version, GPT-5-specific transformation) and
`llms/azure_ai/chat/transformation.py` (separate Foundry protocol URL and auth
handling). Reviewed https://docs.litellm.ai/docs/providers/azure_ai and Microsoft
Foundry endpoint documentation:
https://learn.microsoft.com/en-za/azure/foundry/foundry-models/concepts/endpoints?view=foundry
which demonstrates non-OpenAI deployments on `/openai/v1` with implicit versioning.
The model catalog retains source commit and MIT attribution recorded in
`apps/api/internal/aigateway/reference/README.md`.

## Required evidence

Regression: exact screenshot URL enables test with matching deployment/mode;
test and save send canonical base; mismatched deployment/mode are explained;
unsafe URL variants cannot erase query data silently or pass validation. Both
Add Model and Add Credentials share the corrected editor. Existing credential
reuse still hides key/base; endpoint changes invalidate probe/key. Search returns
Llama, DeepSeek, Phi and Mistral for chat without credentials. Actual LiteLLM
SDK fixture verifies non-OpenAI request model/path/parameters via proxy; focused
Go catalog and both edition builds, web checks and rendered preview verification.
Synthetic proof is not live Azure inference. No real key read or submitted.
