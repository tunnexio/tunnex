# Foundry Claude protocol and catalog coverage — 2026-09-08

The user requests their deployed `claude-opus-5` under Azure AI Foundry, with
the portal endpoint `/anthropic/v1/messages`. This explicitly activates the
Anthropic protocol slice deferred by the prior Foundry onboarding correction.

## Locked decisions before implementation

- Keep Azure AI Foundry as one provider. The explicit endpoint selects its
  transport: `/openai` continues to use OpenAI v1; `/anthropic` uses Anthropic
  Messages. Import `/anthropic/v1` and `/anthropic/v1/messages` into that base.
  Never infer the wire protocol from a deployment name or silently convert
  an Anthropic URL into OpenAI. Exact custom deployment names remain supported.
- Reuse the pinned Bifrost native Anthropic adapter for authorized chat and
  streaming inference, and the installed LiteLLM Anthropic adapter for private
  draft and saved-key tests. Both use the explicit Azure origin, mandatory
  authenticated egress proxy, `x-api-key`, and Anthropic version headers.
  No new service, dependency, public API field, or credential storage is needed.
- Permit only chat mode on the Anthropic endpoint, enforced in UI and backend.
  Existing OpenAI endpoints retain their supported modes. Keys and endpoints
  remain connection scoped; changing protocol requires new credentials, so an
  existing key is never silently moved to another origin or transport.
- Include all Azure/Azure AI chat families from the already pinned LiteLLM
  reference, including Claude. Catalog names are suggestions, not discovered
  tenant deployments. Search for supported standard providers must also work
  from the pinned reference when the native catalog lacks those entries.
  Do not claim every vendor model runs on every provider or mode.
- Preserve organization/group authorization, saved-key revision checks, bounded
  preflight, secret redaction, endpoint validation and default-deny egress.
  Catalog checks are separate from inference; a missing Claude models-list
  endpoint must not prevent testing a deployment by its exact name.

## Source and evidence

Read LiteLLM 1.100.0 `llms/azure_ai/anthropic/transformation.py`,
`llms/azure_ai/common_utils.py`, and Bifrost's pinned
`core/providers/anthropic/anthropic.go`. Reuse their protocol translation rather
than implementing a second messages converter. The pinned reference already
contains `azure_ai/claude-opus-5`; no invented catalog entry is needed.

Primary references:
https://docs.litellm.ai/docs/providers/azure_ai
https://learn.microsoft.com/en-us/azure/foundry/foundry-models/how-to/use-foundry-models-claude

Acceptance: auto-search returns Claude; portal URL enables test; actual SDK and
native-engine fixtures receive `/anthropic/v1/messages` with the exact deployment
and correct headers; saved-key tests preserve serving scope; chat and streaming
return gateway-compatible responses; unsupported modes and unsafe URLs fail
before sending secrets. Existing OpenAI behavior remains covered. Render the
local preview. Synthetic wire evidence does not certify live Azure credentials.

## Review dispositions

User approved both review corrections in this session: reject the Azure
Anthropic base under generic Custom (and SageMaker) to preserve one test/serve
protocol, and merge native deployment catalogs with LiteLLM reference names
before deduplication and pagination. This also preserves live aliases when
reusing saved Foundry credentials. Read the retained native catalog through its
existing 100-row pages, with a shared 10-second deadline, a 10,000-row cap and
the existing 1 MiB response bound per page. Catalog failure may fall back to
reference suggestions and configured names, never grant model access.

The folded review caught an initial mismatch with the private engine's 100-row
page limit. The fold now preserves that bound, with a regression through the real
Engine HTTP client over 101 native entries. Both protocol and catalog reviewers
re-reviewed the final fold and reported no remaining introduced regressions.

Held follow-up (P2, pre-existing): saved native model catalogs lack operation
metadata, so an existing chat alias can appear in a non-chat search. The UI
retains its saved mode when testing that existing model. Track separately as
`AI-native-catalog-mode-filtering`, pending user disposition; this Claude chat
slice does not change that behavior. Anthropic endpoints explicitly reject all
non-chat modes before sending a request.
