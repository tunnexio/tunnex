# LiteLLM model flow reference and Foundry gap

Actual UI source reviewed at commit
`168a0055a244acdcf97c330c52e085ab40b1424c`; file Git blobs matched the pinned
tree. Runtime inspection used the separately pinned LiteLLM1.100.0 installation.
The two artifacts are not claimed byte-identical.

## Upstream source

- `ui/litellm-dashboard/src/components/add_model/AddModelForm.tsx`: provider and
  model fields at225, existing credentials at287, Test/Add actions at430.
- `ui/litellm-dashboard/src/components/add_model/provider_specific_fields.tsx`: dynamic
  provider credential fields at182.
- `ui/litellm-dashboard/src/components/add_model/handle_add_model_submit.tsx`: builds
  deployments per model mapping, create payload at215.
- `ui/litellm-dashboard/src/components/add_model/model_connection_test.tsx`: tests the first
  prepared model using the creation settings, starting at43.
- `ui/litellm-dashboard/src/components/provider_info_helpers.tsx`: Foundry's
  `Azure_AI_Studio` metadata ID maps to runtime `azure_ai`.

Model and credential are distinct concepts upstream too. The missing UX behavior
was one Add Model flow with optional existing-credential reuse, not a mandatory
separate create-connection task. Match that entry path and vocabulary while
retaining existing Tunnex key ownership and team policy references.

Upstream root MIT license is retained in `references/litellm/LICENSE`; provider
metadata is already imported there. Do not copy separately licensed enterprise
code. Referenced component imports depend on LiteLLM's UI and API framework;
copying JSX verbatim would not connect Tunnex's authenticated API.

## Foundry needs both request paths

The actual `azure_ai` SDK adapter accepts Azure API Base/Target URI and key, handles
API-version parameters, chooses Azure API-key authentication, and transforms
Foundry/OpenAI-model requests. Its Anthropic adapter is another protocol branch.
Current Tunnex Custom routing strips to an OpenAI `/v1` API and Bearer key; this
cannot faithfully represent Foundry's API.

Recommended integration, pending disposition of the new security contract:

1. Add first-class `azure_ai`, keeping `azure` (Azure OpenAI deployment API)
   distinct. Persist the actual approved upstream URL and explicit API version.
2. Use the same real LiteLLM adapter for preflight and saved inference. Keep
   existing Bifrost encrypted key storage, usage and connection-owned namespaces.
3. Bind the private SDK route to the owning connection and approved upstream;
   authenticate native-to-SDK requests independently of the provider API key.
   Never let a caller choose another route, tenant, endpoint or key reference.
4. Keep the provider key transient in the SDK, mandatory authenticated egress,
   normal TLS checks, no redirect/fallback and bounded requests/streams.
5. Freeze concrete route authentication, revocation/restart semantics and exact
   schema before implementation. Test real pinned SDK preflight AND saved
   inference against local fixtures, including cross-connection/model isolation,
   endpoint refusal, credential rotation, revocation, streaming and replay.

No Azure cloud/resource calls were made. Until this path is implemented and
qualified, do not add a fake working Foundry option or claim full LiteLLM parity.

## Model-first UI validation

Implemented All Models as the default view, a unified Add Model action and a
secondary LLM Credentials management view. Optional credential names default to
a bounded provider/model label. Existing credential reuse retains models,
revision, enabled state and write-only key behavior. Native standard API base
URLs are visible read-only; Custom and SageMaker retain editable approved URLs.

Full web validation: 1,354 tests across118 files passed, TypeScript and Vite
production build passed (existing chunk-size warning). Focused provider suite22
tests includes creating a model without a separately named connection.
Independent static review and root review found no introduced actionable issue.
Preserved boundary: model additions reusing saved keys do not run another
preflight; successful preflight is required for new/replaced credentials.

Actual local CP browser inspection verified All Models first and OpenAI's visible
`https://api.openai.com/v1` field. A second walk selected Custom, typed the approved
fixture URL, selected `private-demo`, left Credential name empty and submitted
Test Connect. Actual local CP/SDK/egress fixture returned success and Add Model
became enabled. No connection saved, policies changed or paid provider called.

Rendered evidence:
`walk-artifacts/ai-gateway-20260907/litellm-model-first-local.jpg` and
`walk-artifacts/ai-gateway-20260907/litellm-add-model-native-url-local.jpg`.
Azure Foundry is still unimplemented; the new saved-request routing contract was
surfaced for user disposition. No schema, backend or cloud changes in this slice.
