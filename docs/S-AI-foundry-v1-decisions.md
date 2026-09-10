# Azure AI Foundry OpenAI v1 provider

User explicitly requests adding Azure Foundry so they can test their provider.
This slice reuses the existing endpoint-bound OpenAI-compatible implementation;
it does not depend on the pending full LiteLLM engine migration.

## Locked implementation

- Provider ID `azure_foundry`, display Azure AI Foundry (OpenAI v1), Azure logo.
- Accept the actual Azure HTTPS API base ending `/openai/v1`, Azure API key,
  and exact deployed model name. Normalize to `/openai` internally, as the
  existing native engine and LiteLLM custom preflight each append `/v1`.
- Restrict this named provider to public Azure resource host formats
  `<resource>.openai.azure.com` and `<resource>.services.ai.azure.com`, HTTPS443,
  exact `/openai` stored path. Existing installation endpoint/CIDR approval,
  private egress, protected-address denial and exact provider kind stay required.
- Add the new kind to the existing connection schema and generated API. Reuse
  connection-owned custom UUID model namespaces, existing write-only secret
  storage, revision verification, team authorization and deny-by-default policy.
- Test Connect uses the existing actual LiteLLM OpenAI adapter with explicit
  Azure base/key/model. Saved requests use the same base/path/Bearer protocol in
  the pinned native engine. No new bridge service, identity or secret migration.
- Saved credentials hide endpoint and key; changing a draft endpoint clears key
  and test proof. Test-before-save remains required in the UI.
- Chat completions only. Clearly exclude legacy `/models`, deployment API-version
  URLs, Anthropic Messages, managed identity, sovereign clouds and other modes.
  These require their own protocol implementations and are not falsely advertised.
- Migration rollback refuses retained Foundry connections, including tombstones.
  Existing rows and all credentials remain unchanged.

## Evidence and correction of earlier finding

Microsoft's current v1 API documents OpenAI client + Azure API key and both host
formats, without dated api-version parameters:
https://learn.microsoft.com/en-us/azure/foundry/openai/api-version-lifecycle
https://learn.microsoft.com/en-us/rest/api/microsoft-foundry/azureopenai/chat

Pinned Bifrost OpenAI adapter appends `/v1/chat/completions` to configured base,
uses Bearer authentication; installed LiteLLM1.100.0 OpenAI adapter accepts the
same base/key. The earlier S-AI-model-first paper correctly excludes legacy
azure_ai routing but did not account for this compatible Microsoft v1 interface.
This narrower provider needs no new dynamic route or authentication contract.

## Validation boundary

Prove generated API/DB constraints, endpoint classification, credential/model
isolation, both API editions, actual SDK request path/auth against a synthetic
transport, and rendered UI. Live Azure inference is for the user's own endpoint
and key; no Azure infrastructure operation or paid invocation is authorized by
this implementation. Never include real keys in logs, tests, screenshots or git.
