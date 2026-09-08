# Self-service provider endpoints and draft catalog

The user explicitly removes per-endpoint manual approval and asks why Search
models is disabled before a connection exists. This supersedes the previous
Foundry paper's requirement to register each public resource URL manually.

## Locked contract

- Installation policy gains `public_https: true`. With the existing authenticated
  egress proxy configured, administrators can enter public HTTPS/443 Custom and
  Azure Foundry endpoints directly. No per-destination approval, DB row, or
  service restart is required. Existing installations without this switch retain
  their exact endpoint rules. Enable it in the local preview and documented
  deployment examples, retaining the protected-host configuration.
- The proxy resolves each destination once per connection, refuses the whole DNS
  answer if any address is nonpublic, protected, local, metadata or denied, and
  dials only validated numeric addresses. Redirects remain disabled in clients.
  Explicit endpoint rules keep precedence: a mismatched provider or narrower
  network scope cannot be bypassed through public fallback. Private HTTP/HTTPS
  and SageMaker bridge endpoints retain existing installation network rules.
- Azure accepts public resource hosts under `openai.azure.com`,
  `services.ai.azure.com`, and `cognitiveservices.azure.com`, with stored `/openai`
  base. The UI accepts a trailing `/v1`. Supporting an input shape does not prove
  that resource exposes the v1 API; Test Connect reports the actual outcome.
- API inventory adds `public_endpoints_available` boolean. It reflects configured
  provider management and validated public egress, not inference availability.
- OpenAPI-first `POST /organizations/{orgId}/ai-gateway/providers/model-catalog`
  (under `/api/v1`) / operation `searchAIProviderCatalog` accepts provider
  (`custom`, `sagemaker`, `azure_foundry`), write-only `api_key`, `endpoint_url`,
  optional `query` (100 characters), `limit` (1..100, default50), and `offset`
  (0..10000, default0). Response reuses `AIProviderModelList`.
- This draft search requires the existing provider-manage permission and real
  management actor, uses the existing per-org/global bridge admission limits,
  and creates no connection or retained secret. It calls the private bridge's
  `/model-catalog` with the same fields; the bridge fetches exactly
  `<normalized-base>/v1/models` with Bearer key through locked proxy transport.
  Bound response to 1MiB/10,000 entries; return sorted/deduplicated valid IDs only,
  with filtering/pagination and sanitized failures. No redirects, pagination
  crawl, inference, ambient credentials or provider response-body reflection.
- Search works before Save once endpoint/key are entered; no model is required.
  Display the missing prerequisites. A search result is a catalog suggestion,
  not proof that the key can run a model or that it is the Azure deployment name.
  Manual deployment entry remains available if the upstream has no model catalog.
  Draft field edits invalidate late search results and prior test success.
- Azure preflight uses bounded `max_completion_tokens=16` for current OpenAI v1
  compatibility; other providers keep existing parameters. No paid test is
  automatically triggered. Existing connection scope, saved credential hiding,
  chat-only transport and default-off organization access remain unchanged.

## Verification and boundary

Prove DNS rebinding/mixed/protected/private refusal, explicit rule precedence,
no-approval public creation/probe, draft search authorization/rate/payload bounds,
secret nonreflection and stale results. Run both API editions and focused real
PostgreSQL tests, actual SDK/native fixtures and web checks. Update the existing
isolated local preview without changing user-entered credentials or invoking
Azure. Full LiteLLM migration and other inference modes remain separate work.
