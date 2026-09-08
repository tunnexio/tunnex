# LiteLLM reuse coverage

User direction: reuse as much LiteLLM functionality as possible, including its
provider/model onboarding patterns. This ledger separates existing Tunnex
capabilities, this implementation and remaining integrations. It is not a full
LiteLLM parity claim.

Reference: LiteLLM source168a0055a244acdcf97c330c52e085ab40b1424c; provider field
metadata117 entries preserved with MIT notice in docs/references/litellm.
Runtime: released SDK1.100.0 wheel, separately pinned in apps/ai-bridge.

| Surface | Current coverage | Remaining work |
| --- | --- | --- |
| Provider picker | Branded/searchable native9, Custom, SageMaker and Foundry OpenAI v1 | Wire additional registry definitions to real routing and typed credentials |
| Model onboarding | Exact models, catalog suggestions, model chips, existing credential reuse | Public aliases/model groups and model-specific modes |
| Test Connect | Real bounded one-model inference before create/new-key save, sanitized result | Live credentials for each supported provider; current development uses synthetic transports |
| SageMaker | Actual OSS SDK SigV4 adapter behind scoped private bridge, approved endpoint/IAM binding | Authorized real AWS endpoint qualification |
| Azure AI Foundry | Actual Azure endpoint/key/deployment via OpenAI v1 chat, scoped saved routing and Test Connect | Real user endpoint qualification; legacy azure_ai /models, Entra identity and other modes remain unsupported |
| Custom upstream | Approved public/private HTTP/HTTPS with authenticated CONNECT and hostname/IP policy | More protocol adapters beyond OpenAI chat compatibility |
| Credentials | Write-only keys, rotation, retained ownership, org scope | Provider-specific compound/cloud credential forms |
| Usage and cost | Daily chart, request/token/cost cards, team/agent/model breakdowns | Additional LiteLLM log explorers and drill-down dimensions |
| Policy | Community organization opt-in, team exact models/key scope, agent credential binding | Additional model groups, individual virtual-key management surfaces |
| Limits | Honest soft spend thresholds, bounded concurrency/output | No strict spend-cap guarantee |
| Protocols | Chat completions and existing streaming contract | Embeddings, image/audio/video, rerank and provider-specific modes |
| Routing | Exact approved provider/model routing | Fallback chains, weighted routing, retry configuration and alias groups |
| Playground | Not implemented | Tenant-authenticated request playground with explicit usage accounting |
| Guardrails/cache | Not implemented as LiteLLM features | Separate integration with existing policy and privacy boundaries |

Reusable MIT code and metadata retain upstream attribution. Separately licensed
enterprise code and global upstream management screens are not imported into a
multi-organization control plane. Unsupported entries are not shown as working
providers merely because metadata exists.

Next functional slice after SageMaker/Test Connect validation: generalize the
bridge's installation model registry and credential forms using the imported
provider metadata, with actual runtime adapter and authorization tests per added
provider family. Keep original9/custom compatibility and scoped ownership intact.
