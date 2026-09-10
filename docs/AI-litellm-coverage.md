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
| Model onboarding | Exact models, automatic mode-aware catalog search, model chips, existing credential reuse and per-model modes | Public aliases/model groups |
| Test Connect | Real bounded one-model inference before create/new-key save, sanitized result | Live credentials for each supported provider; current development uses synthetic transports |
| SageMaker | Actual OSS SDK SigV4 adapter behind scoped private bridge, approved endpoint/IAM binding | Authorized real AWS endpoint qualification |
| Azure AI Foundry | Typed public HTTPS API base, API key/deployment, mode-aware LiteLLM reference search and scoped OpenAI v1 routing | Actual Azure model/mode qualification; legacy azure_ai /models, Entra identity and sovereign clouds |
| Custom upstream | Public HTTPS endpoints checked automatically; private HTTP/HTTPS uses explicit network rules; authenticated CONNECT for all eight mode families | Other provider-specific protocols and deployment qualification |
| Credentials | Write-only keys, rotation, retained ownership, org scope | Provider-specific compound/cloud credential forms |
| Usage and cost | Daily chart, request/token/cost cards, team/agent/model breakdowns | Additional LiteLLM log explorers and drill-down dimensions |
| Policy | Community organization opt-in, team exact models/key scope, agent credential binding | Additional model groups, individual virtual-key management surfaces |
| Limits | Honest soft spend thresholds, bounded concurrency/output | No strict spend-cap guarantee |
| Protocols | Chat, completion, embedding, audio speech/transcription, image, video with owned jobs/status/content, rerank; pinned native synthetic-wire proof for all eight | Every provider/model does not support every mode; live provider qualification, richer payloads and non-token monetary accounting remain |
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

September8 mode implementation: `docs/S-AI-mode-routing-decisions.md` records the
saved-mode and video ownership contract; `docs/AI-mode-validation-20260908.md`
records native fixtures and local UI evidence. Video preflight means accepted,
not completed. Non-token modes refuse monetary-policy admission until actual unit
pricing and terminal cost attribution are qualified; missing costs are not zero.
The serving engine remains pinned Bifrost; preflight uses actual LiteLLM SDK.
Independent model-less credentials, full LiteLLM OSS engine migration and broader
provider onboarding remain outstanding; this is not full LiteLLM parity.
