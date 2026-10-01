# AI provider coverage

Current architecture: Bifrost is the single inference runtime. The hosted
bootstrap installs its private backend without requiring provider credentials;
organization AI access remains disabled until configured. The obsolete Python
SDK bridge and proxy are retired. Earlier dated LiteLLM validation records are
historical evidence, not current deployment instructions.

| Surface | Current implementation | Qualification boundary |
| --- | --- | --- |
| Provider selection | Nine standard providers, Custom, SageMaker and Azure AI Foundry | Actual model/mode access depends on the configured provider account |
| Test Connection | Bounded native draft and saved-key operations | Saved keys remain inside the engine; scope and endpoint revision are checked |
| Model discovery | Authenticated live native provider discovery, separate from static suggestions | Catalog success does not prove inference entitlement |
| Static metadata/pricing | Commit/hash/date/license-pinned data fetched during CI and baked into artifacts | Estimates preserve original USD units; missing/conflicting prices remain unknown |
| SageMaker | Explicit installation IAM/endpoint/model/client bindings and native signed AWS transport | Real AWS endpoint inference requires authorized customer configuration |
| Azure/Custom | Qualified native transports with installation-approved endpoints and CONNECT egress controls | No private credential reaches the CP/browser; live cloud qualification remains deployment-specific |
| Operation modes | Chat, completion, embedding, audio speech/transcription, image, video and rerank | Native synthetic transport tests cover all eight; each provider/model need not support every operation |
| Credentials/policy | Write-only keys, rotation, org ownership, exact key/model restrictions and revocation | Global engine administration is not exposed to tenants |
| Usage/cost | Native request/token/cost logs and Tunnex scoped views | Observed estimates are not a provider invoice or strict monetary cap |

Setup: [AI gateway](AI-gateway-setup.md). Reproducible static data and attribution:
[catalog](../apps/api/internal/aigateway/reference/README.md). Provider runtime
extensions are built from immutable upstream source and tested without paid
provider calls. Public aliases, richer credential forms, advanced routing and
additional provider families require separate implemented transport and policy
qualification; metadata alone does not enable them.
