# LiteLLM reuse — decision record, 2026-09-07

User requests SageMaker, Test Connect before Add, and substantive reuse of as much
LiteLLM functionality as possible. User chose the proposed LiteLLM bridge with
installation-owned AWS IAM/endpoint configuration: "jo litellm krta h whi kro";
then explicitly expanded the request to full possible reuse. This supersedes the
previously pending catalog-only probe proposal. Do not repeatedly ask approval
for the same integration direction.

## Locked first implementation slice

1. Reuse the pinned open-source LiteLLM SDK as a private adapter. Retain Tunnex
   organization/RBAC/model authorization and existing Bifrost ownership/history;
   do not replace the accounting engine or expose a global upstream admin UI.
   Source reviewed:168a0055a244acdcf97c330c52e085ab40b1424c. Preserve MIT notice;
   exclude enterprise/ code, which has a separate restricted license.
2. Test Connect follows LiteLLM's real inference semantics (ahealth_check/chat),
   not a public catalog's HTTP200. One selected model, fixed short prompt, max16
   output tokens, no retries, 10-second deadline. UI states charges may apply and
   that one-model success does not certify every selected model. Development
   proof uses synthetic endpoints only; no existing pasted key or AWS action.
   Return only sanitized status and timing; never raw SDK request/error details.
3. OpenAPI-first POST /organizations/{orgId}/ai-gateway/providers/test-connection:
   provider, model, write-only api_key, optional endpoint_url. Existing dedicated
   provider-manage authorization and human actor gate apply before validation.
   Successful SDK result yields status=success; HTTP200 alone is insufficient.
   Global8/per-organization1 concurrent probes,6 attempts/minute/org, bounded
   limiter map. No native draft connection, key persistence or audit payload with
   secrets. Create stays a separate action; UI requires fresh success for its
   exact provider/key/endpoint/model selection and clears stale responses.
4. SDK runtime has private admin token for CP preflight and scoped installation
   client keys for its inference endpoints. No inherited callbacks/proxies,
   redirects, raw request logging, arbitrary provider kwargs or client env/secret
   references. Standard provider origins/auth are fixed. Custom HTTP AND HTTPS
   retain the mandatory authenticated CONNECT path and normal TLS verification.
5. SageMaker uses LiteLLM's sagemaker_chat adapter, not Bedrock and not a fabricated
   Bifrost slug. Operator-configured model aliases bind explicit AWS region,
   endpoint and IAM credential/role configuration; caller cannot choose AWS
   profiles, STS/runtime URLs or override that binding. Approved scoped bridge
   client keys authorize only listed aliases. AWS secrets remain on this private
   adapter and never enter CP persistence or agents.
6. Add a real AWS SageMaker provider option backed by connection-owned native
   custom-UUID routing through the approved bridge. Reuse custom immutable endpoint,
   namespace, model scope, revocation and key handling. Operator policy endpoint
   entries gain provider=custom|sagemaker (omitted means custom). Expose separate
   sanitized SageMaker availability/endpoints. Migration0145 extends provider
   constraints and refuses rollback with retained SageMaker ownership/policies.
7. Bridge deployment is opt-in/private/default off, using pinned OSS dependency,
   a readonly operator model/client configuration and dedicated secrets. Existing
   nine providers and custom behavior remain compatible when bridge is absent.
   Test Connect is visible but unavailable with an honest setup message then.

## Broader requested reuse

Import LiteLLM's provider-create metadata as the source for future generic
credential forms (117 definitions at the reviewed pin); preserve registry ID
versus runtime slug, including SageMaker/sagemaker_chat versus legacy SAGEMAKER.
Advance provider configuration, credential management, virtual keys, model groups,
usage/logs and other OSS surfaces in reviewable slices while preserving Tunnex
identity/tenant boundaries. Do not advertise all117 providers or full parity until
configuration, routing, authorization and tests for those surfaces are complete.
Current first slice is SageMaker routing + real pre-save Test Connect; subsequent
feature coverage and omissions must remain explicit in the handoff.
