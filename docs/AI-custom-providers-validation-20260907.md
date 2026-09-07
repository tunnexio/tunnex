# Custom egress and expanded provider validation — 2026-09-07

Local branch `ai-improvement`; no push, merge, release or paid provider calls.
Decision papers: `87fd7b33`, `7b34ecd7`, `6b7beab3`, `1255a79b`.
Generated API contract: `7737a97a`. This ledger supplements the prior
multi-provider validation; it does not turn earlier incomplete full gates green.

## Delivered boundary

Searchable provider dropdown with actual attributed brand SVGs, no implicit
OpenRouter selection, standard API key caption, and a Custom option. Native
inventory: OpenAI, Anthropic, Gemini, OpenRouter, Groq, Mistral, Cerebras, xAI and
DeepSeek. Together lacks a native adapter in the pin; Perplexity's public catalog
is not credential proof, so neither is advertised as a qualified native option.

Custom OpenAI-compatible HTTP/HTTPS endpoints require operator-approved exact
base URLs plus address CIDRs and the authenticated bounded CONNECT proxy. Each
connection owns a unique native namespace. Endpoint/provider are immutable;
secrets remain outside CP persistence. Unknown custom prices refuse monetary
policies. Migrations 0143/0144 retain existing ownership and refuse unsafe rollback
while custom/new-provider records, including tombstones, remain.

Compose and Helm custom support is opt-in/default off. CP and native engine use
the same proxy URL secret; the proxy gets only its dedicated credentials and
read-only policy. Configuration application verifies the immutable endpoint,
operation allowlist and exact environment reference/redacted shape. Native
redaction cannot prove full secret equality; connection health is separate.

The requested **Test connection before Add** is NOT delivered in this checkpoint.
The surfaced design proposes a transient ten-second, zero-inference
credential/catalog request without creating a native draft key. It is pending
user disposition. The existing saved-connection Test remains functional; its UI/API description says
connection/catalog access, because public catalogs cannot prove key validity. A plain
HTTP 200 alone must not be labeled valid credentials without a valid authenticated
provider response. Reference: LiteLLM `168a0055a244acdcf97c330c52e085ab40b1424c`,
`ui/litellm-dashboard/src/components/add_model/model_connection_test.tsx`.

## Validation

- Web: **1,348 tests / 118 files**, typecheck and production build pass. Existing
  bundle-size warning remains. Final log: `/private/tmp/tunnex-provider-ui-final.log`.
- Both API editions build. Focused PostgreSQL custom races pass open **9.436s** and
  enterprise **8.800s**; added-provider/custom/mixed regressions pass open **8.025s**
  and enterprise **15.156s**. Includes isolation, immutable endpoints, owned model
  namespaces, revoked approval, scope reconciliation and rollback tombstones.
- HTTP schema/auth/secret-redaction races for all nine plus Custom: open **4.031s**,
  enterprise **3.164s**. CLI suite passes.
- Pinned native Bifrost full provider/custom race suite **43.285s**. JSON/SSE,
  invalid-key refusal, exact provider paths, mixed scopes, stable IDs and restart
  preservation pass. Custom HTTP/HTTPS and dead/absent/empty/malformed proxy
  settings refuse direct fallback. Separate production egress tests **2.143s**:
  CONNECT authentication, DNS rebinding/mixed answers, metadata/protected address
  refusal, successful forwarding, lifetime and slot recovery.
- Codegen second pass: zero drift across 50 tracked generated artifacts. Compose
  and Helm verification/lint pass, including incomplete custom setup refusal.
- Full API/required composite gates remain **INCONCLUSIVE** due the previously
  measured Docker VM capacity blocker. No VM resize, shared SSO restart, broad
  database cleanup or infrastructure deletion was performed. Exact-head remote CI
  has not run. Provider fixtures substitute for real new-provider account tests;
  they do not prove customer-specific credentials, billing or model entitlement.

## Actual local preview

`http://127.0.0.1:5180/agents/ai-gateway` uses verified task project
`tunnexaiwalk0907repro4` / network `tunnexaiwalk0907repro4_engine`.
Schema **144, dirty=false**. API binary SHA256:
`8ca5fe3a051a0cd1473baaaba0fc4017cfca6d5b8f51312b93df0849898a31b0`.
The exact pinned engine image and state volumes were retained; the original engine
container is preserved stopped/disconnected as `...-cp-engine-before-custom`.
Shared SSO containers and unrelated work/stashes were preserved.

The rendered dropdown exposes nine logos plus searchable Custom. Created
**Private proxy demo (fixture)**, connection
`f8e40d46-00ed-4aae-be79-9d905a562151`, against the inspected private fixture
`http://fixture:8091` with its /32 explicitly approved. Revision1 applied and
saved-connection Test reports catalog success. The edit drawer shows the immutable endpoint,
keeps the replacement key blank and returns the owned private-demo catalog entry.
Fixture recorded authenticated
`GET /v1/models` arrivals through the actual production proxy process. This is a
synthetic local endpoint; no customer endpoint or paid account was contacted.
Existing OpenRouter fixture remains applied revision7, original team policies and
observed usage (8 requests, 56 tokens, $0.000170) unchanged.

Screenshots in `docs/walk-artifacts/ai-gateway-20260907/`:
`branded-provider-dropdown-local.jpg`, `custom-provider-form-local.jpg`,
`custom-private-connection-local.jpg`, `compact-model-form-local.jpg`. The final
model form uses compact suggestions, removable chips, manual exact-name entry and
existing-credential reuse. Browser verification selected the owned OpenRouter
fixture without requesting a new secret; no model/policy mutation was submitted.
These are implementation evidence, not
user visual approval.

## Independent review dispositions

- Native/egress review P2: absent/malformed proxy and production CONNECT success/
  slot proof gaps. Disposition: add focused tests under the frozen contract;
  implemented and final native/egress suites pass.
- Deployment example P2: `/v1` duplicated native suffix. Disposition: correct base
  URL examples and explanation; Compose/Helm checks pass.
- UI P2: raw `custom-model` incorrectly rejected. Disposition: recognize only the
  actual canonical UUID namespace; regression added, peer re-review resolved.
- UI P2: Enter on empty/unavailable picker results could submit the old provider
  form. Disposition: consume Enter while open, select only eligible options;
  enclosing-form regression added, peer re-review resolved.
- Follow-up screenshot-guided model form received a bounded independent review
  with no actionable findings; final web suite/typecheck/build passed. Custom
  endpoint selection precedes API-key entry, preserving safe key clearing on change.
- Bounded independent CP/HTTP/schema and expanded-native review found no additional
  actionable issue. This is not a full-epic or production-security certification.

Next action: disposition the pending pre-save check design, then implement its
OpenAPI contract, transient probe and UI success/invalidation flow before calling
that requested workflow complete.
