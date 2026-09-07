# AI provider onboarding — decisions (2026-09-07)

User-approved scope: add a provider and its API key, select models, test credentials,
and assign team access from the existing Community AI gateway UI. LiteLLM is a
workflow reference. Existing organization opt-in stays default OFF. This paper
precedes product code on `ai-improvement`; no merge or release is authorized.

## Locked decisions

1. **Qualified provider:** OpenRouter first, serving its exact named models. Direct
   OpenAI/Anthropic, Bedrock, Vertex and arbitrary compatible upstream URLs are
   deferred to provider-specific qualification. A native engine's advertised
   support is not Tunnex qualification. No new proxy implementation.
2. **Secret owner:** only private Bifrost stores provider secrets, encrypted with
   its stable deployment encryption key. CP passes a bounded write-only secret
   transiently; CP tables, responses, audit events and logs never contain it,
   including masked native values. CP's existing sealed virtual credentials are
   separate. Reject CP provider-secret copies and browser/provider direct calls.
3. **Configuration authority:** self-service requires an explicit deployment
   setting `TUNNEX_AI_PROVIDER_MANAGEMENT_ENABLED`, default false. Enable only with
   database-owned native provider configuration (no `providers` stanza in the
   startup file). Keep native database volumes, encryption key and environment
   references for legacy keys. An enabled UI must never promise persistence on
   a file-owned deployment. Fresh installs initialize the qualified OpenRouter
   provider with fixed retry settings through its private API. No restart per key.
4. **Authorization:** dedicated `ai_provider:view` and `ai_provider:manage`, granted
   to owner/admin; mutations and credential tests require a human administrator.
   Authorization precedes availability and request-body processing. Every query
   includes the authenticated organization. No cross-tenant existence oracle.
5. **Ownership:** server UUID plus reserved native ID `tnx-managed-<UUID>`; public
   key ID is a non-secret policy reference, never a native virtual credential ID.
   Migration 0141 snapshots existing team key references into an explicit per-org
   legacy ACL. Unknown IDs are denied, never silently enrolled. Reserved-prefix
   legacy collisions must abort migration with an actionable error. Managed keys
   must be same-org, enabled, applied and cover selected models (union across
   selected managed keys; explicit legacy ACL retains operator-configured scope).
   Enforce at policy write, reconcile, credential issue and every inference grant.
6. **State machine:** metadata desired revision commits pending before native
   writes; pending/error/disabled refuses new admission. Serialize connection
   changes with database row locks and expected_revision CAS. Readback must match
   controlled native name containing revision, ID, enabled and exact models before
   applied. Rotation keeps ID stable. An uncertain write stays error and requires
   explicit API-key resubmission; never claim a background retry recovered a key
   CP does not hold. Metadata-only changes internally preserve native masked value.
7. **Concurrency:** admission/policy lock order is device, team, provider FOR SHARE.
   Provider writers never take team row locks; reference checks use snapshots.
   Desired-state transaction closes before native synchronization; synchronization
   locks the provider row and verifies the captured revision before touching native.
   Initialization of the shared OpenRouter provider is serialized across replicas.
   Native operations share a bounded deadline, never unbounded retries.
8. **Limits:** 32 provider connections per org including tombstones; label 1–80
   trimmed characters, secret 1–4096 characters with no whitespace, 1–32 unique
   exact OpenRouter models, existing 8-key team limit. Catalog query <=100 chars,
   page size 1–100 (default 50), offset <=10000. No provider secret in test errors.
9. **Edits/removal:** additions allowed; removal of models referenced by team policy
   returns 409 until policy is changed. Disable immediately blocks new requests;
   already accepted streams retain the established <=30-second bound. Delete
   refuses any retained team reference, disables first, then deletes only that
   native key. Keep tombstone ownership; failure remains disabled/error and visible
   for retry. No team, native virtual-key or usage cascade on connection removal.
10. **Test/catalog:** use the pinned native cached OpenRouter catalog for suggestions;
    no upstream request is needed to browse. Test explicitly refreshes the selected
    native key and checks `status=success` (HTTP 200 alone is insufficient). It makes
    credential/catalog GET calls and zero inference calls. Success does not prove
    every selected model's inference entitlement. Preserve and display last check
    timestamp/result; rotating a key invalidates the prior result.
11. **Customer UI:** Providers & models tab, connection list, Add/edit/rotate,
    searchable model suggestions plus exact-model entry, test, disable and safe
    delete. Team configuration selects owned connections by label and retains
    clearly identified existing legacy references. Password field clears after
    submission and org switch; never return a secret to populate an edit form.
    Usage and configuration remain usable independently of catalog availability.
12. **Migration/rollback:** additive tables and ACL snapshot, no existing policy or
    secret rewrite. Mixed old/new CP writers are unsupported once managed keys are
    enabled: roll all CP replicas before enabling the deployment setting. Rollback
    disables management, drains accepted requests and disables managed assignments
    before reverting CP; preserve database-owned native config and encryption data.
    Never automatically down-migrate populated ownership tables or restore a
    provider file that can remove database-created keys on startup.

## Shared boundaries

OpenAPI operations: list/create/update/delete AI provider connections, test one
connection, and list model suggestions. Provider list includes management_available
and legacy_key_ids for the current org; no secret. Connection response includes id,
key_id, provider, name, models, enabled, revision, applied_revision, status,
last_test_status and optional last_test_at. Create requires API key; update takes
optional API key plus expected_revision. Delete/test take expected_revision.
Models return only exact id and display name, total and pagination metadata.

Native adapter owns CRUD, masked-value preservation, exact readback, initialization,
and test-status interpretation. CP owns transactional desired state, ownership and
safe public errors. UI consumes generated types; generated files have one owner.

## Evidence already established

Pinned native Bifrost transports/v2.0.0 binary SHA256
`31ac451d83706069e580dd1dedf099aa518d1bc47c3c481d20f97203f799275e`:
single-key CRUD, invalid/valid auth refresh, disable/re-enable, legacy-key and
virtual-key preservation, encrypted-at-rest keys, and removal of the provider
stanza across restart all passed. Fixture counted 16 successful credential checks,
4 refusals, zero inference requests and zero spend. Sanitized result digest:
`b38e0407a013923674aca12aaab9422c60a126896a7a35bb0e287861153f7d15`.
This qualifies the native mechanism, not the unimplemented CP/UI integration.

## Verification and stop condition

Prove cross-org/key guessing denial, legacy migration preservation, concurrent
CAS edits, disable/rotate/delete admission, timeout state, native restart
persistence, sanitized API/audit/log output and no-spend test semantics. Run both
API editions, generated drift, web tests/typecheck/build, and render the actual
local CP flow. Record exact content SHAs and remaining remote CI/live-provider
qualification limits. Do not claim NetBird-wide parity from this slice.

## Verified competitor gap register

References checked 2026-09-07:
- [LiteLLM UI](https://docs.litellm.ai/docs/proxy/ui): provider/model setup without
  restarting the proxy — workflow reference for this slice.
- [NetBird quickstart](https://docs.netbird.io/agent-network/quickstart): provider
  connections and tool setup — onboarding here; additional tool examples next.
- [NetBird providers](https://docs.netbird.io/agent-network/providers): broader
  direct-provider support — separate qualification backlog.
- [NetBird usage](https://docs.netbird.io/agent-network/usage-and-logs): per-request
  investigation — aggregate dashboard exists; scoped request/denial logs next.
- [NetBird limits](https://docs.netbird.io/agent-network/policies/limits): observed
  thresholds can overshoot too; broader identity/window limits remain a gap.
- [NetBird connectivity](https://docs.netbird.io/about-netbird/understanding-nat-and-connectivity):
  transport lifecycle is separate NAT work, not proven by this AI slice.

## User-requested UI follow-up (2026-09-07)

Locked: Add/edit provider opens a right-side modal drawer instead of an inline
form below the inventory. Reuse the existing shared Modal focus/dismiss contract,
keep save/cancel in its fixed footer, and use existing theme tokens and Badge
status tones. API/state/security behavior is unchanged. Verify portal placement,
Escape/cancel clearing unsent keys, focus return, existing form submission and
actual local rendering. The user requested this visual refinement; Docker capacity
expansion remains unapproved and outside this change.

## Multi-provider follow-up — user disposition (2026-09-07)

The user's explicit request for LiteLLM-like provider selection supersedes the
OpenRouter-only decision above. Locked slice: actual OpenAI, Anthropic, Gemini
and OpenRouter connections, using their native Bifrost adapters and literal API
keys. No UI-only provider choices or silent routing through OpenRouter.

- Provider definitions come from a CP-owned supported registry exposed in the
  existing authorized provider inventory: id, name, credential label, model
  placeholder. The generated OpenAPI enum is the public supported contract.
  Catalog requests accept provider, defaulting to openrouter for old callers.
- Each connection's provider is immutable. API keys remain transient/write-only;
  current encrypted-native ownership, CAS and revocation rules remain intact.
  Migration 0142 expands the provider constraint; down migration refuses retained
  non-OpenRouter connections/policies, including tombstones. No data rewrite.
- Canonical names split exactly once: provider/upstream-model. OpenRouter's vendor
  segment remains part of its upstream model. All allowlists, cost lookup and
  inference retain the canonical name. Legacy key ACL covers OpenRouter only.
- Reconciliation groups same-org keys by their stored provider and effective exact
  models. Native virtual keys retain stable identity and one exact provider config
  per selected provider. Removed configs disappear; unrelated providers/keys never
  become implicit allow-all. Persisted and runtime readback must match every scope.
- Shared native contract: ProviderKeySpec gains Provider; EnsureProvider(ctx,
  provider); ProviderModels(ctx, provider, query, limit, offset). Add
  EngineProviderScope{Provider, Models, KeyIDs} and optional ScopedPolicyEngine
  EnsureScopedKey(ctx, name, scopes). Existing EnsureKey is a single-scope wrapper;
  older test engines can handle only one scope, never silently merge providers.
- UI: searchable provider picker in the shared right drawer, provider-specific
  key label/catalog/model placeholder, clearing draft key/models/catalog on
  provider switch. Add model can reuse an existing same-provider connection via
  revisioned update without re-entering its key. Model inventory lists exact API
  model ID, provider, credential connection and state, with search/filter and
  edit/test actions. Theme tokens and shared badges stay consistent.
- Arbitrary public aliases, custom upstream URLs, Azure deployments, AWS/Vertex
  workload credentials are deferred to a separately dispositioned mapping/origin
  and authentication contract. This slice preserves exact-model authorization;
  provider names alone are not proof of those additional capabilities.
- Verify provider mismatch/immutability, mixed-provider policy scopes and pricing,
  legacy coverage isolation, model catalog isolation, key-rotation/refusal paths,
  native protocol fixtures, generated drift, both API editions and rendered UI.
  Native fixture qualification is explicitly distinct from paid provider smoke.

Reference: official LiteLLM revision 168a0055a244acdcf97c330c52e085ab40b1424c,
`ui/litellm-dashboard/src/components/add_model/AddModelForm.tsx`,
`provider_specific_fields.tsx`, `handle_add_model_submit.tsx`, and
`provider_info_helpers.tsx`. Its backend provider-field metadata, credential reuse
and model table inform this workflow. Implement with Tunnex components; no source
copy or new LiteLLM runtime dependency. UI source is MIT; enterprise source is
outside the reference scope.

## Provider selector refinement (2026-09-07)

User-dispositioned: replace provider cards with a searchable, keyboard-accessible
brand-logo dropdown. Use real provider SVG artwork with attribution, existing
popover/combobox primitives and theme tokens. New forms begin with no provider
selected instead of an implicit OpenRouter choice. Credential caption is the
standard “API key”; selected-provider context is shown in the dropdown. Preserve
immutable provider on edit and secret/model/catalog clearing when provider changes.
Custom-provider support is explicitly requested; its separate origin and routing
contract is being verified and the public-HTTPS boundary has been surfaced for
user disposition. Do not ship a custom option that silently routes through an
existing provider or accepts unvalidated destinations.

## Custom provider contract — approved 2026-09-07

User explicitly approved private/internal endpoints and the recommended extra
mandatory egress proxy plus installation-controlled host/IP allowlist. Locked:

1. Custom uses the pinned native OpenAI-compatible adapter with a unique provider
   name `custom-<connection UUID>`. Stored/public provider is `custom`. Accept raw
   upstream model names in custom connection writes; return canonical
   `custom-UUID/model` names. Never let a caller choose another connection's native
   namespace. Provider and normalized endpoint_url are immutable. Limit native
   scopes to eight, matching the existing selected-key bound.
2. Installation file `TUNNEX_AI_CUSTOM_ENDPOINTS_FILE` supplies approved endpoints
   and per-endpoint address CIDRs. No API/UI can mutate that allowlist. The API
   exposes approved endpoint URLs to authorized provider administrators. Only an
   exact normalized origin/base path match may be registered; no URL credentials,
   query, fragment, ambiguous encoded path, or /v1 duplication. Both HTTP and HTTPS
   are supported through the native custom adapter and mandatory CONNECT tunnel.
   Private HTTP is explicit operator approval; TLS verification stays on for HTTPS.
3. A dedicated private egress process validates proxy authentication, exact target
   host/port, every resolved destination address and configured allowed CIDRs on
   each dial. Dial the validated IP directly, never resolve it a second time.
   Mixed allowed/forbidden DNS answers refuse. Always block loopback, unspecified,
   multicast, link-local/cloud metadata, and configured control-plane/protected
   hosts and CIDRs. IPv4-mapped IPv6 must not bypass checks. CONNECT only, bounded
   headers/concurrency/dial/connection lifetime; no arbitrary forwarding or logs
   containing keys, bodies or proxy credentials. No TLS interception.
4. Shared egress policy file schema: endpoints array of {name, url, allowed_cidrs},
   protected_hosts array, denied_cidrs array. All are operator-controlled. Custom
   availability requires valid nonempty rules plus an authenticated private proxy
   URL `TUNNEX_AI_CUSTOM_PROXY_URL`. Recheck endpoint approval on every admission
   and reconciliation. Proxy policy changes require restarting the custom egress
   process and CP with the same file; drain/disable custom assignments before
   removing an endpoint. Standard providers remain compatible/default behavior.
5. Native custom provider readback must match immutable base URL, exact configured
   proxy and operation allowlist (list_models, chat_completion,
   chat_completion_stream). Initialize only when absent; do not overwrite global
   provider config. Targeted key CRUD/rotation/delete remains existing mechanism;
   retain empty custom provider config and CP ownership tombstone on key deletion.
   Verify missing/dead proxy fails without direct upstream arrival. Existing native
   localhost exception must never substitute for proxy address enforcement.
6. API inventory adds custom_available and custom_endpoints; custom definition is
   discoverable but unavailable until setup is valid. Create/update accept optional
   endpoint_url, required for custom. Connection response exposes endpoint_url for
   custom only. Custom model catalog requires same-org connection_id; pre-create
   custom model entry is manual. Exact unknown custom prices continue to refuse
   monetary policies. No price or hard-cap claim.
7. Migration 0143 adds endpoint_url and the custom provider value; no secret or
   existing model rewrite. Down refuses retained custom connections/tombstones.
   Rollback preserves ownership and encrypted native state and disables custom
   assignments before reverting CP/egress configuration.
8. Deploy the egress executable with the existing API image as an opt-in private
   service/sidecar; proxy credentials use existing secret delivery mechanisms.
   No host port by default. Default custom support OFF; four standard providers
   and previously approved organization opt-in remain unchanged.

Prove literal and DNS-rebinding refusals (metadata/control-plane/loopback), explicit
private-address allowance, failed-proxy no-direct-fallback, custom native CRUD and
routing, foreign namespace/endpoint refusal, immutable endpoint, approval removal,
rotation, catalog and model UI. Native and egress fixtures are zero-paid-call
qualification; actual customer private endpoint trust/certificate checks remain
installation-specific.

Native representation verification: proxy URL readback is masked. Lock the native
value to `env.TUNNEX_AI_CUSTOM_PROXY_URL` and deliver the same authenticated URL
to CP and Bifrost through the installation secret mechanism. Require exact env
reference plus resolved masked-value evidence, no alternate proxy credentials or
TLS overrides. Pinned code explicitly errors for an unresolved secret reference;
verify absent/malformed values never fall back to direct egress. This changes the
native representation, not the approved proxy/origin boundary.
