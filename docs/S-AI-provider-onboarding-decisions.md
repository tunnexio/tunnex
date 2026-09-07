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
