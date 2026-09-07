# Independent LLM credentials and multiple modes

Status: PROPOSED — new state and protocol decisions await user disposition.
This records the latest LiteLLM references; the existing model-scoped credential
creation control does not satisfy independent credential storage.

## Requested experience

- Add New Credential is a compact modal: required friendly name, branded
  provider, API base and provider-specific credential fields. No model selection.
- Add Model chooses saved credentials OR new endpoint/key. Saved selection hides
  both new-secret and endpoint inputs. Credential rotation stays in its editor.
- Mode includes chat, completion, embedding, speech, transcription, image, video
  and rerank when the corresponding route is actually qualified.
- A model detail view can expose Overview and sanitized configuration JSON,
  with test, credential rotation/reuse and removal actions. No secret or raw
  engine object may appear in that JSON. A provider host shown in a screenshot
  is reference material, not authorization to access that host.

## D1 — independent credential state (recommended; pending)

Reuse the encrypted private engine, not a new CP secret vault. A credential with
no models is saved with models=[] and enabled=false, explicitly enforced by API,
DB constraint, native key spec and exact readback. Successful synchronization is
shown as Saved / Untested, never a successful inference test. Saving cannot need
an inference preflight when there is no selected model. Test Connect remains in
Add Model; adding the first model requires test and explicit activation before
team policy can use it. Empty credentials cannot be enabled from the list.

Pending/error states deny use; provider/endpoint remain immutable, all writes
retain organization ownership and revision checks, and existing rotation,
reference-removal, tombstone and uncertain-write behavior is preserved. Removing
the final model requires disabling in the same transaction. Migration rollback
must refuse while empty credentials remain, never delete them.

Verified pinned Bifrost e4a30d6041c0446603aea615bc5da340dac001b1:
core/schemas/account.go WhiteList.IsAllowed implements empty as deny-all.
core/bifrost.go:8819 has a contradictory stale comment; executable checks at8852
win. Model-less operations skip that filter, so explicit disabled is mandatory.
Provider creation defaults omitted enabled to true: always send enabled:false.
Disabled creation skips automatic catalog refresh (server.go:941–967 and its
upstream disabled-provider regression). These are source findings, not live proof.

Change credential-specific validation only; team policy still requires models.
Affected source: openapi AIProviderInputModels, migration0141 constraints (new
migration, no historical edit), aigateway/providers.go and engine_providers.go.
Regenerate API types. Prove restart/readback, zero upstream calls, denied use,
first-model activation, final-model removal, rotation/assignment races and tenant
isolation against the actual pinned engine before declaring this complete.

## D2 — mode-aware routing (recommended; pending)

Retain current Bifrost encrypted credentials and saved-inference accounting;
reuse its pinned completion/embedding/speech/transcription/image/video/rerank
adapters. Use the matching actual LiteLLM method for preflight. Do not replace
runtime infrastructure just to populate a selector.

Persist per-model mode with chat as the backwards-compatible default. Bind
inference admission and preflight to that mode. Add generated OpenAPI contracts,
mode-specific request bounds/content types, response handling and usage units;
unknown monetary prices continue to refuse monetary-policy requests.

The current Tunnex adapter accepts only chat/messages, JSON text-only input and
JSON/SSE output. Token-only pricing readiness is insufficient for embeddings,
image/second/query prices. Multipart transcription, binary speech and external
media URLs require explicit size/type/egress rules. Do not pass arbitrary URLs
or arbitrary LiteLLM parameters through a generic JSON escape hatch.

Video is asynchronous: create/status/content needs a tenant-owned opaque job
mapping, authorization again on every read, idempotent submission and terminal
cost attribution. Provider job IDs cannot become cross-tenant bearer handles;
the existing 30-second stream contract cannot be silently relaxed.

Qualify JSON completion/embedding/rerank, then binary/multipart/image, then
asynchronous video as separate reviewed slices. All remain requested scope;
unsupported modes must not appear as enabled controls ahead of working routes.
Azure Foundry's saved URL/authentication integration remains the separately
identified routing decision, not solved by this dropdown.

## Disposition boundary

D1 changes Save semantics from tested model-scoped credentials to inactive,
untested independent credentials. D2 introduces persisted mode, additional
content protocols, pricing units and tenant-owned asynchronous jobs. These are
material state/security decisions under CLAUDE.md's mid-build fork rule. The
requested surface is understood; confirm these recommended backend boundaries
before the dependent implementation. Existing authorized UI fixes continue.

## D3 — provider breadth (recommended; pending with routing contract)

The user calls out LiteLLM's 20–30-provider selector. Current Tunnex supports nine
native provider definitions plus Custom and SageMaker. The pinned LiteLLM field
registry contains117 entries; that is a source inventory, not117 qualified Tunnex
providers. Reuse the upstream registry, brand assets and provider-specific field
metadata, with explicit backend capabilities controlling availability.

Expand supported provider families through actual native adapters or the approved
private SDK routing path, including provider-specific endpoint/auth/version,
credential persistence, preflight AND saved inference. API-key, regional AWS IAM,
Azure API-version/Target URI and service-account credentials are different typed
contracts. No public menu count or logo can substitute for those contracts.
Do not silently expose arbitrary LiteLLM options or delegate tenant authorization
to client-supplied configuration. Qualify each added family with deterministic
adapter tests and label outstanding live-provider proof honestly. Existing models,
keys, usage and team access must survive the additive migration.
