# Model mode routing — execution contract

The user again explicitly requests all eight LiteLLM modes in the model selector
on September 8,2026, alongside the already requested working model-call proxy.
Execute the previously proposed D2 mode routing work using the retained native
engine and matching LiteLLM SDK preflight methods. This does not authorize an
engine cutover, secret export, cloud action, release or merge. Independent empty
credentials and the full LiteLLM proxy cutover remain separate work.

## Locked boundaries

1. OpenAPI mode values are `chat`, `completion`, `embedding`, `audio_speech`,
   `audio_transcription`, `image_generation`, `video_generation`, `rerank`.
   Add optional per-model `model_modes` to provider writes/readback. Keys use the
   same names as `models`, normalized to the connection namespace together. On
   create, omitted entries default to chat. On update, omitted entries preserve
   retained model modes; new models default to chat. Unknown/extraneous map keys
   and modes are rejected. Old records use an empty JSON object and resolve chat.
   A mode change of a model referenced by a team policy is refused, like removal;
   remove the policy reference before changing that model's protocol.
2. Current organization, actor, revision, ownership, key, model and endpoint
   checks remain authoritative. Different modes for the same exact model across
   the credentials selected by a policy are ambiguous and deny admission. The
   resolver returns a trusted model mode; the adapter compares the request path
   with that mode. The existing Anthropic messages route is a chat alias. Legacy
   operator-owned models remain chat. Mode is never inferred from a client header.
3. Add the seven nonchat POST routes under `/ai/v1` with explicit OpenAPI
   documentation and existing scoped bearer auth. Reuse pinned native adapters;
   do not implement provider protocols. No generic JSON or remote-media passthrough.
   JSON completion, embedding and rerank are the first qualification slice,
   followed by media and asynchronous video. Enable choices only after their
   actual route/preflight behavior has been qualified.
4. Custom/Foundry provider operation sets must be explicitly reconciled, under
   the existing native-provider lock, retaining exact endpoint/proxy/TLS and key
   state. Never drop the operation allowlist. Only the eight requested operation
   families, their stream forms, catalog, and necessary video status/content are
   eligible. Existing chat configurations need verified additive reconciliation;
   neither unrelated native configuration nor unexpected operation grants may
   be overwritten. Saved SageMaker adapters remain limited by the installation's
   actual SDK model binding and provider support, not a menu label.
5. Preflight includes an explicit mode defaulting chat. Dispatch the matching
   LiteLLM method, with a short fixed prompt/input or bundled tiny audio fixture,
   bounded output and mode-specific response validation. Keep subprocess isolation,
   credential/destination restrictions, admission limits and sanitized results.
   Video success means job accepted, not generation completed. A successful check
   for one provider/model/mode cannot qualify a different one. Changing mode
   invalidates prior test success and catalog results.
6. Preserve the 30-second request lease, four active calls per tenant/agent and64
   global. JSON requests remain256KiB; media uploads are bounded to8MiB with one
   locally supplied audio file and supported MIME types. JSON/media responses
   have finite bounds; no redirects, arbitrary headers or provider URL fetching.
   Image outputs may return bounded data or a provider result URL without fetching
   it. Binary speech/transcription handling must not be treated as chat JSON/SSE.
7. Video needs a tenant/agent/model-owned opaque job ID, reauthorization on every
   status/content request, submission idempotency, bounded retention and explicit
   handling of uncertain submission. Raw provider IDs must not be bearer handles.
   Polling must not resubmit generation; revocation blocks subsequent reads. Video
   is not enabled before this lifecycle has its own wire proof.
8. Existing observed accounting is retained. Token-priced completion/embedding
   needs the correct input/output readiness checks. Non-token-priced modes fail
   monetary-policy admission until their actual price units and terminal cost
   attribution are qualified; no unknown-to-zero conversion or strict-cap claim.
   The reference catalog is mode-filtered metadata, never invoice accounting.

## Verification sequence

Commit this contract before code. Implement disjoint backend persistence/native,
SDK preflight and UI lanes, with central adapter/OpenAPI integration. Prove default
chat compatibility, namespace and tenant boundaries, cross-mode refusal, revision
conflicts and retained-key behavior before adding media/job handling. Both API
editions, isolated PostgreSQL, actual pinned native fixtures, SDK fixtures and web
checks are required. Preserve user data in the local preview; no automatic paid
test. Update the committed handoff with exact completed and remaining slices.
