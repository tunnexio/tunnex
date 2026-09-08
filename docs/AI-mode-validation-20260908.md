# Eight model modes — local qualification, September8,2026

The requested Mode dropdown now offers Chat, Completion, Embedding, Audio speech,
Audio transcription, Image generation, Video generation and Rerank. Selected
modes are saved per exact model, used by Test Connect and enforced by the scoped
model-call proxy. The existing chat default and saved credentials are preserved.
This completes the requested mode slice, not full LiteLLM parity or cloud qualification.

Decision contract: `docs/S-AI-mode-routing-decisions.md`, committed before product
changes (`41a29d45`, numerical video bounds `3ff524b9`). Public endpoint entry and
automatic search slice: `17f7e4c6`; evidence in
`docs/AI-self-service-validation-20260908.md`.

## Verified behavior

- Mode mappings normalize with connection-owned model names. Missing modes default
  to chat on creation and preserve retained modes on update. Referenced model mode
  changes and ambiguous policies are refused. Migration147 defaults old rows to an
  empty map; rollback refuses nonchat mappings, including tombstones.
- The eight actual LiteLLM1.100.0 SDK methods are used for preflight. There are fixed,
  bounded inputs and output checks; tests do not export keys or invoke a real provider.
  Video success reports job acceptance, not completion. SageMaker's existing private
  installation binding remains chat-only and rejects other preflight modes.
- Pinned Bifrost routes all eight modes through an authenticated CONNECT fixture.
  HTTP/HTTPS/Foundry native configuration reconciliation retains saved keys and
  rejects unexpected operation grants. The speech handler's fixed MP3 response
  label is normalized to the validated requested format; actual WAV bytes are preserved.
- Raw API routes enforce current identity/model/mode before forwarding native keys.
  Unknown or duplicate JSON fields, cross-mode requests, foreign tenant/agent access,
  multipart routing headers and unsupported MIME types are refused. Uploads permit
  one audio file up to8MiB; output sizes, socket deadlines and concurrency are bounded.
- Video uses persistent opaque UUIDs and scoped idempotency keys. Concurrent repeats
  submit once; conflicting payloads fail. Status/content reauthorize the exact model.
  Revocation and job expiry stop reads. Uncertain submissions retain their handle
  and never automatically resubmit.24h replay retention,64 nonterminal jobs per
  agent,4096 globally retained rows and128-row expiry cleanup are tested. Migration148
  rollback refuses unexpired handles. Provider IDs, prompts and content are not public
  handles or stored request payloads.
- Nonchat reference search uses668 provider/model/mode rows derived from the same
  pinned LiteLLM catalog source as the Azure reference; mode filtering precedes
  pagination. Reference names do not imply deployment availability or billing rates.

## Checks and evidence

| Check | Result |
| --- | --- |
| Both API editions, affected mode/provider/catalog/HTTP tests with race detector | Passed with verified isolated PostgreSQL project `tunnexai0907`; open17.761s, enterprise18.261s for the aigateway package in the combined runs |
| Additional real-router mode/OpenAPI/video tests, both editions with race detector | Passed; logs `tunnex-mode-routes-open.log`, `tunnex-mode-routes-enterprise.log` |
| Actual pinned Bifrost nonvideo and video lifecycle fixtures | Passed; Adapter→Bifrost→authenticated CONNECT→synthetic provider, video backed by migrated disposable PostgreSQL |
| LiteLLM SDK bridge suite |97 tests passed, including actual SDK request construction beneath locked synthetic transports |
| Web tests |59 focused component tests; full1391 tests across118 files passed |
| Web TypeScript and production build | Passed; existing chunk-size advisory remains |
| API builds | Community Linuxarm64 preview and enterprise server builds passed |
| OpenAPI→Go/CLI/TypeScript/RBAC/sqlc generation | Two passes,50 generated files, second pass zero drift |
| Independent integration review | Job-retention deadline and response-MIME schema findings fixed and re-reviewed; no remaining finding from that review |

Local nonsecret logs are under `/private/tmp/`: `modes-combined-open-final.log`,
`modes-combined-enterprise-final.log`, `tunnex-mode-routes-{open,enterprise}.log`,
`tunnex-adapter-modes-native.log`, `tunnex-adapter-video-native.log`,
`tunnex-ai-video-race-{open,enterprise}.log`, `tunnex-ai-bridge-mode-tests.log`,
`tunnex-mode-ui-{web-tests,typecheck,build}.log`, `modes-final-{typecheck,build}.log`
and `modes-codegen-final.log`. Logs are not credentials or required runtime inputs.
Native proof includes original chat, six additional synchronous routes and the
full create/status/content video path; substitute SDK mocks alone were not counted
as that proof.

## Local UI and preserved data

URL: `http://127.0.0.1:5180/agents/ai-gateway`.
Docker context `colima-tunnex-sso-review`, project `tunnexaiwalk0907repro4`, network
`tunnexaiwalk0907repro4_engine`, labelled PostgreSQL volume
`tunnexaiwalk0907repro4_pg` verified before any database command. Only this preview
was migrated from146 to148; schema clean. Existing3 credentials/4 models compare
identically after excluding the new default-empty mode column. No video job or
real provider inference was created during preview validation. SDK preview was
restarted using its existing private environment file; neither keys nor envfiles
were copied into the repository.

Rendered UI inspection confirms all eight enabled options and two automatic
`text-embedding-3` suggestions in OpenAI Embedding mode, without clicking Search
or supplying an endpoint/key. Screenshot:
`docs/walk-artifacts/ai-gateway-20260908/eight-mode-selector.jpg`.

## Limits and next action

Provider/model support differs; choose the model's supported mode and run an
explicit Test Connect with the user's own credential. No live Azure/AWS/media
provider qualification was performed. Non-token modes refuse monetary-policy
admission until their price units and terminal cost attribution are qualified;
unknown usage is not zero and soft thresholds are not strict spend caps.

Serving inference still uses pinned Bifrost; preflight reuses actual LiteLLM SDK.
Independent model-less credentials, wider provider onboarding, richer payloads and
full LiteLLM engine migration remain separate work tracked in the coverage ledger.
Full composite repository gates and exact-head remote CI are not proven here.
No push, merge, release or cloud action occurred. Next action: run the user's
chosen Azure model/deployment and supported mode through explicit UI Test Connect,
with the real key entered by the user; capture sanitized provider evidence.
