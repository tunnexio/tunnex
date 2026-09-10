# Multi-provider onboarding validation — 2026-09-07

Branch: `ai-improvement`; paper `e46a9255`; generated API contract `c9586549`. Local implementation only; no push,
merge or release. This extends the prior provider slice (`3d988133`) and includes
the approved drawer/theme refinement (`6a069f09`).

## Implemented boundary

OpenAI, Anthropic, Gemini and OpenRouter use their own native adapters and keys.
The authenticated CP inventory supplies the provider forms; OpenAPI generates all
public types. Add provider opens the shared themed right drawer. Models inventory
supports search, provider filters and adding models through an existing credential
connection without re-entering its secret. Canonical API names remain exact
provider/model identifiers, without public aliases or implicit fallback.

Connection provider is immutable, model coverage is provider-scoped, and legacy
references cover OpenRouter only. Virtual-key scopes retain the same credential
and retained provider-config IDs through provider additions/removals. Persistent
and runtime readback must match. Price lookup uses the selected provider and
model suffix; native model-cost histograms may aggregate identical model names
across providers, and the UI does not claim provider-separated spend.

Migration 0142 expands the provider constraint, preserving existing 0141 ownership.
Rollback refuses non-OpenRouter retained connections (including tombstones) or
team policies. No secrets were copied into CP persistence or browser state stores.

## Verified checks

- Web: 117 files, **1,339 tests PASS**; TypeScript and production build PASS.
  Logs: `/private/tmp/tunnex-ai0907-runtime/multiprovider-web.log` and
  `multiprovider-web-build.log` (existing bundle-size advisory remains).
- Both API editions compile with `GOWORK=off GOFLAGS=-mod=readonly`; final native
  code is included. Linux arm64 preview build also passes.
- Focused PostgreSQL/race: open 9.322s, enterprise 10.703s; final open delta 3.884s
  adds the rollback guard assertion. Commands use `run-go.py`, `-p 1`, with verified
  project `tunnexai0907`, container `tunnexai0907-postgres-1`, network
  `tunnexai0907_default`. Logs: `/private/tmp/tunnex-multiprovider-open.log`,
  `tunnex-multiprovider-enterprise.log`, `tunnex-multiprovider-open-final.log`.
- HTTP schema/auth/race: open 3.616s and enterprise 3.120s. Supported providers
  reach the handler; unsupported ones fail validation; authorization precedes
  validation and errors do not expose secret-bearing payloads.
- Pinned native suite: `AI0_BIFROST_BINARY=/private/tmp/tunnex-ai0-bifrost-v2.0.0`
  with `go test -race ./internal/aigateway -run 'TestEngine|TestProviderEngine'
  -count=1` PASS 25.200s. Binary SHA256
  `31ac451d83706069e580dd1dedf099aa518d1bc47c3c481d20f97203f799275e`.
  Log: `/private/tmp/tunnex-ai0907-runtime/core-four-native-final.log`.
  Each provider's real adapter was exercised against local synthetic upstreams:
  auth/catalog, good/bad rotation, strict JSON and terminal SSE, mixed scope
  add/remove, forbidden model without upstream arrival, retained IDs and restart.
  Zero paid provider calls. These are protocol fixtures, not real-account proofs.
- Generated drift guard: two passes, 50 hashed files, zero drift on each final
  pass (API, CLI, TS, RBAC, tokens, sqlc). CLI suite PASS with loopback permission;
  its first sandboxed attempt was blocked by test-server bind permissions.
- Full database/API gates remain **INCONCLUSIVE** from the previously recorded
  Docker VM capacity blocker. No full-gates or remote exact-head CI claim.
  No VM resize, unrelated SSO restart, cloud operation or infrastructure deletion.

## Local rendered walk

Actual CP at `http://127.0.0.1:5180/agents/ai-gateway`, isolated project
`tunnexaiwalk0907repro4`, network `tunnexaiwalk0907repro4_engine`.
Migration readback: `142`, dirty `false`. Final Linux preview binary SHA256:
`582e84155e3c2bf1e126ddd4002a5d2d7a395871c4b838443bd47d59e4ce44e9`.
Only its task-owned API process was refreshed; an inactive prior binary was
replaced after verifying its private host backup. Engine/SSO processes unaffected.

Verified four provider choices from live API, Anthropic-specific key field and
cached model search, shared drawer with fixed actions, and model inventory.
Added `openrouter/openai/gpt-4o` using existing **Engineering demo (fixture)**
credential without submitting a secret. Prior `gpt-4o-mini` remains; both applied.
Demo connection is still unassigned to team policy. Usage remained unchanged:
8 requests, 56 tokens (32 input, 24 output), estimated $0.000170. Browser width/document width
both 857px; reviewed screenshots show the drawer and model table.

- [Provider picker](walk-artifacts/ai-gateway-20260907/multiprovider-drawer-local.jpg)
- [Model inventory](walk-artifacts/ai-gateway-20260907/multiprovider-models-local.jpg)

## Review dispositions and remaining qualification

Independent UI/CP and native reviews were completed. One P2 proof finding was
folded within the frozen acceptance contract: substring-only native success was
replaced by strict JSON assistant content/finish checks and terminal SSE checks.
The folded proof and retained config-ID verification were re-reviewed with no
additional findings; the native race suite was rerun. UI review also tightened
255-character schema alignment, selected-provider draft preservation and refusal
to reuse pending/error connections without resubmitting their key through Edit.

Azure, Bedrock, Vertex, custom upstream URLs and public aliases require separate
credential/origin/mapping contracts. Other API-key providers need qualification
before inclusion. Real OpenAI/Anthropic/Gemini account smoke, full local gates,
exact pushed-head CI, and explicit merge/release approval remain outstanding.
Next action: resolve the recorded Docker capacity blocker, then run required full
gates before any separately approved push/PR and exact-head CI.
