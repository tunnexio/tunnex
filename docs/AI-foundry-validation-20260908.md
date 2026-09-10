# Azure Foundry provider validation — 2026-09-08

Local implementation on `ai-improvement`, following paper commit `a95f605e`.
The content SHA is recorded in PLAN.md after this implementation commit.
No push, merge, release or Azure infrastructure operation occurred.

## Implemented behavior

The provider picker includes **Azure AI Foundry (OpenAI v1)** with the Azure
logo. Add Model and Add Credentials accept an actual Azure API base, raw model
deployment name and write-only Azure API key. Existing Credentials hides the key
and endpoint fields. Test Connect precedes creation; changing the endpoint clears
the draft key and invalidates the previous result.

Supported API base examples (placeholders, not configured destinations):

```text
https://YOUR-RESOURCE.services.ai.azure.com/openai/v1
https://YOUR-RESOURCE.openai.azure.com/openai/v1
```

The UI normalizes the base to `/openai`. The LiteLLM preflight and saved native
inference each append `/v1/chat/completions`, send the raw deployment name, and
use Bearer authentication with the actual Azure key. The existing per-connection
custom UUID model namespace and organization/team authorization remain in force.
Provider metadata, API schemas, generated Go/TS clients, persistence constraints
and the egress policy all recognize `azure_foundry`.

## Verification

| Subject | Result and practical boundary |
| --- | --- |
| Web | 32 focused provider tests; 1,364 tests in 118 files; typecheck and production build pass. Final CSS adjustment built and visually inspected. Existing bundle-size warning remains. |
| Go API | Focused provider/Foundry/egress/HTTP tests pass in both open and enterprise editions. Both complete API editions compile. |
| PostgreSQL | `TestAIFoundryProvidersPostgres` passes against actual isolated PostgreSQL, open and enterprise (enterprise with race detector). Covers persistence, connection model scope, foreign tenant refusal, policy admission, endpoint reclassification and rollback refusal with tombstones. |
| LiteLLM bridge | 55 tests pass, including 29 new Foundry cases. Actual pinned LiteLLM 1.100.0 OpenAI SDK sends the expected path/model/Bearer key through authenticated CONNECT/TLS against synthetic Azure-hostname fixtures. No Azure call or billing proof. |
| Native saved inference | `TestEngineNativeCustomProxy` passes with the pinned Bifrost v2.0.0 binary, including the new `FoundryOpenAIV1` fixture. Verifies `/openai/v1/models`, chat path, raw model, Bearer key, streaming/nonstreaming and proxy refusal behavior against a local synthetic upstream. |
| Generation | OpenAPI Go/CLI/TS, RBAC, tokens and sqlc generators pass; two passes produce no drift across 50 hashed generated files. Cached pinned generators used without dependency installation. |
| Review | Independent Go/API/schema/UI review found no blocking issue. Root reviewed SDK classification and endpoint/key UI. This is a provider slice, not full-epic qualification. |

The final package-manager wrapper attempted a network/dependency check and exited
before building. The existing installed `tsc -b` and `vite build` were then run
directly and passed; no dependency reinstall or lockfile change was made.

Focused database verification checked `COMPOSE_PROJECT_NAME=tunnexai0907`, the
`tunnexai0907-postgres-1` label and `tunnexai0907_default` network before access.
Each integration test created its own temporary database and applied migration
0146. No shared/default database was migrated by those tests.

## Local preview

The existing local CP at `http://127.0.0.1:5180/agents/ai-gateway` now serves this
provider. Docker context `colima-tunnex-sso-review`, project
`tunnexaiwalk0907repro4`, CP/engine container labels, engine network and the
project's PostgreSQL volume were verified before the targeted update. The API,
egress executable and host SDK bridge were updated; prior executables remain.
The CP schema moved from 145 clean to 146 clean. A before/after digest of provider
rows was identical: three credentials and four models remain. No engine cutover,
volume cleanup or VM resize occurred.

Rendered screenshots were inspected:

- [Provider picker](walk-artifacts/ai-gateway-20260907/foundry-provider-local.jpg)
- [Endpoint and Azure key fields](walk-artifacts/ai-gateway-20260907/foundry-endpoint-local.jpg)

The local picker correctly displays **Setup required**. The user's reply supplied
no actual resource URL, so no destination was invented or added to the allowlist.
Test Connect and Add Model remain disabled until the installation configuration
and required form fields are valid. The UI has not been approved by the user yet.

## Limits and next action

This slice supports OpenAI v1 chat completions only. Legacy `/models`, dated
deployment/API-version URLs, Anthropic Messages, Entra identity, sovereign clouds
and additional inference modes are unsupported. The bounded probe uses
`max_tokens=16`; models needing another token parameter, including o1, need
separate support. A passing first-model probe does not certify all selected models.

The earlier full LiteLLM OSS proxy migration, independent model-less credentials,
additional modes/provider adapters and model details remain pending. Full
composite gates and exact-head remote CI have not been established for this
checkpoint. Synthetic transports and local PostgreSQL are substitutes for Azure
qualification; the trigger for that proof is the user's actual Foundry test.

**One next action:** obtain the user's actual Azure resource URL, configure that
exact normalized destination as `provider: azure_foundry` with approved IP ranges
in the existing CP/egress and SDK bridge installation policy, and then have the
user enter their deployment name and key in the UI for Test Connect. Keep the
actual key out of chat, logs, screenshots and Git.
