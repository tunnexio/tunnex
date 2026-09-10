# Public endpoints and automatic LiteLLM catalog search

Date: 2026-09-08. Local branch `ai-improvement`. Papers `48a5dd25` and `a06e30aa`.

## Result

Public HTTPS/443 Custom and Azure endpoints can be entered without registering
each destination. The installation enables `public_https`; the authenticated
proxy validates DNS/IP safety at every dial. Existing rules retain precedence;
private/internal destinations retain explicit network configuration. Foundry
accepts the OpenAI v1 resource suffixes `services.ai.azure.com`, `openai.azure.com`
and `cognitiveservices.azure.com`.

Unsaved Azure model search uses a pinned LiteLLM reference catalog without an
endpoint or key. 71 eligible Azure chat model names; `gpt-5` matches29. This is not
Azure deployment discovery. Saved credentials keep their scoped endpoint catalog.
Custom/SageMaker drafts can fetch a bounded authenticated endpoint catalog before
saving; those requests do not persist the key or run inference.

The user subsequently requested automatic search. Search has a500ms typing
pause; no Search button, automatic retries or paid inference. Responses from old
queries/provider selections cannot replace the current query's results.

## Verification

- Both API editions: affected aigateway/aiegress/HTTP race tests passed.
- Actual isolated PostgreSQL `TestAISelfServiceProvidersPostgres` passed in open
  and enterprise/race. `COMPOSE_PROJECT_NAME=tunnexai0907`, labeled postgres and
  `tunnexai0907_default` verified before the database-capable command.
- 74 Python bridge tests passed, including synthetic TLS/CONNECT and draft catalog.
- Pinned native Bifrost `TestEngineNativeCustomProxy` passed HTTP, HTTPS and
  Foundry v1 cases. Stopping the fixture proxy refused further traffic.
- Generated OpenAPI Go/CLI/TS, RBAC and sqlc outputs reproduced in a second pass
  with zero drift across50 generated files.
- 45 focused and1,377 full web tests/118 files, typecheck and Vite build passed.
  Automatic search, stale results and dismissal behavior have regressions.
- Helm lint, public-mode empty rules, protected host emission, disabled-mode
  refusal, invalid type and explicit Foundry endpoint schema/render checks passed.

## Local process walkthrough

Updated only the existing isolated local CP/egress binaries and SDK bridge.
`COMPOSE_PROJECT_NAME=tunnexaiwalk0907repro4`, both labeled CP/postgres containers,
`tunnexaiwalk0907repro4_engine` and existing PG volume verified first. Schema146
remained clean. Provider metadata digest was identical before/after:3 credentials
and4 models. Old host binaries and policy retained; no volume cleanup.

A separate browser tab preserved the user's draft. Selecting Foundry and typing
`gpt-5` returned29 suggestions with empty endpoint/key. A synthetic cognitive
resource URL and synthetic key enabled Test Connect without an approval prompt.
No test was submitted to Azure and no credential/model was saved during this walk.
Screenshot: `walk-artifacts/ai-gateway-20260908/public-foundry-ready.jpg`.

## Limits and next action

These are synthetic/local proofs, not actual Azure credential or deployment
qualification. This slice does not add nonchat inference, replace observed cost
accounting with reference prices, or complete the full LiteLLM proxy migration.
Full composite final gates and exact-head remote CI remain unproven; no push,
merge or release occurred. User now requests all eight model modes; that work
continues with persisted mode, matching preflight and bounded proxy routing.
