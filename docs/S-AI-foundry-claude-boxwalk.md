# Foundry Claude catalog and protocol verification — 2026-09-08

Decision record: [S-AI-foundry-claude-decisions.md](S-AI-foundry-claude-decisions.md).
Paper commit: `fac254ab`; implementation based on `8df6c5c0` on `ai-improvement`.

## Observed behavior

The local UI at `http://127.0.0.1:5180/agents/ai-gateway` now returns six Opus
suggestions under Azure AI Foundry, including `claude-opus-5`. Exact-name search
returns that one model without pressing a search button. The portal Messages
URL is accepted without rewriting its protocol. A synthetic key enables Test
Connect; clearing it disables the button. No test request was sent to Azure.

Screenshots captured and visually inspected:

- [Exact Claude catalog result](../walk-artifacts/ai-foundry-claude-20260908/catalog.png)
- [Endpoint and Test Connect readiness](../walk-artifacts/ai-foundry-claude-20260908/test-ready.png)

The masked value in the readiness screenshot is a disposable synthetic string,
not an Azure key. It was cleared after verification. Existing credential and
model counts remain four and five respectively; no Claude credentials or model
were saved by this walkthrough.

## Actual adapter fixtures

The SHA-verified native Bifrost v2.0.0 binary ran all four custom proxy fixtures:
HTTP, HTTPS, Foundry OpenAI v1 and Foundry Anthropic. The Anthropic case uses a
locally issued TLS certificate and synthetic Azure hostname, with the mandatory
authenticated CONNECT proxy routing solely to the local fixture. Production
provider configuration is loaded at engine startup, then verified through the
production readback path. Creation-time external Azure DNS is not exercised by
this fixture.

Observed `/anthropic/v1/messages`, exact deployment names, `x-api-key`,
`anthropic-version`, native chat translation and streaming translation. Absent,
stopped and malformed proxy paths fail without directly contacting upstream.
Existing OpenAI fixtures pass unchanged.

The real installed LiteLLM SDK runs draft and saved-key tests against local TLS
fixtures for all three supported Azure hostname suffixes. Exact arbitrary
deployment aliases and `claude-opus-5` use Anthropic Messages; OpenAI catalog
and inference cases retain their existing protocol. Saved-key tests traverse
the private extended engine and verify serving scope is preserved. Generic
Custom/SageMaker Azure Anthropic inputs and non-chat Foundry Anthropic requests
are refused before worker dispatch.

These fixtures prove adapter behavior with synthetic servers. They are a
SUBSTITUTE for live Azure inference, not a live Azure success claim. The named
remaining proof trigger is the operator entering the intended resource's key
and running Test Connect for `claude-opus-5` in the updated preview.

## Verification ledger

- API: full `go test -count=1 -p 1 ./...` in both open and enterprise editions.
  After the catalog fold, both editions reran `internal/aigateway`,
  `internal/http` and `internal/aiegress`; all passed.
- Catalog regressions: merge older native matches with newer references,
  preserve saved deployment aliases, deduplicate and page once. A real Engine
  HTTP-client test covers 101 native models across two bounded pages.
- Native: `TestEngineNativeCustomProxy`, all four subtests passed against the
  pinned binary, including chat and SSE behavior.
- Bridge: all 121 tests passed using the real installed SDK and private saved
  probe binary. Non-applicable Claude catalog combinations are excluded from
  the parameter matrix, not counted as successful wire tests.
- Both open and enterprise API builds (`go build ./...`) passed.
- Web: full suite 1,454 tests across 121 files passed; final affected suites
  reran 108 tests after the Custom-provider validation fold. Typecheck and
  production build passed.
- Code generation: all seven pinned generators ran twice over 50 generated
  artifacts; the second pass had zero drift. The large generated Go diff is
  the compressed embedded OpenAPI description update, not a public type change.
- Independent protocol and catalog reviews were repeated after the two
  user-approved fixes. No introduced findings remain. The decision paper holds
  one pre-existing non-chat catalog follow-up for separate disposition.

No node-agent/helper/client code changed. Their platform/fleet gates and remote
CI were not rerun in this local AI slice. No push, PR or merge was performed.

## Local rollout and preservation

Only the isolated `tunnexaiwalk0907repro4` preview API and dedicated local SDK
bridge process were reloaded. No Mac or Docker VM restart. Before any database
read, the non-default project label, running container and network were verified.
The previous API binary and database dump were saved privately outside Git.

Provider-row fingerprints before/after are identical; schema remains version
150 with `dirty=false`. The test database is separately isolated under
`tunnexai0907`, verified by its runner. No provider keys, private environment
files, database dumps, or other credentials are included in committed evidence.

Loaded Linux API SHA-256:
`5ed8f068cd410c3b3af28f84d6f190d95e5a7098a4d2304fd666ab6a713cab92`.
