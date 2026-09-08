# Saved credentials: onboarding and model test validation

Local branch `ai-improvement`, 2026-09-08. Decision commits `7063d346` and
`7b4aa384` precede implementation. This records this correction, not full LiteLLM
parity or story-end acceptance.

## Behavior

- Add Model offers usable saved credentials before a provider is selected.
  Selection chooses the provider, clears draft secrets and hides endpoint,
  credential-name and API-key inputs. The native engine retains the saved key.
- A saved credential can test an existing or new exact model. The bounded private
  operation checks organization ownership, expected revision, enabled/applied
  state and immutable endpoint. Testing changes neither serving model scope nor
  team access. Only Add Model saves the expanded model list.
- HTTP 200 plus a successful result emits Sonner
  `Test connection successful · HTTP 200`, retains inline feedback and enables
  Add Model. Error envelopes and stale responses cannot produce success. Results
  expire after five minutes and invalidate on relevant form/revision changes.
- The public OpenAPI operation supports either a new key or saved connection ID
  plus revision. The control plane never receives a stored key. The private
  native engine resolves it and calls the existing LiteLLM SDK bridge.

## Builds and regression evidence

| Check | Result |
| --- | --- |
| Focused `aiproviderworkspace.test.tsx` | 68 passed |
| Full web Vitest suite | 119 files, 1,436 tests passed |
| Web TypeScript and Vite production build | Passed; existing bundle-size warning |
| API `internal/aigateway` and `internal/http`, open edition | Both packages passed with isolated PostgreSQL |
| Same API packages, enterprise edition | Both packages passed with isolated PostgreSQL |
| Focused enterprise race checks | Passed |
| API Linux arm64 builds, both editions | Passed |
| OpenAPI generation, two deterministic passes | Passed; generated Go/TS clients included |
| LiteLLM bridge full SDK suite | 106 passed |
| Final native saved-key Foundry wire cases | 3 passed after final auth-helper/mode-refusal change |
| Extended native macOS and Linux image builds | Passed |
| `git diff --check` | Passed |

The full SDK run preceded the final test-helper deprecation cleanup and stricter
invalid-mode case. All three affected saved-key cases were then rerun and passed.
They cover `openai.azure.com`, `services.ai.azure.com` and
`cognitiveservices.azure.com`, using a new Llama model outside the saved key's
allowlist. The actual engine, SDK, authenticated CONNECT proxy and TLS fixture
are involved. Native unauthenticated, revision/endpoint mismatch, injected-key,
wildcard and malformed-mode requests are refused; key readback stays masked and
the original serving allowlist stays unchanged.

API database tests used `COMPOSE_PROJECT_NAME=tunnexai0907`, labelled container
`tunnexai0907-postgres-1` and network `tunnexai0907_default`. Both editions' package
runs and the new HTTP selector tests used this isolated database.

Native source pin: `9537b2fadf42af90eb34ed47d3d4252e1beff4a0`
(Bifrost transports v2.0.0). The extension is one administrator-protected route.
Upstream LICENSE and third-party notices ship in the image. Official unmodified
artifacts remain available; older engines refuse the new operation.

Built Linux image:
`sha256:e28b4efe0350536d313d2e9b41ad1c52f32f6c43c1d95472d3961eb8b89c192b`.
Local enterprise API binary SHA-256:
`c325a297e100b26ba49e55420fe86b94192f10cdf6c1adbf229e04809f4de493`.

## Local browser and running stack

The verified preview is `http://127.0.0.1:5180/agents/ai-gateway`, backed by
`tunnexaiwalk0907repro4` and network `tunnexaiwalk0907repro4_engine`.
A separate verification tab selected `LiteLLM preflight (fixture)` before a
provider, automatically selected Custom provider and hid key/endpoint inputs.

Both saved `private-demo` and unsaved `private-demo-new` passed Test Connect through
the running Linux engine and bridge. The exact HTTP 200 toast was observed in the
DOM, and Add Model was enabled. No Add Model submission was performed. The draft
was cancelled and only the verification tab was closed.

- [Saved credential, inline success and enabled Add Model](walk-artifacts/ai-saved-credentials-20260908/saved-model-test-200.png)
- [HTTP 200 toast capture](walk-artifacts/ai-saved-credentials-20260908/saved-model-toast-200.png)

The toast capture catches its entrance animation near the viewport edge; the
exact visible toast text and enabled button were separately asserted.

Final read-only verification confirmed schema `148`, clean, and byte-identical
whole provider-row fingerprints before cleanup and after all tests. The local
stack had three fixture credentials/four models before and after. No real Azure
credential was read or submitted. This proves the local flow and synthetic wire;
the user's actual Azure deployment remains to be tested through the UI.

## Approved Docker capacity work

Only Docker context `colima-tunnex-sso-review` was changed. Approved cleanup
removed build cache, 28 stopped/created containers and unused images. No volumes
were deleted. The VM disk grew from 8 GB to 16 GB, with a VM restart; macOS was
not restarted. Final Docker data-mount usage was 11 GB used, 4.0 GB available.

All 12 running services were restored. The updated engine is healthy and the
control plane health request returned HTTP 200. A stopped original engine
container is deliberately retained for rollback with its preserved volumes.
After restart, the synthetic fixture IP changed; only its two existing approved
destination CIDRs were updated to the actual fixture IP. Public endpoint policy,
protected-host rules and denied networks were preserved.

A backup-admin-password diagnostic was rejected by automatic approval review
before execution because that credential source was not authorized for the
diagnostic. It was not retried. Normal UI testing and scoped read-only checks
identified the fixture routing issue and proved the repaired flow.

## Remaining acceptance

Full composite repository gates, remote CI and real-provider qualification were
not completed in this slice. Full LiteLLM engine migration, broader provider
forms/model-less credentials and model-detail parity remain earlier outstanding
work. No push, PR, merge, release or cloud deployment is included. The refreshed
local UI is ready for the user's Azure test and visual review.
