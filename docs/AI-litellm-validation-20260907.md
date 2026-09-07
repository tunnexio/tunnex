# LiteLLM SDK, SageMaker and pre-save Test Connect validation

Branch: ai-improvement. Approved paper70046bcb; artifact/coverage paper46228c92.
This supersedes the older pending catalog-only pre-save proposal. It does not
claim full LiteLLM parity; see AI-litellm-coverage.md.

## Delivered

OpenAPI-first authenticated transient inference probe, private source-attributed
LiteLLM1.100.0 SDK runtime with hash-locked dependencies, SageMaker provider using
actual SDK SigV4/event-stream adapters, scoped installation IAM/model bindings,
mandatory approved CONNECT for selected custom/SageMaker bridge endpoints,
migration0145 and opt-in Compose/Helm wiring. No AWS credentials reach CP storage.

Provider setup exposes Test Connect before Save; successful status for the exact
key/provider/model/endpoint selection expires after five minutes. Failed tests,
edits and late responses cannot enable Create. Saved catalog checks are explicitly
called Check catalog; their historical status does not represent preflight
inference. Tests may incur provider charges and are excluded from gateway usage
totals. No test credentials or raw SDK errors are retained.

## Local checks

- Real installed SDK: **26 tests pass**,6.20s. All9 standard adapter paths with
  synthetic origins/auth; Custom HTTP and HTTPS through authenticated CONNECT;
  proxy407 without target arrival; actual SageMaker SigV4 JSON and AWS event-stream
  transforms at a mocked HTTP boundary; explicit-role denial with no fallback;
  scoped aliases, selected endpoint, memory bounds and child cancellation/reaping.
  Log: /private/tmp/tunnex-litellm-sdk-final.log.
- Web: full **1352 tests /118 files** pass; final provider20-test rerun after copy
  clarification, TypeScript and production build pass. Existing bundle-size
  warning remains. Logs: /private/tmp/tunnex-litellm-web-all.log,
  /private/tmp/tunnex-litellm-ui-final.log and
  /private/tmp/tunnex-litellm-web-build-final.log.
- Both API editions compile. Focused PostgreSQL lifecycle/probe isolation races:
  open5.578s; enterprise5.478s; final open unit additions2.367s and egress2.832s.
  Dedicated project tunnexai0907 and container/network labels verified before DB
  commands. Early cancellation-test teardown hang was fixed in the fixture;
  final runs passed. No shared/default DB touched.
- HTTP auth-before-validation, supported schemas, cross-org refusal and secret
  redaction races: open3.746s /enterprise3.771s. Generated CLI package passes.
- Two-pass pinned code generation:50 hashed generated files, zero drift.
- Compose rendering checks correct SDK build context, private API routing, no
  host ports and readonly mounts. New/existing Helm static checks and lint pass.
- Git diff whitespace check passes. Dedicated SDK CI job added; no remote run or
  image build is claimed.

## Independent review

Ranked findings were dispositioned and corrected before acceptance: selected
SageMaker endpoint must receive the probe; response/log limits must apply before
accumulation; disconnect must cancel/reap SDK workers. Re-review closed each,
including independently running7 bounds tests. A final malformed non-ASCII Bearer
case now returns generic401 on all3 routes and rejects incompatible configured
secrets; independently reviewed with no remaining finding in that scope.

## Actual local browser and network proof

Preview http://127.0.0.1:5180/agents/ai-gateway uses isolated
`tunnexaiwalk0907repro4`, schema145 clean. Task-only loopback SDK18200 and proxy
relay18190 connect to production aiegress and a synthetic private upstream.
No external model or AWS request was made. The root API Linux artifact SHA256 is
848eed7fdbcb2076bdecb13c9f171c5e87c7a819d61883bd859fabfc45b73663.

Browser proof: wrong synthetic key produces failure and disabled Create; valid
key produces success and an actual POST /v1/chat/completions at the fixture;
editing the key invalidates that success; retest then Create saves and applies
connection74dc1255-2ea4-4571-b5ad-a93b3b58c8e4 at revision1. Existing OpenRouter
revision7, prior Custom revision1, team assignments and retained usage remain.
SageMaker branded option, approved bridge selector, scoped Gateway API key and
Test Connect are visible. No SageMaker connection is claimed live-qualified.
Screenshots are under walk-artifacts/ai-gateway-20260907/litellm-preflight-*.jpg
and sagemaker-test-connect-local.jpg. They are evidence, not user visual approval.

Prior API/proxy binaries and original engine container/state volumes remain
retained. SDK uses no AWS models/credentials in the local preview. All fixture
and admin runtime configuration stays in private temporary files, outside Git.

## Remaining qualification

Full composite gates remain INCONCLUSIVE due to the existing Docker VM disk
capacity limitation. The new Docker image has not been built locally; exact-head
remote CI has not run. No push/merge/release occurred. Before release: sufficient
isolated gate capacity, image build, exact-head required CI and authorized live
AWS/provider qualification. Synthetic SDK tests SUBSTITUTE for live provider
proof; the trigger is release qualification of this provider integration.

Next implementation action: extend the imported provider metadata into additional
real credential/routing families per AI-litellm-coverage.md, preserving tenant
boundaries. This slice does not deliver all117 providers, aliases/fallbacks,
playground, every modality or the full LiteLLM dashboard.


## Subsequent approved live OpenRouter preflight

Following explicit approval of one possibly billable OpenRouter request with the
existing burner key, the authenticated local CP probe completed successfully:
HTTP200, status=success, duration5647ms, modelopenrouter/openai/gpt-4o-mini,
maximum16 output tokens, no SDK retries. The fixed SDK OpenRouter adapter made
real external inference. No connection was saved, no team/agent policy changed,
and the key remained in its existing0600 temporary file. Actual invoice cost was
not measured; pre-save tests are excluded from gateway usage totals.

The first attempt was rejected by the local CSRF guard before provider dispatch;
adding the required X-Tunnex-CSRF client header allowed the approved single live
inference. Prior automatic approval review rejections executed no commands;
the live call occurred only after the user explicitly approved the exact action.
Sanitized result: walk-artifacts/ai-gateway-20260907/openrouter-live-preflight.json.

This closes the live OpenRouter pre-save probe proof only. A real SageMaker walk
remains blocked on the designated control-plane host, existing endpoint name,
region and installation IAM configuration; approval alone does not identify
those resources. Enrolled-agent forwarding with the new bridge and full remote
CI/image/release qualification remain separate from this preflight result.
