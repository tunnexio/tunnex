# Private LiteLLM SDK bridge

This optional service reuses LiteLLM's provider transformations and SageMaker chat
adapter. It is not the LiteLLM proxy or dashboard. Tunnex remains responsible for
tenant authorization; Bifrost remains the inference key and accounting engine.
Do not publish port 8200. Only the control plane and approved inference/egress
services should reach it.

Run `python bridge.py` after installing `requirements.txt` with
`pip install --require-hashes -r requirements.txt`. The Docker build context is
this directory. The image runs as UID/GID 65532 and needs no writable application
state. Mount operator files read-only and deliver referenced secrets through the
installation's secret mechanism. Do not bake secrets into images.

## Operator configuration

- `TUNNEX_AI_BRIDGE_LISTEN`: default `0.0.0.0:8200`.
- `TUNNEX_AI_BRIDGE_ADMIN_TOKEN`: separate random token, minimum 16 characters.
- `TUNNEX_AI_BRIDGE_CONFIG_FILE`: optional JSON below. Empty models/clients permits
  standard and policy-permitted endpoint connection tests without any AWS configuration.
- `TUNNEX_AI_CUSTOM_ENDPOINTS_FILE`: the shared provider egress policy. Set
  `public_https: true` to allow public HTTPS/443 Custom and Azure URLs without
  destination registration. It defaults false. Private/internal and SageMaker
  URLs need explicit `custom`, `azure_foundry` or `sagemaker` endpoint/CIDR rules;
  existing rules take precedence over public fallback.
- `TUNNEX_AI_CUSTOM_PROXY_URL`: required authenticated HTTP CONNECT proxy for
  Custom, Azure and selected SageMaker probes/catalogs. HTTP and HTTPS both use CONNECT;
  proxy failure never falls back to a direct connection. The separate egress
  service enforces resolved-address CIDRs and protected destinations.
- `SSL_CERT_FILE` / `SSL_CERT_DIR`: optional operator trust roots, including a
  private CA for an approved HTTPS endpoint. TLS verification stays enabled.

```json
{
  "models": [{
    "alias": "support-chat",
    "endpoint": "operator-installed-chat-endpoint",
    "region": "ap-south-1",
    "access_key_id_env": "SUPPORT_AWS_ACCESS_KEY_ID",
    "secret_access_key_env": "SUPPORT_AWS_SECRET_ACCESS_KEY",
    "session_token_env": "SUPPORT_AWS_SESSION_TOKEN"
  }],
  "clients": [{"key_env": "SUPPORT_BRIDGE_CLIENT_KEY", "models": ["support-chat"]}]
}
```

Session token is optional. An optional `role_arn` and `external_id` binds an
explicit role to the configured source credentials. The worker calls only the
fixed regional STS endpoint with those credentials, one attempt, no proxy from
environment, and bounded connect/read timeouts. It passes the returned credentials
to LiteLLM; role failure does not fall back to ambient credentials. Ambient AWS
profiles, instance metadata, caller-supplied AWS endpoints and caller IAM settings
are not accepted. Client keys require at least 16 characters; use independently
generated high-entropy secrets. Operators must install a compatible SageMaker
chat endpoint; arbitrary model-serving request formats are not translated here.

## Protocol and bounds

`POST /test-connection` requires the administrator Bearer token and accepts
`provider`, `model`, `api_key`, optional `endpoint_url`, and optional `mode`
(default `chat`). Native providers use
canonical provider-prefixed models; Custom, Azure and SageMaker use the raw
model/deployment name or configured bridge alias.
The response contains only `status` (`success` or `error`) and `duration_ms`.
The eight modes dispatch actual LiteLLM SDK methods: `chat` (`acompletion`),
`completion` (`atext_completion`), `embedding` (`aembedding`), `audio_speech`
(`aspeech`), `audio_transcription` (`atranscription`), `image_generation`
(`aimage_generation`), `video_generation` (`avideo_generation`), and `rerank`
(`arerank`). Unsupported provider/model/mode combinations return sanitized errors;
the selector is not a provider capability guarantee. Custom rerank reuses the
SDK's proxy-compatible rerank adapter at the approved `/v1/rerank` endpoint.

Tests use fixed short inputs: chat/completion at most 16 output tokens, one text
embedding, one ranked document, speech with the `alloy` voice and WAV output,
a locally generated 100 ms silent WAV transcription fixture, one image, or one
four-second video submission. Non-token modes receive no token-limit parameters.
Each response must match its mode, including finite embedding/rank numbers and
nonempty valid WAV speech. Image URLs are never fetched. Video success means
**job accepted**, not generation completed; IDs/content are discarded and no
polling or further requests occur. These tests do not add saved video-job routing.
All probes retain a 10-second overall deadline and no retries. They can incur provider
charges. A SageMaker test calls the selected approved bridge endpoint through
CONNECT using its submitted scoped key, rather than testing a local substitute.
The installed SageMaker bridge remains chat-only and rejects other probe modes.

`POST /model-catalog` requires the same administrator token and accepts
`provider`, `endpoint_url`, write-only `api_key`, optional `query`, `limit` and
`offset` and `mode`. Mode is validated, but the upstream names-only catalog does
not certify a model's supported operations. It fetches
`<normalized-base>/v1/models` through locked CONNECT egress,
without inference or stored credentials. Results are bounded to 1 MiB and 10,000
valid entries, sorted/deduplicated and paginated; errors never reflect upstream
bodies. The control plane uses this for new Custom/SageMaker drafts. New Azure
UI searches instead read a bundled pinned LiteLLM reference catalog in the CP,
without endpoint/key or Azure traffic. Saved endpoint catalogs remain authenticated.

`GET /v1/models` and `POST /v1/chat/completions` use a separately scoped client
Bearer key. Only its configured aliases are accessible. Completion accepts text
messages, `max_tokens` (1–4096), `stream`, `temperature` (0–2), and
`stream_options.include_usage`. Unknown fields are refused. Public responses and
stream chunks use the public alias, never the operator's endpoint name. Streaming
is incremental SSE with a 30-second overall deadline; failed streams emit a
sanitized error and do not emit a successful terminal marker.

There are eight concurrent operations per process. Requests are bounded to
32 KiB. Upstream bodies are bounded to 1 MiB before SDK parsing, compressed
responses are refused, worker output is bounded to 1 MiB, and streaming lines are
bounded to 64 KiB. Workers get an explicit minimal environment and are killed and
reaped on cancellation, timeout or size failure. Redirects, environment proxies,
SDK callbacks and SDK/content logs are disabled. SDK diagnostic output is
discarded, not buffered. No provider or AWS secrets are persisted by this service.

## Artifact provenance and qualification

The reviewed source was LiteLLM commit
`168a0055a244acdcf97c330c52e085ab40b1424c`, which declared unreleased 1.101.0.
The installable artifact is the official **1.100.0** wheel, with platform hashes
and all transitive dependency hashes in `requirements.txt`; these are deliberately
not represented as the same artifact. The SageMaker chat transformation file and
AST of the health-check/SageMaker-chat entrypoints match the reviewed source.
The reviewed HTTP handler adds environment-proxy handling; this bridge injects
its own fixed-origin, nonredirecting transport instead. The SDK's health helper
logs raw requests, so the bridge uses the underlying `acompletion` operation and
sanitizes its result. The SDK role helper can fall back to ambient credentials;
the explicit role resolver described above avoids that path. OSS attribution is
retained in `LICENSE.litellm`; no enterprise/proxy code is deployed.

Tests use synthetic credentials and local fixtures only: actual released SDK
calls for all nine native providers; HTTP and HTTPS through authenticated
CONNECT; real SageMaker SigV4 request construction and AWS event-stream decoding
against a mocked HTTP boundary; explicit-role refusal; scope, selected endpoint,
stream aliases, response bounds and subprocess cleanup. They do not establish
live AWS IAM, installed endpoint behavior, provider billing, or cloud deployment.
Run `python -m pytest tests -q` with pytest and pytest-asyncio in a private test
venv. No production credential or paid call is needed.

## Azure AI Foundry

Use the deployed model name and Azure resource API key. Paste the portal's
`/anthropic/v1/messages` URL for Claude, or `/openai/v1` for OpenAI-compatible
Azure deployments. Resource hosts under `services.ai.azure.com`,
`openai.azure.com` and `cognitiveservices.azure.com` are accepted. The control
plane stores the base `/anthropic` or `/openai`; the explicit path selects the
protocol independently of the deployment name. Existing credentials keep their
immutable endpoint. Create separate credentials when the protocol differs.

Test Connect uses the pinned LiteLLM Anthropic or OpenAI adapter through the
mandatory authenticated egress proxy. Saved-key tests resolve the key privately
inside the engine and preserve its serving model scope. Authorized inference
uses Bifrost's corresponding native adapter. Claude supports chat and streaming;
other modes are refused before sending the key. Both paths send `x-api-key` and
`anthropic-version: 2023-06-01` for Claude. GPT reasoning deployments retain their
existing token parameter handling.

With public HTTPS enabled, endpoint entry needs no individual approval. Private
hosts retain explicit endpoint/CIDR rules. DNS and numeric dials remain controlled
by the egress proxy. Foundry searches use the pinned LiteLLM Azure/Azure AI
reference, including Claude, even with saved credentials. Suggestions do not
certify a deployed model or access. A successful connection test verifies the
chosen deployment and mode. Live Azure qualification needs the operator's key;
synthetic SDK/native tests do not claim that proof. Legacy serverless `/models`,
Entra identity and sovereign-cloud endpoints remain outside this adapter.
