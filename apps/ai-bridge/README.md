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
  standard and approved custom connection tests without any AWS configuration.
- `TUNNEX_AI_CUSTOM_ENDPOINTS_FILE`: the shared approved endpoint policy. Each
  selected URL must have its correct `custom` or `sagemaker` discriminator.
- `TUNNEX_AI_CUSTOM_PROXY_URL`: required authenticated HTTP CONNECT proxy for
  custom and selected SageMaker bridge probes. HTTP and HTTPS both use CONNECT;
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
`provider`, `model`, `api_key`, and optional `endpoint_url`. Native providers use
canonical provider-prefixed models; custom and SageMaker use the raw alias.
The response contains only `status` (`success` or `error`) and `duration_ms`.
This performs actual inference with the fixed prompt `Reply OK.`, at most 16
output tokens, a 10-second overall deadline and no retries. It can incur provider
charges. A SageMaker test calls the selected approved bridge endpoint through
CONNECT using its submitted scoped key, rather than testing a local substitute.

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

## Azure AI Foundry (OpenAI v1)

The provider `azure_foundry` uses the actual Azure resource API key and deployed
model name. Its API base is `https://<resource>.services.ai.azure.com/openai/v1`
or `https://<resource>.openai.azure.com/openai/v1`; the control plane stores
`/openai` without the final `/v1`. Add the normalized URL to the existing
installation egress policy as `provider: azure_foundry`, with its approved IP
ranges, on both the CP/egress service and this bridge. No wildcard destination
or automatic Azure network discovery is enabled. Reload the task's services
when installation policy changes; do not expose bridge administrator credentials.

Test Connect invokes the pinned LiteLLM OpenAI adapter against that exact URL.
Saved inference uses the same OpenAI v1 protocol and existing connection-owned
model scope. This slice supports chat completions, including streaming; it does
not implement legacy `/models` or dated deployment URLs, Entra identity, other
modes, or sovereign-cloud endpoints. The bounded probe uses `max_tokens=16`;
models that require another token parameter (such as o1) need separate support.
Live Azure qualification requires the operator's actual endpoint/key/model.
