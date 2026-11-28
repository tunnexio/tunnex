# AI-COMPAT-1: SDK and agent-framework compatibility for the AI Gateway

Status: implemented on `story/ai-vpn-models-1` (local, not pushed). Builds on
AI-VPN-MODELS-1 (model list over the VPN, no `extra_fields`).

## Problem

A LangChain 0.3 / LangGraph run from a VPN-connected laptop against the test
deployment passed only plain invoke, stream, multi-turn and async. Everything an
agent framework does by default failed:

| Check | Result | Cause |
|---|---|---|
| `stream_usage` | 400 | `stream_options` not allowlisted |
| tools, tool round trip, parallel tools | 400 | `tools`, `tool_choice`, assistant `tool_calls`, `role: tool` refused |
| `with_structured_output` (all three methods) | 400 | `response_format`, `tool_choice`, `parallel_tool_calls` refused |
| LangGraph `create_react_agent` invoke/stream | 400 | tool messages |
| `max_tokens=6000` | 400 | output cap 4096 |
| `batch` of 8 | 429 | four active requests per subject |
| ~400 KB prompt | 413 | 256 KiB chat body cap |
| embeddings (not yet run) | would be 400 | LangChain sends token arrays (`[[64],[65]]`) |

Reading the code found more 30-second walls that the run had not reached yet:

1. Every resolver issues a **30-second grant lease**. The adapter puts the
   upstream context and the write deadline on that lease, so every stream ended at
   30 s whatever the timeout constants said.
2. The router's generic `requestTimeout(30s)` wraps the public `/ai/` inference,
   the workload bearer path and the console inference path.
3. The adapter's HTTP client has `Timeout: 30s` (whole body, streams included) and
   `ResponseHeaderTimeout: 30s` (non-stream providers send headers only when done).
4. The response cap of 2 MiB counts every upstream SSE byte. A 6000-token stream
   with engine metadata exceeds it and is aborted.
5. A missing `max_tokens` was rewritten to 1024, so every default LangChain call
   was silently truncated.
6. nginx `/ai/` had `proxy_read_timeout 35s` and nginx's default 1 MiB body limit
   (HTML 413).
7. The engine config has `max_request_body_size_mb: 1`.
8. The VPN relay (node) has a 35 s context, 30 s response-header wait, 40 s
   server write timeout and 1 MiB body; it serves only chat and the model list.
9. The workload wrapper has a 35 s request timeout (streams included), a 30 s
   response-header wait and 35 s server timeouts.

## Principle

Tunnex must not be the reason a standard SDK or framework call fails. Every
field is still allowlisted (unknown fields are refused), every newly allowed field
has a type, shape and size check, malformed input fails closed before
authorization, and identity, policy and cost admission are unchanged.

## Decisions

### 1. Request allowlist (validated before authorization)

The capture of what langchain-openai 0.3.35, langchain-anthropic 0.3.22, the
OpenAI Python SDK 2.x, the Messages SDK and LangGraph `create_react_agent`
actually send (local fake server, no live calls) is the baseline. The allowlist
covers all of it plus the standard fields below.

**`/v1/chat/completions`** top-level fields:

| Field | Validation |
|---|---|
| `model` | string 1–256, required |
| `messages` | array 1–`max_messages` (see limits), required |
| `stream` | boolean |
| `stream_options` | object, only `include_usage` (boolean) |
| `max_tokens`, `max_completion_tokens` | integer ≥ 1, lowered to the output ceiling; not both |
| `temperature` | number 0–2 |
| `top_p` | number 0–1 |
| `frequency_penalty`, `presence_penalty` | number −2–2 |
| `stop` | string 1–256 bytes, or array of 1–4 such strings |
| `seed` | integer |
| `n` | integer, exactly 1 (more choices multiply spend and accounting is per request) |
| `user`, `safety_identifier`, `prompt_cache_key` | string 1–256 |
| `logprobs` | boolean |
| `top_logprobs` | integer 0–20 |
| `logit_bias` | object, ≤ 300 entries, keys decimal token ids, values −100–100 |
| `reasoning_effort` | `minimal`, `low`, `medium`, `high` |
| `verbosity` | `low`, `medium`, `high` |
| `metadata` | object, ≤ 16 string values, key ≤ 64, value ≤ 512 bytes |
| `service_tier` | `auto` or `default` only (`flex`, `priority`, `scale` change the price outside the catalog estimate) |
| `store` | `false` only (stored completions would keep content at the provider under the organization's key) |
| `parallel_tool_calls` | boolean |
| `tools` | array 1–128 of `{"type":"function","function":{name, description?, parameters?, strict?}}`; name `^[A-Za-z0-9_-]{1,64}$`, unique; description ≤ 4096 bytes; `parameters` a JSON object ≤ 64 KiB; all tools together ≤ 1 MiB |
| `tool_choice` | `none`, `auto`, `required`, or `{"type":"function","function":{"name"}}` naming a declared tool |
| `response_format` | `{"type":"text"}`, `{"type":"json_object"}`, or `{"type":"json_schema","json_schema":{name, description?, schema (object ≤ 64 KiB), strict?}}` |

Not allowed (refused as unknown): `functions`/`function_call` (deprecated),
`audio`/`modalities`/`prediction`/`web_search_options` (output audio, predicted
outputs and provider-side web search are separate qualifications), engine routing
fields (`fallbacks`, provider overrides), anything else.

**Chat messages**: roles `system`, `developer`, `user`, `assistant`, `tool`.
Each message may carry only the fields its role uses:

- `system`/`developer`: `content` (string or text parts), `name`.
- `user`: `content` (string or parts), `name`.
- `assistant`: `content` (string, text/refusal parts, or `null` when
  `tool_calls` is present), `name`, `tool_calls` (1–128 of
  `{"id","type":"function","function":{"name","arguments"}}`, id ≤ 256 bytes,
  arguments a string ≤ 256 KiB), `refusal` (string).
- `tool`: `content` (string or text parts), `tool_call_id` (string 1–256).
- `name` matches `^[A-Za-z0-9_-]{1,64}$`.

Content parts: `text` (`text` string), `image_url` (`image_url.url` and optional
`detail` `auto|low|high`), `input_audio` (`data` base64, `format` `wav|mp3`).
**Images are accepted only as `data:image/(png|jpeg|gif|webp);base64,` URLs**,
decoded size ≤ 20 MiB within the request body cap. Remote `https` image URLs are
refused: the pinned engine downloads image URLs itself for some providers
(Gemini) with no destination check, which would be server-side request forgery
from the engine network. Audio data is ≤ the body cap. Parts per message ≤ 256.

**`/anthropic/v1/messages`** (Messages API): `model`, `messages`, `max_tokens`
(integer ≥ 1, lowered to the output ceiling; the chat default is supplied when absent), `system` (string or text blocks), `stream`,
`temperature` 0–1, `top_p` 0–1, `top_k` integer 1–1000, `stop_sequences`
(≤ 16 strings ≤ 256 bytes), `metadata` (`user_id` string ≤ 256 only),
`tools` (1–128 custom tools: `name` pattern as above, `description` ≤ 4096,
`input_schema` object ≤ 64 KiB, optional `cache_control`; `type` absent or
`custom`; server tools such as web search, code execution, computer use and
remote `mcp_servers` are refused), `tool_choice` (`auto`, `any`, `none`, or
`tool` naming a declared tool, optional `disable_parallel_tool_use`),
`thinking` (`{"type":"enabled","budget_tokens": 1024 ≤ n < max_tokens}` or
`{"type":"disabled"}`). Roles `user` and `assistant` only. Content is a string or
blocks: `text` (with optional `cache_control`, `citations` refused), `image`
(`source.type: base64`, png/jpeg/gif/webp; `url` sources refused as above),
`tool_use` (assistant; `id`, `name`, `input` object ≤ 256 KiB), `tool_result`
(user; `tool_use_id`, `content` string or text/image blocks, `is_error`),
`thinking` (assistant; `thinking`, `signature`) and `redacted_thinking`
(assistant; `data`) so multi-turn tool use with thinking works. `cache_control` is
`{"type":"ephemeral"}` with optional `ttl` `5m|1h`.

**`/v1/responses`** (see decision 3).

**`/v1/embeddings`**: `input` is a string, an array of 1–2048 strings, an array
of token ids, or an array of 1–2048 token-id arrays (each ≤ 8192 ids, ids
0–10,000,000). LangChain sends token arrays by default (`chunk_size` 1000).
`encoding_format` `float|base64`, `dimensions`, `user`.

**`/v1/completions`**: unchanged fields plus `stop`, `top_p`, `seed`, `user`,
`stream_options`; `max_tokens` up to the output ceiling.

### 2. Output tokens

- `TUNNEX_AI_MAX_OUTPUT_TOKENS` (default **32768**) is the ceiling for any
  requested output limit on every text route. A larger requested value is
  lowered to the ceiling rather than refused (newer framework releases default
  `max_tokens` to the model's maximum, e.g. 64000, and refusing would break
  default calls); a Messages API thinking budget above the lowered limit is
  lowered with it. Non-integers, zero and values above 100,000,000 are refused.
- When a chat, completions, responses or Messages API request names no limit,
  the adapter inserts `TUNNEX_AI_DEFAULT_OUTPUT_TOKENS` (default **4096**) for
  every model, capped by the ceiling (founder decision 2026-11-28; the catalog
  maximum is not used). This replaces the fixed 1024 that truncated LangChain
  answers. An explicit value up to the ceiling is passed through; the provider
  decides.
- Cost: daily thresholds are observational admission, not a reservation.
  Admission still runs before every request is forwarded. The worst case past a
  threshold is about `max_tokens × output price × concurrent requests` per
  subject. With the defaults and a model priced at $15 per million output tokens,
  that is 32768 × 15e-6 × 16 ≈ $7.90 in flight per subject for requests that ask
  for the ceiling, and 4096 × 15e-6 × 16 ≈ $0.98 for requests that name no limit.

### 3. `/v1/responses`

The pinned engine (Bifrost v2.0.0) serves `POST /v1/responses` for every
provider it converts, with the same virtual-key authorization and accounting.
The adapter forwards it as **chat mode** (same grants, same cost admission,
same per-subject limits). Allowed: `model`, `input` (string or items), 
`instructions`, `max_output_tokens`, `temperature`, `top_p`, `stream`,
`tools` (function tools only), `tool_choice`, `parallel_tool_calls`, `text`
(`format` text/json_object/json_schema, `verbosity`), `reasoning` (`effort`,
`summary`), `include` (`reasoning.encrypted_content`,
`message.output_text.logprobs`), `top_logprobs`, `truncation`, `metadata`,
`user`, `safety_identifier`, `prompt_cache_key`, `store` (`false` only; the
adapter always sends `store:false`). Input items: messages (roles
user/assistant/system/developer, content string or `input_text`,
`input_image` data URL, `output_text`, `refusal` parts), `function_call`,
`function_call_output`, `reasoning` (summary, encrypted content). Refused:
`previous_response_id`, `conversation`, `background`, `store:true` (they create
or read provider-side state under the organization's shared key, which other
subjects could reference), built-in tools (web/file search, code interpreter,
computer use, remote MCP, image generation), `item_reference`, file ids and
non-default `service_tier`. The stored-response GET/DELETE routes stay absent.

### 4. Limits (administrator settings)

All are API container environment variables, validated at startup (the server
exits on an invalid value). They are passed through `deploy/tunnex.yml` and the
Helm values.

| Variable | Default | Range | Meaning |
|---|---|---|---|
| `TUNNEX_AI_MAX_OUTPUT_TOKENS` | 32768 | 256–1,000,000 | output ceiling |
| `TUNNEX_AI_DEFAULT_OUTPUT_TOKENS` | 4096 | 1–ceiling | output limit inserted when a request names none (every model) |
| `TUNNEX_AI_MAX_MESSAGES` | 2048 | 1–10,000 | chat/messages history length, responses input items |
| `TUNNEX_AI_MAX_REQUEST_BYTES` | 8 MiB | 64 KiB–32 MiB | JSON body (transcription keeps 8 MiB audio + 64 KiB) |
| `TUNNEX_AI_MAX_RESPONSE_BYTES` | 16 MiB | 1–64 MiB | buffered (non-stream) JSON response |
| `TUNNEX_AI_MAX_STREAM_BYTES` | 64 MiB | 1–1024 MiB | upstream bytes of one stream |
| `TUNNEX_AI_BODY_READ_TIMEOUT` | 60 s | 5 s–10 min | reading the request body, before authorization |
| `TUNNEX_AI_REQUEST_TIMEOUT` | 5 min | 10 s–30 min | non-streaming request |
| `TUNNEX_AI_STREAM_TIMEOUT` | 10 min | 10 s–60 min | streaming request |
| `TUNNEX_AI_IDLE_TIMEOUT` | 150 s | 5 s–30 min | no upstream bytes for this long cuts the request |
| `TUNNEX_AI_MAX_CONCURRENT` | 256 | 1–4096 | active requests in one API process |
| `TUNNEX_AI_MAX_CONCURRENT_PER_SUBJECT` | 16 | 1–1024 | active requests per user/agent/workload, all replicas |
| `TUNNEX_AI_MAX_CONCURRENT_PER_ORG` | 256 | 1–65,536 | active requests per organization, all replicas |

- The admission slot is taken before the body is read, so the body read has its
  own short deadline; only after authorization are the socket deadlines extended
  to the request or stream timeout. Slow uploads cannot hold a slot for minutes.
- Upstream: no total client timeout; the response-header wait is the request
  timeout; body reads are bounded by the idle timeout and the total deadline. An
  idle cut aborts the client connection (no clean end that could look like a
  complete answer). `MaxConnsPerHost` follows `TUNNEX_AI_MAX_CONCURRENT`.
- The engine bounds non-streaming provider calls at 300 s and stream gaps at
  120 s (Bifrost defaults; Tunnex creates providers without overriding them), so
  raising the request timeout above 5 minutes or lowering the idle timeout below
  the engine's 120 s has limited effect. The idle default is 150 s so the engine's
  own idle error arrives first.
- Outer bounds outside the API process are fixed so any allowed setting fits:
  nginx (`/ai/` and the console inference path) accepts 33 MiB, does not buffer
  request bodies (the API cuts oversize bodies early) and allows 31 minutes
  between reads. The node relay and the workload wrapper allow 33 MiB bodies,
  31-minute response-header waits and 61-minute requests; the control plane
  enforces the real limits.

### 5. Grant lease renewal

The 30-second grant lease stays: it is how a revocation reaches an in-flight
request. A request that runs longer now renews its lease before it ends (at two
thirds of the lease). Renewal re-checks live identity, the model grant, provider
state and the organization's AI switch through the same resolver code as
admission. It does **not** re-run cost admission (admission is per request) and
does **not** require the starting bearer to be unexpired: workload tokens and
agent AI credentials live five minutes and rotate, so a ten-minute stream would
otherwise die when its bearer expires although the identity is still authorized.
Instead, renewal binds to the identity the bearer proved at admission:

- workload: the same org, workload, instance, key generation, workload epoch and
  organization AI revision; instance must still be active;
- agent: the same device and runtime credential revision (still current, not
  revoked), the agent assignment, team policy and key binding;
- static key (AI-KEYS-1; public route and internal endpoint): the same key on
  the same ingress, re-checking revocation, expiry, workload switch and epoch,
  scope, the public opt-in or the internal endpoint and its peer range, the
  key's source ranges and the model grant; the per-minute rate limit and cost
  admission are per request and are not repeated;
- user (console and VPN): the same resolver as admission (no bearer involved);
  VPN renewal re-checks the peer evidence, membership and permission, the
  provisioned ingress (manual TLS route) or the gateway's fresh readiness
  report (automatic route), and for the automatic HTTP route the automatic VPN
  switch and the saved "Inside the VPN" HTTP policy.

A failed or mismatched renewal (different tenant, subject, mode or key) aborts
the request at once (context cancelled and socket deadlines moved to now).
Revocation latency for an in-flight request is therefore at most one lease
(30 s). An authorizer that provides no renewal keeps today's hard stop at lease
end.

### 6. Concurrency shared across replicas

The per-subject and per-organization limits use Redis leases so several API
replicas enforce one limit: a sorted set per key, member = random lease id,
score = expiry (Redis server time). Acquire removes expired members and adds one
only below the limit, atomically in one script. Leases last 60 s and are renewed
every 20 s while the request runs; a crashed replica's slots expire within 60 s.
Release removes the member. Redis unavailable at admission: 503
`ai_gateway_unavailable` (fail closed). A renewal error is retried; a lease that
cannot be renewed for longer than its lifetime aborts the request. The
process-wide limit stays in memory as a local safety bound. The server always
runs with Redis (sessions require it); an adapter built without a Redis client
(tests, tools) keeps the in-process per-subject limiter.

### 7. Upstream errors

Previously every engine non-2xx became 502 `ai_engine_unavailable`, which blames
Tunnex for provider problems (seen live: an OpenRouter credit refusal and a
Gemini overload both reached callers as "AI engine is unavailable"). Mapping now,
with static messages and no provider text:

| Engine answer | Caller gets |
|---|---|
| 400, 404, 413, 422 | 400 `ai_provider_rejected` "The AI provider refused this request." |
| 402 | 402 `ai_provider_payment_required` "The AI provider refused the request for billing or credit reasons. Check the provider account." |
| 429 | 429 `ai_provider_rate_limited` |
| 503, 529, or a 5xx whose error type names overload | 503 `ai_provider_unavailable` "The AI provider is temporarily unavailable. Try again later." |
| anything else (other 5xx, 401/403 from the engine, transport failure) | 502 `ai_engine_unavailable` |

For 429 and 503 the provider's `Retry-After` (seconds or an HTTP date) is passed
as whole seconds bounded to 1–300; an unparsable value is dropped. Only a 16 KiB
prefix of the engine's error is read, to classify it.

### 8. Three access paths carry every mode

Modes: chat completions, completions, embeddings, audio speech, audio
transcription, image generation, rerank, Messages API, responses. Video
generation is an asynchronous job with follow-up GET routes keyed to the subject
and stays on the public origin only; it is not relayed over the VPN and not listed
there.

- **VPN user.** The relay accepts `POST` on `/ai/v1/<route>`, `/ai/anthropic/v1/messages`
  and the org-scoped `/api/v1/organizations/{org}/ai-gateway/inference/...`
  equivalents for the exact routes above, plus the model list. Same host check,
  kernel peer resolution, evidence-only headers (Content-Type is forwarded so
  multipart transcription works). 64 slots per gateway. The control plane
  registers the same routes on `/agent/ai`, `/agent/ai-http` with the same
  prelude and resolvers as chat; the adapter's mode check (grant mode must equal
  the route's mode) is unchanged. The VPN model list now returns every granted
  model whose mode the relay serves (all but video).
  *Version skew*: a new control plane behind an old relay lists e.g. embeddings
  that the old relay refuses. Gateways follow the control plane's version and
  there are no customers before launch, so this is accepted rather than gated on a
  relay capability report.
- **AI agent runtime.** Agents obtain a five-minute `tnx_ai_` credential from
  `POST /api/v1/agent/runtime/ai-credential` and call the public `/ai/` origin
  directly; there is no loopback proxy in the CLI. Its fixes are the router
  exemption, nginx, the adapter limits and lease renewal.
- **Static keys, internal endpoint.** The gateway's internal listener uses the
  AI VPN relay's outer bounds (33 MiB bodies, 61-minute requests, 31-minute
  header wait, 64 slots), reads bodies whole within 60 s and a 256 MiB memory
  budget before relaying, and relays `/v1/responses` too.
- **Workload.** The wrapper forwards the same route list (adding `/v1/responses`)
  with the outer bounds above.

### 9. Router

The generic 30-second request timeout skips the exact inference paths
(`/ai/<inference route>` and `/api/v1/organizations/{org}/ai-gateway/inference/<route>`);
the adapter owns their deadlines. Video job routes and everything else keep it.

### 10. Engine body limit

The engine configs (`deploy/ai-gateway/config*.json`, Helm `bifrost-config.json`)
set `max_request_body_size_mb` to 33. The engine re-reads the file on restart
(file wins on a hash change). Existing installations keep their `ai-engine.json`;
the installer and the upgrade replace it only when it differs from the release
file solely in that one value (an administrator-edited file, including a
whitespace-only edit, is preserved). When it was updated, the engine container
is recreated after the stack starts, because Compose does not recreate a
container for a changed bind-mounted file. This is an installer change and needs
a real-stack upgrade walk (**pending**: the founder runs it before release).

## Founder decisions (2026-11-28)

1. **Output tokens.** The ceiling `TUNNEX_AI_MAX_OUTPUT_TOKENS` stays 32768; an
   explicit larger value is lowered to it. When `max_tokens` is absent, every
   model gets `TUNNEX_AI_DEFAULT_OUTPUT_TOKENS` = 4096 (not the catalog maximum).
2. **Lease renewal skips cost admission.** A running stream is not cut when the
   daily threshold is crossed; the threshold applies to each new request.
3. **Remote image URLs stay refused** (data URLs only) until the engine's image
   download is guarded.
4. **Installer and upgrade change.** The real-stack upgrade walk is pending; the
   founder runs it before release.
5. **Relay version skew** is accepted (gateways follow the control plane's
   version; no customers before launch).

## Qualification

- Unit tests cover every allowlisted field (accepted shapes, refused malformed
  or oversized values), roles and content parts, limits, lease renewal, idle
  and request timeouts, shared concurrency (two adapters on one Redis) and
  each path's routing of each mode.
- Every request body that langchain-openai, langchain-anthropic, LangGraph, the
  OpenAI SDK and the Messages SDK sent in the capture and in a full run of the
  matrix script against a local fake engine (79 bodies) passes the validators.
- `scripts/ai-compat/lc_matrix.py` is the manual, paid qualification against a
  real deployment (VPN, agent runtime/public origin, workload wrapper); see its
  header for usage. CI never runs it.

## Not done

- Remote image URLs (refused, see decision 1).
- Stored responses, background responses, provider-side tools.
- Video over the VPN.
- `n > 1`.

## As built: spending refusals reach the caller (2026-11-28)

Found on the test deployment: a request refused by a daily cost limit or for
a model without a price returned the generic 403 `ai_policy_denied`, because
the adapter maps every resolver 403 to one message. The caller could not tell
that a limit or a missing price was the reason. These two exact codes now pass
through with static messages (no resolver text): 403
`ai_daily_threshold_reached` ("The daily AI spending limit for this group,
workload or key has been reached. It resets at 00:00 UTC.") and 403
`ai_price_unavailable` ("This model has no price and a spending limit applies.
Ask an administrator to set the model price."). Every other refusal keeps the
generic 403. They describe only the caller's own spending state.
