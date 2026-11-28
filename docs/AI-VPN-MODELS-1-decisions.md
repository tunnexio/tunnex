# AI-VPN-MODELS-1: model list over the VPN and no engine metadata in responses

Status: implemented on `story/ai-vpn-models-1` (local, not pushed).

## Problems (seen on a live test deployment)

1. SDK tools (Cursor, Continue, LangChain, Open WebUI) call `GET /v1/models`
   before anything else. On the VPN path the gateway relay only knew
   `POST .../chat/completions`; `GET /ai/v1/models` fell through to the web
   handler, so tools could not discover models.
2. A successful chat response carried the engine's `extra_fields` object:
   `routing_info` with the internal engine key name (`tnx-managed-<uuid>-rN`),
   `provider_response_headers` (Cf-Ray, X-Request-Id, X-Ratelimit-*, Via),
   latency and similar. That leaks internal identifiers and upstream details to
   every caller of the adapter (public, VPN and workload paths).

## Decisions

### Model list over the VPN

- The relay accepts exactly two new requests: `GET /ai/v1/models` and
  `GET /api/v1/organizations/{orgId}/ai-gateway/inference/v1/models`. No query
  string, no encoded path, no body (`Content-Length` must be 0; chunked bodies
  are refused). Same host check (421), same 16-slot limit, same 35 s bound, same
  kernel peer-key resolution, same evidence-only header set. A `POST` to a
  models path is refused with 400 like a `GET` to the chat path is today.
- The relay forwards to new control-plane routes `/agent/ai/v1/models`,
  `/agent/ai/organizations/{orgId}/v1/models` and the `/agent/ai-http/...`
  equivalents for the automatic HTTP relay. No other relay behaviour changes.
- The control plane uses the same prelude as chat: node certificate, org in the
  path must equal the node's org, adapter/policies configured, and for the
  automatic HTTP route `AutomaticVPNEnabled()` and the saved "Inside the VPN"
  HTTP policy. Exactly one `X-Tunnex-VPN-IP` and one `X-Tunnex-VPN-Key`.
- User resolution is shared with chat, not copied: the VPN peer query (exact
  org, gateway node, key, address, active human WireGuard device, live
  membership, `ai.model.use` permission, single live membership for the alias)
  and the live-user check (active verified user, org AI enabled) are one code
  path used by both `resolveUserModel` and the new list. The manual TLS route
  still requires the provisioned ingress node; the automatic route still
  requires a fresh ready report for the exact gateway address.
- The list is `Policies.UserModels` for that user, the same list the console's
  "my models" shows, which re-resolves every grant (provider, mode, sealed key).
- **Chat models only.** The VPN relay serves only `chat/completions`; listing an
  embeddings or image model would make tools offer a model that the relay then
  refuses. Each entry carries `"mode":"chat"` so the shape matches the workload
  list (`GET /ai/v1/models`): `{"object":"list","data":[{"id","object":"model",
  "owned_by":"tunnex","mode"}]}`.
- The list runs the shared identity check in its own transaction, then
  `UserModels` re-resolves every grant (including the live-user check) in its
  own transactions. The two steps are not one atomic snapshot; that is fine for
  a read-only list, and every chat request repeats the full check.
- On the manually provisioned TLS host, `GET /ai/v1/models` used to fall through
  to the web upstream (the public workload bearer list). It now answers with the
  VPN user's list, the same way `POST /ai/v1/chat/completions` on that host has
  always used VPN identity rather than a bearer. The org-scoped models path used
  to return 404 there. Workloads keep using the public origin.
- A user with no grants gets `{"object":"list","data":[]}`. An unknown peer, a
  wrong org, a non-live user, automatic mode off or VPN HTTP off are refused with
  the same static errors chat uses; resolver messages are never forwarded.

### No `extra_fields` in responses

- The adapter removes a top-level `extra_fields` member from every JSON object
  response (chat, completions, embeddings, transcription JSON, image JSON, the
  Anthropic messages route) and from the JSON payload of every SSE event.
  Video jobs already answer with a Tunnex-built body and are unchanged.
- Removal is a byte splice: the member and its separating comma are cut out of
  the original bytes. Nothing is re-encoded, so field order, number formatting
  and whitespace stay exactly as the engine sent them. A body without the
  member is passed through byte for byte. Non-object or non-JSON payloads
  (`[DONE]`, text transcription, audio) are passed through unchanged. Duplicate
  `extra_fields` members are all removed.
- Streams are processed one SSE event at a time (lines up to the blank line
  that ends an event). An event is written and flushed as soon as it is
  complete; nothing is held beyond one event. An event whose data spans several
  `data:` lines is joined per the SSE rules before stripping and written back
  on the same number of lines when unchanged, or split on the payload's own
  newlines when stripped. Comment, `event:`, `id:` and `retry:` lines are kept
  in place.
- The existing 2 MB response cap still counts every upstream byte, so a single
  event can never buffer more than the cap. The existing deadlines, lease
  expiry and abort-on-overflow are unchanged.

## Not done

- No new modes over the VPN relay (embeddings, images, audio). That is a
  separate decision: each needs its own relay route and body cap.
