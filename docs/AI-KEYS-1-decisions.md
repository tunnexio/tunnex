# AI-KEYS-1: static API keys for workloads, internal only by default

Status: decision paper, 2026-11-28. Direction approved by the founder on
2026-11-28. Open questions answered (see "Founder decisions"). Being built. Branch `story/ai-static-keys-1`, not pushed. Open
questions are at the end, each with a recommended answer.

## Problem

People reach models through their VPN identity, with no key. The gateway
listens on its tunnel address and the control plane decides
(`apps/node/internal/aivpn/relay.go:79-158`,
`apps/api/internal/http/agentchannel_ai.go:30-73`).

Applications use **Workloads** (AI Gateway → Access → Workloads). A workload has
an enrollment key, the `tunnex workload run` wrapper, a per-replica identity,
5-minute tokens, a model list and a daily USD soft threshold
(`docs/workload-model-access.md`, `apps/api/internal/aigateway/workloads.go`,
`workload_auth.go:172-215`).

The wrapper cannot run on:

- serverless functions (Lambda and similar);
- Windows (`docs/workload-model-access.md:22-23`);
- SaaS and no-code tools;
- quick scripts.

Without a key, customers paste the provider's raw key into these tools. They
lose model control, limits, usage per application and audit. The provider key
also leaves Tunnex for good.

## What exists today (read before the decisions)

### The VPN AI listener: the gateway listens, the control plane decides

- The gateway runs an inference-only listener on its private WireGuard
  address, TCP 8083 (`apps/node/internal/aivpn/runtime.go:16`, `:49-56`). It
  starts only when `TUNNEX_AI_VPN_AUTO` is on and the backend is kernel
  WireGuard (`apps/node/cmd/agent/ai_vpn_runtime.go:14-35`).
- It is bound to the WireGuard interface with `SO_BINDTODEVICE`
  (`apps/node/internal/aivpn/runtime_linux.go:45-56`). It exists only while
  the address is the ownership-projected one, the device is live and the
  reconciler is healthy. It closes on any doubt (`runtime.go:143-194`).
- It identifies the caller from the TCP source address and the kernel
  WireGuard peer table (`relay.go:21-73`, `:132-148`). It never uses
  `Authorization`, cookies or forwarding headers. The outgoing request carries
  only `Content-Type` plus two evidence headers the gateway sets itself,
  `X-Tunnex-VPN-IP` and `X-Tunnex-VPN-Key` (`relay.go:94-101`). A key sent to
  port 8083 is dropped, not forwarded.
- Limits: 16 concurrent requests (`relay.go:90`, `:125-131`), a 35 s request
  deadline (`relay.go:137`), a 1 MiB body (`relay.go:155`). Server timeouts:
  header 5 s, read 35 s, write 40 s, idle 30 s, 16 KiB of headers
  (`runtime.go:52`, `:172-176`).
- It relays to the control plane over the node mTLS channel. The transport
  reuses the rotating node certificate, opens a new connection per request,
  and caps 16 connections, 30 s to response headers and 10 s for the TLS
  handshake (`apps/node/internal/control/ai_vpn_transport.go:13-27`).
- The control plane serves the relay on `/agent/ai-http/...`
  (`apps/api/internal/http/agentchannel.go:185-188`). It authenticates the
  node from its client certificate and refuses an organization in the path
  that is not the node's (`agentchannel_ai.go:31-39`). It checks the saved
  "Inside the VPN" HTTP setting (`agentchannel_ai.go:44-53`). It then calls
  `Adapter.ServeAuthorized` with an authorizer bound to that node and the
  evidence (`agentchannel_ai.go:64-72`). The automatic resolver also needs a
  fresh capability report (90 s) for that node
  (`apps/api/internal/aigateway/vpn_auto.go:45-56`).
- Readiness is reported as typed fields, `ai_vpn_http_ready` and
  `ai_vpn_http_address` (`apps/node/internal/control/client.go:246-249`,
  `:282-283`). The control plane rebuilds the capabilities JSON from typed
  fields only, so an unknown field is dropped
  (`apps/api/internal/nodes/service.go:2531-2553`).

### The MCP listener (AI-SEC-2): the same pattern, a second time

- `apps/node/internal/mcpgw` reuses the AI listener lifecycle through
  `aivpn.ListenerConfig` (`aivpn/runtime.go:58-97`). It listens on TCP 8084
  (`apps/node/internal/k8snetprep/types.go:64-67`). It exists whenever the
  backend is kernel WireGuard (`apps/node/cmd/agent/mcp_gateway_runtime.go:10-20`).
- For each call it asks the control plane over mTLS
  (`apps/node/internal/control/mcp_gateway.go:51-76`). It forwards only on
  allow. Upstream connect and headers are capped at 5 s and one decision at
  10 s (`apps/node/internal/mcpgw/relay.go:29-41`).
- Rate limits use a shared Redis store, not process memory
  (`apps/api/internal/mcpdecision/limiter.go:14-26`,
  `apps/api/cmd/server/main.go:711`). If the limiter fails, the call is
  denied (`mcpdecision/service.go:207-219`).
- Capability gating: the control plane sends a deny only to a gateway that
  reports `mcp_gateway_ready` as a typed true and a policy ceiling of at least
  16 (`apps/api/internal/policy/mcp_direct_path.go:43-58`). A gateway that
  lacks it gets no MCP at all rather than an artifact it would refuse
  (`docs/AI-SEC-2-decisions.md:115-126`).

### A listener on a LAN address: the DNS LAN listener

- Private DNS can listen on a gateway's LAN address. The administrator gives
  an address, an interface and 1 to 32 private source CIDRs
  (`apps/node/internal/nodepolicy/nodepolicy.go:235-241`).
- The gateway refuses an address it does not own on that interface
  (`apps/node/internal/dnsforward/lan_listeners.go:73-91`). It checks every
  query's source against the CIDRs (`lan_listeners.go:93-95`).
- The control plane refuses a CIDR that spans public space
  (`apps/api/internal/fqdnresources/resolver_static.go:128-160`). It also
  refuses an address or source outside the gateway's approved site subnets
  (`resolver_static.go:177-193`). It refuses a gateway whose fresh report
  lacks the needed version (`resolver_static.go:195-203`).
- The gateway reports per-listener readiness and errors
  (`lan_listeners.go:221-243`, `client.go:286-288`).

### Where the control plane authorizes a bearer

- Two public paths reach the adapter.
  1. `workloadMiddleware` runs first (`apps/api/internal/http/router.go:243`).
     It handles `/ai/*` with `Bearer tnx_wai_` and calls
     `Workloads.Authorize` through `ServeAuthorized`
     (`apps/api/internal/http/ai_workload_handlers.go:178-203`). It also serves
     `GET /ai/v1/models` for workload tokens
     (`ai_workload_handlers.go:246-253`).
  2. `aiInferenceMiddleware` (`router.go:333`,
     `apps/api/internal/http/ai_gateway_handlers.go:209-231`) calls
     `adapter.ServeHTTP`. With no authorizer, the adapter uses its default
     closure (`apps/api/internal/aigateway/adapter.go:174-179`, and for
     videos `video_jobs.go:254`).
- The default closure is built in `main.go`. A `tnx_wai_` prefix goes to
  `Workloads.Authorize`; anything else goes to `Credentials.Authorize`
  (`apps/api/cmd/server/main.go:556-561`). `ai_gateway_handlers.go:229` is the
  only `adapter.ServeHTTP` caller. So the default closure is reachable only
  from the public router.
- Today a `tnx_sk_` bearer on the public path would fall through to
  `Credentials.Authorize` and be refused there.
- **Ingress is known by route, not by inspection.** The public router uses
  the default closure or the workload middleware. The mTLS agent channel uses
  `ServeAuthorized` with a node-bound closure (`agentchannel_ai.go:64`).
  Nothing inside `Authorize` can tell them apart today, and it should not try.
- The adapter turns every resolver error into a fixed public message
  (`adapter.go:179-194`, `:305-331`). It caps a body at 256 KiB, or 8 MiB plus
  64 KiB for transcription (`adapter.go:130-134`, `adapter_modes.go:17`). It
  allows 64 requests at once and 4 per subject, per process
  (`adapter.go:37-39`, `:200-208`). A request has 30 s (`adapter.go:60`,
  `:105-114`).
- The public `/ai/` path can run over plain HTTP when the server's "Allow
  HTTP" setting is on (`apps/api/internal/http/ai_transport_settings_handlers.go:62-103`).
- The client address on the public path is not trustworthy as is.
  `middleware.RealIP` rewrites `RemoteAddr` from client headers
  (`router.go:192-210`). Caddy sets `X-Real-IP` to the client it saw, and
  nginx passes it through (`deploy/nginx/nginx.conf:42-47`). The trusted
  immediate peer is known to `requestTransport.trusted`
  (`apps/api/internal/http/request_transport.go:57-87`), but today it is used
  only for `X-Forwarded-Proto` (`request_transport.go:89-127`). The Helm edge
  sets `X-Real-IP` from its own peer instead
  (`deploy/helm/tunnex-cp/files/edge-ai-nginx.conf:38`).

### How workload requests are authorized and counted

- `Workloads.authenticate` looks the token up by hash across organizations,
  then scopes every later read to the stored organization and workload
  (`workload_auth.go:224-265`). Enrollment does the same
  (`workload_auth.go:94-97`).
- `resolve` checks the workload is applied, the model is on its list, the
  provider allows it, and the organization revision still matches
  (`workload_auth.go:281-307`). It then runs `enforceCostBindings` with the
  workload's one native engine key (`workload_auth.go:308-317`) and opens the
  sealed engine key (`workload_auth.go:318-326`).
- A workload has one engine key, `native_key_id`, made by `Reconcile` with the
  workload's model scopes (`workloads.go:262-332`).
- Usage is attributed by native engine key id. `bindingUsageIDs` unions bound
  keys, user grants and workloads (`apps/api/internal/aigateway/usage.go:15-40`).
  The dashboard does the same and labels workload rows
  (`usage_dashboard.go:62-69`, `:105-160`). The engine returns cost per key
  (`usage_dashboard.go:95-120`).
- `enforceCostBindings` asks the engine for today's UTC cost for the given ids
  and refuses at or above the threshold (`usage.go:134-179`).
- An organization has at most 64 engine bindings: workloads, user grants and
  bound keys together (`usage.go:13`, `workloads.go:228-234`). A usage query
  over more than 64 ids is refused (`usage.go:37`).
- Disabling a workload bumps `credential_epoch` and revokes its enrollment
  keys (`workloads.go:237-247`). Tokens carry the epoch and die with it
  (`workload_auth.go:241-243`).
- `daily_usd_threshold` is `double precision` with a check of (0, 100000]
  (`apps/api/db/migrations/0156_ai_workload_identity.up.sql:10`). Child tables
  use a composite foreign key `(org_id, workload_id)` with cascade
  (`0156_ai_workload_identity.up.sql:28`, `:44-45`).
- Workload actions need `ai_workload:manage`, reads need `ai_workload:view`
  (`apps/api/internal/http/ai_workload_handlers.go:18-38`). Owner, Admin and
  AI Gateway admin hold manage (`apps/api/internal/rbac/rbac.go:300-306`).

### Certificates for TLS served by a gateway

- The only gateway-served TLS today is the manual `ai-vpn-relay`. It reads an
  operator's certificate and key files on every handshake and refuses an
  unexpected SNI (`apps/node/cmd/ai-vpn-relay/main_linux.go:104-111`).
- App Access gateway listeners use a leaf from the enrollment CA with a fixed
  name (`deploy/app-access/CERTIFICATES.md:1-30`). That paper warns not to
  broaden gateway trust or swap certificate roles.
- Public certificates for App Access and Local Sharing are operator files
  today. ACME DNS-01 automation (`app-certs`) is planned in AA-EN-1 Phase 1b,
  not built (`docs/AA-EN-1-first-class-app-access-enablement.md:50-51`,
  `:137-160`).

## Decisions

### D1. A static key is a second way to connect a workload

- A workload gets a second connection method, a **static API key**. Workload
  tokens and enrollment keys stay as they are.
- A key belongs to exactly one workload. It inherits the workload's model list
  and daily USD threshold, read live at each request.
- Optional per key: a daily USD soft threshold (it can only be lower than the
  workload's) and a rate limit in requests per minute.
- People do not get personal keys. The VPN identity stays the human path.
- Rejected: personal keys for people. They would break the rule that a person's
  access follows their device, group and membership, and they outlive offboarding.
- Rejected: a key not tied to a workload. Every limit, model list and usage row
  hangs off the workload.

### D2. Key format and storage

- Format: `tnx_sk_` then 43 random base62 characters (about 256 bits), then a
  6-character base62 CRC32 of the random part. Total 56 characters.
  - The fixed prefix lets secret scanners match it. The checksum lets them
    drop false matches offline. GitHub secret scanning registration is a
    follow-up.
  - Base62 avoids `-` and `_` inside the secret, so a pattern ends cleanly.
- Stored only as SHA-256 of the full key, like workload tokens
  (`workload_auth.go:228`). The secret has full entropy, so a slow hash adds
  nothing.
- The console shows the key once, with the same one-time modal used for
  enrollment keys (`apps/web/src/components/AIWorkloads.tsx:329`). Afterwards
  it shows `tnx_sk_…` and the last 4 characters only.
- Rejected: a different prefix per scope. It tells a finder the scope and the
  control plane must check the database anyway.
- Rejected: a signed self-describing token (JWT). It cannot be revoked
  without a lookup, and it is long and awkward to paste.

### D3. Mandatory expiry, rotation with overlap, revoke

- Expiry is required, at most 90 days from creation. The console default is
  30 days. Expiry cannot be extended; rotate instead.
- **Rotate** creates a new key with the same settings and shows it once. The
  old key then expires at the earlier of its own expiry and now plus an
  overlap. The overlap is 1 hour to 7 days, default 24 hours.
- **Revoke** takes effect on the next request. No cache holds a key.
- Disabling the workload revokes all its keys, as it revokes enrollment keys
  (`workloads.go:242-247`). Each key stores the workload's `credential_epoch`
  at creation and is refused when it differs, as tokens are
  (`workload_auth.go:241-243`). Re-enabling the workload does not bring them back.
- A key checks the organization's live `ai_gateway_enabled` flag on each
  request. It does not pin `ai_gateway_revision`, so an unrelated settings
  change does not kill every key.
- At most 8 active keys per workload. Rotation overlap needs 2.

### D4. Scope "Internal only" is the default

- The scope is chosen at creation and cannot change. To move a key, create a
  new one.
- An internal key is accepted only on the new **internal AI endpoint**. That
  endpoint is served by one of the organization's gateways, on a private
  address, with TLS.
- The control plane's public AI endpoint refuses an internal key, even a valid
  one.
- Networks elsewhere reach the endpoint through site-to-site or the VPN.
- The gateway checks the caller's direct TCP peer address against the
  endpoint's source CIDRs. The control plane checks it again against the
  endpoint's CIDRs and the key's own CIDRs. A header is never used.
- Rejected: one key that works on both endpoints and is narrowed by IP list.
  A leaked key would then be usable from the internet whenever the list is
  empty or wrong.
- Rejected: internal keys sent over the existing 8083 listener. That listener
  identifies a person by WireGuard key and drops `Authorization` by design
  (`relay.go:97`). Site and LAN callers do not have a WireGuard peer.

### D5. Scope "Public" is opt-in

- A public key is accepted only on the control plane's public AI endpoint.
  It is for SaaS tools that cannot reach a private network.
- **HTTPS only.** A static key on a plain HTTP request is refused before
  lookup, whatever the "Allow HTTP" setting says. The check uses the observed
  transport, `requestHTTPS` (`request_transport.go:129-132`).
- A source IP allowlist is strongly encouraged. Saving a public key with no
  allowlist needs a second confirmation: "Allow from any address".
- A public key's allowlist may hold only public ranges. A private range would
  match the proxy's own address when the proxy chain is misconfigured, and let
  every caller through.
- The client address is read only through the trusted proxy chain (see
  "Admission, public").
- Public keys are off for an organization until an AI administrator turns on
  "Allow public static keys". See Open question 3.
- Rejected: public keys as the default. It repeats the problem of pasted
  provider keys, only with a Tunnex prefix.

### D6. Ingress is a parameter set by the route

- `StaticKeys.Authorize(ctx, raw, model, ingress)` takes an explicit ingress:
  `Public{clientAddr}` or `Internal{orgID, nodeID, endpointID, peerAddr}`.
- The public route builds `Public`. The new mTLS agent-channel route builds
  `Internal` from the node certificate. `Authorize` never guesses the ingress.
- The default closure in `main.go:556-561` gains a `tnx_sk_` branch that
  **always refuses**. A static key that reaches it came through a path that
  did not set an ingress. That is a bug, and it must fail closed.
- Rejected: a request header or flag that says "came from the gateway". Any
  public caller could send it.

### D7. Each key has its own engine key

- Each static key gets its own engine virtual key with the workload's model
  scopes. The name is `ai-workload-key-<org>-<keyId>`, like the workload's
  (`workloads.go:314`).
- This gives cost per key directly from the engine (`usage_dashboard.go:95-120`).
- `Workloads.Reconcile` also ensures the engine key of every active static key
  when the model list changes. If any of them fails, the workload status is
  "error", as today (`workloads.go:301-331`).
- On revoke or expiry the engine key is disabled. Its native id stays in the
  table forever, for history.
- Rejected: share the workload's engine key and count per key in Tunnex. The
  adapter cannot count tokens reliably. Streaming responses carry usage only
  with `stream_options`, which the adapter refuses (`adapter.go:371-375`). Per
  key cost would be missing or wrong.
- This choice affects the 64-binding cap. See "Audit and Usage" and Open
  question 1.

### D8. TLS on the internal endpoint is required

A key must not cross even a private network in clear text. The endpoint serves
HTTPS only. Two certificate modes in v1.

- **Tunnex private CA (default).** Each organization gets its own internal AI
  CA. Its key is sealed with the master key, like other bound secrets
  (`key_envelope.go`).
  - The gateway makes a key pair in memory. It sends a CSR over the node
    channel. The control plane signs a leaf only for the configured address
    (IP SAN) and DNS name (DNS SAN), valid for 30 days.
  - The gateway renews when a third of the life is left. A restart makes a
    new key and asks again. No private key is written to disk.
  - The console offers the CA certificate (`ca.pem`) and short instructions:
    `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, the Windows
    certificate store and the Java trust store.
- **Customer certificate.** The operator puts `tls-cert.pem` and `tls-key.pem`
  in `/var/lib/tunnex-node/ai-internal/` on the gateway host (mode 0600). The
  gateway reads them on each handshake, as `ai-vpn-relay` does
  (`main_linux.go:104-111`). It reports the SHA-256 fingerprint, SANs and
  expiry. The console warns 14 days before expiry, and when the certificate
  does not cover the configured address or name.
  - The private key never goes to the control plane.
- Rejected: the enrollment CA. It is the node mTLS trust root. Clients would
  have to trust it, and anything it signs, which is the broadening
  `CERTIFICATES.md` warns against.
- Rejected: one CA for the whole installation. A client in one organization
  would trust leaves issued for another organization's gateways.
- Rejected for v1: gateway self-signed with a pinned fingerprint. Most SDKs
  and SaaS tools cannot pin. People would turn verification off instead.
- Deferred: ACME DNS-01. It needs a public DNS name, a DNS API credential, and
  it puts the name in Certificate Transparency logs. The `app-certs` service
  is not built yet. When it is, a third mode can reuse it.

### D9. The listener configuration is its own agent-channel document

- A gateway fetches `GET /agent/ai-internal/desired-state` over mTLS. It
  polls every 15 s and also on a watch kick. This is the same pattern as
  `/agent/app-access/desired-state` (`agentchannel.go:177`).
- Rejected: put the listener in the policy artifact, as the DNS LAN listener
  is. That needs a new artifact version (17) and changes the gateway's policy
  hash. An old gateway that receives it refuses the whole artifact and denies
  all traffic (`apps/node/internal/nodepolicy/nodepolicy.go:20-49`). The
  listener is not packet enforcement, so it does not belong there.
- The control plane re-checks the endpoint row on every request, so turning
  the endpoint off takes effect at once, even before the gateway polls.

## Data model

Migration **0258**. The highest number on origin/main is
`0256_rbac1_roles`. Another open branch takes 0257 for a user-group cost limit,
so this story takes the one after. Renumber at merge time if that changes.

`0258_ai_workload_static_keys.up.sql` creates three tables. Every table
follows the migration conventions: UUIDv7 key, `created_at`, `updated_at` and
the `set_updated_at` trigger (`apps/api/db/migrations/README.md:14-35`).

### `ai_workload_static_keys`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid PK | |
| `org_id` | uuid NOT NULL | |
| `workload_id` | uuid NOT NULL | FK `(org_id, workload_id)` → `ai_workloads(org_id, id)` ON DELETE CASCADE, as 0156 |
| `name` | text NOT NULL | 1 to 100 characters, no line breaks (`validWorkloadName`) |
| `secret_hash` | bytea NOT NULL UNIQUE | `octet_length = 32` |
| `hint` | text NOT NULL | last 4 characters |
| `scope` | text NOT NULL | `internal` or `public` |
| `source_cidrs` | cidr[] NOT NULL DEFAULT '{}' | at most 32 |
| `daily_usd_threshold` | double precision NULL | (0, 100000], same check as 0156 |
| `rate_limit_per_minute` | integer NULL | 1 to 60000 |
| `workload_epoch` | bigint NOT NULL | `credential_epoch` at creation |
| `expires_at` | timestamptz NOT NULL | CHECK `expires_at <= created_at + interval '90 days'` |
| `revoked_at` | timestamptz NULL | |
| `revoked_by` | uuid NULL | |
| `rotated_from_id` | uuid NULL | FK to this table, same org and workload |
| `native_key_id` | text NOT NULL DEFAULT '' | engine key id, kept after revoke |
| `sealed_key` | text NOT NULL DEFAULT '' | sealed engine key value |
| `binding_revision` | bigint NOT NULL DEFAULT 0 | |
| `status` | text NOT NULL DEFAULT 'pending' | `pending`, `applied`, `error`, `revoked` |
| `last_used_at` | timestamptz NULL | written at most once a minute |
| `last_used_ingress` | text NULL | `internal` or `public` |
| `last_used_source` | inet NULL | |
| `last_used_node_id` | uuid NULL | internal only |
| `last_refused_at` | timestamptz NULL | |
| `last_refused_reason` | text NULL | e.g. `wrong_ingress`, `source_not_allowed`, `rate_limited`, `concurrency_limit`, `threshold_reached` |
| `created_by` | uuid NOT NULL | |

Indexes: unique `(org_id, workload_id, id)`; `(org_id, workload_id)
WHERE revoked_at IS NULL`; `(expires_at)`.

### `ai_internal_endpoints`

One row per gateway that serves the endpoint.

| Column | Type | Notes |
| --- | --- | --- |
| `id` | uuid PK | |
| `org_id` | uuid NOT NULL | |
| `node_id` | uuid NOT NULL UNIQUE | FK to `nodes`, same org, ON DELETE CASCADE |
| `enabled` | boolean NOT NULL | |
| `listen_addresses` | inet[] NOT NULL | 1 or 2 private IPv4: the gateway's tunnel address and/or one LAN address (see "Reach") |
| `port` | integer NOT NULL DEFAULT 9443 | 1024 to 65535, not 8083 or 8084 |
| `dns_name` | text NULL | lower case, valid hostname |
| `source_cidrs` | cidr[] NOT NULL | 1 to 32 private IPv4 CIDRs |
| `tls_mode` | text NOT NULL DEFAULT 'tunnex_ca' | `tunnex_ca` or `custom` |
| `revision` | bigint NOT NULL DEFAULT 1 | |
| `created_by`, `updated_by` | uuid | |

### `ai_internal_cas`

| Column | Type | Notes |
| --- | --- | --- |
| `org_id` | uuid PK | |
| `certificate_pem` | text NOT NULL | public |
| `sealed_key` | text NOT NULL | sealed with the master key, purpose `tunnex-ai-internal-ca` |
| `not_after` | timestamptz NOT NULL | 10 years |

The organization column `ai_public_static_keys_allowed boolean NOT NULL
DEFAULT false` goes on `organizations` (Open question 3).

## API

All paths are under `/api/v1/organizations/{orgId}/ai-gateway`. Contract
changes go in `openapi/openapi.yaml` next to the workload paths
(`openapi/openapi.yaml:855-980`).

### Keys

Reads need `ai_workload:view`. Writes need `ai_workload:manage`, the same
permission that manages workloads.

- `GET /workloads/{workloadId}/static-keys?after=&limit=` → page of
  `AIWorkloadStaticKey`. No secret.
- `POST /workloads/{workloadId}/static-keys` → 201
  `{ "key": AIWorkloadStaticKey, "secret": "tnx_sk_..." }`.
  Request:
  ```json
  {
    "name": "lambda-invoice-parser",
    "scope": "internal",
    "expires_at": "2027-01-27T00:00:00Z",
    "source_cidrs": ["10.20.0.0/16"],
    "daily_usd_threshold": 5,
    "rate_limit_per_minute": 120
  }
  ```
  - 400 `invalid_static_key` for a bad field.
  - 403 `public_static_keys_disabled` for a public key when the organization
    switch is off.
  - 400 `static_key_capacity` at 8 active keys on the workload, or when the
    organization binding cap is reached.
  - 403 when the workload is disabled.
- `PUT /workloads/{workloadId}/static-keys/{keyId}` with
  `name`, `source_cidrs`, `daily_usd_threshold`, `rate_limit_per_minute` and
  `expected_updated_at`. Scope and expiry cannot change. 409 on a stale edit.
- `POST /workloads/{workloadId}/static-keys/{keyId}/rotate` with
  `{ "overlap_hours": 24, "expires_at": "..." }` → 201
  `{ "key": ..., "secret": ..., "previous": ... }`.
- `POST /workloads/{workloadId}/static-keys/{keyId}/revoke` → 204.

`AIWorkloadStaticKey` fields: `id`, `workload_id`, `name`, `hint`, `scope`,
`source_cidrs`, `daily_usd_threshold`, `rate_limit_per_minute`, `expires_at`,
`revoked_at`, `rotated_from_id`, `status`, `last_used_at`, `last_used_ingress`,
`last_used_source`, `last_used_node_id`, `last_refused_at`,
`last_refused_reason`, `created_at`, `updated_at`.

### Internal endpoints

Reads need `ai_workload:view`, so a workload manager can see the URL to give
an application. Writes need `ai_gateway:manage` (Owner, Admin, AI Gateway
admin; `rbac.go:300-306`), because the endpoint is a gateway setting.

- `GET /internal-endpoints` → one row per gateway in the organization with
  its configuration (if any), capability and status: `supported`, `ready`,
  `error`, `certificate_not_after`, `certificate_sha256`, `url`.
- `PUT /internal-endpoints/{nodeId}` with `enabled`, `listen_addresses`, `port`,
  `dns_name`, `source_cidrs`, `tls_mode`, `expected_revision`.
  - 409 `ai_internal_endpoint_unsupported` when the gateway's fresh report
    (90 s) lacks `ai_internal_endpoint_version >= 1`.
  - 409 `ai_internal_endpoint_address_unapproved` when an address is neither
    the organization's pool gateway address (`ipalloc.GatewayCIDR`, as in
    `vpn_auto.go:22-41`) nor inside an approved subnet of the gateway's site
    (same query as `resolver_static.go:177-193`). At most one of each.
  - 400 for public or overlapping CIDRs, using the DNS LAN validation
    (`resolver_static.go:128-160`).
- `DELETE /internal-endpoints/{nodeId}` → 204.
- `GET /internal-endpoints/ca.pem` → the organization's internal AI CA
  certificate. Created on first use.
- `PUT /settings` gains `public_static_keys_allowed` (`ai_gateway:manage`).

### Agent channel (node mTLS)

- `GET /agent/ai-internal/desired-state` →
  `{ "version": 1, "endpoint": null | { "id", "revision", "listen_addresses",
  "port", "dns_name", "source_cidrs", "tls_mode" } }`.
- `POST /agent/ai-internal/certificate` with a PEM CSR → leaf and chain. The
  control plane signs only the configured SANs, for the calling node.
- `POST /agent/ai-key/v1/{chat/completions | completions | embeddings |
  audio/speech | audio/transcriptions | images/generations | rerank}` and
  `POST /agent/ai-key/anthropic/v1/messages`.
- `GET /agent/ai-key/v1/models`.

## Admission flow

### Internal scope

1. The application calls `https://<address or dns name>:<port>/v1/chat/completions`
   with `Authorization: Bearer tnx_sk_...`.
2. The gateway accepts the TCP connection only if the direct peer address is
   inside the endpoint's `source_cidrs`. Otherwise it closes the connection
   before TLS. No response, no TLS handshake to probe.
3. TLS handshake with the endpoint certificate. Plain HTTP is not served.
4. The gateway checks the path against the allowlist above, the method, no
   query string, exactly one `Authorization` header starting `Bearer tnx_sk_`
   with the right length. Anything else gets a local 400, 401 or 404. Other
   bearers (human tokens, `tnx_wai_`) are not forwarded.
5. The gateway takes a concurrency slot (16) or answers 429.
6. The gateway relays over mTLS to `/agent/ai-key/...`. It sends only
   `Content-Type`, `Accept`, `Authorization` and `X-Tunnex-Peer-IP` (set by
   the gateway from the TCP peer). The body is capped as in the adapter.
7. The control plane authenticates the node from its certificate
   (`agentchannel.go:515`). The node must be active and not revoked.
8. It loads the node's `ai_internal_endpoints` row. It must exist, be enabled,
   and belong to the node's organization. `X-Tunnex-Peer-IP` must be a single
   valid IPv4 address inside the row's `source_cidrs`.
9. It calls `Adapter.ServeAuthorized` with a closure that calls
   `StaticKeys.Authorize(ctx, raw, model, Internal{org, node, endpoint, peer})`.
10. `Authorize`:
    1. Format and checksum, then lookup by `secret_hash` (cross-organization,
       like `workload_auth.go:96`).
    2. `key.org_id` must equal the node's organization. Otherwise refuse, as
       unknown.
    3. Not revoked, not expired, `workload_epoch` matches.
    4. `scope = internal`. A public key here is refused with reason
       `wrong_ingress`.
    5. If the key has `source_cidrs`, the peer address must be inside them.
    6. The organization has AI on. The workload is enabled and applied. The
       model is on its list. Provider access holds. Same checks as
       `workload_auth.go:281-307`.
    7. Rate limit through the Redis limiter, key `ai-static-key:<id>`, per
       minute. Limiter error means refuse.
    8. Cost: the key's own threshold over the key's engine key. Then the
       workload threshold over the workload's engine key plus the engine keys
       of all its static keys that were active at any time today.
    9. Open the key's sealed engine key. Return a `Grant` with
       `SubjectKind: "workload_key"`, `Agent: <key id>`, `Instance: ""`,
       expiry 30 s. The adapter's concurrency counter is keyed by
       `Tenant/SubjectKind/Agent` (`adapter.go:200-208`), so each key gets its
       own 4 slots per process instead of sharing the workload's. Nothing else
       reads `Grant.Agent` or `Grant.Instance` today (`adapter.go:30`,
       `workload_auth.go:326`).
11. The adapter forwards to the engine and streams the answer back, unchanged
    from today (`adapter.go:196-300`).
12. `last_used_*` is updated when older than one minute. A refusal sets
    `last_refused_*` the same way.

### Public scope

1. The SaaS tool calls `https://<control plane>/ai/v1/chat/completions` with
   the key.
2. `aiTransportMiddleware` runs. Then `workloadMiddleware` sees
   `Bearer tnx_sk_`.
3. Not HTTPS by `requestHTTPS`: refuse 403 before lookup.
4. The client address comes from the trusted chain only. A new step in
   `requestTransport.middleware`, which runs before `middleware.RealIP`
   (`router.go:204-210`), records it. It records `X-Real-IP` only when the
   immediate peer is trusted and the header is exactly one valid IP. With no
   trusted proxy configured, it records the raw peer address. Otherwise it
   records nothing.
5. `StaticKeys.Authorize(ctx, raw, model, Public{clientAddr})`. Same steps as
   above, except:
   - `scope` must be `public`. An internal key is refused with reason
     `wrong_ingress`.
   - The organization switch must be on.
   - If the key has `source_cidrs`, the client address must be known and
     inside them. An unknown address is refused.
6. `GET /ai/v1/models` with a static key lists the workload's models, as for
   tokens (`ai_workload_handlers.go:246-253`).

### Refusals

- The caller sees the adapter's fixed messages, 401 or 403
  (`adapter.go:305-331`). A valid internal key on the public endpoint gets the
  same 403 as any other policy refusal. It does not confirm that the key is
  valid.
- The administrator sees the exact reason on the key ("Last refused: used on
  the public endpoint, from 203.0.113.7, 2 minutes ago") and in the audit log.

## Gateway internal listener

- **Reach.** A caller needs a route to the listen address. v1 allows up to
  two addresses per gateway:
  - **The gateway's tunnel address**, the organization pool gateway address
    the 8083 listener uses (`vpn_auto.go:22-41`). Every VPN device on that
    gateway already routes it, with no subnet grant. This is the path for
    laptops, Windows machines and build agents on the VPN.
  - **One LAN address** inside an approved subnet of the gateway's site
    (`resolver_static.go:177-193`). Hosts on that LAN reach it directly.
    Other sites reach it over site-to-site, because the site subnet is
    already routed between linked sites. A VPN device reaches it only if it
    has a route and grant to that subnet, as for any site resource.
  - A gateway without a site can use only its tunnel address.
  - The leaf certificate carries every configured address as an IP SAN.
  - See Open question 9.
- **Package.** A new `apps/node/internal/aiinternal`. It reuses the relay
  shape of `aivpn` (reverse proxy, `FlushInterval: -1`, fixed outgoing
  headers, `relay.go:91-103`) and the transport from
  `client.AIVPNTransport()` (`ai_vpn_transport.go:13-27`).
- **Not bound to a device.** It listens on each `listen_addresses` entry, on `port`, with
  `tcp4`, without `SO_BINDTODEVICE`. VPN and site traffic to the LAN address
  arrives on the tunnel interface. A device-bound socket would refuse it. The
  peer CIDR check is the guard.
- **Ownership.** It binds only when the address is on an active,
  non-loopback interface of the gateway, like `ownedLANAddress`
  (`lan_listeners.go:73-91`). It re-checks every second and closes on doubt,
  like `aivpn.Runtime.Reconcile` (`runtime.go:143-194`).
- **No backend requirement.** It does not read the WireGuard peer table, so
  it does not need kernel WireGuard. It does need the control channel over
  HTTPS with the rotating node certificate.
- **Capability.** The gateway reports, as typed fields:
  `ai_internal_endpoint_version: 1` (always, from this build),
  `ai_internal_endpoint_ready`, `ai_internal_endpoint_address`,
  `ai_internal_endpoint_port`, `ai_internal_endpoint_error`,
  `ai_internal_endpoint_cert_not_after`, `ai_internal_endpoint_cert_sha256`.
  Add them to `PolicyStatus` (`client.go:246-255`), to the report payload
  (`client.go:264-288`) and to the control plane's rebuilt capabilities JSON
  (`nodes/service.go:2531-2553`). Bound the error string. A readiness change
  kicks the report, as the AI listener does (`main.go:435-440`).
- **Old gateways.** A gateway without the version cannot be configured. The
  console says "Upgrade this gateway to use the internal AI endpoint". If a
  row exists and the gateway is later downgraded, the gateway never calls the
  desired-state route, the report has no ready flag, and the console shows
  "not serving".
- **Peer address check.** Done twice on the gateway, at accept (before TLS)
  and in the handler, on the TCP peer address after `Unmap()`. Never on
  `X-Forwarded-For`, `X-Real-IP` or `Forwarded`.
- **Firewall.**
  - VM gateways have no Tunnex input rule for LAN traffic. The operator opens
    the port in the host or cloud firewall, for the source ranges only. The
    console says so.
  - In-cluster gateways drop tunnel input except listed listeners
    (`apps/node/internal/egress/egress_linux.go:960-996`). Add one rule while
    the endpoint is on: tunnel ingress, `tcp dport <port>`, destination the
    tunnel address (`fib daddr . iif type local`, as the 8083 rule) or the
    configured LAN address (`ip daddr <address>`), accept. Add its comment to `k8snetprep` and to
    `validateTunnexInput`, because that chain's shape is a contract
    (`egress_linux.go:975`).
  - This input accept sits outside Zero Trust forward rules. The source CIDRs
    and the key are the only controls. The console says so next to the CIDRs.
- **TLS.** TLS 1.2 minimum. `GetCertificate` returns the current leaf. With a
  DNS name set, an SNI that is neither the name nor empty is refused, as in
  `ai-vpn-relay` (`main_linux.go:105-107`). A handshake has 10 s.
- **Limits, copied from the existing relays.**
  - 16 concurrent requests (`relay.go:90`).
  - Request deadline 35 s (`relay.go:137`).
  - Server: header 5 s, read 35 s, write 40 s, idle 30 s, 16 KiB of headers
    (`runtime.go:172-176`).
  - Body: 256 KiB, or 8 MiB plus 64 KiB for transcription, the adapter's caps
    (`adapter.go:130-134`). An oversized body never leaves the gateway.
  - Upstream: fresh mTLS per request, 16 connections, 30 s to headers
    (`ai_vpn_transport.go:22-26`).
- **Not proxied.** Videos (they need the video job routes), any other path,
  any query string.
- **Errors.** Fixed short messages, as `relay.go:102` and `:110-148` do. No
  upstream detail.

## Audit and Usage

### Audit log

Rows use the existing `audit_logs` shape (`workload_auth.go:70-73`).

- Administrator actions: `ai_workload.static_key_created`, `_rotated`,
  `_updated`, `_revoked`. Metadata: workload, scope, expiry, CIDR count,
  limits. Never the secret or its hash.
- System: `ai_workload.static_key_revoked` with cause `workload_disabled`.
- Security signal: `ai_workload.static_key_refused` for `wrong_ingress` and
  `source_not_allowed`, at most once per key per hour, with ingress, source
  and gateway.
- Endpoint: `ai_gateway.internal_endpoint_changed` and `_removed`.
- Allowed requests are not audit rows. Volume is unbounded. They show as
  `last_used_*` and in Usage, as AI-SEC-2 decided for MCP calls
  (`docs/AI-SEC-2-decisions.md:80-85`).

### Usage

- `bindingUsageIDs` (`usage.go:18-23`) and the dashboard union
  (`usage_dashboard.go:62-69`) add static key engine ids. A key is included
  when it was active at any time in the query window: `created_at < to` and
  `coalesce(revoked_at, expires_at) > from`.
- Static key cost rolls up into its workload row. A new `workload_keys`
  attribution list on `AIUsageDashboard` shows each key: id, name, workload,
  scope, cost, requests.
- The workload threshold counts the workload's engine key plus its keys that
  were active today. A key revoked today still counts today.
- **Capacity.** Only active keys count toward the 64 binding cap
  (`workloads.go:228-234`). A usage query can still pass 64 ids once keys
  rotate. The engine calls are therefore split into batches of 64 and summed,
  instead of refusing at `usage.go:37`. See Open question 1.

## UI

### Workload page

- The "Connect application" card (`AIWorkloads.tsx:284-292`) offers two
  choices, in this order:
  - **Run with Tunnex CLI (recommended)**. "Each replica gets its own identity
    and short-lived tokens. Linux and macOS."
  - **Static API key (for serverless, Windows and SaaS tools)**. "One key you
    paste into the tool. It expires and you rotate it."
- A new tab, **API keys**, next to "Enrollment keys" and "Instances"
  (`AIWorkloads.tsx:187`). Columns: name, scope, last 4, expires, last used
  (where from), status.
- Create key, step by step:
  1. Name.
  2. Where the tool runs:
     - **Inside your network (recommended)**. "The key works only on your
       internal AI endpoint. It is refused on the internet."
     - **Public internet**. "For SaaS tools that cannot reach your network.
       Limit it to the tool's IP addresses." Disabled, with the reason, when
       the organization switch is off.
  3. Expiry: 7, 30 or 90 days, or a date. Default 30.
  4. Optional: allowed source ranges, daily limit, requests per minute.
  5. Show once. Then show how to use it: the base URL (internal endpoint URL
     or `https://<control plane>/ai/v1`), the CA download for an internal
     endpoint that uses the Tunnex CA, and code samples.
- With no internal endpoint configured, the internal choice says "No gateway
  serves the internal AI endpoint yet" and links to the settings below.
- Expiring keys show a badge 14 days ahead. Rotate and Revoke are row actions.

### AI Gateway settings

- A new section, **Internal AI endpoint**. One row per gateway: status,
  address, port, DNS name, source ranges, certificate mode and expiry.
- Edit form fields: address, port (default 9443), DNS name (optional), source
  ranges (required), certificate mode.
- The form says: "Open TCP <port> from these ranges in your firewall. Traffic
  to this port is not covered by access rules."
- Old gateway: "Upgrade this gateway to use the internal AI endpoint."
- A switch, **Allow public static keys**, off by default.

### Usage

The workload row expands to its keys.

## Upgrade and compatibility

- The migration only adds tables and one column. Nothing existing changes.
- Upgrade the control plane first. Gateways follow.
- New control plane, old gateway: no capability, so the endpoint cannot be
  configured on it. Public keys work.
- Old control plane, new gateway: `/agent/ai-internal/desired-state` answers
  404. The gateway keeps the listener off and reports version 1 with no ready
  flag. Nothing breaks.
- Existing workloads, tokens, the CLI, the desktop client, the 8083 and 8084
  listeners: unchanged.
- One-click upgrade covers it. There is no new service, no new port on the
  control plane, and no new environment variable.
- In-cluster gateways need the image that renders the new input rule. The
  capability is reported only by that image.

## Security analysis

### A leaked internal key

- **Can:** call the workload's models from inside an allowed source range, on
  a gateway that serves the endpoint. That is up to the key's and workload's
  limits, until expiry or revoke.
- **Cannot:** be used from the internet. The public endpoint refuses it. It
  cannot be used from outside the endpoint's source ranges or the key's
  ranges. It cannot reach other models, other workloads or other
  organizations, change settings, or outlive 90 days.

### A leaked public key

- **Can:** call the workload's models from any address in the key's
  allowlist, or from anywhere if it has none, within its limits, until expiry
  or revoke.
- **Cannot:** be used over plain HTTP, on the internal endpoint, past its
  limits, or past 90 days.
- Detection: last used (where from) and refusals per key, the
  `static_key_refused` audit row, and secret scanning through the prefix.

### Insider risk

- Anyone who can see the key can use it within its scope. That includes the
  people running the SaaS tool or the Lambda. This is the cost of a static
  key. It is why the CLI stays recommended and why expiry is mandatory.
- A person inside an allowed range with a stolen internal key looks like the
  workload. The audit shows the source address and gateway. Narrow per-key
  ranges make this visible.
- Only `ai_workload:manage` holders create keys. Only `ai_gateway:manage`
  holders open the endpoint or allow public keys.

### The gateway

- The gateway terminates TLS, so it sees keys in transit. A compromised
  gateway already sees all traffic through it. It cannot mint keys or read
  stored ones (only hashes are stored). It cannot use a key for another
  organization: the control plane refuses a key whose organization differs
  from the node certificate's.
- A gateway cannot claim another gateway's endpoint. The control plane loads
  the endpoint row by the node in the certificate.
- `X-Tunnex-Peer-IP` is trusted only on the mTLS route, as `X-Tunnex-VPN-IP`
  is today (`agentchannel_ai.go:54-63`). Public handlers never read it.

### NAT and load balancer caveat

- Internal: the CIDR check sees the direct peer. If traffic passes source NAT
  (a NAT gateway, a remote site that masquerades, a load balancer in front of
  the gateway), the peer is the NAT address. Every caller behind it then
  looks the same. The console says so next to the source ranges.
- VPN callers keep their tunnel address. Site-to-site traffic to the gateway
  itself keeps its source, unless the far side translates it.
- Public: the address comes from the trusted proxy chain. Behind an external
  load balancer (`TUNNEX_TLS_MODE=terminated`) it needs
  `TUNNEX_EDGE_TRUSTED_PROXIES` and the balancer must pass the client address
  (`docs/trusted-proxy-transport.md:22-40`). The Helm edge sets `X-Real-IP`
  from its own peer (`edge-ai-nginx.conf:38`), so it must be fixed before
  allowlists work there. When the chain cannot give an address, keys with an
  allowlist are refused and the settings page says "Client address not
  available behind this proxy".
- Lambda without a fixed egress (no NAT gateway) has no stable public
  address. Use an internal key from a VPC, or a public key without an
  allowlist and a short expiry.

## Open questions for the founder

1. **Per-key engine keys and the 64-binding cap.** Each key needs its own
   engine key to show cost per key. Rotation adds retired engine keys over
   time.
   - Recommended: own engine key per static key (D7). Only active keys count
     toward the 64 cap. Usage queries are window-scoped and batched in 64s.
     Revisit the cap itself in a separate story.
2. **What the caller sees for a valid key on the wrong endpoint.**
   - Recommended: the same generic 403 as any policy refusal. The exact
     reason goes to the key page and the audit log. A leaked key should not
     confirm it is valid.
3. **An organization switch for public keys.**
   - Recommended: yes, "Allow public static keys", off by default, held by
     `ai_gateway:manage`. It keeps "internal only" true for an organization
     until an AI administrator chooses otherwise.
4. **Pin an internal key to specific gateways.**
   - Recommended: not in v1. An internal key works on any gateway of its
     organization that serves the endpoint. The source ranges already narrow
     it. Add pinning if a customer asks.
5. **The Anthropic SDK sends `x-api-key`, not `Authorization`.**
   - Recommended: accept `x-api-key: tnx_sk_...` on `/anthropic/v1/messages`
     only, on both endpoints, with exactly one credential header present.
6. **TLS default on the internal endpoint.**
   - Recommended: Tunnex private CA per organization by default, customer
     files as the second mode. Self-signed pinning is rejected. ACME DNS-01
     waits for `app-certs`.
7. **Expiry reminders.**
   - Recommended: a console badge from 14 days, plus an alert through the
     existing alert outbox (`main.go:505`) at 14 and 3 days to `ai_workload:manage`
     holders.
8. **Workload tokens (`tnx_wai_`) on the internal endpoint.**
   - Recommended: not in v1. The CLI path already works over the public
     endpoint. Adding it later is one more prefix on the gateway allowlist.
9. **Which addresses the internal endpoint may listen on.**
   - Recommended: the gateway's tunnel address (every VPN device routes it,
     no subnet grant needed) and at most one LAN address in an approved site
     subnet (LAN and site-to-site callers). Not an arbitrary address on a
     gateway without a site.
10. **Concurrency per key.** The adapter allows 4 requests at once per
    subject per process (`adapter.go:200-208`). Lambda fan-out can hit it.
    - Recommended: give each key its own 4 (Admission flow, internal scope, step 10.9), keep the
      number in v1 and document it. The per-minute rate limit is the real
      control. Raise it in a separate change if the walk or a customer needs
      more. The 429 body says "AI request limit reached" for both, so the
      key page shows which limit refused.

## Founder decisions (2026-11-28)

The founder approved building AI-KEYS-1 with the recommended answer to every
open question above:

1. Each static key has its own engine key. Only active keys count toward the
   64-binding cap. Usage queries are window-scoped and batched in groups of 64.
2. A valid key on the wrong endpoint gets the same generic 403 as any policy
   refusal. The exact reason is shown on the key page and in the audit log.
3. The organization switch "Allow public static keys" exists, is off by
   default and is held by `ai_gateway:manage`.
4. No per-gateway pinning of internal keys in v1.
5. The `x-api-key` header is accepted only on the `/anthropic/v1/messages`
   route, on both endpoints, and only when it is the one credential header
   present.
6. TLS on the internal endpoint: a private Tunnex CA per organization by
   default, customer certificate files as the second mode, DNS-01 later.
7. Expiry: a console badge from 14 days, plus alerts at 14 and 3 days.
8. No workload tokens (`tnx_wai_`) on the internal endpoint in v1.
9. The internal endpoint listens on the gateway tunnel address plus at most
   one LAN address in an approved site subnet.
10. 4 concurrent requests per key per process. The per-minute rate limit is the
    real control.

## Validation plan

### Unit

- Key format, checksum, length and hash. Display hint.
- Expiry: required, at most 90 days, rotate overlap bounds.
- `StaticKeys.Authorize`, one test per refusal: unknown key, other
  organization, revoked, expired, epoch mismatch, wrong ingress both ways,
  source outside key ranges, unknown public address with an allowlist, public
  keys switched off, workload disabled or not applied, model not on the list,
  rate limit, limiter down, key threshold, workload threshold including a key
  revoked today.
- The default closure in `main.go` refuses `tnx_sk_`.
- Public path: HTTP refused whatever "Allow HTTP" says. Client address taken
  from `X-Real-IP` only from a trusted peer. A spoofed `X-Forwarded-For` or
  `X-Real-IP` from an untrusted peer ignored.
- Gateway: connection from outside the ranges closed before TLS. Forged
  `X-Forwarded-For` and `X-Tunnex-Peer-IP` from the caller ignored and
  overwritten. Only `tnx_sk_` forwarded. Path allowlist, body caps, 16 slots,
  timeouts. Listener closes when the address leaves the interface.
- Agent-channel route: node of another organization refused, disabled
  endpoint refused, peer outside endpoint ranges refused.
- Certificate signing: only configured SANs, only for the calling node.
- In-cluster input chain renders the new rule and `validateTunnexInput`
  accepts it.

### Integration (Postgres, engine fake, Redis)

- Create, list, edit, rotate, revoke, with audit rows.
- Disable the workload: keys refused, re-enable does not revive them.
- Usage: per-key rows, roll-up to the workload, more than 64 ids in a window.
- Capability gating: save refused without a fresh report.
- `make generate-check`, changed Go packages in both editions, web unit
  suite, typecheck, build, gofmt.

### Real walk on the GCP test machines

Control plane and gateway on one machine, the agent VM on the other, as in
the AI-SEC-2 walk. Never run gcloud on the laptop; give Cloud Shell commands
for any firewall rule.

1. Configure the internal endpoint on the gateway's private address, port
   9443, source range = the agent VM's subnet, Tunnex CA. Open the port in the
   GCP firewall from that subnet only.
2. Create a workload with one model and a $1 threshold. Create an internal
   key.
3. From the agent VM, with `ca.pem` trusted, call
   `https://<gateway private IP>:9443/v1/chat/completions`. It works. Usage
   shows the key under the workload.
4. Same key against `https://<control plane>/ai/v1/chat/completions`.
   Refused with the generic 403. The key page shows "used on the public
   endpoint". An audit row exists.
5. Same key over plain HTTP, and with TLS verification on but without
   `ca.pem`. Both fail.
6. Narrow the endpoint range to the agent VM's /32. Call from the control
   plane host: the connection is closed before TLS. Restore the range.
7. Add the gateway's tunnel address to the endpoint. From a VPN-connected
   device on that gateway (in the range), call
   `https://<gateway tunnel address>:9443/v1/chat/completions`: it works.
   Then give that device a route and grant to the gateway's LAN subnet and
   call the LAN address: it works too. That request arrives on the tunnel
   interface for an address on the LAN interface, which proves the listener
   is not bound to a device.
8. Turn on public keys. Create a public key with the agent VM's public egress
   IP as the allowlist. Call the public endpoint from the agent VM: works.
   Call from another address: refused. Call the internal endpoint with it:
   refused.
9. Create a key whose expiry is a few minutes out (no minimum applies).
   After expiry: refused.
10. Revoke a key during a stream of requests. The next request is refused.
11. Rotate with a 1-hour overlap. Both keys work. Revoke the old one. Only the
    new one works.
12. Rate limit 5 per minute: the sixth request in a minute gets 429, and the
    key page shows `rate_limited`.
13. Key threshold, then workload threshold: requests stop at each.
14. Disable the endpoint in the console: refused at once, then the listener
    closes within one poll.
15. Run the old gateway image: the console refuses to configure it and says
    to upgrade.

## As built

Built on `story/ai-static-keys-1` in phases (control plane public scope,
internal endpoint control plane side, gateway listener, web console, docs).
Everything follows the paper and the founder decisions except the points
below. Where the paper turned out unsafe or ambiguous in the code, the safer
option was taken.

### Data model

- **Migration 0258 with a gap.** origin/main ends at 0256 and 0257 is reserved
  for the user-group cost limit branch. golang-migrate reads the sorted file
  list, so a fresh database goes 0256 → 0258 and `down` goes 0258 → 0256
  (checked: up, down, up on a scratch database). Caveat for merge order: a
  database that already recorded 0258 will never run a 0257 merged later,
  because migrate only moves forward from the recorded version. 0257 must
  merge first, as planned, or this migration must be renumbered at merge time.
- **Extra columns on `ai_workload_static_keys`.** `engine_disabled_at` (the
  maintenance sweep disables an engine key once and retries on failure),
  `last_refused_ingress`, `last_refused_source`, `last_refused_node_id` (the key
  page shows where a refusal came from), `last_refusal_audit_at` (the hourly
  audit limit), `expiry_alert_14_at` and `expiry_alert_3_at` (each reminder is
  sent once). The API also derives a status `expired` for display.
- **`ai_internal_endpoints.node_id`** references `nodes(id)` with cascade, plus a
  trigger that refuses a row whose node belongs to another organization.
  `nodes` has no `(org_id, id)` unique key to build a composite foreign key on,
  and adding one would change an existing table.
- **Alert event.** The migration widens the four alert event-key checks with
  `ai_workload.static_key_expiring` (the same pattern as 0254). Its down
  migration refuses to run while such alert rows exist, so history is never
  deleted.

### Keys and admission

- **The organization switch has its own route**,
  `GET/PUT /ai-gateway/static-key-settings`, instead of a new field on
  `PUT /ai-gateway` (the existing opt-in body has `additionalProperties: false`
  and only `enabled`; changing it would change the enable flow). GET needs
  `ai_workload:view` so the create form can explain why Public is disabled;
  PUT needs `ai_gateway:manage`.
- **Update also takes `allow_any_source`**, so removing every range from a
  public key needs the same second confirmation as creating it.
- **A key's daily limit may equal the workload's** (the paper says "lower");
  equal is harmless because both are checked on every request.
- **Internal key ranges and endpoint ranges** use the DNS LAN rule: RFC 1918
  IPv4 only (10/8, 172.16/12, 192.168/16), canonical, no duplicates.
- **Public key ranges** refuse any range that overlaps private, CGNAT,
  loopback, link-local, multicast, reserved or documentation space, in IPv4 and
  IPv6. 0.0.0.0/0 and ::/0 therefore fail; "any address" is an empty list plus
  the confirmation.
- **Rate limit.** The shared Redis limiter used for MCP calls
  (`mcpdecision.RedisLimiter`), key `ai-static-key:<id>`, one-minute window. A
  limiter error, or no limiter at all, refuses the request (503). The adapter
  maps only the static key sentinel `ErrRequestLimited` to its fixed 429 body;
  every other resolver keeps today's 401/403/503 mapping.
- **Refusal recording.** Every refusal of a known key records its reason on the
  key (at most once a minute per reason), written after the admission
  transaction rolled back so it never changes the response. Only
  `wrong_ingress` and `source_not_allowed` also write
  `ai_workload.static_key_refused`, at most once per key per hour. A key of
  another organization arriving on a gateway is refused as unknown and nothing
  is recorded on it.
- **Authorize re-checks the endpoint row** (enabled, peer inside its ranges) in
  its own transaction, in addition to the mTLS route's check.
- **Videos** are refused for static keys on the public path (404), as on the
  internal endpoint, because they need the video job routes.
- **The default closure** moved from `main.go` into
  `aigateway.DefaultAuthorize` so its `tnx_sk_` refusal has a unit test.
- **Engine keys.** Created in the same transaction as the key. If the engine
  call fails the key stays `error` (or `pending` while the workload has no
  models) and cannot authorize; maintenance retries it. Revoke disables the
  engine key right after the commit and maintenance retries a failure. When a
  workload loses all its models, its static keys' engine keys are not disabled
  (the workload's own key is); admission refuses every model anyway, and the
  engine key values are known only to the control plane.
- **Usage windows.** Static key engine ids are picked with one hour of slack on
  each side of the window (the engine itself filters by time), so clock skew
  between the API host and the database cannot drop a key. Lists longer than 64
  ids are validated without the 64 bound and sent in batches of 64.
- **Expiry reminders** go through the alert outbox to the organization's alert
  destinations subscribed to `ai_workload.static_key_expiring` (warning at 14
  days, critical at 3), not directly to `ai_workload:manage` holders: alert
  routing is by subscription today. A key created with less than 3 days left
  gets one reminder, not two.

### Internal endpoint

- **The CA download is `GET /ai-gateway/internal-endpoint-ca`** and returns
  JSON (`certificate_pem`, `not_after`, `sha256`); the console saves it as
  `ca.pem`. A literal `/internal-endpoints/ca.pem` next to
  `/internal-endpoints/{nodeId}` would have been ambiguous for the validator.
- **Capability fields.** `ai_internal_endpoint_addresses` is a list (the
  endpoint can listen on two addresses) instead of one
  `ai_internal_endpoint_address`, and `ai_internal_endpoint_revision` was added
  so the console shows Ready only for the revision actually being served.
- **CSR signing** accepts ECDSA P-256/P-384 and RSA of at least 2048 bits,
  ignores every name in the CSR, and writes a system audit row
  `ai_gateway.internal_endpoint_certificate_issued` per leaf.
- **The CA is created on first use by any reader** of the CA route
  (`ai_workload:view`); it holds no secret the reader can see.

### Gateway listener

- **Handshake deadline 5 s**, not 10 s: net/http bounds the TLS handshake by
  its smallest server timeout (header 5 s). Stricter.
- **In-cluster input rule** matches `ip daddr <configured addresses>` for both
  the tunnel and LAN address (one rule shape, narrower than `fib daddr`). It
  is rendered only while the endpoint is served; with no endpoint the chain is
  byte-identical to before (existing goldens unchanged). `validateTunnexInput`
  checks the rule's shape, not the configured values, so a restarted agent
  does not refuse its previous chain before it has fetched the document.
  Still to prove on Linux: the kernel's JSON for a two-address set.
- **SNI.** With no DNS name set, any non-empty SNI is refused (clients that
  connect by IP send none). With a DNS name, only that name or no SNI.
- **Custom certificate** that does not cover the configured addresses is still
  served and reported as `custom_certificate_not_covering` (the console warns,
  as the paper says). An expired certificate, a mismatched pair or a key file
  readable by group or others is not served.
- **A fresh in-memory key per CSR**, not one per process.
- **The gateway checks the key's shape only** (prefix, length, base62); the
  checksum and everything else are checked by the control plane.
- **Desired-state errors.** Any 3xx/4xx (including 404 from an old control
  plane), a non-200 or an invalid document stops the listener at once. Network
  errors, timeouts and 5xx keep the last good document for at most 60 s.
- **Errors reported** are fixed codes only (`invalid_desired_state`,
  `desired_state_unavailable`, `certificate_unavailable`,
  `custom_certificate_unavailable`, `custom_key_permissions`,
  `custom_certificate_not_covering`, `address_not_owned`, `bind_failed`).
- **Bodies are buffered** at the paper's caps so an oversized body never leaves
  the gateway (worst case about 130 MiB across 16 slots).

### Console

- Create key is one form with numbered steps, not a multi-page wizard.
- The "Inside your network" choice stays selectable when no gateway serves the
  endpoint yet (with the note and link); otherwise, with public keys off, no
  key could be created at all. The key works once a gateway serves it.
- The Internal AI endpoint section sits beside the existing AI Gateway settings
  card on the Settings page, so that component and its tests are unchanged.
- The API keys tab loads its data only when opened; existing requests on the
  workload page are unchanged.

### Not proven yet

- The real walk on the GCP test machines (validation plan, 15 steps) has not
  run. Linux-only gateway tests (egress and k8snetprep goldens with the new
  rule, `cmd/agent`, real interface ownership and binding) compile but have not
  run on Linux.
