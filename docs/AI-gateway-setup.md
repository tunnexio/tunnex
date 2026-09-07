# Optional customer-owned AI gateway

This Compose slice installs one private Bifrost engine beside the control plane. AI is available in Community but every organization's AI setting starts disabled. Installing the engine never opts organizations in. Existing VPN and direct clients keep their existing behavior. Provider credentials stay on the customer's engine; agents receive a separate, short-lived Tunnex AI credential.

The qualified engine is Bifrost v2.0.0. `deploy/ai-gateway/compose.yml` pins the official `maximhq/bifrost` OCI index digest `sha256:cf71be9fad4e0749b6e26cbb774c687413dad9a0970b83f4e1dadb6f503ea208`. Read-only Docker Hub inspection on 2026-09-07 returned Linux amd64 manifest `sha256:dd628f6a72347853066c16e9190340a6eb125d7e7682d3e1f79c6c65122eac8c` and Linux arm64 manifest `sha256:e066b4dcef06d5745bc08e79f2fd0aad790d5d0b94a2e4e3c3d62ad7c6e32303`. These are container manifests, separate from the Mac qualification binary digest.

## Configure and install

Use the existing installation's explicitly verified Compose project and root environment file. Never change the project name during an upgrade: it selects persisted state. Examples below assume the operator has exported `COMPOSE_PROJECT_NAME` and `AI_ENV_FILE`; the latter names a private environment file containing the existing stack settings and the four additional variables in `deploy/ai-gateway/.env.example`. Give that file owner-only permissions. Do not put it in Git, paste its contents into support logs, or print resolved Compose configuration with real credentials.

Populate these values through the customer's normal secret-management process:

- `TUNNEX_AI_GATEWAY_ADMIN_USER` and `TUNNEX_AI_GATEWAY_ADMIN_PASSWORD`: private engine administration credentials shared only by the API and engine.
- `TUNNEX_AI_OPENROUTER_API_KEY`: the customer's OpenRouter provider credential, delivered only to Bifrost.
- `TUNNEX_AI_ENGINE_ENCRYPTION_KEY`: a durable private encryption passphrase, at least 16 bytes. Preserve it with encrypted backups; replacing it is not an upgrade procedure.

`config.json` references environment variables instead of containing secret values. The provider key ID is operator configuration: the sample uses `openrouter-primary` and the exact provider model `openai/gpt-4o-mini`. If changing either, edit the non-secret configuration and use the identical provider key ID/model in the Tunnex policy configuration. The inference model identifier is `openrouter/openai/gpt-4o-mini`. The sample grants no virtual keys; the control plane provisions scoped keys through the private admin API when policy is applied. Do not create a shared all-model agent key.

From the repository root, after reviewing the selected project:

```sh
: "${COMPOSE_PROJECT_NAME:?Select the existing installation project}"
: "${AI_ENV_FILE:?Set the absolute private environment-file path}"
docker compose --env-file "$AI_ENV_FILE" -p "$COMPOSE_PROJECT_NAME" \
  -f docker-compose.yml -f deploy/ai-gateway/compose.yml --profile ai config --quiet
docker compose --env-file "$AI_ENV_FILE" -p "$COMPOSE_PROJECT_NAME" \
  -f docker-compose.yml -f deploy/ai-gateway/compose.yml --profile ai up -d bifrost api
```

The override passes `TUNNEX_AI_GATEWAY_URL=http://bifrost:8080` and engine admin credentials to the API. Engine HTTP runs only on the dedicated Compose network shared with the API. No engine data/admin port is published to the host; there is no proxy route to the Bifrost dashboard. Provider HTTPS egress is required, so the engine network is not Docker `internal:true`. Host administrators and processes with Docker access remain trusted. Verify the runtime port bindings and network attachments before enabling an organization.

After the engine is healthy, explicitly enable the organization's AI setting and apply an authorized agent policy with exact models and provider key IDs. An enabled setting alone does not grant model access. Check installation availability and policy-application status before issuing AI credentials.

## Enrolled-agent request flow

Enroll through the existing agent bootstrap workflow. Retain the returned current runtime credential in the agent's protected credential store. The bootstrap token is single-use and cannot be substituted for the runtime bearer. Send the current runtime credential only to the TLS-protected control plane:

```http
POST /api/v1/agent/runtime/ai-credential
Authorization: Bearer <current-runtime-credential>
```

A successful `201` response contains `token`, `audience: tunnex-ai`, `expires_at`, and `endpoint`. Treat `token` as a secret and renew before its five-minute expiry; never log the response. Send that AI token to the public Tunnex AI endpoint, not to Bifrost:

```http
POST /ai/v1/chat/completions
Authorization: Bearer <short-lived-ai-token>
Content-Type: application/json

{"model":"openrouter/openai/gpt-4o-mini","messages":[{"role":"user","content":"Reply only OK"}],"stream":true,"max_tokens":16}
```

The qualified Anthropic-compatible route is `/ai/anthropic/v1/messages`. Provider keys, engine virtual keys, engine admin credentials, user session tokens, and bootstrap tokens are not AI bearer credentials. Do not expose engine headers in client configuration.

## Accounting, retention and limits

The engine enables accounting logs with `disable_content_logging:true`; prompt and response content logging remains disabled. Both client log retention and log-store retention are set to seven days. Metadata can contain model, timestamps, usage/cost, request identifiers, and agent-related attribution, so its storage and access still require protection. A pinned-native synthetic-provider check on 2026-09-07 retained one scoped request and seven tokens in `/api/logs/stats`, then verified both unique prompt and response markers were absent from the SQLite logical dump and raw database/WAL bytes after shutdown. Run it without provider credentials using `AI0_BIFROST_BINARY=/absolute/path/to/pinned-binary python3 deploy/ai-gateway/verify-metadata.py`. This proves the tested non-streaming response path on the pinned native engine; it does not establish every provider/error/streaming path or Linux container behavior.

Usage thresholds are soft notifications based on asynchronous accounting, not strict spend caps. Already accepted requests may continue until their authorization/request deadline (at most the documented 30-second request bound); disabling AI or revoking identity does not claim instant active-stream cancellation. No automatic provider retry or fallback is configured. Missing/invalid engine credentials or absent scoped policy must fail closed.

## Disable, preserve and upgrade

Disable the organization's AI setting first to refuse new work. To stop the optional engine, use the same project, environment file and both Compose files with `stop bifrost`. This preserves both named volumes. If removing installation support completely, recreate the API using the base configuration without this override after removing AI engine environment settings. Existing organizations must remain disabled until the engine and policy are intentionally restored.

The project-scoped `ai_engine_config` volume holds Bifrost SQLite configuration and persisted virtual-key revocations. The distinct `ai_engine_logs` volume holds accounting metadata. Back up these volumes with the matching encryption key and configuration under the customer's backup process. Use a consistent SQLite backup or a stopped-engine snapshot. No `down -v`, volume deletion, or database reset is part of disable, restart or upgrade.

For an upgrade, qualify a new exact image digest first, take a restorable consistent backup, update the pin, and recreate only the engine using the same volumes. Verify protected admin/inference listeners, retained revocations, an independent active scoped key, and metadata-only logging after restart. A downgrade may require restoring the matching database backup; do not assume an older engine can read a migrated SQLite schema. Keep the last qualified image digest and backup until verification finishes.

## Verification boundary

`python3 deploy/ai-gateway/verify.py` renders Compose with dummy values and asserts the image pin, optional profile, API-only engine network, absent published ports, separate persistent state, secret references, fail-closed inference configuration and content logging setting. It starts no containers and accesses no application database. The edge `/ai/` location forwards to the API with proxy buffering/cache disabled and a 35-second proxy idle timeout; the adapter retains its own 30-second total request bound. Static assertions cover these settings; an nginx runtime parser was unavailable locally. Actual Linux image startup, volume ownership, engine reachability, restart persistence and metadata omission require the deployment walkthrough before production qualification.
