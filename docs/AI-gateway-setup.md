# Optional customer-owned AI gateway

This Compose slice installs one private Bifrost engine beside the control plane. AI is available in Community but every organization's AI setting starts disabled. Installing the engine never opts organizations in. Existing VPN and direct clients keep their existing behavior. Provider credentials stay on the customer's engine; agents receive a separate, short-lived Tunnex AI credential.

The qualified engine is Bifrost v2.0.0. `deploy/ai-gateway/compose.yml` pins the official `maximhq/bifrost` OCI index digest `sha256:cf71be9fad4e0749b6e26cbb774c687413dad9a0970b83f4e1dadb6f503ea208`. Read-only Docker Hub inspection on 2026-09-07 returned Linux amd64 manifest `sha256:dd628f6a72347853066c16e9190340a6eb125d7e7682d3e1f79c6c65122eac8c` and Linux arm64 manifest `sha256:e066b4dcef06d5745bc08e79f2fd0aad790d5d0b94a2e4e3c3d62ad7c6e32303`. These are container manifests, separate from the Mac qualification binary digest.

## Configure and install

### UI-managed providers

The **AI gateway → Models & endpoints** workspace lets an owner/admin add an
OpenAI, Anthropic, Gemini, OpenRouter, Groq, Mistral, Cerebras, xAI, DeepSeek,
Custom, Azure AI Foundry (OpenAI v1), or a configured SageMaker bridge
connection, select exact models, check catalog access, rotate the key and
disable or remove an unreferenced connection. Saved catalog checks make no inference
request; catalog inclusion does not guarantee inference access to every model.
Provider keys are write-only and encrypted only in the private engine database.
Use the site's TLS URL; never put provider secrets in team policies or agent config.

For a new Compose installation, add the managed override:

```sh
: "${COMPOSE_PROJECT_NAME:?Select the verified installation project}"
: "${AI_ENV_FILE:?Set the absolute private environment-file path}"
docker compose --env-file "$AI_ENV_FILE" -p "$COMPOSE_PROJECT_NAME" \
  -f docker-compose.yml -f deploy/ai-gateway/compose.yml \
  -f deploy/ai-gateway/compose-managed.yml --profile ai config --quiet
docker compose --env-file "$AI_ENV_FILE" -p "$COMPOSE_PROJECT_NAME" \
  -f docker-compose.yml -f deploy/ai-gateway/compose.yml \
  -f deploy/ai-gateway/compose-managed.yml --profile ai up -d bifrost api
```

This sets `TUNNEX_AI_PROVIDER_MANAGEMENT_ENABLED=true` and mounts
`config-managed.json`, which has no `providers` stanza: the native provider
configuration database is authoritative. Admin credentials and the durable
engine encryption key remain mandatory. A fresh installation needs no provider
key in its environment file; enter it when creating the connection in the UI.
For Helm, set `aiGateway.providerManagementEnabled: true` with the normal AI
settings. Only the legacy provider Secret entry becomes optional; admin and
encryption-key references remain required. AI remains single-instance.

1. Open **Models & endpoints → Add Model**, select a provider, then choose model
   suggestions or enter exact model/deployment names. Choose saved credentials or
   enter the endpoint and API key; the credential name is optional.
   **LLM Credentials → Add Credentials** also creates credentials with at least
   one model in scope. Selecting saved credentials hides endpoint/key inputs.
2. For new or replacement keys, run **Test Connect**, then save after success and
   wait for applied status. This is a small inference request and can incur a
   provider charge. If a save is uncertain, resubmit the key explicitly; the CP
   cannot recover a secret it does not store.
3. In **Configuration**, enable the org AI setting, select a team, its provider
   connections and allowed models, then assign agents. Creating a connection
   alone does not grant access.
4. Use the enrolled-agent credential exchange and proxy routes below; inspect
   **Usage & cost** for observed estimates.

Model names retain the provider prefix: `openai/gpt-4o-mini`,
`anthropic/claude-sonnet-4-20250514`, `gemini/gemini-2.5-flash`, or
`openrouter/openai/gpt-4o-mini` are examples, subject to your account's model access.
A team may select connections from several providers. Each key remains restricted
to its provider and selected models. Existing operator-managed key references
cover OpenRouter only. To change a connection's provider, create a new connection;
editing a connection cannot transfer its secret to another provider.

The provider picker is supplied by the server's supported registry. Azure OpenAI
v1 and Custom endpoints follow the public/private egress rules below. Bedrock,
Vertex, legacy Azure protocols and public model aliases are outside this slice. Catalog checks do not generate model tokens. Public catalogs may not validate API keys. Real-account
inference qualification remains distinct from local synthetic protocol tests.

For existing deployments, take a consistent backup, upgrade every CP replica and
apply migrations through 0142 before enabling multi-provider management. Migration
0141 snapshots existing team key references into explicit per-org legacy ownership. New arbitrary key IDs cannot
be used in policy: create an owned connection instead. Reserved `tnx-managed-`
prefix collisions refuse migration and require operator review. Keep the same
engine volumes, encryption key and environment variables used by legacy keys.
Never restore a file-managed provider stanza after this transition: native
startup reconciliation can remove UI-created keys. The pinned-engine transition
has been tested with a retained legacy key, new encrypted key and scoped virtual key.

Rotation preserves the key ID and usage history. Disable blocks new requests;
previously accepted work retains its 30-second bound. Delete refuses any retained
team reference; remove references first. Connection deletion preserves teams and
historical usage, while failed deletion stays disabled and visible for retry.
Rollback requires disabling managed assignments before reverting the CP binary;
preserve ownership tables and database-owned native config. Do not automatically
apply down migrations or restore an old file-managed provider stanza.

### Existing file-managed providers

The remaining file-managed instructions preserve existing deployments. For new
installations prefer the managed flow above. Existing org/key references are
preserved by migration; newly created policies must select explicitly owned keys.

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

The qualified Anthropic-compatible route is `/ai/anthropic/v1/messages`. Messages accept string text content only. Image/audio blocks, tool calls, extra message controls and duplicate fields are refused before authorization. OpenAI roles are `user`, `assistant` and `system`; Anthropic messages use `user`/`assistant` with optional top-level system text. Provider keys, engine virtual keys, engine admin credentials, user session tokens, and bootstrap tokens are not AI bearer credentials. Do not expose engine headers in client configuration.

## Accounting, retention and limits

The engine enables accounting logs with `disable_content_logging:true`; prompt and response content logging remains disabled. Both client log retention and log-store retention are set to seven days. Metadata can contain model, timestamps, usage/cost, request identifiers, and agent-related attribution, so its storage and access still require protection. A pinned-native synthetic-provider check on 2026-09-07 retained one scoped request and seven tokens in `/api/logs/stats`, then verified both unique prompt and response markers were absent from the SQLite logical dump and raw database/WAL bytes after shutdown. Run it without provider credentials using `AI0_BIFROST_BINARY=/absolute/path/to/pinned-binary python3 deploy/ai-gateway/verify-metadata.py`. This proves the tested non-streaming response path on the pinned native engine; it does not establish every provider/error/streaming path or Linux container behavior.

Usage thresholds are soft admission thresholds based on asynchronous accounting, not strict spend caps. New requests are refused once observed usage reaches the threshold; concurrent accepted requests can overshoot it. No notification delivery is provided. Already accepted requests may continue until their authorization/request deadline (at most the documented 30-second request bound); disabling AI or revoking identity does not claim instant active-stream cancellation. No automatic provider retry or fallback is configured. Missing/invalid engine credentials or absent scoped policy must fail closed.

## Disable, preserve and upgrade

Disable the organization's AI setting first to refuse new work. This is an eligibility
toggle: explicitly re-enabling it can resume still-unexpired tokens when identity
and policy remain current. Use canonical agent revocation to permanently invalidate
that runtime identity. To stop the optional engine, use the same project, environment file and both Compose files with `stop bifrost`. This preserves both named volumes. If removing installation support completely, recreate the API using the base configuration without this override after removing AI engine environment settings. Existing organizations must remain disabled until the engine and policy are intentionally restored.

The project-scoped `ai_engine_config` volume holds Bifrost SQLite configuration and persisted virtual-key revocations. The distinct `ai_engine_logs` volume holds accounting metadata. Back up these volumes with the matching encryption key and configuration under the customer's backup process. Use a consistent SQLite backup or a stopped-engine snapshot. No `down -v`, volume deletion, or database reset is part of disable, restart or upgrade.

For an upgrade, qualify a new exact image digest first, take a restorable consistent backup, update the pin, and recreate only the engine using the same volumes. Verify protected admin/inference listeners, retained revocations, an independent active scoped key, and metadata-only logging after restart. A downgrade may require restoring the matching database backup; do not assume an older engine can read a migrated SQLite schema. Keep the last qualified image digest and backup until verification finishes.

## Verification boundary

`python3 deploy/ai-gateway/verify.py` renders Compose with dummy values and asserts the image pin, optional profile, API-only engine network, absent published ports, separate persistent state, secret references, fail-closed inference configuration and content logging setting. It starts no containers and accesses no application database. The edge `/ai/` location forwards to the API with proxy buffering/cache disabled and a 35-second proxy idle timeout; the adapter retains its own 30-second total request bound. Static assertions cover these settings; an nginx runtime parser was unavailable locally. The pinned Linux arm64 image has passed an isolated native-engine walkthrough for startup, private reachability, restart persistence, admin rotation, metadata omission and same-version restore; see [Linux qualification](AI-4-linux-installation-qualification-20260907.md). This used dedicated fixture state and is not a full Compose or Helm installation proof.

## Helm installation option

The existing `deploy/helm/tunnex-cp` chart also supports the optional engine. `aiGateway.enabled` defaults to `false`; the default rendered manifests are byte-identical to the pre-AI chart for the verification fixture. Enabling AI requires `api.replicas: 1` and always deploys one Bifrost replica using `Recreate`. This is explicitly a single-instance AI installation, with downtime during engine replacement; no AI HA claim is made.

Use a dedicated namespace for one control-plane release. The chart already reserves `api`, `web` and `edge` Service names; AI additionally reserves the exact private name `bifrost`. Another release or a pre-existing Service named `bifrost` must not share that namespace. The API uses `http://bifrost:8080`; no engine Ingress, LoadBalancer, NodePort or hostPort is created.

Provision and back up an existing Kubernetes Secret through the customer's secret-management process. The chart references four keys, configurable through `aiGateway.secretKeys`: `admin-user`, `admin-password`, `openrouter-api-key`, and `encryption-key`. It does not create Secrets or accept secret values in Helm values. The encryption key must remain stable across upgrades/restores. Example non-secret values:

```yaml
api:
  replicas: 1
aiGateway:
  enabled: true
  existingSecret: customer-ai-engine
  providerKeyID: openrouter-primary
  models: [openai/gpt-4o-mini]
  persistence:
    configSize: 1Gi
    logsSize: 5Gi
```

Combine these settings with the existing required control-plane values (external stores, existing master key, public URL, TLS and image pins). Review the rendered chart, then use the installation's normal Helm upgrade lifecycle and the same release/namespace. The bundled migration hook remains the schema authority. The chart adds no database, managed relay, privileged gateway or new infrastructure controller.

The engine's mandatory NetworkPolicy permits ingress only from this release's API-labelled pods in the same namespace. Egress permits DNS to configured namespace/pod selectors (default `kube-system`/`k8s-app:kube-dns`) and public TCP 443, excluding private, link-local, loopback and multicast ranges. Standard NetworkPolicy cannot restrict HTTPS by provider hostname; FQDN-aware egress enforcement belongs to the customer's network layer. A CNI that enforces NetworkPolicy is required, with no overlapping broad allow policy selecting the engine. Clusters using NodeLocal DNS or different DNS labels need an explicitly reviewed compatible DNS configuration before enabling AI. Verify DNS, provider reachability and blocked access from unrelated pods in the customer walkthrough; static rendering is not isolation proof.

Two separately named PVCs persist configuration and metadata. Both carry `helm.sh/resource-policy: keep`; disable/uninstall retains them for recovery rather than deleting AI state. Re-enabling a retained installation uses the same release name and volumes. Verify retained-resource ownership before reinstalling; never delete retained PVCs to resolve an ownership conflict without a reviewed backup/restore procedure. Changes to mounted secret values require rolling the affected API and engine pods through the normal maintenance process. Do not rotate the encryption key merely to refresh credentials.

With AI enabled, the edge mounts a chart-specific nginx configuration. ClusterIP names resolve through Kubernetes DNS at nginx startup, and `/ai/` streams to the API without proxy buffering or caching. If a Service is deleted and recreated with a new ClusterIP, restart the edge through the normal deployment lifecycle. Ordinary API/web pod rollouts keep Service IPs stable. The existing public edge TLS/Ingress boundary applies; the engine receives no public route.

`ruby deploy/ai-gateway/verify-helm.rb` performs static rendering/lint checks using dummy Secret names. It confirms default-off resources, digest pin, single replicas, private Service, Secret references, retained PVCs, CP-only ingress and streaming proxy; enabling without a Secret or with multiple API replicas fails validation. No cluster, image pull or provider request occurs. Linux image/PVC ownership, CNI isolation, Helm restart/restore and TLS wire behavior remain customer walkthrough proofs.

## Apply one explicit AI team

Create an ordinary Agent Group and explicitly add the enrolled agent through the existing group workflow. A device may belong to several ordinary groups but chooses exactly one AI team. The following management calls require an owner/admin with `ai_gateway:manage` in the named organization. Examples show non-secret JSON bodies; use the existing authenticated administration client and never put provider credentials in these team-policy requests. Use an owned connection key ID from Providers & models; `openrouter-primary` below is an existing legacy-reference example.

1. Enable access with `PUT /api/v1/organizations/{orgId}/ai-gateway` and `{"enabled":true}`.
2. Create the group's AI policy with `PUT /api/v1/organizations/{orgId}/ai-gateway/teams/{teamId}`:

   ```json
   {"models":["openrouter/openai/gpt-4o-mini"],"key_ids":["openrouter-primary"],"daily_cost_limit":null,"expected_revision":0}
   ```

3. Assign the enrolled agent with `PUT /api/v1/organizations/{orgId}/ai-gateway/agents/{deviceId}`:

   ```json
   {"team_id":"<existing-agent-group-uuid>","enabled":true,"models_override":["openrouter/openai/gpt-4o-mini"],"expected_revision":0}
   ```

4. Read `GET /api/v1/organizations/{orgId}/ai-gateway/agents`. If synchronization needs a retry, use `POST /api/v1/organizations/{orgId}/ai-gateway/agents/{deviceId}/reconcile`. Do not issue a working-access claim until `status` is `applied` and applied revisions match the desired assignment/team. Subsequent updates must use the last returned revision rather than repeating `0`.
5. Exchange the current runtime credential at `/api/v1/agent/runtime/ai-credential`, then call the AI routes described above. AI does not require the paid managed-runtime feature to be enabled.

The current limit is 64 retained agent bindings per organization. Daily soft thresholds use native observed usage since midnight UTC. An agent override can only narrow the team's exact model set. Disabling access or losing required group membership refuses new requests; it does not promise cancellation of an already accepted stream.

## Rotate provider credentials

For UI-managed connections, edit the connection and supply a new key; no engine
restart is required. The procedure below applies only to legacy environment keys.

Disable the affected organizations during maintenance, update the provider secret
in the private environment file or existing Kubernetes Secret, and recreate the
engine through the normal installation lifecycle. Keep the provider key ID, engine
encryption key and configuration/accounting volumes unchanged. After a successful
scoped request and retained-usage check, retire the old credential through the
provider's normal management process and intentionally restore organization access.
No provider secret is copied into CP or agent configuration. Native hot reload and
changing the provider key ID are not covered by this procedure.

The pinned Linux engine passed a synthetic provider-authentication rotation test:
old secret refused, new secret accepted, unchanged native key and retained history.
See [rotation evidence](AI-gateway-provider-rotation-20260907.md). The full installed
API process walkthrough, including streaming and soft threshold refusal, is recorded
in [AI-5 evidence](AI-5-installed-process-walk-20260907.md).

## Custom OpenAI-compatible endpoints (opt-in)

Custom and Azure connections require provider management and the authenticated
provider egress proxy. Set `public_https: true` once in the shared installation
policy to let administrators enter public HTTPS/443 endpoints directly. No
per-destination registration or restart is needed for those public URLs. The
switch defaults to false for existing installations; their explicit rules remain
in effect until enabled.

Private/internal HTTP or HTTPS endpoints and SageMaker bridges still need explicit
URL/provider/CIDR rules. HTTPS always verifies certificates. Explicit rules take
precedence over public fallback, including their provider kind and narrower CIDRs.

Store a nonsecret JSON policy outside the repository, for example:

```json
{
  "public_https": true,
  "endpoints": [],
  "protected_hosts": ["api", "bifrost", "postgres", "redis", "control.internal"],
  "denied_cidrs": ["10.21.0.0/24"]
}
```

For private access, add an endpoint entry such as
`{"name":"Private inference","provider":"custom","url":"https://inference.internal","allowed_cidrs":["10.20.0.0/24"]}`.
Use `provider: sagemaker` for a private SageMaker bridge and `azure_foundry` for
an explicit Azure rule. Replace example hosts/CIDRs with verified installation
inventory and include all protected control-plane, engine and datastore addresses.

Policy entries use the normalized upstream base without trailing `/v1`; the UI
accepts `/v1` and strips it before submission. Each proxy connection resolves the
destination once and dials only validated numeric addresses. Public fallback
refuses the entire DNS answer if any address is private, protected, loopback,
link-local, metadata, unspecified or multicast. Explicit rules require every
answer to fit their allowed CIDRs and still cannot permit prohibited addresses.
Redirects cannot escape these checks.

### Azure AI Foundry (OpenAI v1)

Enter the actual Azure API key, exact deployed model name and an HTTPS base such
as `https://resource.services.ai.azure.com/openai/v1`. The resource host can end
in `services.ai.azure.com`, `openai.azure.com` or `cognitiveservices.azure.com`.
The stored base ends `/openai`; both inference and endpoint catalog calls append
`/v1`. A supported URL shape does not prove that resource exposes this API.

For new Azure credentials, **Search models** reads the bundled SHA-pinned LiteLLM
reference catalog without an endpoint, key or Azure request. Use your deployment
name if it differs from a suggestion; reference entries do not prove access.
Custom and SageMaker draft searches require endpoint/key and fetch the actual
endpoint catalog without saving credentials or generating inference tokens.
Saved endpoint-backed credentials retain their authenticated catalog search.
If a catalog is unavailable, enter the exact deployment/model name manually.

Azure **Test Connect** makes a bounded chat request using
`max_completion_tokens=16`. It can incur a charge and is never triggered by
catalog search. Only OpenAI v1 chat completions are supported here; legacy
`/models`, dated deployment API-version URLs, managed identity, sovereign clouds
and other protocols/modes require separate support.

For Compose, append `-f deploy/ai-gateway/compose-custom.yml` after the base AI and
managed-provider overlays. Continue using the existing explicitly named project
and retained engine volumes. Securely supply `TUNNEX_AI_CUSTOM_ENDPOINTS_FILE`
(an absolute path), `TUNNEX_AI_CUSTOM_PROXY_USERNAME`,
`TUNNEX_AI_CUSTOM_PROXY_PASSWORD`, and `TUNNEX_AI_CUSTOM_PROXY_URL`. The URL is
`http://<encoded-user>:<encoded-password>@ai-egress:8190`; percent-encode its userinfo
and ensure it matches the separate username/password. CP and Bifrost receive the
same URL. No proxy host port is published; no database or master key is passed to
the egress service. Its API-image HTTP healthcheck is disabled because the proxy
only accepts CONNECT. Use container/process status and explicit credential checks;
do not interpret the absence of that healthcheck as upstream health.

For Helm, set `aiGateway.enabled`, `aiGateway.providerManagementEnabled` and
`aiGateway.customProviders.enabled` to true. Set `publicHTTPS: true` for public
self-service URLs; `endpoints` may be empty in that mode. The chart defaults this
switch to false for upgrade compatibility. Example nonsecret values:

```yaml
aiGateway:
  enabled: true
  providerManagementEnabled: true
  customProviders:
    enabled: true
    publicHTTPS: true
    endpoints: []
    protectedHosts: [postgres, redis, control.internal]
    deniedCIDRs: [10.21.0.0/24]
    existingSecret: ai-egress-credentials
```

Configure `endpoints`, `protectedHosts` and `deniedCIDRs` with the same policy
entries as above. The chart always adds API/Bifrost service names to protected
hosts. Set `aiGateway.customProviders.existingSecret` to a pre-created Secret with
`proxy-url`, `proxy-username`, and `proxy-password` keys. The URL uses `api:8190`,
not localhost, so the separate engine pod can reach it. Secret values belong in
secure Secret delivery, never Helm values/history. Both containers mount the same
policy ConfigMap read-only; the sidecar receives only proxy credentials. Its TCP
probe proves listener readiness only. The private API Service conditionally adds
8190, and the engine's NetworkPolicy permits that port only to this release's API
pods in the same namespace. Standard provider HTTPS egress remains available.

Changing the installation policy requires coordinated CP/egress/SDK-bridge
reloads with the same policy. Adding a public URL in the UI does not change that
policy or require a restart. Drain or disable affected assignments before removing
a private endpoint rule or narrowing allowed network access.
Keep database-owned native state, encryption keys and ownership tombstones during
rollback. These manifests have static render verification; installation-specific
CNI enforcement, private DNS reachability and certificate trust require a local
qualification walk before enabling customer traffic.
