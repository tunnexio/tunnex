# Workload model access — local control plane

This guide describes the implementation deployed into the local control plane. It is
**not released or production-qualified**. Use a CLI, API and web build from this
implementation together; installing the current public release does not establish
that these commands are available. Temporary authentication failures are covered by
local regressions; ordinary restarts and replacement replicas were also exercised
against the installed control plane. Multi-API failover and production deployment qualification
remain unfinished.

A workload gives an application a stable model policy and usage identity. Its
replicas enroll independently under that workload, without a human `tunnex login`
or network-device enrollment. After an administrator provisions the configuration
and enrollment key, the runtime command is:

```sh
tunnex workload run --config /run/secrets/tunnex/workload.json -- python agent.py
```

Replace `python agent.py` with your application command. This implementation provides
model access. Central MCP execution, trusted-issuer/OIDC federation and the
Windows workload runtime are not available. Where the wrapper cannot run
(serverless functions, Windows, SaaS and no-code tools, quick scripts), use a
[static API key](#static-api-keys) instead.

## Configure access

In **AI Gateway → Access → Workloads**, an AI administrator creates a workload,
chooses its exact configured models and optionally sets a daily USD soft
threshold. Configure provider credentials and models in **Models & endpoints**
first. Wait for the workload's access state to show **Applied**. A workload with
no models has no inference permission, and `run` will not start its application.

Select the workload and use **Connect application** to download its configuration
and view its permitted model IDs. Create an enrollment key:

| Enrollment type | Current behavior |
| --- | --- |
| Single instance | One successful enrollment; the UI gives the key 24-hour validity. |
| Autoscaling deployment | Reusable; the UI defaults to 30 days and allows up to 90 days. The optional use limit counts total successful enrollments, not concurrent replicas. Empty or zero means unlimited uses within its validity. |

The secret is shown once. Deliver it through your deployment's secret store or
another protected file-provisioning mechanism. Keep it out of command arguments,
logs, images and source control. A reusable key authorizes new instances of its
workload; it does not attest which physical machine is using it.

## Provision private files

The configuration has exactly these fields:

```json
{
  "server": "https://tunnex.example.com",
  "enrollment_key_file": "/run/secrets/tunnex/enrollment-key",
  "state_directory": "/var/lib/tunnex-workload"
}
```

Set `server` to the Tunnex origin reachable by the application, without `/ai/v1`,
a query string or embedded credentials. HTTPS is required except for loopback
HTTP development. Check the downloaded value when the dashboard is reached
through a local preview address or a different hostname.

All file and directory paths must be absolute. The configuration and enrollment
key must be regular, non-symlink files with permissions `0600` or stricter. The
state directory must be a private, writable, non-symlink directory with permissions
exactly `0700`. Provision these as the application user, which should run
unprivileged. For example, a privileged Linux provisioning step can install files
already staged securely; replace the source paths and `APP_USER`/`APP_GROUP`:

```sh
install -d -m 0700 -o APP_USER -g APP_GROUP /run/secrets/tunnex /var/lib/tunnex-workload
install -m 0600 -o APP_USER -g APP_GROUP /protected-staging/workload.json /run/secrets/tunnex/workload.json
install -m 0600 -o APP_USER -g APP_GROUP /protected-staging/enrollment-key /run/secrets/tunnex/enrollment-key
```

Do not overwrite an existing deployment's files without planning its key change.
On macOS, choose equivalent private absolute paths writable by the application
user. Projected secrets that use symlinks must be copied into private regular
files by trusted deployment setup before invoking the CLI.

Every replica needs its **own state directory and storage**. Containers may use
the same path text with independent volumes; processes sharing a filesystem need
different paths. The CLI creates a private instance signing key and locks its
state. Do not share this directory, copy it to another replica, or bake it into
an image. The image can contain the binary and application; provision secrets
and instance storage at deployment time.

## macOS local setup

The downloaded configuration uses example Linux/container paths. Downloading it
into `Downloads` does not create `/run/secrets/tunnex`. For a new local instance,
save the one-time enrollment-key download as `~/Downloads/enrollment-key.txt`
and keep the configuration at `~/Downloads/workload.json`.

Provision a private configuration using your actual home directory:

```sh
install -d -m 700 "$HOME/.config/tunnex/workloads/local-test"
install -m 600 "$HOME/Downloads/enrollment-key.txt" \
  "$HOME/.config/tunnex/workloads/local-test/enrollment-key"
python3 - <<'PYTHON'
import json, os
from pathlib import Path
base = Path.home() / ".config/tunnex/workloads/local-test"
assert (base / "enrollment-key").is_file(), "Download and install the enrollment key first"
config = json.loads((Path.home() / "Downloads/workload.json").read_text())
config["enrollment_key_file"] = str(base / "enrollment-key")
config["state_directory"] = str(base / "state")
with os.fdopen(os.open(base / "workload.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as output:
    output.write(json.dumps(config, indent=2) + "\n")
os.chmod(base / "workload.json", 0o600)
PYTHON
tunnex workload enroll --config "$HOME/.config/tunnex/workloads/local-test/workload.json"
```

Check the downloaded filename: if the browser saved it without `.txt` or with a
numbered suffix, use that filename as the source of `install`. The installed
filename must match `enrollment_key_file`. A lost one-time key cannot be read
back; create a replacement through **Enrollment keys**.

After enrollment, run from the directory containing your application:

```sh
tunnex workload run --config "$HOME/.config/tunnex/workloads/local-test/workload.json" -- python3 agent.py
```

`agent.py` is an example application command, not a file generated by the download.
Keep the same state directory for ordinary restarts. An `offline` instance means
no recent authenticated contact; it does not mean its credential was revoked.
Use **Revoke** in the Instances table or `tunnex workload retire --config` with
this same configuration path for permanent removal.

## Run the application

Run the one-liner above as the application user. The wrapper enrolls a fresh
instance if needed, obtains a five-minute model-access token, and checks the
authorized model list before starting the child. This startup check does not send
a paid inference request or prove the upstream model is reachable.

The child receives `OPENAI_BASE_URL` and `OPENAI_API_KEY` for an authenticated
loopback endpoint. Use an OpenAI-compatible client that honors those settings and
select an exact permitted model ID. Applications with hardcoded endpoints or
credentials need their configuration changed. The wrapper also supplies
`ANTHROPIC_BASE_URL` at the loopback origin and `ANTHROPIC_API_KEY`; its native
message path is `/v1/messages`. Compatibility with every SDK is not established.

The wrapper holds the remote token in memory, renews it before expiry, and replaces
the local session credential with the remote bearer on allowed gateway requests.
It streams responses; its current request timeout is 35 seconds, including
streams. The application receives a local credential, not the remote bearer.
Only supported AI routes are forwarded. This is not a general network proxy or
an isolation boundary between processes running as the same operating-system user.

The gateway checks the current workload, instance, model policy and provider
state for each new request. Scaling to twenty replicas creates twenty instance
identities under one workload, with a shared policy and stable workload accounting;
it does not create twenty separate workload policies or billing keys. Changing
the policy governs subsequent admissions without editing each replica's files.

## Kubernetes, ECS and container examples

[`deploy/examples/ai-workload/`](../deploy/examples/ai-workload/) has a
starting point for each platform:

- `kubernetes.yaml`: a Deployment whose init container copies the Secret's
  symlinked files into owner-only regular files, with one state directory per
  pod. Use a StatefulSet with a volume claim template for a stable identity per
  replica.
- `ecs-task-definition.json` and `entrypoint.sh`: the enrollment key comes
  from Secrets Manager as an environment variable; the entrypoint writes it to
  a private file, removes it from the environment and starts the wrapper. The
  same entrypoint works for plain Docker, Cloud Run and Nomad.
- `Dockerfile`: an application image with the `tunnex` binary and the private
  directories owned by the non-root application user.

On EC2 or any VM, provision the files as in "Provision private files" and run
the wrapper from the application's systemd unit.

## Replica replacement and access changes

VMs, containers, bare-metal hosts and on-premises deployments use the same HTTPS
enrollment protocol. Deployment automation must deliver the current key and
private storage to each new replica. There is no cloud-specific identity setup
in this basic path.

Rotate an autoscaling enrollment key before it expires: create a replacement,
provision it for new replicas, verify a fresh replica enrolls, then revoke the
previous key. Existing enrolled instances authenticate with their own signing
keys; expiration, exhaustion or key-only revocation blocks new joins without
ending those existing credentials. If an enrollment response is still pending,
retain that attempt's original state and key to recover its receipt; do not swap
the key underneath it.

| Administrative action | Effect on new admissions |
| --- | --- |
| Revoke enrollment key | Stops new instances joining with that key. Existing instances retain their independent authority. |
| Revoke instance | Stops that instance's token issuance and model requests. Sibling instances continue. |
| Revoke key and select “Also revoke every instance enrolled with this key” | Stops new joins and revokes the key's existing instances together. Instances from other keys continue. |
| Disable workload | Stops enrollment, token issuance and model requests for the whole workload. Policy and history remain. Re-enabling requires fresh tokens; old tokens do not become valid again. Revoked instances remain revoked. |

Requests already admitted may finish. Revoking one instance does not stop a
holder of a still-valid reusable key from enrolling a different instance. Use
combined revocation or workload disable when that enrollment key is compromised.

Disabling also permanently revokes the workload's enrollment keys. After
re-enabling, issue a replacement key for new replicas.

Application completion, crashes and supervisor restarts preserve the enrolled
instance in its private state directory. Restarts authenticate using that stored
instance key and do not consume another enrollment use. For planned permanent
removal, stop the application, then retire its instance explicitly:

```sh
tunnex workload retire --config /run/secrets/tunnex/workload.json
```

Retirement blocks future reuse of that state. If the gateway is unavailable, the
command records local retirement intent and reports that remote retirement is
unconfirmed. If the response was lost after the server retired the instance, a
retry is refused because its credentials are already invalid. An AI administrator
can check the authoritative status in the workload’s Instances tab, or revoke
the instance there if it remains active. Do not delete
state or automatically reenroll to bypass revocation.

The server's inactivity cleanup separately retires ephemeral instances after
24 hours without authenticated contact, subject to its cleanup/recovery checks.
Automatic token renewal counts as contact even without inference traffic.
Durable instances are excluded from that inactivity sweep.

## Cost and connectivity limits

The optional daily USD soft threshold uses observed spend across all instances
of the workload, from midnight UTC. Once observed cost reaches the threshold,
new calls are refused. Concurrent calls and delayed accounting can overshoot it;
it is not a guaranteed hard spending cap. When a threshold is configured, missing
required model prices or usable cost data can also block admission. Replica
replacement does not reset the workload's daily spend.

The application host must reach the configured Tunnex HTTPS origin. The gateway
and its configured model connection must reach the provider endpoint. Workload
enrollment creates neither a VPN tunnel nor a private network route. Private
providers need an already configured gateway/egress network path. The wrapper
does not use `HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY` environment settings and
removes those settings from the child environment.

Token renewal attempts can retain an unexpired token during some transient
failures; they never extend its expiry. A network, API, database or provider outage
can still stop requests. Retryable 429, 502, 503 and 504 responses receive bounded
retries; confirmed 401/403 credential refusals remain terminal. This does not
guarantee uninterrupted service during an outage. On access refusal,
check the workload and instance state with the AI administrator and preserve
private state for diagnosis.

## Static API keys

A workload has two ways to connect an application. **Run with Tunnex CLI** is
recommended: each replica gets its own identity and 5-minute tokens. A **static
API key** is one key you paste into a tool that cannot run the wrapper. It
expires, and you rotate it.

A key belongs to exactly one workload. It uses the workload's model list and
daily threshold, read live on every request. Optionally a key has its own lower
daily USD threshold and a requests-per-minute limit. People do not get personal
keys; a person's access stays tied to their device.

### Create a key

Select the workload, open **API keys** and choose **Create key**. Only holders of
`ai_workload:manage` (Owner, Admin, AI Gateway admin) can create, edit, rotate
or revoke keys.

| Setting | Behaviour |
| --- | --- |
| Where the tool runs | **Inside your network (recommended)**: the key works only on your internal AI endpoint and is refused on the internet. **Public internet**: the key works only on the control plane's public endpoint, over HTTPS. Chosen at creation; it never changes. |
| Expiry | Required, at most 90 days. Default 30. It cannot be extended: rotate instead. A badge shows from 14 days before expiry, and an alert (`ai_workload.static_key_expiring`) is sent 14 and 3 days before. |
| Source ranges | Optional, up to 32. Internal keys: private IPv4 ranges. Public keys: public ranges only; private, reserved and all-address ranges are refused. A public key with no ranges needs the extra confirmation **Allow from any address**. |
| Daily limit | Optional USD soft threshold for this key, not higher than the workload's. |
| Requests per minute | Optional, 1 to 60000, shared by every control-plane replica. |

The key is shown once, in the form `tnx_sk_` plus 49 characters. Afterwards the
console shows only its last 4 characters. Only a SHA-256 hash is stored. At most
8 keys per workload are active at once; rotation needs two for the overlap.

Public keys are off for an organization until an AI Gateway administrator turns
on **Allow public static keys** in AI Gateway settings.

### Use a key

Send the key as `Authorization: Bearer tnx_sk_...`. On the messages route
(`/anthropic/v1/messages`) the `x-api-key: tnx_sk_...` header is also accepted,
but only when it is the one credential header on the request.

```sh
# Internal key, Tunnex private CA trusted from ca.pem
curl --cacert ca.pem https://10.123.0.1:9443/v1/chat/completions \
  -H "Authorization: Bearer $TUNNEX_KEY" -H "Content-Type: application/json" \
  -d '{"model":"openrouter/openai/gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'

# Public key
curl https://<control plane>/ai/v1/chat/completions -H "Authorization: Bearer $TUNNEX_KEY" ...
```

OpenAI-compatible SDKs take the base URL (`https://<address>:<port>/v1` or
`https://<control plane>/ai/v1`) and the key. `GET /v1/models` lists the
workload's models. Videos are not available with a static key.

Each key may run 4 requests at once per control-plane process; the
requests-per-minute limit is the main control. A refused request gets the same
short message as any policy refusal (`401`, `403`, or `429 AI request limit
reached`). The key's row shows the exact reason ("Used on the wrong endpoint",
"Source address not allowed", "Daily limit reached", ...) and where it was last
used from. Wrong-endpoint and source refusals also write an audit row
(`ai_workload.static_key_refused`), at most once per key per hour.

### Rotate and revoke

**Rotate** creates a new key with the same settings and shows it once. The old
key then expires after the overlap (1 hour to 7 days, default 24 hours) or at
its own expiry, whichever is first. **Revoke** takes effect on the next request.
Disabling the workload revokes all its keys; enabling it again does not bring
them back.

### The internal AI endpoint

An internal key is accepted only on the internal AI endpoint, served by one of
your gateways on a private address with TLS. Configure it in **AI Gateway →
Settings → Internal AI endpoint** (`ai_gateway:manage`):

- **Addresses.** The gateway's tunnel address (every VPN device on that gateway
  already routes it), and at most one LAN address inside an approved subnet of
  the gateway's site (LAN hosts reach it directly; other sites reach it over
  site-to-site). A gateway without a site can use only its tunnel address.
- **Port.** Default 9443. Open this TCP port from the source ranges only, in the
  host or cloud firewall. Traffic to this port is not covered by access rules:
  the source ranges and the key are the only controls.
- **Source ranges.** 1 to 32 private IPv4 ranges. The gateway closes a
  connection from outside them before TLS, and the control plane checks the
  address again, together with the key's own ranges. If traffic passes source
  NAT (a NAT gateway, a load balancer, a site that masquerades), every caller
  behind it looks the same.
- **Certificate.** *Tunnex private CA* (default): each organization has its own
  CA; the gateway keeps its key in memory and gets a 30-day certificate for the
  configured addresses and DNS name. Download `ca.pem` from the settings page and
  trust it: `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` (Python), `NODE_EXTRA_CA_CERTS`
  (Node.js), the Windows certificate store, or the Java trust store. *Your own
  certificate*: put `tls-cert.pem` and `tls-key.pem` (mode 0600) in
  `/var/lib/tunnex-node/ai-internal/` on the gateway host; the private key never
  leaves it.

A gateway must run a version that reports the internal endpoint before it can
be configured; the console says "Upgrade this gateway to use the internal AI
endpoint" otherwise. Turning the endpoint off refuses requests at once and
closes the listener within one poll.

Public keys: behind an external load balancer the control plane needs the
client address from a trusted proxy (`TUNNEX_EDGE_TRUSTED_PROXIES`, see
[trusted proxy transport](trusted-proxy-transport.md)); when it cannot get one,
keys with source ranges are refused.

### Usage

A key's cost is counted on its own engine key and rolls up into its workload's
row in Usage, where the workload row expands to its keys. Keys revoked today
still count toward the workload's threshold today.

## Advanced commands

These commands operate on the same private configuration and state:

```sh
tunnex workload enroll --config /run/secrets/tunnex/workload.json
tunnex workload token --config /run/secrets/tunnex/workload.json
tunnex workload rotate --config /run/secrets/tunnex/workload.json
```

`enroll` returns a public receipt. `token` explicitly prints a short-lived bearer
token as JSON: treat its output as a secret and keep it out of logs. An integration
using tokens directly must handle renewal itself and call the remote `/ai/v1`
gateway. `rotate` explicitly rotates the instance signing key and returns its
receipt; old keys and tokens are refused after promotion. Scheduled instance-key
rotation is not implemented. These are separate operations, not required setup
steps before `run`. The state lock prevents them from sharing a directory with an
active `run` process. None changes the saved human CLI login.

The [decision record](S-AI-workload-identity-decisions.md) also contains intended
later behavior, including trusted-issuer federation; it is not a release-status
document. Current commands and storage rules are in the
[CLI implementation](../apps/cli/internal/cli/workload.go), management controls in
[the workload UI](../apps/web/src/components/AIWorkloads.tsx), and enforcement in
[workload authentication](../apps/api/internal/aigateway/workload_auth.go),
[workload management](../apps/api/internal/aigateway/workloads.go),
[maintenance](../apps/api/internal/aigateway/workload_maintenance.go) and
[cost admission](../apps/api/internal/aigateway/usage.go). Static keys are in
[static key admission](../apps/api/internal/aigateway/static_key_auth.go),
[static key management](../apps/api/internal/aigateway/static_keys.go) and
[the internal endpoint](../apps/api/internal/aigateway/internal_endpoints.go);
the decisions are in [AI-KEYS-1](AI-KEYS-1-decisions.md).
