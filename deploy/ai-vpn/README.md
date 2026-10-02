# VPN identity AI ingress (WireGuard)

## Automatic installed gateway

Hosted installation and upgrade enable `TUNNEX_AI_VPN_AUTO=true` on the API and
node agent. The remote Docker enrollment command and gateway Helm chart enable
it too; an explicit installed opt-out is preserved. In the CP Helm chart, the
setting applies when `aiGateway.enabled` is true. No extra relay service, host
port, provider key or user token is needed.

The node agent starts an inference-only listener on its actual private WireGuard
address, port 8083, bound to the WireGuard interface. The gateway reports listener
readiness separately from ordinary VPN readiness. An AI bind or setup failure
does not stop a working VPN gateway. The same mechanism works with the CP on the
gateway machine or on a separate machine; the gateway uses its existing enrolled
mTLS connection to the CP.

The server administrator's saved **Settings → AI Gateway transport → Allow HTTP**
setting must permit this HTTP listener. The client-to-gateway traffic is inside
WireGuard encryption; the gateway-to-CP connection uses mTLS. Installation does
not change that saved setting, enable organization AI, or grant model access.
Every request checks the current device, user, membership and model grant.

For an approved chat model, **Connection & code** obtains the private endpoint
from the API for the signed-in user's active WireGuard device. Every language
uses that endpoint. REST examples send no key; the OpenAI SDK uses its required
`unused` placeholder. There is no public-origin or token fallback. VPN examples
currently support chat completions and human WireGuard devices; this does not
add OpenVPN, IPsec or workload identity support.

If no example is available, check the following:

- The organization has AI enabled and the user's group has a current model grant.
- The user's active WireGuard device belongs to the gateway they connect through.
- Both API and gateway have automatic VPN AI enabled, and saved HTTP access is on.
- The gateway's current report includes `ai_vpn_http_ready=true` with its actual
  organization pool gateway address. Reports older than 90 seconds are refused.
- The gateway has `NET_RAW` for interface binding. Its logs report
  `ai_vpn_control_channel_unavailable`, `ai_vpn_bind_unavailable` or listener withdrawal;
  check the exact interface/address and whether port 8083 is occupied.

Do not publish port 8083 or add a public forwarding rule. Test the copied example
while connected and verify refusal outside the tunnel. Existing browser sessions,
provider configuration and public API authentication retain their normal checks.

## Existing explicitly configured HTTPS relay

This opt-in deployment keeps the existing HTTPS hostname. The OpenAI SDK can
send any dummy API key; authentication comes from an individual WireGuard peer,
the enrolled gateway's mTLS certificate, and CP's current device/user/model grant.
The public login and agent bearer endpoints retain their existing requirements.

The initial slice supports chat completions through one explicitly provisioned
WireGuard gateway. OpenVPN and HA/failover ingress are not enabled by this slice.
Do not advertise them as supported by this proof.

## Components and activation order

1. Enroll the gateway and verify its WireGuard interface is up. Run the modified
   node agent with `TUNNEX_AI_VPN_HOSTNAME` and `TUNNEX_AI_VPN_ADDRESS` to serve one
   exact DNS answer on its existing VPN DNS listener. Other DNS is unchanged.
2. Run `ai-vpn-relay` in that gateway's network namespace. It requires NET_RAW for
   SO_BINDTODEVICE, the existing read-only node certificate directory, and a
   valid HTTPS certificate/key for the hostname. Do not publish a host port.
   The listener must bind the exact VPN interface and address. Its web upstream
   resolves via the gateway's normal DNS, not the client's split DNS.
3. Verify the relay socket is listening, then configure CP with
   `TUNNEX_AI_VPN_HOSTNAME`, `TUNNEX_AI_VPN_NODE_ID`, `TUNNEX_AI_VPN_ADDRESS`.
   CP emits the resolver and /32 route only in the active owner's device-specific
   routed-ranges poll for that gateway. Organization AI must also be enabled.
4. Connect the native Tunnex client. Its existing routed-ranges/resolver channel
   should install/remove the resolver with the tunnel. Verify this on the actual
   client; a CLI login is not a tunnel and a static WireGuard export does not poll.

The relay forwards only the chat inference path over the private node channel.
Other web requests retain normal web authentication. Each chat request observes
kernel AllowedIPs, rejects site/routed or ambiguous peers, strips client identity
headers, and sends the observed peer IP/key over mTLS. CP matches the current
human device, gateway and organization; checks posture/status, active membership,
AI-use permission and group model grants in the authorization transaction.

Gateway enrollment, like CLI credential issuance, happens downstream of normal
user authentication. This transport does not fabricate an interactive login or
claim that a fresh browser MFA challenge happened on every inference request.

## Rollback and limitations

Remove CP's VPN ingress configuration first so device polls withdraw the resolver,
then restore prior node/API images and stop the relay. Retain enrolled node keys,
provider credentials, volumes and HTTPS material. Existing clients may retain DNS
until their next successful poll/disconnect; verify withdrawal before stopping
VPN DNS. Failed/stale DNS must not be reported as successful rollback.

The separate HTTPS relay remains operator-provisioned. Pin its images and retain
its deployment overlay across upgrades. Never disable public authentication or
trust X-Forwarded-For to make a VPN demonstration pass.

## Building binary overlays

Use Python 3 and Docker with an approved **repository manifest digest** for the
existing API or node image. Floating tags and local image IDs are not accepted.
The base must be the matching Tunnex runtime image, including its existing tools,
entrypoint, user, healthcheck and configuration; a plain Alpine image is not a
substitute for a deployment base.

Place the Linux binaries for the base image's architecture in a build directory:
`api` needs `tunnex-api`; `node` needs `tunnex-node` and `tunnex-ai-vpn-relay`.
Then run from the repository root:

```sh
python3 deploy/ai-vpn/build-overlay.py api \
  --base-image "$API_IMAGE_WITH_SHA256_DIGEST" \
  --context "$API_BINARY_DIRECTORY" --tag tunnex-api:local-overlay
python3 deploy/ai-vpn/build-overlay.py node \
  --base-image "$NODE_IMAGE_WITH_SHA256_DIGEST" \
  --context "$NODE_BINARY_DIRECTORY" --tag tunnex-node:local-overlay
```

The builder validates the digest reference and required binary files before
invoking Docker. It supplies a literal `FROM repository@sha256:...` recipe over
stdin, pulls that exact digest, and only copies the replacement binaries. It
preserves inherited runtime metadata and does not deploy or restart anything.
This replaces the old `Dockerfile.api` / `Dockerfile.node` interface with its
unrestricted `--build-arg BASE_IMAGE`. Resolve and record the approved registry
manifest digest before building; do not pass a tag as a fallback.
