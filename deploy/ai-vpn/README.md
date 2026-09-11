# VPN identity AI ingress (WireGuard)

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

This is not a published installer integration. Pin the custom images and retain
the deployment overlay across upgrades. Never disable public authentication or
trust X-Forwarded-For to make a VPN demonstration pass.
