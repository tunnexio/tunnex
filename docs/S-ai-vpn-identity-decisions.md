# AI inference authenticated by VPN identity

Status: implementation and focused tests complete; deployment and client wire proof in progress.
Base: origin/main d378e332b5770a1c66986ffed8eed54c4f80711c.
Branch: story/ai-vpn-identity.

## Locked user requirements

- A user connects with the Tunnex VPN client (or equivalent CLI tunnel).
- OpenAI SDK calls require only the AI base URL and exact gateway model name.
  The SDK may send a dummy API key. No user login file, provider credential or
  application bearer token is required by the user's Python application.
- Authentication comes from the verified VPN device/peer and its owning user.
- Existing organization enablement and group/model grants still apply.
- Build and validate before SCP/deployment to the authorized CP host
  ubuntu@15.206.183.232. Preserve current credentials, data and unrelated work.

## Observed gap

The public organization inference route authorizes a login principal in
apps/api/internal/http/ai_user_access.go. The existing /ai/v1 route authenticates
agent AI bearers. Neither establishes a human identity from a VPN peer.
The CLI AI commands read the saved login; a successful CLI call does not prove
VPN authentication. HTTP 401 with a dummy key is therefore expected today.

The public router applies RealIP, which accepts forwarded client-IP headers.
That value is not VPN identity evidence. Public ingress, a shared NAT address,
a tunnel-looking IP, or an arbitrary header must never grant model access.

## D1: AI address and routing — locked by user

User selected the existing dashboard hostname, internal.tunnex.app, with
VPN-specific DNS/routing. Use a VPN-interface-bound TLS relay and the existing
gateway mTLS channel. Non-inference traffic retains ordinary web authentication.
The dedicated AI hostname alternative is rejected to preserve the requested URL.
No DNS or routing change has been deployed yet.

## Proposed implementation boundary (subject to D1)

1. The gateway relay accepts requests only through a VPN-restricted listener.
   Bind/interface and firewall policy must establish VPN ingress provenance;
   looking up a source IP alone is insufficient. Map only an active individual
   device peer; never map a site/connector routed subnet to a human user.
2. Strip all caller identity, provider-key and forwarding headers. Ignore the SDK
   dummy key on this listener only. Forward the bounded request through the
   existing authenticated node mTLS channel, with gateway-observed peer evidence.
3. CP authenticates and checks the current gateway certificate, then verifies
   gateway/org/device/peer ownership and active user membership from authoritative
   state. Resolve the current user's model grants through the existing policy
   resolver. Do not mint or impersonate an interactive login/session principal.
4. Preserve provider credential isolation, model qualification, usage attribution,
   body/deadline limits and revocation semantics. Public bearer routes retain
   their current behavior. No broad public authentication bypass is acceptable.
5. Deploy the CP and gateway components together with rollback artifacts. The
   user's SDK file then points to the verified VPN-only endpoint.

## Required proofs before deployment claims

- Dummy key succeeds only over the verified VPN path for a granted user/model.
- Off-VPN requests and forged forwarding/identity headers cannot authenticate.
- Cross-org, wrong-gateway, revoked device/user/gateway and missing grants refuse.
- Routed site peers cannot claim individual user identity; stale identity refuses.
- Existing login and agent bearer APIs keep their authentication behavior.
- API builds/tests pass in open and enterprise editions; node tests and affected
  generation/deployment checks pass. Security review and live VPN wire proof are
  required; mock tests do not establish live ingress provenance.

## Deployment evidence needed

Last read-only CP inspection found no WG interface in its node-agent namespace.
Recheck active gateway enrollment and VPN state before selecting a listener or
claiming that the laptop is connected. No private key or user token is needed
in the SDK demonstration or evidence files.

Deployment finding: the co-located node reports no_identity_no_token. Enrollment
and a real client tunnel are prerequisites for live proof; a running container
is not a ready gateway.
