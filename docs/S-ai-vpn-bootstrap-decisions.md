# Automatic VPN AI access on installed gateways

Status: implementation in progress. Base: origin/main 44618e4 (v0.1.37).

## Requirement and observed failure

The user requires fresh bootstrap to install everything needed for AI, including
SDK inference authenticated by the connected VPN device and existing model grants.
No application/provider token is required on that path. The new signed install has
a healthy private AI backend but no VPN AI relay binary, listener or configuration.
Connection & code nevertheless emits a dummy-key SDK example using the public
browser origin, which receives an expected 401 from public authentication.

Read-only live checks confirm the user's site, approved VPC range, active device,
gateway binding, user-to-site policy, client route and source NAT. Private HTTP
reaches the CP and redirects to its public HTTPS origin. Private TLS stalls after
TCP connects; the cause remains unproven and separate from AI authentication.

## Decisions

- Locked: package VPN AI support in the signed node image and start/supervise the
  automatic listener from the enrolled native WireGuard agent. Bind only its exact
  interface and actual private gateway address. Never publish a Docker host port.
  Reconcile interface/address changes and report actual readiness separately.
- Locked: automatic mode uses an inference-only HTTP endpoint on port 8083 inside
  the encrypted WireGuard tunnel. It introduces no new DNS dependency, public-IP
  route or private CA. The existing server-wide HTTP policy must permit each
  request; OFF or an unreadable policy denies it. Bootstrap/upgrade preserve that
  saved policy and never enable organization AI or grant a model implicitly.
  This fits the user's already approved HTTP option and IP-based installation.
- Locked: identify every request by the observed individual WireGuard peer,
  authenticated enrolled gateway mTLS identity, current active human device/user,
  organization membership and model grant. A dedicated mTLS HTTP-relay route fixes
  the incoming transport kind; no client-supplied scheme/identity headers are trusted.
  Public endpoints retain normal authentication. Site peers never become users.
- Locked: deployment enables automatic mode explicitly. The enrolled gateway ID
  and device ownership bind each request; do not choose the first gateway by name.
  Existing manually configured hostname/TLS relay support remains compatible.
- Locked: use the existing node capability report to carry bounded listener
  readiness/address. Publish a VPN inference URL only for the requesting human's
  active WireGuard device and a fresh, ready gateway report whose address matches
  the authoritative organization pool. No guessed public-origin SDK URL.
- Locked: return endpoint metadata through the OpenAPI contract and use it in
  Connection & code for every language, not Python alone. No generated public URL
  or token fallback is permitted. Off-VPN access to these example endpoints must
  fail. Unsupported VPN operations must say so instead of silently using a public
  route. A missing endpoint has an actionable explanation; the UI must
  not generate an apparently working dummy-key example for the public API.
- Locked: fix the observed initial-enrollment startup race with API health ordering
  and bounded/safe retry semantics. Retained node identity and consumed tokens must
  survive restarts and upgrades without re-enrollment.
- Deferred to a separate transport investigation: private CP browser HTTPS stalls
  and public-origin HTTP redirect. No VPC return-route change is warranted by the
  current evidence. No MTU cause has been proved.
- Rejected: public authentication bypass, source-IP/header identity inference,
  routing the gateway's public underlay address into its own tunnel, silent HTTP
  opt-in, fresh provider/user tokens as a substitute, or an untracked host overlay.

## Verification required

Exercise fresh install/upgrade packaging; listener lifecycle/readiness; current
HTTP ON/OFF/read-error enforcement; wrong gateway/org/peer and revoked user/device/
grant refusal; public and forged-header refusal; actual VPN-only listener reachability;
correct SDK endpoint; unchanged tunnel underlay route; both API editions and node/web
checks. Unit tests do not satisfy a real VPN inference proof. Keep existing AWS data,
provider credentials, policies, bastion and unrelated work intact. Deployment and
release publication must not be described as complete until independently verified.
