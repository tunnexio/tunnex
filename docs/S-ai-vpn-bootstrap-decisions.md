# Automatic VPN AI access on installed gateways

Status: implemented review candidate; same-host sandbox wire proof completed on
2026-10-02. Signed publication, broader layout qualification and the limitations
below remain open. Base: origin/main 44618e4 (v0.1.37).

## Requirement and observed failure

The user requires fresh bootstrap to install everything needed for AI, including
SDK inference authenticated by the connected VPN device and existing model grants.
No application/provider token is required on that path. The original signed
install had a healthy private AI backend but no configured VPN AI listener.
Connection & code emitted a dummy-key SDK example using the public browser origin,
which received an expected 401 from public authentication. The review candidate
now discovers the private gateway listener; the wire walk below proves that path.

Read-only live checks confirm the user's site, approved VPC range, active device,
gateway binding, user-to-site policy, client route and source NAT. Private HTTP
reaches the CP and redirects to its public HTTPS origin. Private TLS stalls after
TCP connects. Subsequent packet captures and size probes show size-dependent
loss; the exact failing outer component and corrected MTU remain unproved. The
edge certificate and HTTP redirect also use the public origin. These are separate
from the now-working private AI inference path.

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
- Locked: the short private `/ai/v1` alias is available only when the authenticated
  human has one active organization. Multi-organization users retain the explicit
  organization-scoped private endpoint; the alias never guesses a tenant.
- Locked: managed AI Agents retain their managed-agent device identity, agent-group
  assignments and runtime-credential exchange. Human VPN model grants do not
  authorize agents; enrollment never creates model access.
- Deferred to private-CP transport acceptance: resolve the measured packet-size
  loss and the independent private TLS identity/redirect requirement. No VPC
  return-route change is warranted by this capture. Do not claim the private
  browser path is fixed until a valid TLS session succeeds over private routing.
- Deferred to managed-agent fresh-host bootstrap acceptance: provide a supported
  delivery path for host dependencies and the currently unpublished standalone
  release verifier. The staged test-host prerequisites are not automatic install
  evidence.
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

## Completed sandbox proof and remaining acceptance

The [wire walk](S-ai-vpn-bootstrap-boxwalk.md) records private short-URL human
inference, non-VPN-interface timeout, public identity-forgery refusal, gateway
restart recovery and isolated real WireGuard ingress. The new managed AI Agent
enrolled, applied its configuration, preserved its identity across restart and
correctly refused AI credential issuance without an agent model grant. The
review deployment and API-only follow-up preserved the compared existing
settings, providers, grants, service mounts and unrelated containers.

These results satisfy the observed same-host human inference failure. They do
not establish signed-release publication, an unmodified fresh install/upgrade,
live separate-host or Kubernetes deployment, physical desktop VPN disconnect,
live revocation/HTTP-policy negatives, positive agent inference or private CP
browser HTTPS. Local tests substitute for unwalked cases. The wire walk names
the acceptance trigger for each remaining proof and records the fresh-agent
dependency limitation explicitly.
