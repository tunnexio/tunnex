# Public-IP HTTPS repair — 2026-10-01

Subsequent HTTP opt-in work: [administrator transport review](ai-http-admin-20261001.md).
The later review permits HTTP explicitly while preserving this HTTPS endpoint.

## Subject and scope

Existing AWS control plane, application release v0.1.36, with the deployment
changes from `codex/public-ip-https`. This is a live repair of the edge and its
configuration, not evidence that the published v0.1.36 already contains the
new capability. No new AWS resource, security-group opening, or DNS change.

## Before

The release upgrade completed and all containers were healthy. The application
still used public HTTP. The AI settings endpoint reported `available: false`,
`engine_installed: true`, `unavailable_reason: https_required`, and
`private_http_allowed: false`. Provider/model requests returned 503. The browser
had disabled Add Model and Add Credentials controls. Service health alone did
not satisfy the functional acceptance check.

## Wire proof

- The installed digest-pinned Caddy 2.11.4 successfully adapted the new config.
- Caddy obtained a Let's Encrypt IP certificate through TLS-ALPN on public TCP
  443. TCP 80 stayed restricted to the existing operator IP in the AWS firewall.
- Python's normal trust store validated TLS 1.3 against the exact public IPv4
  SAN; issuer was Let's Encrypt YE2. Initial certificate expiry was
  2026-10-08 01:47:14 UTC. HTTPS `/healthz` returned 200. No trust bypass used.
- The edge redirects HTTP requests to the HTTPS IP origin. Its existing
  `caddy_data` and `caddy_config` volumes remain mounted for renewal.
- Updated the real public origin and secure-cookie setting, restored the
  private `http://bifrost:8080` integration, and kept private HTTP disabled.
- Added the console IP to the existing egress policy's protected hosts without
  changing endpoint rules. Recreated API and egress to load the configuration.
- The AI settings endpoint now reports `available: true`, no unavailable
  reason, and `private_http_allowed: false`. Provider and model requests
  return 200. Provider capabilities report management, testing, Foundry, and
  public endpoints available.
- Authenticated browser inspection at the trusted HTTPS origin shows the
  existing configured Groq model and two saved credentials. Add Model is
  enabled and opens the wizard; the Azure credential step is reachable.
  Add Credentials is enabled. Existing disabled Azure connection status and
  organization activation preference were preserved; no new provider key,
  model, access grant, or inference request was submitted during this repair.

## Preservation

Before mutation, retained root-only environment, Compose, egress policy and
helper backups under `/opt/tunnex/review-backups/public-ip-https-20261001T104541Z`.
Compared all environment values by fingerprint: only the planned public-origin,
edge, cookie, AI-backend and Compose-hash values changed. Encryption/admin/proxy
keys and all unrelated values were unchanged. Existing provider egress rules
were unchanged. The original gateway and AI engine retained the same container
IDs, start times and named volumes. Both remain healthy, as do API and egress.

The patched upgrade helper is installed in both the root-runner and manual
locations. It rejects a signed target lacking IP-TLS support before replacing
managed deployment files. Source changes still require PR merge and a new
signed release for general installer distribution.

## Verification and limits

Passed public URL, full installer bootstrap, actual edge startup script,
upgrade helper, upgrade application and upgrade runner contracts. Independent
review found malformed IP authority acceptance, missing CI wiring and a rerun
capability-guard bypass; all three were fixed and re-reviewed with passing
contracts. CI now invokes the public URL and edge startup tests.

Issuance and usability are live proofs. Renewal scheduling uses Caddy's existing
persistent automation; a six-day renewal cycle was not waited out. A future
EC2 public-IP change requires updating the configured origin. Direct IPv6 is
outside this change. Provider inference success is not claimed by this transport
repair; credential validity, model entitlement and access grants remain separate.
