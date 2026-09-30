# First organization and optional local gateway

## Accepted behavior

- Collect “Your first organization” during CLI setup. The bootstrap administrator is its owner, so the existing single-organization login flow opens it without another setup step.
- Recommend a separate Linux gateway by default. Offer the same Linux host only as a quick-start option, explicitly labelled “Not recommended for production”, with a separate yes/no confirmation. Portable hosts require a separate gateway.
- For a fresh installation, create the administrator, organization, owner membership, audit records and optional name-bound, one-hour gateway join token atomically. Existing deployments never acquire a new organization, administrator or join token on restart or installer rerun.
- The installer generates the local gateway token; the API receives only its SHA-256 hash. The node receives the token through the existing Compose enrollment mechanism. Never print it. Wait for the agent's readiness endpoint, not merely container liveness, before reporting success.
- Retain split-tunnel defaults. Creating an organization and gateway does not invent private subnets or grant access to them. Explain that administrators configure private routes/permissions and invite users; full-tunnel remains a later choice.
- Show the reported gateway address in the inventory, including IPv4, IPv6 or hostname as supplied. Do not label a hostname as a verified public IP or fabricate addresses for NAT-only gateways.
- Print host requirements and TLS-mode-specific firewall guidance before confirmation. Opening external/cloud firewall rules remains an operator action.

## Boundaries and compatibility

No production install, publication, host firewall edits or existing database mutation is part of development. Preserve installed settings on rerun. Without new bootstrap configuration, API startup retains its established behavior. Versioned Compose/API payloads must support first-organization bootstrap before a fresh installer offers it. Older releases retain manual dashboard setup; reject explicit automatic-organization or same-host requests before installation rather than silently ignoring them.

## Validation

Exercise first-run/no-op/failure paths, atomic setup and credential non-disclosure, installer default/consent/portable/rerun paths, gateway readiness failure, and IPv4/IPv6/hostname/absent inventory addresses. Run focused existing installer and UI checks. Render local previews. A mocked install is not a live VPN connectivity proof.

## Setup inputs

Interactive setup asks for the first organization and gateway placement. Unattended setup accepts `TUNNEX_BOOTSTRAP_ORG_NAME`, `TUNNEX_GATEWAY_PLACEMENT=separate|same-host`, and, for same-host only, `TUNNEX_COLOCATED_GATEWAY_CONFIRM=yes`. `--yes` alone does not supply that consent. `TUNNEX_GATEWAY_ADDRESS` optionally supplies the directly reachable gateway IP/hostname; bracket IPv6 addresses and omit the port. The local gateway uses UDP 51820.

On rerun, organization input is ignored with a preservation notice and gateway placement cannot change. Existing installations without a placement setting retain their old local/portable behavior. The old portable-control-plane flag remains true for Linux CP-only installs so older upgrade helpers also leave the local gateway scaled to zero.

## Local evidence — 2026-09-28

- Bootstrap/config unit tests passed; both server editions built.
- An isolated PostgreSQL 16 container proved transaction rollback after injected membership failure, concurrent first startup, a single owner-visible organization on first login, one bound gateway token, audit records, and inert restart. No existing database was used.
- Installer decision tests and the full command-stub host walkthrough passed, including explicit same-host consent, readiness, consumed-token removal, saved placement and special-character organization names parsed by Compose.
- Existing provenance, external-database, Windows bootstrap, preview parity/isolation and upgrade contracts passed.
- Web type-check and production build passed. Across the full run and a targeted retry, all 138 test files completed: 1,674 passed tests and two existing expected failures. The first run had worker-startup timeouts; those ten files passed with one worker.
- The actual gateway page rendered against local fixture data with IPv4, IPv6, hostname and missing-address states. Browser search by IP and clearing the search were checked.

Still required before release: a real Linux same-host installation and remote client VPN connection, plus normal publication/review gates. No commit, push, release or production deployment was performed here. The new automatic setup requires a published API/Compose payload containing this change; older payloads retain manual setup.
