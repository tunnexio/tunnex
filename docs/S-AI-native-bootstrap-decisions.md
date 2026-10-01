# Native AI gateway and hosted bootstrap decisions

## Scope

Carry the reviewed AI gateway work onto current main: native provider operations,
pinned model metadata, usable connection tests, inline user-group creation,
automatic hosted backend and secured egress setup, and matching publication
contracts. Existing VPN, onboarding, database migrations and provider state remain
authoritative. The companion website PR carries documentation and installer-sync
changes.

## Decisions

- Use the signed Tunnex Bifrost engine built from pinned upstream source with
  native saved-credential tests and operations. Remove the separate LiteLLM
  bridge/proxy deployment and publication targets.
- Bake reproducible provider/model metadata into the release. A catalog listing
  does not establish account entitlement or inference access.
- Enable Test Connect for valid required inputs and endpoint syntax. Report
  installation, policy and provider failures in the result. Activation still
  requires a successful test; installation sends no paid inference request.
- Permit policy managers to create a user group inside the model grant dialog.
  Preserve the selected model and select the new group; granting remains an
  explicit subsequent operation.
- Normal hosted setup prepares the private engine, encrypted storage, durable
  credentials and authenticated destination-restricted egress. Public HTTPS is
  permitted while private, metadata and protected service destinations are denied.
  Existing operator policy and keys are preserved. Ambiguous partial state is
  refused before replacement.
- AI organization access starts disabled. HTTPS remains required by default.
  Private HTTP requires explicit operator policy and verified private/VPN access;
  setup never infers those protections from an address.
- Signed release metadata binds both engine architectures. The proxy reuses the
  API image's existing egress helper. Bootstrap source is fetched at the signed
  immutable source SHA; host secrets are not release assets.
- Stable release promotion requires exact public POSIX and Windows launcher
  bytes before making the release latest. Main prereleases remain available so
  reviewed website synchronization can finish first.
- The published v0.1.34 updater cannot bootstrap this first transition in its
  already-running process. The reviewed transition uses the new verified
  installer with matching backups, installation directory and project.

## Validation boundaries

The private review exercised native engine/API/UI operation and preserved the
existing VPN and provider state. Installer/upgrade command fixtures, real Compose
rendering, egress authentication/policy tests and publication contracts are
substitutes for a clean installation of the eventual signed release.

Before release promotion, require the exact PR-head CI checks, full multi-platform
publication, matching public installer deployment, and a clean-VM signed-install
walk. Real Windows Docker runtime qualification remains deferred to the Windows
release qualification gate; simulated native-path conversion is not that proof.
No merge or release publication is authorized by this feature-branch PR request.
