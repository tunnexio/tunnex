# Managed-agent bootstrap without manual host preparation

Status: accepted implementation plan, 2026-10-02. Follow-up to
[S-ai-vpn-bootstrap-decisions.md](S-ai-vpn-bootstrap-decisions.md).

## Requirement and observed gap

The user requires the generated AI Agent enrollment command to install necessary
host dependencies and obtain its release verifier automatically. The sandbox
walk required preinstalled tools and a locally compiled verifier. Ubuntu's
existing resolver compatibility worked, but the requested openresolv package
was unavailable; that partial host preparation is not a completed bootstrap.
Existing control-plane upgrades, human VPN inference, agent identity, policy,
credentials and working installations must retain their current behavior.

## Dispositions

- Locked: support the generated automatic host setup on Ubuntu/Debian Linux,
  amd64 and arm64, using systemd and root or sudo. Check platform, privileges and
  preexisting managed runtime ownership before package or installation changes.
  Install only missing required packages with the distribution package manager.
  Reuse working resolver compatibility; do not replace it merely because the
  package named openresolv is absent. Unsupported hosts and failed prerequisites
  stop clearly before bootstrap-token redemption.
- Locked: keep the existing signed `release.json` schema and canonical signed
  bytes unchanged. Existing readers reject unknown fields, and re-marshaling an
  expanded manifest would also break their signature check. Adding an optional
  verifier field to that manifest is therefore rejected, even though a new
  reader could read old releases.
- Locked: publish `releaseverify-linux-amd64`, `releaseverify-linux-arm64` and a
  separate `agent-bootstrap-verifier.json` alongside each new immutable main/tag
  release. The detached descriptor uses the existing pinned Ed25519 key and
  binds its purpose, schema, source commit, release version and both exact asset
  names/hashes. Domain/purpose and key identity are verified in addition to the
  signature. CI must build, sign, attach and verify all three before promoting a
  release; existing release-source ledger and draft guards remain authoritative.
- Locked: the authenticated control plane obtains the detached descriptor only
  from the installed release's immutable asset directory. Bound HTTPS fetching,
  redirects, response size and time. Verify signature, expected source, version,
  key and exact architecture asset names before projecting optional public
  `release.verifier` metadata through the OpenAPI bootstrap response. Fetch or
  verification failure never produces guessed or unverified hashes.
- Locked: a genuine missing descriptor for an older release retains the legacy
  preinstalled-verifier path, with an explicit diagnostic when that executable
  is absent. Other fetch or validation failures fail closed. No unsigned
  checksum, mutable latest binary or trust-on-first-use fallback is permitted.
- Locked: the command obtains the selected verifier only from the immutable
  release directory and checks its SHA-256 against trusted control-plane
  metadata **before executing it**. It then independently verifies the runtime
  manifest signature and source/key identity, followed by the existing runtime
  binary and unit checks. This is not circular verification: the first executable
  is authenticated by the already-verified control-plane projection; that
  executable then independently checks the downloaded runtime manifest.
- Locked: redeem the existing single-use token only after prerequisites and
  all downloaded artifacts are verified. Preserve private-key generation on
  the host, retained identity/refusal rules, ownership/modes, rollback and
  service startup behavior. Package installation is not silently rolled back.
- Rejected: new authentication routes, public inference access, changes to AI
  grants or provider credentials, fake hashes for old releases, rewriting
  published release assets, or counting a local publisher fixture as signed
  production publication.

## Required evidence

- Real signing/verification tests reject altered data, wrong source/version/key,
  incomplete architecture assets, oversized/trailing payloads and unsafe fetches.
  The existing signed runtime manifest remains accepted unchanged.
- API projection contains only verified public descriptors; older missing
  descriptors follow the explicit legacy path. Failed descriptor validation
  must not mint or consume a bootstrap token.
- CI contract verifies both architecture builds and assets, separate signing,
  source-ledger guards, checksum/descriptor consistency and ordering before
  release promotion for main builds and tags.
- A shell harness exercises automatic dependency setup, existing resolver reuse,
  architecture selection, verifier hash-before-execution, manifest verification,
  clean-host success and refusal before redemption on dependency/tamper failures.
- A clean supported VM wire walk remains required before fresh-host acceptance.
  Until the next signed release exists, a clearly identified review publisher
  fixture can prove mechanics but does not satisfy real release publication.
