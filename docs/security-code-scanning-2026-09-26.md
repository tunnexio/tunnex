# Code-scanning remediation — 2026-09-26

Baseline: 111 open code-scanning alerts retrieved from GitHub with pagination. Alert state is not modified by this work. Changes require review, merge, and fresh scans before closure can be claimed.

## Implemented

- Pin external workflow actions to resolved upstream commit SHAs and static Docker base images to registry manifest digests.
- Default CI token permissions to contents:read while preserving explicit release/publication permissions.
- Use npm ci, a pinned govulncheck release, and hash-locked Python test dependencies. Fetch GHCR token JSON directly instead of piping a download to an interpreter.
- Validate the discovered OAuth authorization endpoint directly, without constructing a synthetic URL with empty state. Actual login randomness, nonce, and PKCE remain intact.
- Share bounded single-line log sanitization across HTTP access, throttling, and internal-error logs. Remove the ineffective suppression comment.
- Let append perform checked rekey message growth instead of adding attacker-controlled lengths for allocation capacity; preserve signing golden vectors.
- Remove redundant identity replacements and use directory entries without stat-before-read in the source census.
- Remove the accidentally committed seed executable; keep source, Make target, and an ignore rule.
- Patch x/crypto to 0.56.0 and React Router to 7.18.0. Align all first-party Go pins to 1.26.8 as required by crypto. Preserve the separately pinned upstream AI-engine toolchain.
- Preserve CLI consent return navigation across Router 7 transitions and reject unsafe or recursive login destinations.

## Remaining review / policy findings

These are not silently dismissed or suppressed. Removing required release permissions would break publication; repository history and independent approvals cannot be repaired with code.

| Alert | Rule | Disposition |
| --- | --- | --- |
| [#171](https://github.com/tunnexio/tunnex/security/code-scanning/171) | PinnedDependenciesID | Build-time BASE_IMAGE is supplied externally; changing this interface needs the image publisher to supply and enforce a digest. |
| [#170](https://github.com/tunnexio/tunnex/security/code-scanning/170) | PinnedDependenciesID | Build-time BASE_IMAGE is supplied externally; changing this interface needs the image publisher to supply and enforce a digest. |
| [#161](https://github.com/tunnexio/tunnex/security/code-scanning/161) | TokenPermissionsID | Push-only publication job needs contents:write for release/provenance operations. |
| [#123](https://github.com/tunnexio/tunnex/security/code-scanning/123) | TokenPermissionsID | Release publishing needs contents:write. |
| [#122](https://github.com/tunnexio/tunnex/security/code-scanning/122) | TokenPermissionsID | Release publishing needs contents:write. |
| [#121](https://github.com/tunnexio/tunnex/security/code-scanning/121) | TokenPermissionsID | Release guard reads private/draft release state using the existing release credentials. |
| [#100](https://github.com/tunnexio/tunnex/security/code-scanning/100) | SASTID | Historical scan coverage; cannot retroactively scan earlier commits by editing this branch. |
| [#98](https://github.com/tunnexio/tunnex/security/code-scanning/98) | TokenPermissionsID | Tag-only SBOM/signature publication needs contents:write. |
| [#73](https://github.com/tunnexio/tunnex/security/code-scanning/73) | VulnerabilitiesID | Current API/node scans find no reachable vulnerability, but x/crypto still contains unused, unmaintained openpgp (GO-2026-5932), with no patched module version. The application does not import that package. |
| [#72](https://github.com/tunnexio/tunnex/security/code-scanning/72) | MaintainedID | Repository age/maintenance history; cannot fix by changing source. |
| [#70](https://github.com/tunnexio/tunnex/security/code-scanning/70) | CodeReviewID | Actual independent review history; cannot manufacture approvals. |
| [#69](https://github.com/tunnexio/tunnex/security/code-scanning/69) | CIIBestPracticesID | Best Practices badge requires an owner-completed assessment. |
| [#1](https://github.com/tunnexio/tunnex/security/code-scanning/1) | BranchProtectionID | Enforcing administrator protections / increasing required reviewers is a repository policy decision. |

## Verification

Evidence and exact test totals are recorded in the pull request. Checks include workflow syntax, toolchain agreement and negative tests, frontend tests/build/audit, Go logging/OIDC/rekey regressions, Linux gateway/CLI/operator builds, API/node vulnerability scans, hash-locked Python tests, and browser E2E. CodeQL/Scorecard closure remains dependent on a fresh scan, not on this document.
