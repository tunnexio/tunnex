# BYODB development completion — 2026-09-06

Product implementation: `09e1ce42530e4e121724b2d9de4d18b3313f9bf2`, plus the
following Helm NOTES documentation correction. No production-release claim.

## Closed development findings

- Legacy/new migration advisory-lock identity and required channel-binding
  enforcement, including native backup environment parity: regression-proven.
- Native verified-TLS backup uses the same default system roots and URL-presence
  precedence as runtime. URL empty values override environment, not vice versa.
  Exact previously failing absent-root and explicitly-empty-root preflight/dump
  reproductions pass on final candidate `tunnex-byodb-compat:20260906g`.
- Fresh-start API health grace is 900 seconds; installer and upgrade Compose waits
  are bounded to 900 seconds. Kubernetes startup probe is 180 x 5 seconds.
  Successful health ends startup grace immediately; unhealthy instances are not
  reported as successful installs.
- Real Docker delayed-start proof: API delayed 75 seconds (beyond previous failure
  window), then migrated a fresh fixture and became healthy with zero restarts;
  dependent service started automatically. Negative proof required the exact
  three-second readiness timeout, elapsed <15 seconds and a running/unready
  fixture, rejecting unrelated setup failures as evidence.
- macOS bootstrap test fixture now supplies real SHA256, asserts intentional
  startup exit 42, and rejects tampered runtime bytes before service changes.
  CP web typecheck, all 1282 tests and production build passed under Node 22.

## Final wire proofs

- Final candidate g: fresh PG16/17/18 TLS + required-binding migration up/down/up,
  legacy lock contention, matching-major dump/archive/actual restore, and default
  system-trust preflight/dump passed. All restores reported `136|f`.
- Final candidate g deployed to existing AWS/Neon CP after verifying account
  735391218823. API became healthy; fresh HTTPS login and existing organization
  readback passed. Earlier same-mechanism Neon dump/restore proof is recorded in
  compatibility-fixes.md. RDS data/volumes retained; public test URL serves Neon.
- Actual local Kubernetes Helm install/upgrade, separate runtime/migration roles,
  custom URL Secret keys, mTLS, missing-certificate rejection, in-pod native backup
  and operator-driven runtime credential rotation passed. See kubernetes-mtls.md.
  Its final check.go fingerprint matches committed 09e1ce4. Old runtime credentials
  were rejected; master key, migration role and certificates were preserved.
- Independent scoped multi-finder reviews completed. Reported lock, authentication,
  trust mapping and bounded-test findings were corrected and re-reviewed. No
  remaining actionable finding was reported within those scopes.

Installer/upgrade behavioral contracts, provenance and runner contracts, Helm lint
and BYODB chart contracts, and generate-check passed. Both API editions and node
gates are being rerun; exact-final GitHub checks remain the merge authority.
The completion checkpoint is not itself proof that CI has finished.

Customer documentation PR40 tip `7a3050079c3221102a53d1430ade3a044ed21da0` passed
typecheck, 214 tests, lint, format, installer sync, build and full-site accessibility
in both themes. No production launcher pin changed or new screenshot invented.

## Explicit release boundary

The user chose **keep current scope; signed walk at release**. The first
BYODB-capable production-signed release must pass the real signed installer and
upgrade walk before public availability claims or launcher-pin advancement.
No private-distribution feature, trust bypass, public release or merge was made.
Native IAM renewal, automatic credential rotation, moving existing bundled data,
arbitrary engines and managed-cloud/HA topology qualification remain outside this
scope. Current rotation proof is explicitly operator-driven.

All credentials, private keys, kubeconfigs and database dumps stay in protected
scratch storage outside Git. Isolated test resources remain retained; no cleanup.
