# S16 — Control Plane upgrade decisions

Status: local design and implementation batch; not pushed.

## Locked decisions

- Releases are identified by a signed descriptor containing the source SHA, a monotonically increasing sequence, compatibility/protocol requirements, release notes, and immutable OCI digests for all five images on amd64 and arm64.
- The web/API surface is read-only and admin/owner scoped. It may show release notes, downtime, compatibility, and copyable operator commands, but it never receives Docker-socket or host-root capability and never performs an upgrade.
- Actual changes run through an explicit host-side updater/CLI. It must verify the descriptor signature and digests, run the existing backupctl/preflight gates, apply migrations, health-check the result, and support idempotent recovery from a verified backup. No silent upgrade and no downgrade.
- Online mode fetches the signed descriptor and images. Air-gapped mode accepts an operator-imported descriptor plus pre-pulled image archives and performs the same signature/digest/preflight checks before applying.
- Skipped releases are allowed only when the descriptor compatibility contract says the jump is safe; downgrades are refused.

## Deferred until implementation evidence

- Final signing key storage and rotation mechanism (KMS/CI secret plus published key id) remains an operational deployment decision; the verifier is fail-closed and supports an explicit key id.
- Host updater packaging (standalone binary versus compose-installed helper) will reuse the existing installer/backupctl paths and be selected after the local prototype and tests.
