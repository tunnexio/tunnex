# CLI distribution implementation snapshots

The canonical, independently versioned repositories are:

- https://github.com/tunnexio/homebrew-tap
- https://github.com/tunnexio/packages

These snapshots make the implementation reviewable alongside the Tunnex decision
paper and walk evidence. The control-plane CI does not execute nested workflows.
Changes should be made and validated in the canonical distribution repository,
then snapshots refreshed when updating this record. No private keys are included.

Homebrew, signed Linux packages, the Nix flake and the Arch build recipe are
published and tested. Review dispositions and native execution evidence are
recorded in docs/S-cli-publish-review.md and walk-artifacts/cli-publish/.
