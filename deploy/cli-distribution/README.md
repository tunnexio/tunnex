# CLI distribution records

The independently versioned implementation repositories are:

- [Homebrew tap](https://github.com/tunnexio/homebrew-tap)
- [Signed Linux packages and installer](https://github.com/tunnexio/packages)

Update and test packaging code in those repositories. This directory deliberately
contains no copied formulas, package scripts or nested workflows; those copies
had drifted from their maintained sources.

The September 9, 2026 decision and publication records are preserved in
`docs/S-cli-publish-decisions.md`, `docs/S-cli-curl-installer-decisions.md`,
`docs/S-cli-publish-review.md`, and `walk-artifacts/cli-publish/`.
`docs/S-cli-official-submissions.md` records submission preparation, not acceptance.
These are historical evidence, not proof of current release health or current
external repository eligibility. Recheck the canonical repositories before use.

The current main branch's product status remains in `PLAN.md`; this documentation
does not change control-plane runtime behavior or publish packages.
