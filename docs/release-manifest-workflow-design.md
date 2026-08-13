# Signed release manifest workflow design

This describes the checked-in successful-main release contract. It deliberately
does not use GitHub's mutable `latest` release selection.

## Successful-main release sequence

1. Run after all five image-publish jobs succeed for a `main` commit (and for a
   tagged release when one is made).
2. Authenticate to GHCR with the existing workflow token and inspect each
   multi-architecture image tag. Capture the immutable Linux AMD64 and ARM64
   `sha256:` digests for `api`, `web`, `nginx`, `node-agent`, and `migrate`.
3. Build an unsigned manifest containing the version, full source SHA, monotonic
   workflow sequence, publication time, compatibility facts, release-notes URL,
   and those ten image digests.
4. Sign the canonical manifest with `apps/api/cmd/releasesign` using the
   `TUNNEX_RELEASE_SIGNING_PRIVATE_KEY` Actions secret and a stable key identifier
   from `TUNNEX_RELEASE_KEY_ID`.
   The private key must stay in the runner secret environment and must never be
   written to logs or artifacts.
5. Verify the signed output in the job, then create immutable
   `tunnex-build-<full-source-sha>` release assets containing `release.json` and
   its checksum. Update `tunnex-updates/release.json` as the signed online
   discovery pointer. The pointer is mutable; the signed descriptor and immutable
   source-SHA release are the provenance record.

## Required repository-owner approval

The required repository secrets are already named
`TUNNEX_RELEASE_SIGNING_PRIVATE_KEY` and `TUNNEX_RELEASE_KEY_ID`. The workflow
uses job-scoped `contents: write` only for descriptor assets and fails if either
secret, an image architecture digest, signing, or self-verification is absent.

## Fail-closed checks

The job stops when a secret is absent, a digest is missing or malformed, the
manifest source SHA does not equal the selected successful-main commit, signing
fails, or self-verification fails. No unsigned or partially populated descriptor
is published.
