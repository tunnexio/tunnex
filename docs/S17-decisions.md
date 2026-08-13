# S17 — Signed successful-main release contract

Status: decision record; implementation follows in this story.

## Locked decisions

- A customer install continues to select the newest successful `main` CI run; it
  never falls back to `releases/latest` or a mutable image tag.
- After all five multi-architecture image publications have succeeded, CI creates
  an immutable GitHub Release named `tunnex-build-<full source SHA>`. Its signed
  `release.json` binds the full source SHA, CI run sequence, compatibility facts,
  notes URL, and AMD64/ARM64 OCI digests for every shipped image.
- CI also updates a distinct `tunnex-updates` release asset. This is only a
  discovery pointer: the descriptor itself is signed, and the immutable
  source-SHA release remains the provenance record. A modified pointer cannot
  make an installation accept an unsigned or wrong-key descriptor.
- The signing private key is read only from the already-provisioned Actions
  secret `TUNNEX_RELEASE_SIGNING_PRIVATE_KEY`; its key identifier comes from
  `TUNNEX_RELEASE_KEY_ID`. Neither value is logged, copied into an image, or
  returned by the API.
- The installer fetches the immutable descriptor matching its selected main SHA,
  verifies it with the API image's `releaseverify` command before starting the
  stack, and persists the descriptor plus installed source/version/sequence.
  It must fail closed if the descriptor is missing, altered, or mismatched.
- Compose forwards only public release metadata and mounts the descriptor
  read-only into the API. The API polls the signed `tunnex-updates` descriptor
  for online installations; setting `TUNNEX_RELEASE_UPDATE_CHECK=false` disables
  that network check for air-gapped deployments while local verification and
  host-side upgrade remain available.
- The browser remains read-only and admin/owner scoped. It receives only a
  verified status and a host command; it never gains Docker, root, or secret
  authority.

## Explicit non-goals

- No image or database rollback is automated. The established forward-only
  policy remains restore from a verified backup.
- No release descriptor is generated from a PR, failed run, partial image set,
  or manually supplied image tag.
