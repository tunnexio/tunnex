# Contributing to Tunnex

Thanks for your interest in Tunnex.

## External pull requests are not being accepted yet

Tunnex is in active early development and the contribution process is not open
yet. **Unsolicited external pull requests will be respectfully declined for now**
— not because the input isn't valued, but because we cannot merge outside
contributions until a Contributor License Agreement (CLA) or Developer Certificate
of Origin (DCO) sign-off flow is in place. Merging contributions without one would
cloud the project's copyright and its ability to (re)license, which matters
especially for the open-core split below.

**What you can do in the meantime:**

- **Open an issue** — bug reports, reproductions, and design questions are welcome.
- **Discuss before building** — if you want to work on something, raise it in an
  issue first so effort isn't wasted on a change that can't yet be merged.

When the CLA/DCO flow is established this document will be updated with the exact
steps, and the PR door opens.

## Licensing of contributions

This repository is open-core:

- The **Open edition** is licensed under **Apache-2.0** (root `LICENSE`).
- The **Enterprise edition** — `apps/api/internal/enterprise/` and anything gated
  behind the `enterprise` build tag — is **proprietary and source-available**
  (`apps/api/internal/enterprise/LICENSE`).

Contributions to each are governed by that part's license and, once available, the
CLA/DCO. Do not copy Enterprise Code into the Open edition or vice versa; the
`make test-editions` build-tag guard exists to keep the two from bleeding together.
