# Saved public SSH keys

Source-only slice based on 9b5d17d. Registry belongs to the authenticated human account, across organizations; organization-scoped routes use existing sandbox view/create authorization. No caller-supplied owner is accepted. Keys are parsed with the existing public-key validator, comments discarded, and SHA256 fingerprints deduplicated per account. Names are trimmed and limited to 80 characters. Maximum 50 saved keys per account.

First saved key is the default. Explicit default selection is serialized per account. Deleting the default leaves no default; no implicit replacement. Deletion and default changes only affect future selections. Sandbox creation continues to submit an immutable snapshot of public key text, preserving manual input compatibility and existing sandbox access.

No private keys, live access changes, infrastructure, deployment, or push. Local tests substitute for live proof; live proof is deferred to approved integration of this slice.
