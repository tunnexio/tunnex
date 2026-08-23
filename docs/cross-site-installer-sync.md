# Cross-site installer sync

`get.tunnex.io` is served by the separate `tunnex-web` repository. The POSIX
launcher originates at `deploy/get.sh`, while the native Windows launcher
originates at `deploy/install.ps1`; both delegate to the canonical product flow
in `deploy/install.sh`. The public copies must never drift silently.

## Flow

1. A push to `main` or a version tag publishes all Tunnex images successfully.
2. The `sync-installer-site` CI job dispatches `tunnex-main-published` to
   `tunnexio/tunnex-web`, carrying the full source SHA plus immutable raw URLs
   for `deploy/get.sh` and `deploy/install.ps1`.
3. `tunnex-web` fetches both launchers at that exact SHA, validates the POSIX
   launcher and PowerShell entrypoint, records that SHA as deployment metadata,
   and opens a reviewable PR from a clean `main` base.
4. After the required review and explicit rebase merge, the web deploy workflow
   updates `get.tunnex.io`. Its Worker serves the copied POSIX launcher with the
   canonical payload URL pinned to the recorded immutable SHA, and serves the
   matching `/install.ps1` endpoint and checksums.

No public launcher fetches `main` after the event or follows a mutable release
pointer. The source SHA is validated before a PR is created, so a repeated event
is idempotent and an unrelated branch cannot be published as the installer. A
version tag is useful release metadata, but the launcher and the product payload
always come from the event's immutable commit SHA; the public endpoint never
resolves a mutable `latest` tag at install time.

## Required secret

Add a fine-grained GitHub token as the `tunnex` repository Actions secret
`TUNNEX_WEB_SYNC_TOKEN`. It needs access only to `tunnexio/tunnex-web` with
Actions: read and write repository dispatch events (or the equivalent contents
and pull-request permissions used by the receiving workflow). Keep it out of
the repository, logs, and installer.
