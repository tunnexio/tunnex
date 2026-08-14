# Cross-site installer sync

`get.tunnex.io` is served by the separate `tunnex-web` repository, while the
canonical installer lives in this repository at `deploy/get.sh`. The two copies
must never drift silently.

## Flow

1. A push to `main` or a version tag publishes all Tunnex images successfully.
2. The `sync-installer-site` CI job dispatches `tunnex-main-published` to
   `tunnexio/tunnex-web`, carrying the full source SHA and an immutable raw URL.
3. `tunnex-web` fetches `deploy/get.sh` at that exact SHA, runs shell and sync
   checks, and opens a reviewable PR from a clean `main` base.
4. Merging that PR runs the existing web deploy workflow, updating
   `get.tunnex.io` with the verified installer bytes.

No workflow fetches `main` after the event or follows a mutable release pointer.
The source SHA is validated before a PR is created, so a repeated event is
idempotent and an unrelated branch cannot be published as the installer. A
version tag is useful release metadata, but the installer bytes always come
from the event's immutable commit SHA; the public endpoint never resolves a
mutable `latest` tag at install time.

## Required secret

Add a fine-grained GitHub token as the `tunnex` repository Actions secret
`TUNNEX_WEB_SYNC_TOKEN`. It needs access only to `tunnexio/tunnex-web` with
Actions: read and write repository dispatch events (or the equivalent contents
and pull-request permissions used by the receiving workflow). Keep it out of
the repository, logs, and installer.
