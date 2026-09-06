# Local installer review

Branch: `cli-installtion-improvement`, based on `origin/main` at `6a4ae8c5`.
The original working tree and its in-progress changes remain in place.

From this worktree, preview the shared macOS/Linux/Windows onboarding UI:

```sh
sh deploy/install.sh --ui-preview
```

Preview the matching five-step flow in native PowerShell (also runs on macOS):

```powershell
pwsh -NoProfile -File deploy/install.ps1 -UiPreview
```

Both commands display labeled sample data and exit before host preparation or
network operations. Animation requires an interactive terminal. `NO_COLOR=1`,
`TERM=dumb`, or `TUNNEX_LOADER=never` disables the shell animation.
The real installation commands on get.tunnex.io have not been changed.

Review the wordmark, step headings, spinner, plan card, and completion copy.
Both previews display the same five-step flow and require no Docker or Git Bash.
A real Windows install first prepares Docker Desktop and Git Bash, then runs the
shared installer for the same configuration, review, launch, and health checks.

Validation: POSIX host bootstrap, release provenance, Windows bootstrap under
local PowerShell, preview isolation, and exact preview-text parity checks pass. No live installation or
native Windows terminal visual acceptance has been performed. Full story gates and a real installation box walk remain pending.

Current wordmark: original installer glyphs and spacing with burgundy EX coloring,
per the user reference. Earlier solid-cell comparison images are superseded.
