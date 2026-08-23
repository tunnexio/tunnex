# F20 local onboarding walk

Date: 2026-08-22

## Scope

This walk is intentionally local. It proves the customer-visible onboarding
and host-bootstrap control flow without changing the developer machine or the
public `get.tunnex.io` installer.

## Local proof

Command:

```bash
TUNNEX_TEST_SHOW_OUTPUT=1 sh deploy/install-host-bootstrap_test.sh
```

Observed result: `install host bootstrap contract: PASS`.

The run showed the Tunnex wordmark and slogan, all five numbered stages, the
fresh-Ubuntu Docker/Compose work in the review, the selected public URL and TLS
mode, verified release provenance, and the final running/next-step summary.

The same contract also proved:

- a fresh Ubuntu host installs Docker Engine, Buildx, and Compose v2 packages;
- answering no exits before the host-mutation marker;
- a usable existing Docker installation causes no package-manager call;
- a root-only Docker socket completes the current install through `sudo`;
- a hostile `os-release` fixture is parsed as metadata and cannot execute its
  command-substitution marker;
- the generated `.env` preserves the selected TLS mode and release source SHA;
- Linux records `TUNNEX_PORTABLE_CONTROL_PLANE=false` and starts the co-located
  gateway with the rest of the stack;
- a macOS fixture records `TUNNEX_PORTABLE_CONTROL_PLANE=true`, starts the
  control plane with `node-agent` scaled to zero, and preserves that shape in
  the generated upgrade helper; and
- an installed but stopped macOS Docker Desktop receives the visible startup
  action and is verified ready before the installer continues; and
- the Git-Bash/MINGW handoff used by Windows persists the same portable
  control-plane shape and starts no local privileged `node-agent`.

The PTY contract deliberately unsets `NO_COLOR` and forces colour. It strips
terminal control sequences only for text assertions while separately requiring
the white and red ANSI segments, so the two-colour wordmark is genuinely
exercised rather than hidden by a test-runner preference. A separate
`NO_COLOR=1 TUNNEX_COLOR=always` regression proves the operator opt-out
suppresses all ANSI sequences without losing the terminal-safe wordmark.

The native Windows adapter contract was also run locally:

```powershell
pwsh -NoProfile -File deploy/install-windows-bootstrap_test.ps1
```

Observed result: `install windows bootstrap contract: PASS`. It proves the two-colour wordmark and
slogan, reuse of an already-ready Docker Desktop, automatic `winget` preparation of a missing Docker
Desktop, and hand-off into the canonical product installer.

The local installer-site contract also serves that exact PowerShell file only
from `https://get.tunnex.io/install.ps1`; it proves that URL cannot fall back
to the POSIX launcher and publishes a checksum for the exact bytes served. The
site sync guard requires both source launcher files and the Worker-injected
canonical payload SHA to come from the same immutable core commit.

## Deployment-shape boundary

The portable macOS and Windows result is deliberately a control plane, not a
WireGuard gateway. The gateway needs Linux TUN and network-administration
capabilities. The final onboarding handoff names a separate Linux gateway as
the next step instead of reporting a misleading full single-host success.

Focused installer, upgrade, release, public-URL, public-key, and edge-TLS
contracts passed after the change. `git diff --check` also passed.

## Ledger

This local command-stub run is a **SUBSTITUTE**, not the live-wire proof. It
does not claim that package installation, image pulls, service startup, DNS,
TLS, or the public launcher have passed on a real fresh VPS.

Named triggers for the real proofs are:

1. **Operator approves the local flow and provides or selects a disposable
   fresh supported Linux VPS** — run the exact one-liner and retain installer,
   container-health, and co-located-gateway evidence.
2. **macOS public-installer readiness** — run the exact public command on a
   clean macOS host and retain portable-control-plane and separate-gateway
   handoff evidence.
3. **Windows public-installer readiness** — run the exact PowerShell command on
   a clean Windows host and retain the same evidence.

Until those triggers are satisfied, the local command-stub and native
PowerShell runs remain substitutes and `get.tunnex.io` is unchanged.
