# F20 — One-command control-plane onboarding

## Outcome

A customer can start from a fresh Linux, macOS, or Windows control-plane host
and run one platform-native command once. Linux and macOS use
`curl -fsSL https://get.tunnex.io | sh`; Windows uses the documented PowerShell
entrypoint. Every entrypoint presents the same Tunnex wordmark and slogan,
guides the operator through the same configuration decisions, reviews the plan
before mutation, prepares a compatible container runtime when needed, and
finishes with a verified running control plane without requiring copied
prerequisite commands. Linux may also run the co-located WireGuard gateway;
macOS and Windows finish by directing the operator to enroll a gateway on a
Linux host.

## Decisions

### D1 — One product flow sits above platform adapters

Release selection, signature and digest verification, configuration validation,
review, installation, and post-install health checks have one shared contract.
Thin platform adapters own only host detection, privilege escalation, container
runtime preparation, service lifecycle, and filesystem conventions. Linux
adapters cover the common apt, dnf/yum, zypper, pacman, and apk families; an
unknown distribution may proceed when a usable Docker Engine and Compose v2
already exist. macOS uses an available Docker-compatible runtime and guides or
prepares one when absent. Windows uses PowerShell and a Docker-compatible
runtime. Platform adapters must not fork product configuration or release
verification behavior.

### D2 — Readiness means a usable daemon, not a binary on PATH

Preflight distinguishes missing software, a stopped runtime, a caller who needs
elevated Docker access, and a platform transition that requires a logout,
desktop launch, or reboot. After the operator confirms the plan, the platform
adapter prepares and starts the runtime and requires both `docker info` and
`docker compose version` to succeed. The current Linux installation may use
elevated Docker access; adding the invoking user to the Docker group is only a
convenience for their next login. A required reboot is reported as a resumable
checkpoint, not as a successful installation.

### D3 — Host readiness is explicit; product mutation follows one confirmation

The installer first shows the original three-line terminal-safe Tunnex wordmark —
`TUNN` in bright white and `EX` in Tunnex red when colour is available — plus the slogan
“Connect Everything. Trust Nothing.” It then detects the host, resolves the
release, and asks one question at a time for deployment, TLS, administrator,
and SMTP choices. The SMTP password is masked. A platform launcher may prepare
missing host prerequisites before the product wizard when the platform requires
them (for example Docker Desktop and Git Bash on Windows); that work is visible,
additive, and safe to resume by running the same command again. One
plain-language summary precedes the single confirmation for creating or
changing the Tunnex workspace and deployment. Interactive and non-interactive
runs use the same validation and execution path; environment variables supply
answers when no terminal exists.

### D4 — OpenClaw contributes interaction principles, not product coupling

F20 adopts the useful onboarding pattern: visible preflight, guided defaults,
review before apply, verification after apply, and safe reruns. It does not copy
OpenClaw code, branding, configuration, or runtime behavior. Tunnex retains its
own wordmark, language, security model, and release-verification contract.

### D5 — Reruns repair prerequisites and preserve deployments

Re-running the command reuses a working Docker installation and the existing
Tunnex database password and configuration. Host bootstrap is additive and
idempotent. It must not silently remove an existing Docker distribution or
overwrite an existing `.env` with newly prompted values.

### D6 — Public delivery remains canonical and synchronized

The POSIX and PowerShell launchers live with the core release and are published
through the existing installer-site synchronization contract. Shared fixtures
assert that both launchers select and verify the same immutable release and
produce the same product configuration. Platform syntax may differ, but there
is no separately versioned or manually maintained product installer.

### D7 — Portable control plane does not pretend to be a portable gateway

The API, web, database, Redis, migration, and edge services run through a
Docker-compatible runtime on Linux, macOS, and Windows. The co-located gateway
is different: it requires Linux `/dev/net/tun`, `NET_ADMIN`, IP forwarding, and
host networking behavior that Docker Desktop does not provide faithfully.
Therefore Linux installs the full single-host shape, while macOS and Windows
install the control plane with `node-agent` scaled to zero and show the exact
next step for enrolling a separate Linux gateway. The deployment shape is
persisted in `.env` and preserved by upgrades and reruns.

### D8 — An installation directory owns an isolated Compose project

The installer derives and persists a safe Compose project name from the target
directory (or accepts an explicit `TUNNEX_COMPOSE_PROJECT` override). Every
installer Compose invocation passes that project explicitly, and `upgrade.sh`
continues to read the persisted name. A second target directory therefore
cannot recreate or attach to an existing Tunnex stack merely because the
shared compose file contains its historical `name: tunnex` default.

## Acceptance

- Fresh Linux, macOS, and Windows hosts reach the same guided onboarding from
  their platform-native one-liner even when Docker and Compose are absent.
- Linux reaches a verified control plane plus co-located gateway. macOS and
  Windows reach a verified portable control plane, keep the Linux-only gateway
  container disabled, and receive a clear separate-Linux-gateway handoff.
- The compact two-colour wordmark, slogan, numbered stages, every interactive
  prompt, masked SMTP secret, review summary, and final next steps are visible
  in a real pseudo-terminal run.
- Missing Docker/Compose are prepared visibly by the platform readiness stage;
  a working installation is untouched and an interrupted bootstrap resumes by
  running the same command again.
- A stopped daemon and root-only Docker socket are handled and verified.
- Cancellation occurs before Tunnex workspace or deployment mutation.
- Focused POSIX and PowerShell tests cover fresh-host bootstrap,
  existing-runtime reuse, root-only access where applicable, cancellation,
  equivalent release verification, and branded onboarding output.

## Non-goals

- Provisioning a VM, public IP, DNS record, load balancer, firewall, or cloud
  security-group rule.
- Replacing a working third-party Docker installation.
- Emulating the Linux WireGuard data plane inside Docker Desktop on macOS or
  Windows.
- Changing Tunnex TLS termination, release signing, image provenance, or
  upgrade semantics.
