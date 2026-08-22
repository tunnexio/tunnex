# F20 — One-command control-plane onboarding

## Outcome

A customer can start from a fresh supported Linux control-plane host and run
`curl -fsSL https://get.tunnex.io | sh` once. The installer presents the
Tunnex wordmark and slogan, guides the operator through configuration, reviews
the plan before mutation, installs Docker Engine and Compose when needed, and
finishes with a verified running stack without requiring copied package-manager
commands.

## Decisions

### D1 — The public installer owns its host prerequisites

On supported Debian/Ubuntu and RPM-family Linux hosts, the canonical installer
installs Docker Engine, the Compose v2 plugin, and required host utilities when
they are absent. An already usable Docker installation is preserved; the
installer does not replace or remove working packages. Unsupported operating
systems fail before mutation with one specific compatibility message.

### D2 — Readiness means a usable daemon, not a binary on PATH

Preflight distinguishes missing software, a stopped daemon, and a caller who
needs elevated Docker access. After the operator confirms the plan, the
installer enables/starts Docker where systemd is available and requires both
`docker info` and `docker compose version` to succeed. The current installation
may use elevated Docker access; adding the invoking user to the Docker group is
only a convenience for their next login.

### D3 — One guided confirmation precedes host and product mutation

The installer first shows the Tunnex wordmark and the slogan “Connect
Everything. Trust Nothing.”, detects the host, resolves the release, and
collects deployment, TLS, administrator, and SMTP choices. It then displays one
plain-language summary including prerequisite work and asks for confirmation.
Interactive and non-interactive runs use the same validation and execution
path; environment variables supply answers when no terminal exists.

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

`deploy/install.sh` remains the only onboarding implementation. The
`get.tunnex.io` launcher continues to fetch it from the core repository, and
the existing installer-site synchronization contract remains the release path.
This story makes no separate, drifting installer copy.

## Acceptance

- A fresh supported host reaches the guided onboarding from the public
  one-liner even when Docker and Compose are absent.
- The banner, wordmark, slogan, numbered stages, review summary, and final next
  steps are visible in a terminal run.
- Missing Docker/Compose are installed only after confirmation; a working
  installation is untouched.
- A stopped daemon and root-only Docker socket are handled and verified.
- Cancellation occurs before package, service, workspace, or deployment
  mutation.
- Focused shell tests cover fresh-host bootstrap, existing-Docker reuse,
  root-only access, cancellation, and branded onboarding output.

## Non-goals

- Provisioning a VM, public IP, DNS record, load balancer, firewall, or cloud
  security-group rule.
- Replacing a working third-party Docker installation.
- Supporting non-Linux control-plane hosts in the one-command bootstrap.
- Changing Tunnex TLS termination, release signing, image provenance, or
  upgrade semantics.
