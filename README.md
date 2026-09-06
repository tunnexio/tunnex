# Tunnex.io

Self-hosted, multi-tenant VPN & Zero Trust access platform — a modern, open alternative to Pritunl.

- **WireGuard** management (OpenVPN later), with a control-plane / data-plane split.
- **Auth**: local users, Google & Microsoft SSO.
- **Clients**: the headless CLI lives here; the Windows and macOS desktop application is maintained in [tunnex-client](https://github.com/tunnexio/tunnex-client).
- **One-command install**: a single guided installer brings up the whole stack from **prebuilt images** — no source build, no file edits — and auto-generates every secret/key on first boot.

> The full product roadmap — every epic and story — lives in [`PLAN.md`](./PLAN.md). Point any session at it and name the current story (e.g. "we're on S1.3").

## Deploy (self-host)

> **New here? Read [docs/self-host.md](docs/self-host.md).** It is the end-to-end story — control plane,
> first gateway, first device — plus the collected honest limits, what to monitor, and the two recovery
> stories. Every procedure in it is marked with whether we have actually run it.

**Prerequisite: a Linux, macOS, or Windows host and a public address** (a DNS name or public IP that
users and gateways can reach). The platform launcher prepares a compatible Docker runtime and Compose
v2 when they are absent, then hands off to the same signed-release installer. Linux can run the complete
single-host control plane and gateway. macOS and Windows install a portable control plane and then guide
you to enroll the WireGuard gateway on a separate Linux host. A usable runtime is preserved. The installer
does not provision the server, DNS, firewall, load balancer, or public IP.

**Recommended — download, verify, inspect, then run** (our audience is sovereignty/security-conscious;
never pipe a script you haven't read into a root shell):

```bash
curl -fsSL https://get.tunnex.io -o get.sh
curl -fsSL https://get.tunnex.io/SHA256SUMS -o SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
less get.sh
sudo sh get.sh
```

**Convenience — one-liner:**

```bash
# Linux or macOS
curl -fsSL https://get.tunnex.io | sh
```

```powershell
# Windows Administrator PowerShell
irm https://get.tunnex.io/install.ps1 | iex
```

Every platform shows the same branded guide. It checks the host, selects the latest signed semantic release, collects
the deployment address, TLS mode, administrator, and SMTP choice, then shows one review before it
changes the machine. It installs missing host prerequisites, generates the DB secret, writes a clean
`./tunnex/.env`, and pins the compose manifest and every `ghcr.io/tunnexio/tunnex-*` image to that
release's verified source commit. No `git clone`, no source build, no compose editing. Re-running
preserves a usable Docker installation and reuses the DB password.

> **Why macOS/Windows use a separate gateway:** the gateway requires Linux `/dev/net/tun`, `NET_ADMIN`,
> IP forwarding, and host networking. The portable installer keeps `node-agent` disabled instead of
> claiming that Docker Desktop can provide an equivalent data plane.

Non-interactive (CI / no terminal) — pass the required inputs as env vars:

```bash
curl -fsSL https://get.tunnex.io | \
  TUNNEX_PUBLIC_BASE_URL=https://vpn.acme.com \
  TUNNEX_TLS_MODE=direct \
  TUNNEX_ADMIN_EMAIL=owner@example.com \
  TUNNEX_SMTP=skip sh -s -- --yes
```

- Dashboard → the exact public URL selected during onboarding.
- Config lives in `./tunnex/.env` (edit values there; never hand-edit `tunnex.yml`).
- Provenance: `.env` records the semantic release, immutable image digests, and exact source commit.

> `get.tunnex.io` serves [`deploy/get.sh`](deploy/get.sh) directly with a five-minute revalidation
> window. That small launcher downloads and delegates to the canonical
> [`deploy/install.sh`](deploy/install.sh). Windows starts with
> [`deploy/install.ps1`](deploy/install.ps1), which prepares Docker Desktop and Git Bash before the
> same canonical hand-off. CI exercises both platform contracts and the shared release resolver.

## Develop locally

The dev stack builds from source. Configure a real SMTP endpoint in `.env` for email flows (no public address):

```bash
make up                   # build + start postgres, redis, api, web, nginx, node-agent
```

Then:

- App shell → http://localhost
- API health → http://localhost/healthz

Node ≥20 is required for the web/client workspaces (pinned via `.nvmrc` + `engine-strict`).

Tear down:

```bash
make down     # stop, keep data
make reset    # stop and wipe all volumes
```

## Repository layout

```
apps/
  api/       Go control-plane API (chi, sqlc, Postgres, Redis)
  node/      tunnex-node data-plane agent (owns WireGuard via wgctrl)
  cli/       tunnex CLI client            (EPIC 5)
  web/       React + Vite SPA dashboard
packages/
  shared/    Generated TypeScript API client (OpenAPI-first)
deploy/
  docker/    Dockerfiles
  nginx/     Reverse-proxy config
```

Desktop development, installers, native helper code and platform CI live in
[tunnex-client](https://github.com/tunnexio/tunnex-client). Download desktop installers from its
[releases](https://github.com/tunnexio/tunnex-client/releases). This repository continues to own the
control-plane APIs, device enrollment, posture and authorization used by those clients.

## Architecture (why the split)

The **API is the control plane**; it never touches WireGuard directly. A **`tunnex-node` agent** owns the **data plane** and reconciles desired state (from the API) against the actual `wgctrl` interface state. In the compose quickstart the agent runs on the same host; the same abstraction later powers site-to-site gateways and the Kubernetes operator.

## Editions

Open-core. The multi-tenant schema lives in core; the open build limits org creation. Enterprise features (SSO, Zero Trust policies, Kubernetes operator) sit behind an `internal/enterprise/**` boundary.

## Development

Requires Docker, Go 1.23+, Node 20+, pnpm 9+.

```bash
make api      # run API locally
make agent    # run node agent locally
make web      # run web dev server
make logs     # tail compose logs
```

## Licensing

Tunnex is **open-core**:

- The **Open edition** — everything except the enterprise boundary below — is
  licensed under the **[Apache License 2.0](./LICENSE)**.
- The **Enterprise edition** — `apps/api/internal/enterprise/` and any code gated
  behind the `enterprise` build tag — is **proprietary and source-available**
  under a separate license (**[`apps/api/internal/enterprise/LICENSE`](./apps/api/internal/enterprise/LICENSE)**):
  readable for reference/evaluation, but production use requires a commercial
  agreement and it may not be redistributed.

The two editions are kept from bleeding into each other by the build-tag guard
`make test-editions`, which compiles + tests BOTH the open build and the
`-tags enterprise` build so a stray cross-edition import fails CI.

See [`NOTICE`](./NOTICE) for attribution and [`CONTRIBUTING.md`](./CONTRIBUTING.md)
(external PRs are paused pending a CLA/DCO flow).

Copyright 2026 Tunnex.
