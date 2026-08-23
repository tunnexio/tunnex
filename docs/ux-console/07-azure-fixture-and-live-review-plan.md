# Azure Rapid-Development Fixture and Live-Review Plan

**Documentation only. Do not start services until the first approved implementation story. Never use production credentials or production data.**

## Exact non-production procedure (do not run during Phase 0)

Use one explicitly named, isolated compose project for the Agents slice. The commands below are derived from `Makefile`, `docker-compose.yml`, `docker-compose.dev.yml`, `apps/api/cmd/seed-fixtures`, and `apps/web/vite.config.ts`. They leave the normal `tunnex` project untouched.

`make up-enterprise` is intentionally not a usable command: edition is selected by a paid licence, not a build tag. Therefore the only honest enterprise precondition is a securely supplied **non-production paid fixture licence**. Do not substitute production credentials or invent a key.

```bash
# Terminal A: persistent, named fixture project only. Host ports do not overlap
# the normal project's 80/8443/51820.
tmux new-session -d -s tunnex-agents-stack \
  'cd /home/ubuntu/tunnex && COMPOSE_PROJECT_NAME=tunnex-agents HOST_HTTP_PORT=8082 HOST_API_MTLS_PORT=8445 HOST_WG_PORT=51822 make up'

# Terminal B: explicit migration and deterministic base + populated fixture seed.
# seed-fixtures defaults to http://nginx:8080 inside the same compose network;
# strict mode is retained so a missing posture-blocked fixture fails the seed.
cd /home/ubuntu/tunnex
COMPOSE_PROJECT_NAME=tunnex-agents HOST_HTTP_PORT=8082 HOST_API_MTLS_PORT=8445 HOST_WG_PORT=51822 make migrate
COMPOSE_PROJECT_NAME=tunnex-agents HOST_HTTP_PORT=8082 HOST_API_MTLS_PORT=8445 HOST_WG_PORT=51822 make seed
COMPOSE_PROJECT_NAME=tunnex-agents HOST_HTTP_PORT=8082 HOST_API_MTLS_PORT=8445 HOST_WG_PORT=51822 TUNNEX_SEED_FORCE=true make seed-fixtures

# Health and edition evidence, from the host-exposed nginx surface.
curl -fsS http://localhost:8082/healthz
curl -fsS http://localhost:8082/api/v1/meta

# Install the separately supplied non-production paid fixture licence as the demo owner
# through Settings → Licence; confirm /meta reports enterprise, then layer its fixture rows.
COMPOSE_PROJECT_NAME=tunnex-agents HOST_HTTP_PORT=8082 HOST_API_MTLS_PORT=8445 HOST_WG_PORT=51822 make seed-enterprise

# Terminal C: persistent Vite server, proxied to this fixture nginx endpoint.
tmux new-session -d -s tunnex-agents-web \
  'cd /home/ubuntu/tunnex && TUNNEX_DEV_API=http://localhost:8082 pnpm --filter @tunnex/web dev -- --host 0.0.0.0 --port 5173'

# Stop only the named fixture project and retain its volumes.
COMPOSE_PROJECT_NAME=tunnex-agents HOST_HTTP_PORT=8082 HOST_API_MTLS_PORT=8445 HOST_WG_PORT=51822 docker compose -f docker-compose.yml -f docker-compose.dev.yml down
```

The seed order is mandatory: `migrate` → `seed` → `seed-fixtures` → (after licence activation) `seed-enterprise`. `seed` is idempotent and refuses real organizations unless forced; `seed-fixtures` layers the populated AI-Agent fixtures onto the demo organization and, in its default strict mode, fails if it cannot create the product-owned `posture_blocked` state. `seed-enterprise` requires the running stack's matching `tunnex_secrets` volume and therefore follows `make up` and `make seed`.

The intentional reset is destructive and requires separate approval. It is limited to this exact project:

```bash
COMPOSE_PROJECT_NAME=tunnex-agents HOST_HTTP_PORT=8082 HOST_API_MTLS_PORT=8445 HOST_WG_PORT=51822 \
  docker compose -f docker-compose.yml -f docker-compose.dev.yml down -v
```

Then repeat the start, migration, and seed sequence above. Never use `docker system prune`, bare `make reset`, a bare `docker compose down -v`, production data, a real IdP, or a production licence.

### Fixture identities and coverage

All credentials below are development-only constants in `apps/api/internal/seeddata/seeddata.go`; they are not production secrets.

| Persona | Login | Password | Review use |
|---|---|---|---|
| Owner / CP admin | `owner@demo.tunnex.local` | `tunnex-demo-password` | Licence installation, full Agents actions. |
| Member | `member@demo.tunnex.local` | `tunnex-demo-password` | Read-only/permission-denied actions. |
| Unverified admin | `unverified-admin@demo.tunnex.local` | `tunnex-demo-password` | Verified-email mutation gate. |
| No organization | `fresh-user@demo.tunnex.local` | `tunnex-demo-password` | Empty/onboarding boundary. |
| CP administrator | `cpadmin@demo.tunnex.local` | `tunnex-demo-password` | Separate control-plane governance only; not an organization role. |

`seed-fixtures` supplies the demo organization's populated Agents states, including an active addressed agent, an owner who has departed the organization, an agent with no address, labelled and unlabelled MCP destinations, and an agent with no reachable destination. It expressly does **not** manufacture the structurally impossible unattributable-agent state. Enterprise-only runtime/MCP/JIT controls cannot be browser-reviewed until `/api/v1/meta` reports `edition: enterprise`; that paid fixture licence is the only external prerequisite.

## Fixture procedure and matrix

1. Use an isolated compose project and named DB/Redis volumes only.
2. After authorization, migrate and use existing `apps/api/cmd/seed-fixtures`, `apps/api/cmd/seed-enterprise`, or `apps/api/cmd/seed`; record exact command, SHA, IDs, and reset in story evidence.
3. Reset destroys/recreates only fixture volumes, migrates/seeds, and verifies health—never manual database edits.

| Fixture | Required coverage |
|---|---|
| Open org | owner, admin, operator, member, agent; fresh-empty and populated. |
| Enterprise org | policy/SSO/directory, agents, MCP/JIT/templates, approvals, events/audit. |
| Boundary states | permission denied, edition unavailable, healthy, degraded, stale, offline/unknown, pending, revoked, suspended, archived/deleted, partial read. |

## Browser review protocol

- Review wide/desktop/narrow, keyboard, deep-link and Back behavior.
- For every mutation inspect request/response, refreshed server truth, durable result, audit entry, console, failed requests, API code/request ID, and related links.
- Screenshots: `walk-artifacts/UX/<story>/<YYYYMMDDTHHMMSSZ>/<route>-<state>-<viewport>.png`, with `review-record.md` describing fixture, persona, URL, expected/observed state, and console/network result.
- Rapid visual work may defer unit tests/CI only with explicit debt. Typecheck, build, local gates, and exact-head CI remain required before completion/merge.
