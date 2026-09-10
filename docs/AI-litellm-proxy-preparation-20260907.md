# Actual LiteLLM OSS proxy preparation evidence

User direction: use the actual LiteLLM model proxy, not only its SDK test bridge
or a similar UI. Decision record: S-AI-litellm-proxy-decisions.md (70957bb1).

## Delivered locally

- apps/ai-proxy contains the full unmodified OSS proxy server dependency set,
  LiteLLM1.100.0 plus MIT proxy extras0.4.91 and Prisma0.15.0.109 distributions
  resolved/installed into a separate temporary Python3.12 environment with hashes.
- Proprietary optional litellm-enterprise is excluded. Its actual wheel license
  was audited; no license checks were changed. Both retained MIT notices ship.
- Non-root Dockerfile and standalone opt-in Compose: independent DB and file
  secrets, no host ports/current CP network, both preparation networks internal.
- Independent master/salt/database secrets, fixed separate DSN, admin UI and
  automatic schema update disabled. No models/provider keys seeded.

## Checks

- Five private-secret/entrypoint guards passed under Python3.12.
- Full proxy import exposed75 FastAPI routes with enterprise package absent.
- CLI help and initialization with --skip_server_startup passed using a no-DB
  fixture and socket.connect forbidden. This is NOT a listening-server proof.
- Actual upstream ConfigGeneralSettings accepted the config; Compose config
  --quiet and git diff --check passed.
- Independent read-only review found no blocking issues within preparation scope.

## Concrete runtime blocker and outstanding contract

Read-only Docker check on2026-09-07 used context colima-tunnex-sso-review and
container tunnexaiwalk0907repro4-cp-postgres. Its live project label was
`tunnexaiwalk0907repro4`, network `tunnexaiwalk0907repro4_engine`. df reported
/dev/vdb1:7.8G total,7.3G used,82.0M available,99 percent used. No SQL, migration,
cleanup, resize, restart, image pull or startup followed. Existing volumes stay.

Docker image build, Linux Prisma engine generation, fresh native schema
provisioning, non-root container startup and actual model calls remain unproven.
The local CP still routes to Bifrost. Full LiteLLM integration requires the
proposed backend identity, credential-specific deployment aliases, idempotent
virtual keys, retained usage aggregation and per-organization cutover contract.
Do not map LiteLLM empty virtual-key models to deny-all: it means all models.
Existing Bifrost secrets require operator re-entry/rebinding; supported read APIs
are masked, and no native DB export was attempted. No migration or mode/provider
parity claim is made. No push, exact-head remote CI, merge or release occurred.

Next action: disposition the compatibility-safe proxy integration contract and
provide local runtime capacity, then implement admission/ownership bindings and
qualify real scoped inference through the actual proxy.
