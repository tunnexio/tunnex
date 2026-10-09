# Local AI Gateway UI fixture

This optional development profile uses the real private Bifrost engine and Tunnex API with a small simulated OpenAI-compatible provider. It creates visibly named local models, active and paused credentials, demo user-group grants, and active/disabled workload policies. Responses say that no external model was called. Usage comes from actual local requests recorded by the native engine; token values are synthetic and pricing remains unknown. No instances, VPN readiness, provider entitlement, or spend limits are fabricated.

The engine and provider join only the `internal: true` fixture network, with no published ports or external egress. The API keeps its normal network as well. Other native providers and models will remain unavailable in this profile. Provider secrets are generated locally, stored privately in the ignored `.env`, and passed through the normal encrypted provider/grant reconciliation paths. Prompt/response content logging is disabled.

Prerequisites: the usual local stack and seeded **Demo Organization** already exist, and Docker has a compatible pinned native AI engine image, `python:3.12.13-slim-bookworm`, and `alpine:3.23`. Set `TUNNEX_DEV_AI_ENGINE_IMAGE` to that engine image before running Compose. This helper never reseeds unrelated organizations or changes the server-wide HTTP transport policy; local development must already permit its HTTP origin.

From the repository root:

```sh
python3 deploy/ai-gateway/local-ui/prepare.py
docker compose -f docker-compose.yml -f docker-compose.dev.yml -f deploy/ai-gateway/local-ui/compose.yml --profile ai-fixture up -d --no-build --wait bifrost ai-fixture-provider
docker compose -f docker-compose.yml -f docker-compose.dev.yml -f deploy/ai-gateway/local-ui/compose.yml --profile ai-fixture up -d --no-build --no-deps api
docker exec -i tunnex-postgres-1 sh -c 'exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -X -v ON_ERROR_STOP=1' < deploy/ai-gateway/local-ui/fixtures.sql
docker run --rm --network tunnex_default -v "$PWD:/repo:ro" -w /repo python:3.12.13-slim-bookworm python3 deploy/ai-gateway/local-ui/seed.py --base http://api:8080
```

If your existing stack has additional Compose overrides, keep them in both `compose` commands. Keep the explicit local fixture override and profile when restarting this fixture. The ordinary development and deployment files do not start it or connect the API to its network. Preparation preserves existing `.env` settings and refuses to replace a different configured AI Gateway. Keep the private credential values together with the dedicated `ai_ui_fixture_config` and `ai_ui_fixture_logs` volumes; changing encryption credentials does not recover encrypted engine state. An x86 engine image may use host emulation on ARM64.

The SQL only adds the fixed demo review group and its two existing demo users. The API seeder preserves reviewer changes to existing fixtures and never generates workload enrollment keys or creates instances. It performs 12 chat requests (including streaming) and one embedding, then waits up to 20 seconds for actual native usage to appear. Repeat it with `--requests 0` to verify provider/catalog/access/usage without generating more successful traffic. A model outside the grants must return HTTP 403. Secrets and cookies are never printed.

Open the existing development browser at `/ai-gateway/models`, `/ai-gateway/credentials`, `/ai-gateway/access`, `/ai-gateway/access?subject=workloads`, `/ai-gateway/my-models`, or `/ai-gateway/usage`. Local fixture chat/code models support browser chat; embeddings use the embeddings API. VPN SDK availability follows the actual gateway/mode readiness and may remain unavailable. Removing or disabling sample access uses the real local policy controls.
