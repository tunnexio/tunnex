#!/usr/bin/env python3
"""Read-only static Compose/config contract; uses dummy values, starts nothing."""
import json
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[2]
env = dict(os.environ)
env.update({
    "COMPOSE_PROJECT_NAME": "tunnexaicontract",
    "TUNNEX_AI_GATEWAY_ADMIN_USER": "fixture-admin",
    "TUNNEX_AI_GATEWAY_ADMIN_PASSWORD": "fixture-password-only",
    "TUNNEX_AI_OPENROUTER_API_KEY": "fixture-provider-only",
    "TUNNEX_AI_ENGINE_ENCRYPTION_KEY": "fixture-encryption-only",
    "DATABASE_URL": "postgres://fixture:fixture@postgres/fixture",
    "REDIS_URL": "redis://redis:6379",
})
command = ["docker", "compose", "--env-file", "/dev/null", "-p", "tunnexaicontract",
           "-f", str(root / "docker-compose.yml"), "-f", str(root / "deploy/ai-gateway/compose.yml"),
           "--profile", "ai", "config", "--format", "json"]
config = json.loads(subprocess.check_output(command, cwd=root, env=env, text=True))
engine = config["services"]["bifrost"]
assert engine["image"] == "maximhq/bifrost:v2.0.0@sha256:cf71be9fad4e0749b6e26cbb774c687413dad9a0970b83f4e1dadb6f503ea208"
assert engine["profiles"] == ["ai"] and not engine.get("ports")
assert set(engine["networks"]) == {"ai_engine"}
assert {name for name, service in config["services"].items() if "ai_engine" in service.get("networks", {})} == {"api", "bifrost"}
assert config["services"]["api"]["environment"]["TUNNEX_AI_GATEWAY_URL"] == "http://bifrost:8080"
volumes = {v["target"]: v for v in engine["volumes"]}
assert volumes["/app/data"]["source"] == "ai_engine_config"
assert volumes["/app/data/logs"]["source"] == "ai_engine_logs"
assert volumes["/app/data/config.json"]["read_only"]
bootstrap = json.loads((root / "deploy/ai-gateway/config.json").read_text())
assert bootstrap["client"]["enforce_auth_on_inference"] is True
assert bootstrap["client"]["enable_logging"] is True
assert bootstrap["logs_store"]["enabled"] is True
assert bootstrap["logs_store"]["retention_days"] == 7
assert bootstrap["client"]["log_retention_days"] == 7
assert bootstrap["client"]["disable_content_logging"] is True
assert bootstrap["governance"]["auth_config"]["is_enabled"] is True
assert bootstrap["governance"]["virtual_keys"] == []
assert bootstrap["providers"]["openrouter"]["network_config"]["max_retries"] == 0
assert bootstrap["providers"]["openrouter"]["keys"][0]["value"] == "env.OPENROUTER_API_KEY"
nginx = (root / "deploy/nginx/nginx.conf").read_text()
ai_route = nginx.split("location /ai/ {", 1)[1].split("}", 1)[0]
for directive in ("set $tunnex_api api:8080;", "proxy_pass http://$tunnex_api;", "proxy_buffering off;", "proxy_read_timeout 35s;"):
    assert directive in ai_route
print("PASS: pinned opt-in engine, private network/no host ports, distinct persistent state, secret references, enforced authentication, content logging off")

# The explicit managed overlay is usable without a provider secret at install
# time and replaces only startup configuration, retaining the same state volumes.
managed_command = command[:-5] + ["-f", str(root / "deploy/ai-gateway/compose-managed.yml")] + command[-5:]
managed_env = dict(env)
managed_env.pop("TUNNEX_AI_OPENROUTER_API_KEY")
managed = json.loads(subprocess.check_output(managed_command, cwd=root, env=managed_env, text=True))
managed_engine = managed["services"]["bifrost"]
assert managed["services"]["api"]["environment"]["TUNNEX_AI_PROVIDER_MANAGEMENT_ENABLED"] == "true"
managed_volumes = {v["target"]: v for v in managed_engine["volumes"]}
assert managed_volumes["/app/data"] == volumes["/app/data"]
assert managed_volumes["/app/data/logs"] == volumes["/app/data/logs"]
assert managed_volumes["/app/data/config.json"]["source"].endswith("/config-managed.json")
assert managed_volumes["/app/data/config.json"]["read_only"]
managed_bootstrap = json.loads((root / "deploy/ai-gateway/config-managed.json").read_text())
assert "providers" not in managed_bootstrap
assert managed_bootstrap == {k: v for k, v in bootstrap.items() if k != "providers"}
assert not managed_engine.get("ports")
assert managed_engine["environment"]["OPENROUTER_API_KEY"] == ""
assert "TUNNEX_AI_PROVIDER_MANAGEMENT_ENABLED" not in config["services"]["api"]["environment"]
print("PASS: explicit self-service overlay uses database-owned provider configuration, preserves volumes and does not require a preinstalled provider key")
