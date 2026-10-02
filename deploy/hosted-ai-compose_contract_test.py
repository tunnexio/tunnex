#!/usr/bin/env python3
"""Render hosted Compose with fixture values; start no containers."""
import json
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
env = dict(os.environ)
env.update({
    "POSTGRES_PASSWORD": "fixture-postgres",
    "DATABASE_URL": "postgres://fixture@postgres/tunnex",
    "APP_BASE_URL": "http://192.0.2.10",
    "TUNNEX_EDGE_LISTEN": "http://:80",
    "TUNNEX_NODE_ENDPOINT": "192.0.2.10:51820",
    "TUNNEX_AI_ENGINE_IMAGE": "ghcr.io/tunnexio/tunnex-ai-engine@sha256:" + "a" * 64,
    "TUNNEX_AI_GATEWAY_ADMIN_USER": "fixture-admin",
    "TUNNEX_AI_GATEWAY_ADMIN_PASSWORD": "fixture-password",
    "TUNNEX_AI_ENGINE_ENCRYPTION_KEY": "fixture-encryption-key",
    "TUNNEX_AI_GATEWAY_URL": "",
    "TUNNEX_AI_CUSTOM_ENDPOINTS_FILE": "/tmp/hosted-ai-fixture-policy.json",
    "TUNNEX_AI_CUSTOM_PROXY_USERNAME": "fixture-proxy",
    "TUNNEX_AI_CUSTOM_PROXY_PASSWORD": "fixture-proxy-password",
    "TUNNEX_AI_CUSTOM_PROXY_URL": "http://fixture-proxy:fixture-proxy-password@ai-egress:8190",
    "COMPOSE_PROFILES": "bundled-db",
    "TUNNEX_AI_VPN_AUTO": "true",
})
config = json.loads(subprocess.check_output([
    "docker", "compose", "--env-file", "/dev/null", "--project-name", "hosted-ai-contract",
    "-f", str(root / "deploy/tunnex.yml"), "config", "--format", "json",
], env=env, text=True))
services = config["services"]
engine = services["bifrost"]
assert not engine.get("ports") and not engine.get("profiles")
assert set(engine["networks"]) == {"ai_engine"}
assert {name for name, service in services.items() if "ai_engine" in service["networks"]} == {"api", "bifrost", "ai-egress"}
assert set(services["api"]["networks"]) == {"default", "ai_engine"}
assert services["api"]["environment"]["TUNNEX_AI_GATEWAY_URL"] == ""
assert services["api"]["environment"]["TUNNEX_AI_ALLOW_PRIVATE_HTTP"] == "false"
assert services["api"]["environment"]["TUNNEX_AI_VPN_AUTO"] == "true"
node = services["node-agent"]
assert node["environment"]["TUNNEX_AI_VPN_AUTO"] == "true"
assert node["depends_on"]["api"]["condition"] == "service_healthy"
assert "NET_RAW" in node["cap_add"]
assert all(port["target"] != 8083 for service in services.values() for port in service.get("ports", []))
assert services["api"]["depends_on"]["bifrost"]["condition"] == "service_healthy"
assert services["api"]["depends_on"]["ai-egress"]["condition"] == "service_healthy"
assert engine["depends_on"]["ai-egress"]["condition"] == "service_healthy"
assert services["api"]["environment"]["TUNNEX_AI_PROVIDER_MANAGEMENT_ENABLED"] == "true"
assert not any("API_KEY" in key for key in engine["environment"])
volumes = {volume["target"]: volume for volume in engine["volumes"]}
assert volumes["/app/data"]["source"] == "ai_engine_config"
assert volumes["/app/data/logs"]["source"] == "ai_engine_logs"
assert volumes["/app/data/config.json"]["read_only"]
proxy = services["ai-egress"]
assert proxy["image"] == services["api"]["image"]
assert not proxy.get("build") and not proxy.get("ports") and not proxy.get("profiles")
assert set(proxy["networks"]) == {"default", "ai_engine"}
assert proxy["entrypoint"] == ["/usr/local/bin/tunnex-ai-egress"]
assert proxy["read_only"] and proxy["cap_drop"] == ["ALL"]
assert "no-new-privileges:true" in proxy["security_opt"]
assert set(proxy["environment"]) == {"TUNNEX_AI_CUSTOM_ENDPOINTS_FILE", "TUNNEX_AI_CUSTOM_PROXY_LISTEN", "TUNNEX_AI_CUSTOM_PROXY_USERNAME", "TUNNEX_AI_CUSTOM_PROXY_PASSWORD"}
assert "407 Proxy Authentication Required" in proxy["healthcheck"]["test"][1]
assert len(proxy["volumes"]) == 1 and proxy["volumes"][0]["read_only"]
for name in ("api", "bifrost", "ai-egress"):
    policy = next(v for v in services[name]["volumes"] if v["target"] == "/etc/tunnex/ai-custom-policy.json")
    assert policy["source"] == env["TUNNEX_AI_CUSTOM_ENDPOINTS_FILE"] and policy["read_only"]
for name in ("api", "bifrost"):
    assert services[name]["environment"]["TUNNEX_AI_CUSTOM_PROXY_URL"] == env["TUNNEX_AI_CUSTOM_PROXY_URL"]
bootstrap = json.loads((root / "deploy/ai-gateway/config-managed.json").read_text())
assert "providers" not in bootstrap
assert bootstrap["client"]["enforce_auth_on_inference"]
assert bootstrap["client"]["disable_content_logging"]
assert bootstrap["governance"]["auth_config"]["is_enabled"]
assert bootstrap["governance"]["virtual_keys"] == []
print("Hosted AI Compose contract passed: automatic private backend and authenticated egress, readiness checks, shared read-only policy, HTTP gate, durable managed state and no seeded provider")
