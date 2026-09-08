"""Optional real-engine helper; all credentials and destinations are synthetic."""
import asyncio
import json
import os
import signal
import socket
import uuid

import aiohttp
import pytest


async def saved_probe(bridge, body, directory):
    binary = os.environ.get("AI_SAVED_PROBE_BINARY")
    if not binary:
        pytest.skip("explicit extended native engine binary required")
    directory.mkdir()
    provider = "custom-" + str(uuid.uuid4())
    key_id = "tnx-managed-" + str(uuid.uuid4())
    key_name = key_id + "-r1"
    for name in ("prices.json", "params.json"):
        (directory / name).write_text("{}")
    config = {
        "encryption_key": "fixture-encryption-key-32-bytes-only",
        "client": {"enforce_auth_on_inference": True, "disable_content_logging": True, "enable_logging": False},
        "config_store": {"enabled": True, "type": "sqlite", "config": {"path": str(directory / "config.db")}},
        "framework": {"pricing": {"pricing_url": (directory / "prices.json").as_uri(), "model_parameters_url": (directory / "params.json").as_uri(), "live_models_sync_interval": 0, "mcp_library_sync_interval": 0}},
        "governance": {"auth_config": {"is_enabled": True, "admin_username": "fixture-admin", "admin_password": "fixture-password", "disable_auth_on_inference": False}},
        "providers": {provider: {"network_config": {"base_url": body["endpoint_url"], "max_retries": 0}, "custom_provider_config": {"base_provider_type": "openai", "is_key_less": False, "allowed_requests": {"chat_completion": True}}, "keys": [{"id": key_id, "name": key_name, "value": body["api_key"], "models": ["previous-deployment"], "weight": 1, "enabled": True}]}},
    }
    config_path = directory / "config.json"
    config_path.write_text(json.dumps(config)); config_path.chmod(0o600)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
    log = directory / "native.log"
    with log.open("wb") as output:
        log.chmod(0o600)
        process = await asyncio.create_subprocess_exec(binary, "-host", "127.0.0.1", "-port", str(port), "-app-dir", str(directory), "-log-level", "error", stdout=output, stderr=output, env={"PATH": os.environ["PATH"], "TUNNEX_AI_LITELLM_URL": str(bridge.make_url("/")).rstrip("/"), "TUNNEX_AI_LITELLM_ADMIN_TOKEN": "admin-foundry-fixture"})
    origin = f"http://127.0.0.1:{port}"
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as client:
            for _ in range(100):
                try:
                    async with client.get(origin + "/health") as r:
                        if r.status == 200:
                            break
                except aiohttp.ClientError:
                    pass
                assert process.returncode is None, "native fixture exited; private log retained"
                await asyncio.sleep(.1)
            else:
                raise AssertionError("native fixture readiness timed out")
            path = origin + f"/api/providers/{provider}/keys/{key_id}"
            headers = {"Authorization": aiohttp.encode_basic_auth("fixture-admin", "fixture-password")}
            async with client.get(path, headers=headers) as r:
                assert r.status == 200
                before = await r.json()
            assert body["api_key"] not in json.dumps(before)
            probe = {"provider": "azure_foundry", "model": body["model"], "mode": "chat", "key_name": key_name, "endpoint_url": body["endpoint_url"]}
            for payload, authenticated, status in [
                (probe, False, 401),
                ({**probe, "key_name": key_id + "-r2"}, True, 409),
                ({**probe, "endpoint_url": "https://other.services.ai.azure.com/openai"}, True, 409),
                ({**probe, "api_key": "injected"}, True, 400),
                ({**probe, "model": "*"}, True, 400),
                ({**probe, "mode": "chat|completion"}, True, 400),
            ]:
                async with client.post(path + "/test-connection", json=payload, headers=headers if authenticated else {}) as r:
                    assert r.status == status
                    assert body["api_key"] not in await r.text()
            async with client.post(path + "/test-connection", json=probe, headers=headers) as r:
                assert r.status == 200
                result = await r.json()
            async with client.get(path, headers=headers) as r:
                assert await r.json() == before, "test changed saved key or serving model scope"
            assert before["models"] == ["previous-deployment"]
            assert body["api_key"] not in json.dumps(result)
            return result
    finally:
        if process.returncode is None:
            process.send_signal(signal.SIGINT)
            try:
                await asyncio.wait_for(process.wait(), 5)
            except TimeoutError:
                process.kill(); await process.wait()
