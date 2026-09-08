"""Foundry OpenAI v1 preflight: strict endpoint scope and actual SDK transport."""

import asyncio
import json
import ssl
import subprocess
import sys
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

sys.path.insert(0, str(Path(__file__).parents[1]))
from bridge import Settings, create_app, foundry_endpoint, sdk_call


ENDPOINT = "https://team-resource.services.ai.azure.com/openai"
ADMIN = "admin-foundry-fixture"
KEY = "synthetic-foundry-key"
DEPLOYMENT = "team-deployment-not-catalog-name"


def request_body(endpoint=ENDPOINT):
    return {
        "provider": "azure_foundry",
        "endpoint_url": endpoint,
        "model": DEPLOYMENT,
        "api_key": KEY,
    }


@pytest.mark.parametrize("suffix", ["openai.azure.com", "services.ai.azure.com", "cognitiveservices.azure.com"])
def test_foundry_canonical_endpoint(suffix):
    assert foundry_endpoint(f"https://TEAM-RESOURCE.{suffix}:443/openai/") == (
        f"https://team-resource.{suffix}/openai"
    )


@pytest.mark.parametrize("endpoint", [
    "http://team-resource.services.ai.azure.com/openai",
    "https://team-resource.services.ai.azure.com:8443/openai",
    "https://team-resource.services.ai.azure.com/models",
    "https://team-resource.services.ai.azure.com/openai/v1",
    "https://team-resource.services.ai.azure.com/openai/deployments/a",
    "https://team-resource.services.ai.azure.com/openai?api-version=2024-10-21",
    "https://team-resource.services.ai.azure.com/openai#fragment",
    "https://team-resource.services.ai.azure.com/openai/%2e%2e",
    "https://team-resource.services.ai.azure.com/openai/../models",
    "https://key@team-resource.services.ai.azure.com/openai",
    "https://team-resource.services.ai.azure.com.attacker.test/openai",
    "https://one.two.services.ai.azure.com/openai",
    "https://services.ai.azure.com/openai",
    "https://team-resource.openai.azure.us/openai",
    "https://127.0.0.1/openai",
    "https://[::1]/openai",
    "https://team-resource.services.ai.azure.com./openai",
    "https://-bad.services.ai.azure.com/openai",
    "https://bad-.services.ai.azure.com/openai",
])
def test_foundry_refuses_non_v1_resource_endpoints(endpoint):
    with pytest.raises(ValueError):
        foundry_endpoint(endpoint)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,proxy,endpoint", [
    ("custom", "http://user:pass@egress:8190", ENDPOINT),
    ("sagemaker", "http://user:pass@egress:8190", ENDPOINT),
    ("azure_foundry", None, ENDPOINT),
    ("azure_foundry", "http://user:pass@egress:8190", "https://other.services.ai.azure.com/openai"),
    ("azure_foundry", "http://user:pass@egress:8190", "http://team-resource.services.ai.azure.com/openai"),
])
async def test_foundry_refuses_scope_mismatch_before_worker(kind, proxy, endpoint):
    calls = []

    async def denied(payload):
        calls.append(payload)
        raise AssertionError("unapproved inference")

    settings = Settings(ADMIN, endpoints={ENDPOINT: kind}, proxy=proxy)
    async with TestClient(TestServer(create_app(settings, denied))) as client:
        response = await client.post(
            "/test-connection", json=request_body(endpoint),
            headers={"Authorization": "Bearer " + ADMIN},
        )
        result = await response.json()
        assert result["status"] == "error"
        assert set(result) == {"status", "duration_ms"}
        assert not calls


def test_foundry_policy_load_and_invalid_classification(tmp_path, monkeypatch):
    path = tmp_path / "policy.json"
    monkeypatch.delenv("TUNNEX_AI_BRIDGE_CONFIG_FILE", raising=False)
    monkeypatch.setenv("TUNNEX_AI_BRIDGE_ADMIN_TOKEN", ADMIN)
    monkeypatch.setenv("TUNNEX_AI_CUSTOM_ENDPOINTS_FILE", str(path))
    monkeypatch.setenv("TUNNEX_AI_CUSTOM_PROXY_URL", "http://user:pass@egress:8190")
    path.write_text(json.dumps({"endpoints": [{"url": ENDPOINT, "provider": "azure_foundry"}]}))
    assert Settings.load().endpoints == {ENDPOINT: "azure_foundry"}
    path.write_text(json.dumps({"endpoints": [{"url": "https://not-azure.test/openai", "provider": "azure_foundry"}]}))
    with pytest.raises(ValueError):
        Settings.load()


@pytest.mark.asyncio
@pytest.mark.parametrize("suffix", ["openai.azure.com", "services.ai.azure.com", "cognitiveservices.azure.com"])
@pytest.mark.parametrize("operation, deployment", [("preflight", "gpt-5"), ("preflight", "Llama-3.3-70B-Instruct"), ("preflight", "deepseek-r1"), ("catalog", DEPLOYMENT)])
async def test_foundry_actual_sdk_v1_through_authenticated_proxy(suffix, operation, deployment, tmp_path, monkeypatch):
    host = "team-resource." + suffix
    endpoint = "https://" + host + "/openai"
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-days", "1",
        "-subj", "/CN=" + host, "-addext", "subjectAltName=DNS:" + host,
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    arrivals, tunnels, errors = [], [], []

    async def upstream(request):
        data = await request.json() if request.method == "POST" else None
        arrivals.append({"path": request.path_qs, "headers": dict(request.headers), "data": data})
        if operation == "catalog":
            assert request.method == "GET"
            return web.json_response({"data": [{"id": DEPLOYMENT, "name": "private metadata"}]})
        return web.json_response({
            "id": "synthetic-foundry-response", "object": "chat.completion",
            "model": DEPLOYMENT,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "PRIVATE-REPLY"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        })

    app = web.Application()
    app.router.add_route("*", "/{path:.*}", upstream)
    server = TestServer(app)
    await server.start_server(ssl=context)
    async with server:
        async def connect(reader, writer):
            try:
                headers = await reader.readuntil(b"\r\n\r\n")
                assert b"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n" in headers
                assert headers.split(b"\r\n")[0] == f"CONNECT {host}:443 HTTP/1.1".encode()
                tunnels.append(host)
                # The apparent Azure hostname never resolves or leaves this host.
                ur, uw = await asyncio.open_connection("127.0.0.1", server.port)
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()

                async def copy(source, destination):
                    try:
                        while chunk := await source.read(8192):
                            destination.write(chunk)
                            await destination.drain()
                    finally:
                        destination.close()

                await asyncio.gather(copy(reader, uw), copy(ur, writer))
            except Exception as error:
                errors.append(type(error).__name__)
                writer.close()

        proxy = await asyncio.start_server(connect, "127.0.0.1", 0)
        try:
            proxy_port = proxy.sockets[0].getsockname()[1]
            settings = Settings(
                ADMIN, public_https=True,
                proxy=f"http://user:pass@127.0.0.1:{proxy_port}",
            )
            async with TestClient(TestServer(create_app(settings, sdk_call))) as client:
                body = request_body(endpoint)
                body["model"] = deployment
                if operation == "catalog":
                    body.pop("model")
                response = await client.post(
                    "/model-catalog" if operation == "catalog" else "/test-connection", json=body,
                    headers={"Authorization": "Bearer " + ADMIN},
                )
                result = await response.json()
                if operation == "catalog":
                    assert result == {"items": [{"id": DEPLOYMENT, "name": DEPLOYMENT}], "total": 1, "limit": 50, "offset": 0}, (result, errors)
                else:
                    assert result["status"] == "success", (result, errors)
                    assert set(result) == {"status", "duration_ms"}
                assert KEY not in json.dumps(result) and "PRIVATE-REPLY" not in json.dumps(result)
            assert len(arrivals) == 1 and tunnels == [host] and not errors
            arrival = arrivals[0]
            assert arrival["path"] == "/openai/v1/" + ("models" if operation == "catalog" else "chat/completions")
            assert arrival["headers"]["Authorization"] == "Bearer " + KEY
            assert "api-key" not in {k.lower() for k in arrival["headers"]}
            if operation == "preflight":
                assert arrival["data"]["model"] == deployment
                token_field = "max_completion_tokens" if deployment == "gpt-5" else "max_tokens"
                assert arrival["data"][token_field] == 16
                assert ("max_tokens" if token_field == "max_completion_tokens" else "max_completion_tokens") not in arrival["data"]
                # LiteLLM omits the default false value on the OpenAI wire request.
                assert arrival["data"].get("stream", False) is False
        finally:
            proxy.close()
            await proxy.wait_closed()
