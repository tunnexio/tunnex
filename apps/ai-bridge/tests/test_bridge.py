import asyncio
import json
import sys
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

sys.path.insert(0, str(Path(__file__).parents[1]))
from bridge import Settings, create_app, sdk_call


@pytest.mark.asyncio
async def test_scope_and_sanitized_preflight():
    calls = []

    async def fake(payload, timeout=10):
        calls.append(payload)
        return {
            "choices": [
                {
                    "message": {"role": "assistant", "content": "OK"},
                    "finish_reason": "stop",
                }
            ]
        }

    settings = Settings(
        "admin-fixture-secret",
        {
            "endpoint-alias": {
                "model": "sagemaker_chat/test",
                "aws_region_name": "ap-south-1",
            }
        },
        [("client-fixture-secret", frozenset({"endpoint-alias"}))],
        {"http://bridge:8200": "sagemaker"},
    )
    async with TestClient(TestServer(create_app(settings, fake))) as client:
        response = await client.post(
            "/test-connection", json={"api_key": "do-not-return"}
        )
        assert response.status == 401 and not calls
        response = await client.post(
            "/test-connection",
            headers={"Authorization": "Bearer admin-fixture-secret"},
            json={
                "provider": "openai",
                "model": "openai/gpt-4o-mini",
                "api_key": "fixture-secret",
            },
        )
        data = await response.json()
        assert data["status"] == "success" and set(data) == {"status", "duration_ms"}
        assert calls[0]["max_tokens"] == 16 and calls[0]["messages"] == [
            {"role": "user", "content": "Reply OK."}
        ]
        response = await client.post(
            "/test-connection",
            headers={"Authorization": "Bearer admin-fixture-secret"},
            json={
                "provider": "sagemaker",
                "model": "foreign-alias",
                "api_key": "client-fixture-secret",
                "endpoint_url": "http://bridge:8200",
            },
        )
        assert (await response.json())["status"] == "error" and len(calls) == 1
        response = await client.get(
            "/v1/models", headers={"Authorization": "Bearer client-fixture-secret"}
        )
        assert [m["id"] for m in (await response.json())["data"]] == ["endpoint-alias"]
        response = await client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer client-fixture-secret"},
            json={"model": "foreign-alias", "messages": []},
        )
        assert response.status != 200 and len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("tls", [False, True])
async def test_actual_sdk_custom_connect(tls, tmp_path, monkeypatch):
    arrivals = []
    tunnels = []

    async def upstream(request):
        assert request.headers.get("Authorization") == "Bearer synthetic-secret"
        payload = await request.json()
        arrivals.append(payload)
        return web.json_response(
            {
                "id": "fixture",
                "object": "chat.completion",
                "model": "fixture",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "OK"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 1,
                    "completion_tokens": 1,
                    "total_tokens": 2,
                },
            }
        )

    app = web.Application()
    app.router.add_post("/v1/chat/completions", upstream)
    options = {}
    if tls:
        import ssl, subprocess

        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "1",
                "-subj",
                "/CN=127.0.0.1",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        options["ssl"] = context
        monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    server = TestServer(app)
    await server.start_server(**options)
    async with server:

        async def connect(reader, writer):
            try:
                headers = await reader.readuntil(b"\r\n\r\n")
                assert b"Proxy-Authorization: Basic dXNlcjpwYXNz" in headers
                authority = headers.split(b" ")[1].decode()
                assert authority == f"127.0.0.1:{server.port}"
                tunnels.append(authority)
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
            except Exception:
                writer.close()

        proxy = await asyncio.start_server(connect, "127.0.0.1", 0)
        try:
            port = proxy.sockets[0].getsockname()[1]
            result = await sdk_call(
                {
                    "provider": "custom",
                    "model": "openai/fixture",
                    "api_key": "synthetic-secret",
                    "endpoint": str(server.make_url("")).rstrip("/"),
                    "proxy": f"http://user:pass@127.0.0.1:{port}",
                    "messages": [{"role": "user", "content": "Reply OK."}],
                    "max_tokens": 16,
                    "stream": False,
                }
            )
            assert result["choices"][0]["message"]["content"] == "OK"
            assert len(arrivals) == 1 and tunnels
        finally:
            proxy.close()
            await proxy.wait_closed()


@pytest.mark.asyncio
async def test_sagemaker_preflight_uses_selected_endpoint_and_key():
    calls = []

    async def fake(payload, timeout=10):
        calls.append(payload)
        return {"choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}]}

    settings = Settings(
        "admin-fixture-secret",
        endpoints={"https://chosen.internal": "sagemaker"},
        proxy="http://user:pass@egress:8190",
    )
    async with TestClient(TestServer(create_app(settings, fake))) as client:
        response = await client.post(
            "/test-connection",
            headers={"Authorization": "Bearer admin-fixture-secret"},
            json={
                "provider": "sagemaker",
                "model": "chosen-alias",
                "api_key": "scoped-client-fixture-secret",
                "endpoint_url": "https://chosen.internal",
            },
        )
        assert (await response.json())["status"] == "success"
        assert (
            calls[0]["provider"] == "custom"
            and calls[0]["endpoint"] == "https://chosen.internal"
            and calls[0]["api_key"] == "scoped-client-fixture-secret"
            and calls[0]["model"] == "openai/chosen-alias"
            and calls[0]["proxy"] == settings.proxy
        )


@pytest.mark.asyncio
async def test_streaming_keeps_scope_alias_and_parameters():
    calls = []

    async def stream(payload):
        calls.append(payload)
        yield {
            "model": "private-endpoint",
            "choices": [
                {"index": 0, "delta": {"content": "OK"}, "finish_reason": None}
            ],
        }
        yield {
            "model": "private-endpoint",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        }

    settings = Settings(
        "admin-fixture-secret",
        {"alias": {"model": "sagemaker_chat/private-endpoint"}},
        [("client-fixture-secret", frozenset({"alias"}))],
    )
    async with TestClient(
        TestServer(create_app(settings, stream_call=stream))
    ) as client:
        response = await client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer client-fixture-secret"},
            json={
                "model": "alias",
                "messages": [{"role": "user", "content": "OK"}],
                "stream": True,
                "temperature": 0.5,
                "stream_options": {"include_usage": True},
            },
        )
        text = await response.text()
        assert (
            response.status == 200
            and text.endswith("data: [DONE]\n\n")
            and "private-endpoint" not in text
            and '"model": "alias"' in text
        )
        assert calls[0]["temperature"] == 0.5 and calls[0]["stream_options"] == {
            "include_usage": True
        }


@pytest.mark.asyncio
async def test_non_ascii_bearer_is_unauthorized():
    settings = Settings("admin-fixture-secret", clients=[("client-fixture-secret", frozenset({"alias"}))])
    async with TestClient(TestServer(create_app(settings))) as client:
        for method, path in [("POST", "/test-connection"), ("GET", "/v1/models"), ("POST", "/v1/chat/completions")]:
            response = await client.request(method, path, headers={"Authorization": "Bearer invalid-é"})
            assert response.status == 401
            assert await response.json() == {"error": "unauthorized"}
