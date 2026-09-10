import asyncio
import json
import sys
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

sys.path.insert(0, str(Path(__file__).parents[1]))
from bridge import Settings, create_app
from diagnostics import ProbeFailure, sanitized


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,code", [("provider", 401), ("provider", 403), ("provider", 404), ("provider", 429), ("provider", 503), ("proxy", 403), ("proxy", 502), ("socket", None), ("body", 200), ("body", 403), ("invalid", 200), ("json", 200), ("encoding", 200)])
async def test_actual_sdk_failure_code_survives_without_secret_text(kind, code):
    async def upstream(request):
        if kind == "body":
            response = web.StreamResponse(status=code, headers={"Content-Type": "application/json", "Content-Length": "1024"})
            await response.prepare(request)
            await response.write(b'{"PRIVATE-RESPONSE-KEY-MARKER":')
            request.transport.close()
            return response
        if kind == "invalid":
            return web.json_response({"id": "fixture", "choices": [{"index": 0, "finish_reason": "content_filter", "message": {"role": "assistant", "content": "PRIVATE-RESPONSE-KEY-MARKER"}}]})
        if kind == "json":
            return web.Response(text="PRIVATE malformed JSON", content_type="application/json")
        if kind == "encoding":
            return web.Response(body=b"PRIVATE", headers={"Content-Encoding": "gzip"})
        return web.json_response({"error": {"message": "PRIVATE-RESPONSE-KEY-MARKER", "type": "permission_error"}}, status=code or 500)
    app = web.Application()
    app.router.add_post("/v1/chat/completions", upstream)
    async with TestServer(app) as target:
        async def connect(reader, writer):
            try:
                await reader.readuntil(b"\r\n\r\n")
                if kind == "proxy":
                    writer.write(f"HTTP/1.1 {code} Refused\r\nContent-Length: 0\r\n\r\n".encode())
                    await writer.drain()
                    return
                ur, uw = await asyncio.open_connection("127.0.0.1", target.port)
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                async def copy(source, dest):
                    try:
                        while chunk := await source.read(8192):
                            dest.write(chunk)
                            await dest.drain()
                    finally:
                        dest.close()
                await asyncio.gather(copy(reader, uw), copy(ur, writer))
            finally:
                writer.close()
        proxy = await asyncio.start_server(connect, "127.0.0.1", 0)
        port = proxy.sockets[0].getsockname()[1]
        if kind == "socket":
            proxy.close()
            await proxy.wait_closed()
        endpoint = str(target.make_url("")).rstrip("/")
        settings = Settings("admin-fixture-secret", endpoints={endpoint: "custom"}, proxy=f"http://user:pass@127.0.0.1:{port}")
        try:
            async with TestClient(TestServer(create_app(settings))) as client:
                response = await client.post("/test-connection", headers={"Authorization": "Bearer admin-fixture-secret"}, json={"provider": "custom", "model": "fixture", "api_key": "PRIVATE-REQUEST-KEY-MARKER", "endpoint_url": endpoint})
                result = await response.json()
                assert response.status == 200 and result["status"] == "error"
                expected = {"kind": "network_error", "source": "proxy"} if kind == "socket" else {"kind": "invalid_response", "source": "provider"} if code == 200 else {"kind": "http_error", "source": "provider" if kind == "body" else kind, "http_status": code}
                assert result["failure"] == expected, result
                assert "PRIVATE" not in json.dumps(result)
        finally:
            proxy.close()
            await proxy.wait_closed()


@pytest.mark.asyncio
async def test_deadline_has_no_fabricated_http_status():
    async def expired(_):
        raise TimeoutError("PRIVATE-ENDPOINT-KEY")
    async with TestClient(TestServer(create_app(Settings("admin-fixture-secret"), expired))) as client:
        response = await client.post("/test-connection", headers={"Authorization": "Bearer admin-fixture-secret"}, json={"provider": "openai", "model": "openai/test", "api_key": "PRIVATE-KEY"})
        result = await response.json()
        assert result["failure"] == {"kind": "timeout", "source": "gateway"}
        assert "PRIVATE" not in json.dumps(result)


@pytest.mark.parametrize("value", [
    {"kind": "PRIVATE", "source": "provider"},
    {"kind": "http_error", "source": "PRIVATE", "http_status": 403},
    {"kind": "http_error", "source": "provider", "http_status": "403"},
    {"kind": "http_error", "source": "provider", "http_status": 200},
    {"kind": "network_error", "source": "provider", "http_status": 502},
])
def test_reject_malformed_diagnostics(value):
    assert sanitized(value) is None
    assert ProbeFailure(value).failure == {"kind": "unknown", "source": "gateway"}


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [
    {"kind": "http_error", "source": "provider", "http_status": 403},
    {"kind": "network_error", "source": "proxy"},
    {"kind": "timeout", "source": "provider"},
    None,
])
async def test_real_saved_engine_preserves_sanitized_failure(tmp_path, failure):
    from native_saved_probe import saved_probe
    calls = []
    async def failed(request):
        assert request.headers["Authorization"] == "Bearer admin-foundry-fixture"
        body = await request.json()
        assert body["api_key"] == "PRIVATE-KEY-MARKER"
        calls.append(body["model"])
        if failure is None:
            await asyncio.sleep(11)
            return web.json_response({"status": "success", "duration_ms": 11000})
        return web.json_response({"status": "error", "duration_ms": 1, "failure": {**failure, "message": "PRIVATE-KEY-MARKER"}, "error": "PRIVATE-KEY-MARKER"})
    app = web.Application()
    app.router.add_post("/test-connection", failed)
    async with TestClient(TestServer(app)) as client:
        result = await saved_probe(client, {"endpoint_url": "https://fixture.services.ai.azure.com/anthropic", "model": "claude-fixture", "api_key": "PRIVATE-KEY-MARKER"}, tmp_path / "native")
        if failure is None:
            assert result["status"] == "error" and 9000 <= result["duration_ms"] < 11000
            assert result["failure"] == {"kind": "timeout", "source": "gateway"}
        else:
            assert result == {"status": "error", "duration_ms": 1, "failure": failure}
        assert calls == ["claude-fixture"]


@pytest.mark.asyncio
async def test_connect_timeout_is_proxy_without_http_response():
    import httpcore
    from diagnostics import capture
    from transport import ConnectBackend
    class Stream:
        closed = False
        async def write(self, *args, **kwargs): pass
        async def read(self, *args, **kwargs): raise httpcore.ReadTimeout("PRIVATE")
        async def aclose(self): self.closed = True
    stream = Stream()
    class Backend:
        async def connect_tcp(self, *args, **kwargs): return stream
    transport = ConnectBackend("http://user:pass@proxy:8190")
    transport.backend = Backend()
    state = {}
    token = capture.set(state)
    try:
        with pytest.raises(httpcore.ReadTimeout):
            await transport.connect_tcp("private-endpoint", 443, timeout=.01)
        assert state == {"failure": {"kind": "timeout", "source": "proxy"}}
        assert stream.closed
    finally:
        capture.reset(token)
