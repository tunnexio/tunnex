import asyncio
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))
import bridge


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["cancel", "timeout", "output"])
async def test_worker_reaped_for_all_termination_paths(monkeypatch, mode):
    original = asyncio.create_subprocess_exec
    children = []

    async def launch(*args, **kwargs):
        code = "import sys,time;sys.stdin.read();time.sleep(60)"
        if mode == "output":
            code = 'import sys,time;sys.stdin.read();sys.stdout.write("x"*1100000);sys.stdout.flush();time.sleep(60)'
        process = await original(sys.executable, "-c", code, **kwargs)
        children.append(process)
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", launch)
    task = asyncio.create_task(
        bridge.sdk_call({}, timeout=0.15 if mode == "timeout" else 5)
    )
    if mode == "cancel":
        while not children:
            await asyncio.sleep(0.001)
        await asyncio.sleep(0.02)
        task.cancel()
    with pytest.raises((asyncio.CancelledError, TimeoutError, ValueError)):
        await asyncio.wait_for(task, 2)
    assert len(children) == 1 and children[0].returncode is not None


def test_short_authentication_tokens_refused():
    with pytest.raises(ValueError):
        bridge.Settings("short")
    with pytest.raises(ValueError):
        bridge.Settings(
            "long-admin-fixture-token", clients=[("short", frozenset({"alias"}))]
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["json", "sse", "compressed"])
async def test_upstream_bound_before_sdk_parse(kind):
    import httpx
    from transport import LockedTransport

    closed = []

    class Body(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(20):
                yield b"x" * 65536

        async def aclose(self):
            closed.append(True)

    async def answer(request):
        assert request.headers["accept-encoding"] == "identity"
        headers = {
            "content-type": "text/event-stream" if kind == "sse" else "application/json"
        }
        if kind == "compressed":
            headers["content-encoding"] = "gzip"
        return httpx.Response(200, headers=headers, stream=Body())

    transport = LockedTransport([("https", "fixture.invalid", 443)])
    await transport.transport.aclose()
    transport.transport = httpx.MockTransport(answer)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(ValueError):
            await client.get("https://fixture.invalid/v1/chat/completions")
    assert closed


@pytest.mark.asyncio
async def test_refused_connect_never_reaches_target():
    import httpx
    from aiohttp import web
    from aiohttp.test_utils import TestServer
    from transport import LockedTransport

    arrivals = []
    connects = []

    async def target(request):
        arrivals.append(True)
        return web.json_response({})

    app = web.Application()
    app.router.add_get("/v1/models", target)
    async with TestServer(app) as server:

        async def refuse(reader, writer):
            connects.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(
                b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"
            )
            await writer.drain()
            writer.close()

        proxy = await asyncio.start_server(refuse, "127.0.0.1", 0)
        try:
            port = proxy.sockets[0].getsockname()[1]
            async with httpx.AsyncClient(
                transport=LockedTransport(
                    [("http", "127.0.0.1", server.port)],
                    f"http://fixture:wrong@127.0.0.1:{port}",
                )
            ) as client:
                with pytest.raises(ValueError):
                    await client.get(str(server.make_url("/v1/models")))
            assert len(connects) == 1 and not arrivals
        finally:
            proxy.close()
            await proxy.wait_closed()
