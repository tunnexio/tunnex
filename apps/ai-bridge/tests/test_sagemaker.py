import json
import struct
import sys
import zlib
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))
import worker
import transport


def event(payload):
    headers = b""
    for name, value in [
        (":message-type", "event"),
        (":event-type", "PayloadPart"),
        (":content-type", "application/octet-stream"),
    ]:
        n = name.encode()
        v = value.encode()
        headers += bytes([len(n)]) + n + b"\x07" + struct.pack("!H", len(v)) + v
    data = json.dumps(payload).encode()
    prelude = struct.pack("!II", 16 + len(headers) + len(data), len(headers))
    message = prelude + struct.pack("!I", zlib.crc32(prelude)) + headers + data
    return message + struct.pack("!I", zlib.crc32(message))


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [False, True])
async def test_actual_sdk_sagemaker_signed_protocol(monkeypatch, stream):
    arrivals = []

    async def answer(request):
        arrivals.append(request)
        assert request.url.host == "runtime.sagemaker.ap-south-1.amazonaws.com"
        assert "/ap-south-1/sagemaker/aws4_request" in request.headers["authorization"]
        assert "Credential=FIXTUREKEY/" in request.headers["authorization"]
        assert request.headers["x-amz-security-token"] == "fixture-session"
        assert request.url.path == "/endpoints/private-endpoint/" + (
            "invocations-response-stream" if stream else "invocations"
        )
        body = json.loads(request.content)
        assert body["messages"][0]["content"] == "Reply OK."
        if stream:
            chunks = [
                {
                    "id": "fixture",
                    "object": "chat.completion.chunk",
                    "created": 1,
                    "choices": [
                        {"index": 0, "delta": {"content": "OK"}, "finish_reason": None}
                    ],
                },
                {
                    "id": "fixture",
                    "object": "chat.completion.chunk",
                    "created": 1,
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                },
            ]
            return httpx.Response(
                200,
                content=b"".join(event(c) for c in chunks),
                headers={"content-type": "application/vnd.amazon.eventstream"},
            )
        return httpx.Response(
            200,
            json={
                "id": "fixture",
                "object": "chat.completion",
                "model": "private-endpoint",
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
            },
        )

    def locked(origins, proxy=None):
        assert (
            origins == [("https", "runtime.sagemaker.ap-south-1.amazonaws.com", 443)]
            and proxy is None
        )
        return httpx.MockTransport(answer)

    monkeypatch.setattr(transport, "LockedTransport", locked)
    result = await worker.invoke(
        {
            "provider": "sagemaker",
            "alias": "public-alias",
            "binding": {
                "model": "sagemaker_chat/private-endpoint",
                "aws_region_name": "ap-south-1",
                "aws_access_key_id": "FIXTUREKEY",
                "aws_secret_access_key": "fixture-secret-key",
                "aws_session_token": "fixture-session",
            },
            "messages": [{"role": "user", "content": "Reply OK."}],
            "max_tokens": 16,
            "stream": stream,
        }
    )
    assert len(arrivals) == 1
    if stream:
        assert any(
            c["choices"][0]["delta"].get("content") == "OK" for c in result["chunks"]
        )
        assert any(
            c["choices"][0].get("finish_reason") == "stop" for c in result["chunks"]
        )
        assert all(c["model"] == "public-alias" for c in result["chunks"])
    else:
        assert (
            result["model"] == "public-alias"
            and result["choices"][0]["message"]["content"] == "OK"
        )


def test_explicit_role_does_not_fallback(monkeypatch):
    import boto3

    calls = []

    class STS:
        def assume_role(self, **kw):
            calls.append(kw)
            raise RuntimeError("AccessDenied")

        def close(self):
            pass

    def client(service, **kw):
        assert (
            service == "sts"
            and kw["endpoint_url"] == "https://sts.ap-south-1.amazonaws.com"
        )
        assert (
            kw["aws_access_key_id"] == "fixture"
            and kw["config"].proxies == {}
            and kw["config"].retries == {"total_max_attempts": 1}
        )
        return STS()

    monkeypatch.setattr(boto3, "client", client)
    with pytest.raises(RuntimeError):
        worker.resolve_binding(
            {
                "aws_region_name": "ap-south-1",
                "aws_access_key_id": "fixture",
                "aws_secret_access_key": "secret",
                "aws_role_name": "role",
                "aws_session_name": "session",
            }
        )
    assert len(calls) == 1
