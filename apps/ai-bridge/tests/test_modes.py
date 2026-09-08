"""Actual pinned SDK dispatch through the production bounded transport."""

import json
import logging
import os
import socket
import sys
from pathlib import Path

import httpx
import pytest
from aiohttp.test_utils import TestClient, TestServer

sys.path.insert(0, str(Path(__file__).parents[1]))
os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "true"
from bridge import Settings, create_app
from worker import MODES, invoke, tiny_audio, validate_preflight
import transport

RESPONSES = {
    "chat": {"id": "test", "object": "chat.completion", "model": "fixture", "choices": [{"index": 0, "message": {"role": "assistant", "content": "OK"}, "finish_reason": "stop"}]},
    "completion": {"id": "test", "object": "text_completion", "model": "fixture", "choices": [{"index": 0, "text": "OK", "finish_reason": "stop"}]},
    "embedding": {"object": "list", "model": "fixture", "data": [{"index": 0, "object": "embedding", "embedding": [0.1, 0.2]}], "usage": {"prompt_tokens": 1, "total_tokens": 1}},
    "audio_transcription": {"text": ""},
    "image_generation": {"created": 1, "data": [{"url": "https://unfetched.example/image.png"}]},
    "video_generation": {"id": "video_fixture", "object": "video", "status": "queued", "model": "fixture", "created_at": 1},
    "rerank": {"id": "test", "results": [{"index": 0, "relevance_score": 0.8}]},
}
PATHS = {"chat": "/chat/completions", "completion": "/completions", "embedding": "/embeddings", "audio_speech": "/audio/speech", "audio_transcription": "/audio/transcriptions", "image_generation": "/images/generations", "video_generation": "/videos", "rerank": "/rerank"}


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", sorted(MODES))
async def test_actual_sdk_modes_bounded_transport(mode, monkeypatch):
    logging.disable(logging.CRITICAL)
    def deny_network(*args, **kwargs):
        raise AssertionError("unexpected network access")
    monkeypatch.setattr(socket, "getaddrinfo", deny_network)
    for name in ("OPENAI_API_KEY", "COHERE_API_KEY", "LITELLM_PROXY_API_KEY"):
        monkeypatch.setenv(name, "ambient-key-must-not-be-used")
    arrivals = []
    async def answer(request):
        body = await request.aread()
        arrivals.append((request, body))
        assert request.method == "POST"
        assert str(request.url) == "https://model.example/api/v1" + PATHS[mode]
        assert request.headers["authorization"] == "Bearer fixture-secret"
        assert request.headers["accept-encoding"] == "identity"
        if mode == "audio_speech":
            with tiny_audio() as audio:
                return httpx.Response(200, content=audio.read(), headers={"Content-Type": "audio/wav"})
        return httpx.Response(200, json=RESPONSES[mode])
    original = transport.LockedTransport.__init__
    def mocked(self, origins, proxy=None):
        assert proxy == "http://user:pass@proxy.example:8190"
        original(self, origins, proxy)
        self.transport = httpx.MockTransport(answer)
    monkeypatch.setattr(transport.LockedTransport, "__init__", mocked)
    result = await invoke({"mode": mode, "provider": "custom", "model": "openai/fixture", "api_key": "fixture-secret", "endpoint": "https://model.example/api", "proxy": "http://user:pass@proxy.example:8190", "messages": [{"role": "user", "content": "Reply OK."}], "max_tokens": 16, "stream": False})
    validate_preflight(mode, result)
    assert len(arrivals) == 1  # No media fetching, polling, or retry.
    request, body = arrivals[0]
    if mode in {"audio_transcription", "video_generation"}:
        assert b'filename="connection-test.wav"' in body if mode == "audio_transcription" else b"fixture" in body
        assert b"max_tokens" not in body and b"max_completion_tokens" not in body
    else:
        data = json.loads(body)
        assert data["model"] == "fixture"
        if mode in {"chat", "completion"}:
            assert data["max_tokens"] == 16
        else:
            assert "max_tokens" not in data and "max_completion_tokens" not in data
    assert "fixture-secret" not in json.dumps(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,body", [
    ("audio_speech", b"<html>success</html>"),
    ("embedding", {"data": [{"embedding": []}]}),
    ("image_generation", {"data": []}),
    ("video_generation", {"id": "video_fixture", "object": "video", "status": "failed"}),
    ("rerank", {"results": []}),
])
async def test_sdk_200_invalid_output_refused(mode, body, monkeypatch):
    arrivals = []
    async def answer(request):
        arrivals.append(request)
        return httpx.Response(200, content=body) if isinstance(body, bytes) else httpx.Response(200, json=body)
    original = transport.LockedTransport.__init__
    def mocked(self, origins, proxy=None):
        original(self, origins, proxy)
        self.transport = httpx.MockTransport(answer)
    monkeypatch.setattr(transport.LockedTransport, "__init__", mocked)
    with pytest.raises(Exception):
        await invoke({"mode": mode, "provider": "custom", "model": "openai/fixture", "api_key": "fixture-secret", "endpoint": "https://model.example/api", "proxy": "http://user:pass@proxy.example:8190", "stream": False})
    assert len(arrivals) == 1


@pytest.mark.parametrize("mode", sorted(MODES))
def test_wrong_protocol_is_not_success(mode):
    with pytest.raises(ValueError):
        validate_preflight(mode, {"status": "ok"})
    if mode != "chat":
        with pytest.raises(ValueError):
            validate_preflight(mode, RESPONSES["chat"])


@pytest.mark.asyncio
async def test_mode_default_validation_and_sanitized_status():
    calls = []
    async def call(payload):
        calls.append(payload)
        if payload["mode"] == "audio_speech":
            return {"audio_bytes": 100}
        return RESPONSES[payload["mode"]]
    headers = {"Authorization": "Bearer admin-fixture-secret"}
    draft = {"provider": "openai", "model": "openai/fixture", "api_key": "fixture-secret"}
    async with TestClient(TestServer(create_app(Settings("admin-fixture-secret"), call))) as client:
        for mode in (None, True, [], "unknown", 1):
            response = await client.post("/test-connection", json={**draft, "mode": mode}, headers=headers)
            assert (await response.json())["status"] == "error"
        assert not calls
        response = await client.post("/test-connection", json=draft, headers=headers)
        assert (await response.json())["status"] == "success" and calls[-1]["mode"] == "chat"
        for mode in sorted(MODES):
            response = await client.post("/test-connection", json={**draft, "mode": mode}, headers=headers)
            result = await response.json()
            assert result["status"] == "success" and set(result) == {"status", "duration_ms"}
            assert calls[-1]["mode"] == mode
            if mode not in {"chat", "completion"}:
                assert "max_tokens" not in calls[-1] and "max_completion_tokens" not in calls[-1]
        count = len(calls)
        response = await client.post("/test-connection", json={**draft, "provider": "sagemaker", "model": "endpoint", "mode": "embedding", "endpoint_url": "https://bridge.example"}, headers=headers)
        assert (await response.json())["status"] == "error" and len(calls) == count


@pytest.mark.asyncio
async def test_catalog_accepts_mode_without_claiming_model_capability():
    calls = []
    async def call(payload):
        calls.append(payload)
        return {"items": [{"id": "deployment", "name": "deployment"}], "total": 1, "limit": 50, "offset": 0}
    settings = Settings("admin-fixture-secret", public_https=True, proxy="http://user:pass@proxy.example:8190")
    headers = {"Authorization": "Bearer admin-fixture-secret"}
    draft = {"provider": "custom", "endpoint_url": "https://model.example/api", "api_key": "fixture-secret"}
    async with TestClient(TestServer(create_app(settings, call))) as client:
        for mode in (None, True, [], "invalid"):
            response = await client.post("/model-catalog", json={**draft, "mode": mode}, headers=headers)
            assert response.status == 400 and not calls
        for mode in sorted(MODES):
            response = await client.post("/model-catalog", json={**draft, "mode": mode}, headers=headers)
            assert response.status == 200
            assert (await response.json())["items"] == [{"id": "deployment", "name": "deployment"}]
            assert "mode" not in calls[-1]  # /models has names, not operation qualification.
