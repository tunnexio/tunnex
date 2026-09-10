"""Actual released LiteLLM SDK paths; every network destination is synthetic."""

import json
import logging
import os
import socket
import sys
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

sys.path.insert(0, str(Path(__file__).parents[1]))
os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "true"
from worker import invoke, ORIGINS


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", sorted(ORIGINS))
async def test_actual_sdk_standard_provider(provider, monkeypatch):
    logging.disable(logging.CRITICAL)
    real = socket.getaddrinfo

    def local_only(host, *args, **kwargs):
        if host not in {"127.0.0.1", "localhost", b"127.0.0.1"}:
            raise OSError("external fixture destination blocked")
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", local_only)
    arrivals = []

    async def reply(request):
        assert request.method == "POST"
        header = {"anthropic": "x-api-key", "gemini": "x-goog-api-key"}.get(
            provider, "Authorization"
        )
        expected = (
            "fixture-secret" if header != "Authorization" else "Bearer fixture-secret"
        )
        assert request.headers.get(header) == expected
        data = await request.json()
        arrivals.append(data)
        if provider == "anthropic":
            return web.json_response(
                {
                    "id": "msg_fixture",
                    "type": "message",
                    "role": "assistant",
                    "model": "fixture",
                    "content": [{"type": "text", "text": "OK"}],
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                }
            )
        if provider == "gemini":
            return web.json_response(
                {
                    "candidates": [
                        {
                            "content": {"role": "model", "parts": [{"text": "OK"}]},
                            "finishReason": "STOP",
                            "index": 0,
                        }
                    ],
                    "usageMetadata": {
                        "promptTokenCount": 1,
                        "candidatesTokenCount": 1,
                        "totalTokenCount": 2,
                    },
                }
            )
        return web.json_response(
            {
                "id": "fixture",
                "object": "chat.completion",
                "model": "fixture",
                "service_tier": "default",
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
    app.router.add_route("*", "/{path:.*}", reply)
    async with TestServer(app) as server:
        monkeypatch.setitem(ORIGINS, provider, str(server.make_url("")).rstrip("/"))
        result = await invoke(
            {
                "provider": provider,
                "model": provider + "/fixture",
                "api_key": "fixture-secret",
                "messages": [{"role": "user", "content": "Reply OK."}],
                "max_tokens": 16,
                "stream": False,
            }
        )
        assert (
            result["choices"][0]["message"]["content"] == "OK"
            and result["choices"][0]["finish_reason"] == "stop"
        )
        assert len(arrivals) == 1
