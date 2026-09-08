"""Draft model catalog authorization, payload bounds and sanitized worker output."""

import asyncio
import json
import sys
from pathlib import Path

import httpx
import pytest
from aiohttp.test_utils import TestClient, TestServer

sys.path.insert(0, str(Path(__file__).parents[1]))
from bridge import Settings, create_app
from worker import invoke
import transport

ADMIN = "catalog-fixture-admin-token"
KEY = "catalog-fixture-provider-secret"
ENDPOINT = "https://public-provider.test/api"
PROXY = "http://user:pass@proxy.test:8190"


def draft(**updates):
    return {"provider": "custom", "api_key": KEY, "endpoint_url": ENDPOINT, **updates}


def test_public_policy_opt_in_and_explicit_kind_precedence():
    disabled = Settings(ADMIN, proxy=PROXY)
    with pytest.raises(ValueError):
        disabled.endpoint("custom", ENDPOINT)
    enabled = Settings(ADMIN, public_https=True, proxy=PROXY)
    assert enabled.endpoint("custom", ENDPOINT) == ENDPOINT
    for provider, endpoint in [
        ("sagemaker", ENDPOINT), ("custom", "http://public-provider.test/api"),
        ("custom", "https://public-provider.test:8443/api"),
    ]:
        with pytest.raises(ValueError):
            enabled.endpoint(provider, endpoint)
    scoped = Settings(ADMIN, endpoints={ENDPOINT: "sagemaker"}, public_https=True, proxy=PROXY)
    with pytest.raises(ValueError):
        scoped.endpoint("custom", ENDPOINT)
    assert scoped.endpoint("sagemaker", ENDPOINT) == ENDPOINT
    for provider, endpoint in [
        ("custom", "https://public-provider.test/other"),
        ("custom", "https://PUBLIC-PROVIDER.test:443/other"),
        ("sagemaker", "https://public-provider.test/other"),
    ]:
        with pytest.raises(ValueError):
            scoped.endpoint(provider, endpoint)
    other_scheme = Settings(
        ADMIN, endpoints={"http://public-provider.test:443/api": "custom"},
        public_https=True, proxy=PROXY,
    )
    with pytest.raises(ValueError):
        other_scheme.endpoint("custom", ENDPOINT)
    with pytest.raises(ValueError):
        Settings(ADMIN, public_https=True).endpoint("custom", ENDPOINT)
    for invalid in (1, "true", None):
        with pytest.raises(ValueError):
            Settings(ADMIN, public_https=invalid)


def test_public_policy_load_requires_authenticated_proxy(tmp_path, monkeypatch):
    policy = tmp_path / "policy.json"
    policy.write_text('{"public_https":true}')
    monkeypatch.setenv("TUNNEX_AI_BRIDGE_ADMIN_TOKEN", ADMIN)
    monkeypatch.setenv("TUNNEX_AI_CUSTOM_ENDPOINTS_FILE", str(policy))
    monkeypatch.delenv("TUNNEX_AI_BRIDGE_CONFIG_FILE", raising=False)
    for proxy in ("", "http://proxy.test:8190", PROXY + "/extra"):
        monkeypatch.setenv("TUNNEX_AI_CUSTOM_PROXY_URL", proxy)
        with pytest.raises(ValueError):
            Settings.load()
    monkeypatch.setenv("TUNNEX_AI_CUSTOM_PROXY_URL", PROXY)
    assert Settings.load().public_https is True
    policy.write_text('{"public_https":"true"}')
    with pytest.raises(ValueError):
        Settings.load()


@pytest.mark.asyncio
async def test_catalog_admin_validation_and_no_model_prerequisite():
    calls = []

    async def call(payload):
        calls.append(payload)
        return {"items": [], "total": 0, "limit": 50, "offset": 0}

    settings = Settings(ADMIN, proxy=PROXY, public_https=True)
    async with TestClient(TestServer(create_app(settings, call))) as client:
        response = await client.post("/model-catalog", json=draft())
        assert response.status == 401 and not calls
        headers = {"Authorization": "Bearer " + ADMIN}
        for change in [
            {"provider": "openai"}, {"provider": True}, {"query": "x" * 101},
            {"query": None}, {"limit": True}, {"limit": 0}, {"limit": 101},
            {"offset": False}, {"offset": -1}, {"offset": 10001}, {"offset": 0.5},
            {"api_key": ""}, {"model": "not-needed"},
        ]:
            response = await client.post("/model-catalog", json=draft(**change), headers=headers)
            assert response.status == 400
            assert KEY not in await response.text()
        assert not calls
        response = await client.post("/model-catalog", json=draft(), headers=headers)
        assert response.status == 200
        assert calls == [{"operation": "catalog", "endpoint": ENDPOINT, "api_key": KEY, "proxy": PROXY, "query": "", "limit": 50, "offset": 0}]


@pytest.mark.asyncio
async def test_catalog_shares_eight_slots_and_sanitizes_worker_failure():
    entered, release = asyncio.Event(), asyncio.Event()
    count = 0

    async def call(payload):
        nonlocal count
        count += 1
        if count == 8:
            entered.set()
        await release.wait()
        raise ValueError(KEY + " private upstream body")

    settings = Settings(ADMIN, proxy=PROXY, public_https=True)
    async with TestClient(TestServer(create_app(settings, call))) as client:
        headers = {"Authorization": "Bearer " + ADMIN}
        tasks = [asyncio.create_task(client.post("/model-catalog", json=draft(), headers=headers)) for _ in range(8)]
        try:
            await asyncio.wait_for(entered.wait(), 2)
            response = await client.post("/test-connection", json=draft(model="fixture"), headers=headers)
            assert response.status == 429 and count == 8
            response = await client.post("/model-catalog", json=draft(), headers=headers)
            assert response.status == 429 and count == 8
        finally:
            release.set()
            responses = await asyncio.gather(*tasks)
        for response in responses:
            assert response.status == 502
            assert await response.json() == {"error": "catalog unavailable"}


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["valid", "unicode-query", "ascii-query", "redirect", "error", "too-many", "large", "malformed", "compressed"])
async def test_catalog_worker_filters_and_bounds_transport(mode, monkeypatch):
    requests = []
    data = {"data": [
        {"id": "Zeta", "name": KEY}, {"id": "alpha"}, {"id": "alpha"},
        {"id": "Beta"}, {"id": "bad id"}, {"id": True}, {"id": "x" * 256},
        {"id": "custom-00000000-0000-0000-0000-000000000000/private"},
        {"id": KEY}, {"id": "reflected-" + KEY}, {"id": "custom/not-raw"}, None,
        {"id": "gpt-model"}, {"id": "ss"},
    ]}

    async def answer(request):
        requests.append(request)
        assert str(request.url) == ENDPOINT + "/v1/models"
        assert request.method == "GET" and request.headers["Authorization"] == "Bearer " + KEY
        if mode == "redirect":
            return httpx.Response(302, headers={"location": "https://foreign.test"})
        if mode == "error":
            return httpx.Response(401, text=KEY)
        if mode == "too-many":
            return httpx.Response(200, json={"data": [{"id": "a"}] * 10001})
        if mode == "large":
            return httpx.Response(200, content=b"x" * (1024 * 1024 + 1))
        if mode == "malformed":
            return httpx.Response(200, json={"data": {"id": "a"}})
        if mode == "compressed":
            return httpx.Response(200, headers={"content-encoding": "gzip"})
        return httpx.Response(200, json=data)

    # Keep the production origin/encoding/byte bounds while replacing only the
    # bottom network layer; synthetic wire tests separately exercise CONNECT.
    original = transport.LockedTransport.__init__

    def mock_network(self, origins, proxy=None):
        original(self, origins, proxy)
        self.transport = httpx.MockTransport(answer)

    monkeypatch.setattr(transport.LockedTransport, "__init__", mock_network)
    payload = {"operation": "catalog", "endpoint": ENDPOINT, "api_key": KEY, "proxy": PROXY, "query": "a", "limit": 1, "offset": 1}
    if mode == "valid":
        assert await invoke(payload) == {"items": [{"id": "Zeta", "name": "Zeta"}], "total": 3, "limit": 1, "offset": 1}
    elif mode == "unicode-query":
        payload.update(query="ß", offset=0)
        assert await invoke(payload) == {"items": [], "total": 0, "limit": 1, "offset": 0}
    elif mode == "ascii-query":
        payload.update(query="GPT", offset=0)
        assert await invoke(payload) == {"items": [{"id": "gpt-model", "name": "gpt-model"}], "total": 1, "limit": 1, "offset": 0}
    else:
        with pytest.raises(ValueError):
            await invoke(payload)
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_catalog_worker_requires_proxy():
    with pytest.raises(ValueError):
        await invoke({"operation": "catalog", "endpoint": ENDPOINT})
