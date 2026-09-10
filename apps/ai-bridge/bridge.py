"""Private LiteLLM adapter. No provider credentials or responses are persisted."""

import asyncio
import contextlib
import math
import hmac
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from aiohttp import web
from worker import MODES, validate_preflight
from diagnostics import ProbeFailure, exception_failure

STANDARD = {
    "openai",
    "anthropic",
    "gemini",
    "openrouter",
    "groq",
    "mistral",
    "cerebras",
    "xai",
    "deepseek",
}
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,254}$")
ENV = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")


def normalized(raw):
    if (
        not isinstance(raw, str)
        or len(raw) > 2048
        or any(c in raw for c in "%\\\r\n\t ?#")
    ):
        raise ValueError("endpoint denied")
    u = urlsplit(raw)
    if u.scheme not in {"http", "https"} or not u.hostname or u.username or u.password:
        raise ValueError("endpoint denied")
    port = u.port
    if port is not None and not 0 < port < 65536:
        raise ValueError("endpoint denied")
    path = u.path.rstrip("/")
    if "//" in path or any(p in {".", "..", "v1"} for p in path.split("/")):
        raise ValueError("endpoint denied")
    host = u.hostname.lower()
    if host.endswith("."):
        raise ValueError("endpoint denied")
    authority = f"[{host}]" if ":" in host else host
    if port and not (
        (u.scheme == "http" and port == 80) or (u.scheme == "https" and port == 443)
    ):
        authority += f":{port}"
    return urlunsplit((u.scheme, authority, path, "", ""))


def foundry_endpoint(raw):
    endpoint = normalized(raw)
    u = urlsplit(endpoint)
    if (
        u.scheme != "https"
        or u.port not in {None, 443}
        or u.path not in {"/openai", "/anthropic"}
        or not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
            r"\.(?:openai\.azure\.com|services\.ai\.azure\.com|cognitiveservices\.azure\.com)",
            u.hostname,
        )
    ):
        raise ValueError("endpoint denied")
    return endpoint


def secret(value):
    return (
        isinstance(value, str)
        and value.isascii()
        and 0 < len(value) <= 4096
        and not any(c.isspace() for c in value)
        and not value.startswith(("env.", "vault.", "os.environ/"))
    )


def env_secret(name):
    if not isinstance(name, str) or not ENV.fullmatch(name):
        raise ValueError("invalid secret reference")
    value = os.environ.get(name, "")
    if not secret(value):
        raise ValueError("missing secret")
    return value


class Settings:
    def __init__(self, admin, models=None, clients=None, endpoints=None, proxy=None, public_https=False):
        if not secret(admin) or len(admin) < 16:
            raise ValueError("invalid administrator token")
        self.admin = admin
        self.models = models or {}
        self.clients = clients or []
        self.endpoints = endpoints or {}
        self.proxy = proxy
        if not isinstance(public_https, bool):
            raise ValueError("invalid public HTTPS policy")
        self.public_https = public_https
        if any(not secret(key) or len(key) < 16 for key, _ in self.clients):
            raise ValueError("invalid client key")

    @classmethod
    def load(cls):
        models = {}
        clients = []
        endpoints = {}
        public_https = False
        path = os.environ.get("TUNNEX_AI_BRIDGE_CONFIG_FILE")
        if path:
            raw = Path(path).read_bytes()
            if len(raw) > 65536:
                raise ValueError("configuration too large")
            config = json.loads(raw)
            if set(config) - {"models", "clients"}:
                raise ValueError("unsupported configuration")
            if (
                len(config.get("models", [])) > 64
                or len(config.get("clients", [])) > 128
            ):
                raise ValueError("configuration limit")
            for row in config.get("models", []):
                if set(row) - {
                    "alias",
                    "endpoint",
                    "region",
                    "access_key_id_env",
                    "secret_access_key_env",
                    "session_token_env",
                    "role_arn",
                    "external_id",
                }:
                    raise ValueError("unsupported IAM binding")
                alias = row["alias"]
                endpoint = row["endpoint"]
                region = row["region"]
                if (
                    not NAME.fullmatch(alias)
                    or alias in models
                    or not re.fullmatch(
                        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", endpoint
                    )
                    or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", region)
                ):
                    raise ValueError("invalid model binding")
                binding = {
                    "model": "sagemaker_chat/" + endpoint,
                    "aws_region_name": region,
                    "aws_access_key_id": env_secret(row["access_key_id_env"]),
                    "aws_secret_access_key": env_secret(row["secret_access_key_env"]),
                }
                if row.get("session_token_env"):
                    binding["aws_session_token"] = env_secret(row["session_token_env"])
                if row.get("role_arn"):
                    if not re.fullmatch(
                        r"arn:aws(?:-cn|-us-gov)?:iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}",
                        row["role_arn"],
                    ):
                        raise ValueError("invalid role")
                    binding.update(
                        aws_role_name=row["role_arn"],
                        aws_session_name="tunnex-ai-bridge",
                    )
                    if row.get("external_id"):
                        binding["aws_external_id"] = row["external_id"]
                models[alias] = binding
            for row in config.get("clients", []):
                if (
                    set(row) != {"key_env", "models"}
                    or not row["models"]
                    or any(m not in models for m in row["models"])
                ):
                    raise ValueError("invalid client scope")
                clients.append((env_secret(row["key_env"]), frozenset(row["models"])))
            if len({k for k, _ in clients}) != len(clients):
                raise ValueError("duplicate client key")
        policy_path = os.environ.get("TUNNEX_AI_CUSTOM_ENDPOINTS_FILE")
        proxy = os.environ.get("TUNNEX_AI_CUSTOM_PROXY_URL")
        if policy_path:
            raw = Path(policy_path).read_bytes()
            if len(raw) > 65536:
                raise ValueError("policy too large")
            policy = json.loads(raw)
            public_https = policy.get("public_https", False)
            if not isinstance(public_https, bool):
                raise ValueError("invalid public HTTPS policy")
            for row in policy.get("endpoints", []):
                provider = row.get("provider", "custom")
                endpoint = (
                    foundry_endpoint(row["url"])
                    if provider == "azure_foundry"
                    else normalized(row["url"])
                )
                endpoints[endpoint] = provider
        if endpoints or public_https:
            u = urlsplit(proxy or "")
            if (
                u.scheme != "http"
                or not u.hostname
                or not u.username
                or not u.password
                or u.path
                or u.query
                or u.fragment
            ):
                raise ValueError("invalid mandatory proxy")
        return cls(
            env_secret("TUNNEX_AI_BRIDGE_ADMIN_TOKEN"),
            models,
            clients,
            endpoints,
            proxy,
            public_https,
        )

    def endpoint(self, provider, raw):
        if provider not in {"custom", "sagemaker", "azure_foundry"}:
            raise ValueError("endpoint denied")
        endpoint = foundry_endpoint(raw) if provider == "azure_foundry" else normalized(raw)
        if provider != "azure_foundry" and urlsplit(endpoint).path == "/anthropic":
            try:
                foundry_endpoint(endpoint)
            except ValueError:
                pass
            else:
                raise ValueError("select Azure Foundry for its Anthropic endpoint")
        if not self.proxy:
            raise ValueError("mandatory proxy missing")
        if endpoint in self.endpoints:
            if self.endpoints[endpoint] != provider:
                raise ValueError("endpoint kind denied")
            return endpoint
        u = urlsplit(endpoint)
        authority = (u.hostname, u.port or (443 if u.scheme == "https" else 80))
        for configured in self.endpoints:
            existing = urlsplit(configured)
            if authority == (
                existing.hostname,
                existing.port or (443 if existing.scheme == "https" else 80),
            ):
                raise ValueError("explicit authority reserved")
        if (
            not self.public_https
            or provider not in {"custom", "azure_foundry"}
            or u.scheme != "https"
            or u.port not in {None, 443}
        ):
            raise ValueError("endpoint denied")
        # The mandatory egress proxy validates all DNS answers and numeric dials.
        return endpoint

    def scope(self, key):
        for value, models in self.clients:
            if hmac.compare_digest(value, key):
                return models
        return frozenset()


def bearer(request):
    value = request.headers.get("Authorization", "")
    return value[7:] if value.isascii() and value.startswith("Bearer ") else ""


@contextlib.asynccontextmanager
async def sdk_process(payload):
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONUNBUFFERED": "1",
        "AWS_EC2_METADATA_DISABLED": "true",
        "DO_NOT_TRACK": "1",
        "LITELLM_LOCAL_MODEL_COST_MAP": "true",
    }
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
        if os.environ.get(name):
            env[name] = os.environ[name]
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        str(Path(__file__).with_name("worker.py")),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        env=env,
        limit=65536,
    )
    try:
        process.stdin.write(json.dumps(payload).encode())
        await process.stdin.drain()
        process.stdin.close()
        yield process
    finally:
        if process.returncode is None:
            process.kill()
        await process.wait()


async def sdk_call(payload, timeout=10):
    async with asyncio.timeout(timeout), sdk_process(payload) as process:
        parts = []
        size = 0
        while chunk := await process.stdout.read(65536):
            size += len(chunk)
            if size > 1024 * 1024:
                raise ValueError("adapter response bound")
            parts.append(chunk)
        await process.wait()
        if process.returncode:
            raise ValueError("adapter failed")
        result = json.loads(b"".join(parts))
        if isinstance(result, dict) and "error" in result:
            raise ProbeFailure(result.get("failure"))
        if not isinstance(result, dict):
            raise ValueError("adapter failed")
        return result


async def sdk_stream(payload):
    async with asyncio.timeout(30), sdk_process(payload) as process:
        size = 0
        done = False
        while line := await process.stdout.readline():
            size += len(line)
            if len(line) > 65536 or size > 1024 * 1024:
                raise ValueError("adapter response bound")
            value = json.loads(line)
            if "error" in value:
                raise ValueError("adapter failed")
            if value == {"done": True}:
                done = True
                break
            yield value
        await process.wait()
        if not done or process.returncode:
            raise ValueError("incomplete adapter stream")


def create_app(settings, call=sdk_call, stream_call=sdk_stream):
    app = web.Application(client_max_size=32768)
    slots = asyncio.Semaphore(8)

    async def test(request):
        if not hmac.compare_digest(bearer(request), settings.admin):
            return web.json_response({"error": "unauthorized"}, status=401)
        started = time.monotonic()
        failure = None
        stage = "configuration_error"
        try:
            data = await request.json()
            if not isinstance(data, dict) or set(data) - {
                "provider",
                "model",
                "api_key",
                "endpoint_url",
                "mode",
            }:
                raise ValueError()
            provider = data["provider"]
            model = data["model"]
            key = data["api_key"]
            mode = data.get("mode", "chat")
            if (
                not secret(key)
                or not isinstance(mode, str)
                or mode not in MODES
                or (provider == "sagemaker" and mode != "chat")
                or not isinstance(model, str)
                or not NAME.fullmatch(model)
            ):
                raise ValueError()
            payload = {
                "mode": mode,
                "messages": [{"role": "user", "content": "Reply OK."}],
                "max_tokens": 16,
                "stream": False,
            }
            if mode not in {"chat", "completion"}:
                payload.pop("max_tokens")
            if provider in STANDARD:
                if data.get("endpoint_url"):
                    raise ValueError()
                prefix = provider + "/"
                if not model.startswith(prefix):
                    raise ValueError()
                payload.update(provider=provider, model=model, api_key=key)
            elif provider in {"custom", "sagemaker", "azure_foundry"}:
                endpoint = settings.endpoint(provider, data["endpoint_url"])
                payload.update(
                    provider="custom",
                    model="openai/" + model,
                    api_key=key,
                    endpoint=endpoint,
                    proxy=settings.proxy,
                )
                if provider == "azure_foundry" and endpoint.endswith("/anthropic"):
                    if mode != "chat":
                        raise ValueError("Anthropic Messages requires chat mode")
                    payload.update(provider="foundry_anthropic", model="anthropic/" + model)
                # Azure hosts other model vendors too. Keep the ordinary token
                # parameter for them; GPT-5/o-series use the reasoning limit.
                if provider == "azure_foundry" and not endpoint.endswith("/anthropic") and mode == "chat" and re.match(r"^(?:gpt-5(?:[.-]|$)|o[134](?:-|$))", model, re.IGNORECASE):
                    payload["max_completion_tokens"] = payload.pop("max_tokens")
            else:
                raise ValueError()
            if slots.locked():
                return web.json_response({"error": "busy"}, status=429)
            async with slots:
                stage = "unknown"
                result = await call(payload)
            stage = "invalid_response"
            validate_preflight(mode, result)
            status = "success"
        except Exception as exc:
            status = "error"
            failure = exception_failure(exc, "gateway")
            if failure["kind"] == "unknown":
                failure = {"kind": stage, "source": "gateway"}
        return web.json_response(
            {"status": status, "duration_ms": int((time.monotonic() - started) * 1000), **({"failure": failure} if failure else {})}
        )

    async def catalog(request):
        if not hmac.compare_digest(bearer(request), settings.admin):
            return web.json_response({"error": "unauthorized"}, status=401)
        try:
            data = await request.json()
            if not isinstance(data, dict) or set(data) - {
                "provider", "api_key", "endpoint_url", "query", "limit", "offset", "mode",
            }:
                raise ValueError()
            if not secret(data["api_key"]):
                raise ValueError()
            endpoint = settings.endpoint(data["provider"], data["endpoint_url"])
            query = data.get("query", "")
            mode = data.get("mode", "chat")
            limit, offset = data.get("limit", 50), data.get("offset", 0)
            if (
                not isinstance(query, str) or len(query) > 100
                or not isinstance(mode, str) or mode not in MODES
                or type(limit) is not int or not 1 <= limit <= 100
                or type(offset) is not int or not 0 <= offset <= 10000
            ):
                raise ValueError()
            payload = {
                "operation": "catalog", "endpoint": endpoint,
                "api_key": data["api_key"], "proxy": settings.proxy,
                "query": query, "limit": limit, "offset": offset,
            }
        except Exception:
            return web.json_response({"error": "invalid catalog request"}, status=400)
        if slots.locked():
            return web.json_response({"error": "busy"}, status=429)
        try:
            async with slots:
                result = await call(payload)
            return web.json_response(result)
        except Exception:
            return web.json_response({"error": "catalog unavailable"}, status=502)

    async def models(request):
        allowed = settings.scope(bearer(request))
        if not allowed:
            return web.json_response({"error": "unauthorized"}, status=401)
        return web.json_response(
            {
                "object": "list",
                "data": [
                    {"id": a, "object": "model", "owned_by": "installation"}
                    for a in sorted(allowed)
                ],
            }
        )

    async def completion(request):
        allowed = settings.scope(bearer(request))
        if not allowed:
            return web.json_response({"error": "unauthorized"}, status=401)
        try:
            data = await request.json()
            if (
                not isinstance(data, dict)
                or set(data)
                - {
                    "model",
                    "messages",
                    "max_tokens",
                    "stream",
                    "temperature",
                    "stream_options",
                }
                or data.get("model") not in allowed
            ):
                raise ValueError()
            messages = data.get("messages")
            if (
                not isinstance(messages, list)
                or not 1 <= len(messages) <= 64
                or any(
                    set(m) - {"role", "content"}
                    or m.get("role") not in {"system", "user", "assistant"}
                    or not isinstance(m.get("content"), str)
                    for m in messages
                )
            ):
                raise ValueError()
            tokens = data.get("max_tokens", 1024)
            if type(tokens) is not int or not 1 <= tokens <= 4096:
                raise ValueError()
            if "temperature" in data and (
                type(data["temperature"]) not in {int, float}
                or not math.isfinite(data["temperature"])
                or not 0 <= data["temperature"] <= 2
            ):
                raise ValueError()
            if "stream_options" in data and (
                not isinstance(data["stream_options"], dict)
                or set(data["stream_options"]) - {"include_usage"}
                or type(data["stream_options"].get("include_usage")) is not bool
            ):
                raise ValueError()
            if type(data.get("stream", False)) is not bool:
                raise ValueError()
            if slots.locked():
                return web.json_response({"error": "busy"}, status=429)
            payload = {
                "provider": "sagemaker",
                "alias": data["model"],
                "binding": settings.models[data["model"]],
                "messages": messages,
                "max_tokens": tokens,
                "stream": bool(data.get("stream", False)),
            }
            for field in ("temperature", "stream_options"):
                if field in data:
                    payload[field] = data[field]
            async with slots:
                if data.get("stream"):
                    response = web.StreamResponse(
                        headers={
                            "Content-Type": "text/event-stream",
                            "Cache-Control": "no-cache",
                        }
                    )
                    await response.prepare(request)
                    try:
                        async for chunk in stream_call(payload):
                            chunk["model"] = data["model"]
                            await response.write(
                                ("data: " + json.dumps(chunk) + "\n\n").encode()
                            )
                        await response.write(b"data: [DONE]\n\n")
                    except Exception:
                        await response.write(
                            b'event: error\ndata: {"error":{"message":"adapter operation failed"}}\n\n'
                        )
                    await response.write_eof()
                    return response
                result = await call(payload, timeout=30)
                result["model"] = data["model"]
                return web.json_response(result)
        except Exception:
            return web.json_response(
                {
                    "error": {
                        "message": "adapter operation failed",
                        "type": "upstream_error",
                    }
                },
                status=502,
            )

    app.router.add_post("/test-connection", test)
    app.router.add_post("/model-catalog", catalog)
    app.router.add_get("/v1/models", models)
    app.router.add_post("/v1/chat/completions", completion)
    return app


if __name__ == "__main__":
    try:
        config = Settings.load()
        host, port = os.environ.get("TUNNEX_AI_BRIDGE_LISTEN", "0.0.0.0:8200").rsplit(
            ":", 1
        )
        web.run_app(
            create_app(config),
            host=host,
            port=int(port),
            access_log=None,
            print=None,
            handler_cancellation=True,
        )
    except Exception:
        raise SystemExit("AI bridge configuration failed")
