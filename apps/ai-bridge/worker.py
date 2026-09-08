"""Single-call isolated SDK worker. Only sanitized protocol output reaches stdout."""

import asyncio
import contextlib
import json
import logging
import os
import re
import sys
from urllib.parse import urlsplit

ORIGINS = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
    "gemini": "https://generativelanguage.googleapis.com",
    "openrouter": "https://openrouter.ai/api/v1",
    "groq": "https://api.groq.com/openai/v1",
    "mistral": "https://api.mistral.ai/v1",
    "cerebras": "https://api.cerebras.ai/v1",
    "xai": "https://api.x.ai/v1",
    "deepseek": "https://api.deepseek.com",
}
MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,254}$")
ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


async def catalog(data):
    import httpx
    from transport import LockedTransport

    if not data.get("proxy"):
        raise ValueError("mandatory proxy missing")
    base = data["endpoint"]
    u = urlsplit(base)
    origin = (u.scheme, u.hostname, u.port or (443 if u.scheme == "https" else 80))
    async with httpx.AsyncClient(
        transport=LockedTransport([origin], data["proxy"]),
        trust_env=False, follow_redirects=False, timeout=9,
    ) as client:
        async with client.stream(
            "GET", base + "/v1/models",
            headers={"Authorization": "Bearer " + data["api_key"]},
        ) as response:
            if response.status_code != 200:
                raise ValueError("catalog failed")
            raw = await response.aread()
    upstream = json.loads(raw)
    if not isinstance(upstream, dict) or not isinstance(upstream.get("data"), list):
        raise ValueError("catalog invalid")
    if len(upstream["data"]) > 10000:
        raise ValueError("catalog bound")
    names = set()
    for item in upstream["data"]:
        name = item.get("id") if isinstance(item, dict) else None
        if not isinstance(name, str) or not MODEL_NAME.fullmatch(name):
            continue
        prefix = name.split("/", 1)[0]
        if "/" in name and (prefix == "custom" or prefix.startswith("custom-")):
            continue
        if data["api_key"] in name:
            continue
        if data["query"].translate(ASCII_LOWER) in name.translate(ASCII_LOWER):
            names.add(name)
    names = sorted(names)
    limit, offset = data["limit"], data["offset"]
    return {
        "items": [{"id": name, "name": name} for name in names[offset:offset + limit]],
        "total": len(names), "limit": limit, "offset": offset,
    }


def resolve_binding(original):
    """Resolve only operator-bound roles; never enter SDK ambient fallback."""
    binding = dict(original)
    role = binding.pop("aws_role_name", None)
    session = binding.pop("aws_session_name", None)
    external = binding.pop("aws_external_id", None)
    if not role:
        return binding
    import boto3
    from botocore.config import Config

    region = binding["aws_region_name"]
    suffix = "amazonaws.com.cn" if region.startswith("cn-") else "amazonaws.com"
    client = boto3.client(
        "sts",
        region_name=region,
        endpoint_url=f"https://sts.{region}.{suffix}",
        aws_access_key_id=binding["aws_access_key_id"],
        aws_secret_access_key=binding["aws_secret_access_key"],
        aws_session_token=binding.get("aws_session_token"),
        config=Config(
            connect_timeout=3,
            read_timeout=5,
            retries={"total_max_attempts": 1},
            proxies={},
        ),
    )
    try:
        params = {"RoleArn": role, "RoleSessionName": session}
        if external:
            params["ExternalId"] = external
        credentials = client.assume_role(**params)["Credentials"]
    finally:
        client.close()
    binding.update(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )
    return binding


async def invoke(data, emit=None):
    if data.get("operation") == "catalog":
        return await catalog(data)
    import httpx
    import litellm
    from litellm.llms.custom_httpx.http_handler import AsyncHTTPHandler
    from transport import LockedTransport

    litellm.set_verbose = False
    litellm.turn_off_message_logging = True
    litellm.telemetry = False
    litellm.callbacks = []
    litellm.success_callback = []
    litellm.failure_callback = []
    litellm.input_callback = []
    litellm.cache = None
    provider = data["provider"]
    params = {
        "messages": data["messages"],
        "stream": data["stream"],
        "timeout": 9,
        "num_retries": 0,
        "caching": False,
    }
    if "max_completion_tokens" in data:
        params["max_completion_tokens"] = data["max_completion_tokens"]
    else:
        params["max_tokens"] = data["max_tokens"]
    if provider == "sagemaker":
        binding = resolve_binding(data["binding"])
        params.update(binding)
        region = binding["aws_region_name"]
        suffix = "amazonaws.com.cn" if region.startswith("cn-") else "amazonaws.com"
        base = "https://runtime.sagemaker." + region + "." + suffix
    elif provider == "custom":
        if not data.get("proxy"):
            raise ValueError("mandatory proxy missing")
        base = data["endpoint"] + "/v1"
        params.update(model=data["model"], api_key=data["api_key"], api_base=base)
    else:
        base = ORIGINS[provider]
        params.update(model=data["model"], api_key=data["api_key"], api_base=base)
    u = urlsplit(base)
    origin = (u.scheme, u.hostname, u.port or (443 if u.scheme == "https" else 80))
    transport = LockedTransport([origin], data.get("proxy"))
    async with httpx.AsyncClient(
        transport=transport, trust_env=False, follow_redirects=False, timeout=9
    ) as client:
        handler = AsyncHTTPHandler(timeout=9)
        await handler.client.aclose()
        handler.client = client
        # Both generic provider handlers and OpenAI-SDK adapters inherit this
        # per-worker client; no other tenant/request exists in this process.
        litellm.aclient_session = client
        if provider in {"anthropic", "gemini", "mistral", "sagemaker"}:
            params["client"] = handler
        for field in ("temperature", "stream_options"):
            if field in data:
                params[field] = data[field]
        response = await litellm.acompletion(**params)
        if data["stream"]:
            chunks = []
            size = 0
            async for chunk in response:
                value = chunk.model_dump(exclude_none=True)
                if data.get("alias"):
                    value["model"] = data["alias"]
                encoded = json.dumps(value)
                size += len(encoded.encode())
                if len(encoded) > 65536 or size > 1024 * 1024:
                    raise ValueError("stream bound")
                if emit:
                    emit(value)
                else:
                    chunks.append(value)
            return {"done": True} if emit else {"chunks": chunks}
        value = response.model_dump(exclude_none=True)
        if data.get("alias"):
            value["model"] = data["alias"]
        return value


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    try:
        raw = sys.stdin.buffer.read(32769)
        if len(raw) > 32768:
            raise ValueError("request bound")
        data = json.loads(raw)
        output = sys.stdout

        def emit(value):
            output.write(json.dumps(value) + "\n")
            output.flush()

        with (
            open(os.devnull, "w") as discard,
            contextlib.redirect_stdout(discard),
            contextlib.redirect_stderr(discard),
        ):
            result = asyncio.run(invoke(data, emit if data.get("stream") else None))
        encoded = json.dumps(result)
        if len(encoded) > 1024 * 1024:
            raise ValueError("response bound")
        output.write(encoded + ("\n" if data.get("stream") else ""))
        output.flush()
    except BaseException:
        sys.stdout.write('{"error":"adapter operation failed"}\n')
