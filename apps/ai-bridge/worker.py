"""Single-call isolated SDK worker. Only sanitized protocol output reaches stdout."""

import asyncio
import contextlib
import base64
import io
import json
import logging
import math
import os
import re
import sys
import wave
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
MODES = frozenset({"chat", "completion", "embedding", "audio_speech", "audio_transcription", "image_generation", "video_generation", "rerank"})


def tiny_audio():
    """A local 100 ms PCM fixture; never fetch media for a connection test."""
    audio = io.BytesIO()
    with wave.open(audio, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(8000)
        wav.writeframes(b"\x00\x00" * 800)
    audio.seek(0)
    audio.name = "connection-test.wav"
    return audio


def validate_preflight(mode, value):
    """Require the selected protocol's response, not merely HTTP success."""
    if not isinstance(value, dict) or value.get("error"):
        raise ValueError("invalid response")
    if mode in {"chat", "completion"}:
        choices = value.get("choices")
        if not isinstance(choices, list) or len(choices) != 1:
            raise ValueError("invalid choices")
        choice = choices[0]
        if not isinstance(choice, dict) or choice.get("finish_reason") not in {"stop", "length"}:
            raise ValueError("unfinished completion")
        if mode == "chat" and not isinstance(choice.get("message"), dict):
            raise ValueError("invalid message")
        if mode == "completion" and not isinstance(choice.get("text"), str):
            raise ValueError("invalid text")
    elif mode == "embedding":
        rows = value.get("data")
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
            raise ValueError("invalid embeddings")
        vector = rows[0].get("embedding")
        if not isinstance(vector, list) or not vector or any(type(n) not in {int, float} or not math.isfinite(n) for n in vector):
            raise ValueError("invalid vector")
    elif mode == "audio_speech":
        if type(value.get("audio_bytes")) is not int or not 44 < value["audio_bytes"] <= 1024 * 1024:
            raise ValueError("invalid audio")
    elif mode == "audio_transcription":
        if not isinstance(value.get("text"), str):
            raise ValueError("invalid transcription")
    elif mode == "image_generation":
        rows = value.get("data")
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
            raise ValueError("invalid image response")
        item = rows[0]
        if isinstance(item.get("b64_json"), str) and item["b64_json"]:
            if not base64.b64decode(item["b64_json"], validate=True):
                raise ValueError("empty image")
        elif isinstance(item.get("url"), str):
            url = urlsplit(item["url"])
            if url.scheme != "https" or not url.hostname or url.username or url.password:
                raise ValueError("invalid image URL")
        else:
            raise ValueError("missing image")
    elif mode == "video_generation":
        if not isinstance(value.get("id"), str) or not value["id"] or value.get("status") not in {"queued", "in_progress", "completed"}:
            raise ValueError("video not accepted")
    elif mode == "rerank":
        rows = value.get("results")
        if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
            raise ValueError("invalid ranking")
        row = rows[0]
        score = row.get("relevance_score")
        if type(row.get("index")) is not int or row["index"] != 0 or type(score) not in {int, float} or not math.isfinite(score):
            raise ValueError("invalid score")
    else:
        raise ValueError("invalid mode")


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
    mode = data.get("mode", "chat")
    if mode not in MODES or (provider == "sagemaker" and mode != "chat"):
        raise ValueError("unsupported mode")
    params = {
        "timeout": 9,
        "num_retries": 0,
        "caching": False,
    }
    if mode in {"chat", "completion"}:
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
    elif provider in {"custom", "foundry_anthropic"}:
        if not data.get("proxy"):
            raise ValueError("mandatory proxy missing")
        base = data["endpoint"] + ("" if provider == "foundry_anthropic" else "/v1")
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
        if provider in {"anthropic", "foundry_anthropic", "gemini", "mistral", "sagemaker"}:
            params["client"] = handler
        for field in ("temperature", "stream_options"):
            if field in data:
                params[field] = data[field]
        audio = None
        try:
            if mode == "chat":
                response = await litellm.acompletion(messages=data["messages"], stream=data["stream"], **params)
            elif mode == "completion":
                response = await litellm.atext_completion(prompt="Reply OK.", **params)
            elif mode == "embedding":
                response = await litellm.aembedding(input=["test"], **params)
            elif mode == "audio_speech":
                response = await litellm.aspeech(input="test", voice="alloy", response_format="wav", **params)
                raw = await response.aread()
                if not 44 < len(raw) <= 1024 * 1024 or raw[:4] != b"RIFF" or raw[8:12] != b"WAVE":
                    raise ValueError("invalid audio response")
                with wave.open(io.BytesIO(raw), "rb") as wav:
                    if wav.getnframes() == 0 or not wav.readframes(1):
                        raise ValueError("empty audio")
                return {"audio_bytes": len(raw)}
            elif mode == "audio_transcription":
                audio = tiny_audio()
                response = await litellm.atranscription(file=audio, **params)
            elif mode == "image_generation":
                response = await litellm.aimage_generation(prompt="A plain blue square.", n=1, **params)
            elif mode == "video_generation":
                params["client"] = handler
                response = await litellm.avideo_generation(prompt="A still blue square.", seconds="4", **params)
            else:
                params["client"] = handler
                if provider == "custom":
                    # Reuse LiteLLM's proxy-compatible rerank adapter. OpenAI
                    # itself has no rerank adapter in the pinned SDK.
                    params.update(custom_llm_provider="litellm_proxy", model=data["model"].removeprefix("openai/"), api_base=data["endpoint"])
                response = await litellm.arerank(query="test", documents=["test"], top_n=1, **params)
        finally:
            if audio is not None:
                audio.close()
        if data.get("stream"):
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
        if "mode" in data:
            validate_preflight(mode, value)
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
