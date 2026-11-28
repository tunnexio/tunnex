#!/usr/bin/env python3
"""Manual qualification: LangChain, LangGraph and the OpenAI / Messages SDKs
against a Tunnex AI Gateway base URL (AI-COMPAT-1).

This makes real, paid model calls. Run it yourself against a deployment you
own; CI never runs it.

Install (Python 3.9+):
    python3 -m venv .venv && . .venv/bin/activate
    pip install 'langchain-openai<0.4' 'langchain-anthropic<0.4' 'langgraph<0.7' openai anthropic

Examples:
    # VPN user (identity comes from the VPN; the key is a placeholder)
    scripts/ai-compat/lc_matrix.py --base http://10.99.0.1:8083/ai --chat-model openrouter/anthropic/claude-haiku-4.5

    # Workload wrapper (run inside `tunnex workload run ... -- python3 ...`):
    # base and key come from OPENAI_BASE_URL / OPENAI_API_KEY automatically.
    scripts/ai-compat/lc_matrix.py --chat-model openrouter/openai/gpt-4o-mini --embedding-model openai/text-embedding-3-small

    # Agent runtime / public origin with a bearer
    TUNNEX_AI_KEY=tnx_ai_... scripts/ai-compat/lc_matrix.py --base https://cp.example.com/ai --chat-model ...

Options:
    --base URL             Gateway origin up to and including /ai (VPN, public) or the
                           wrapper's loopback origin. OpenAI clients use BASE/v1; the
                           Messages SDK uses BASE/anthropic (or BASE for the wrapper,
                           see --messages-base). Default: OPENAI_BASE_URL without /v1.
    --messages-base URL    Base for the Messages SDK. Default: BASE/anthropic, or
                           ANTHROPIC_BASE_URL when set (the workload wrapper sets it).
    --key KEY              Bearer / API key. Default: TUNNEX_AI_KEY, OPENAI_API_KEY, "unused".
    --chat-model ID        Repeatable. Each chat model runs the whole chat matrix.
    --messages-model ID    Repeatable. Models for the Messages API checks (default: chat models).
    --embedding-model ID   Repeatable. Optional embeddings checks.
    --only NAME            Repeatable substring filter on check names.
    --long                 Add a long-output check (max_tokens=6000, usually > 30 s).
    --big                  Add a ~400 KB prompt check.
    --batch N              Parallel batch size (default 8).

Output: one line per check (PASS/FAIL, seconds, detail) and a summary; the exit
code is the number of failures (capped at 100).
"""
import argparse
import asyncio
import json
import os
import sys
import time
from typing import Literal

parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
parser.add_argument("--base")
parser.add_argument("--messages-base")
parser.add_argument("--key")
parser.add_argument("--chat-model", action="append", default=[])
parser.add_argument("--messages-model", action="append", default=[])
parser.add_argument("--embedding-model", action="append", default=[])
parser.add_argument("--only", action="append", default=[])
parser.add_argument("--long", action="store_true")
parser.add_argument("--big", action="store_true")
parser.add_argument("--batch", type=int, default=8)
parser.add_argument("--timeout", type=float, default=600)
args = parser.parse_args()

base = (args.base or os.environ.get("OPENAI_BASE_URL", "").removesuffix("/").removesuffix("/v1")).rstrip("/")
if not base:
    parser.error("--base or OPENAI_BASE_URL is required")
if not args.chat_model:
    parser.error("at least one --chat-model is required")
messages_base = (args.messages_base or os.environ.get("ANTHROPIC_BASE_URL") or base + "/anthropic").rstrip("/")
key = args.key or os.environ.get("TUNNEX_AI_KEY") or os.environ.get("OPENAI_API_KEY") or "unused"
messages_models = args.messages_model or args.chat_model

from pydantic import BaseModel  # noqa: E402
from langchain_core.messages import HumanMessage  # noqa: E402
from langchain_core.tools import tool  # noqa: E402
from langchain_openai import ChatOpenAI, OpenAIEmbeddings  # noqa: E402

results = []


def run(name, fn):
    if args.only and not any(o in name for o in args.only):
        return
    start = time.time()
    try:
        detail = fn()
        results.append((name, "PASS", f"{time.time() - start:.1f}s {detail or ''}"))
    except Exception as e:  # noqa: BLE001 - report every failure and continue
        results.append((name, "FAIL", f"{time.time() - start:.1f}s {type(e).__name__}: {str(e)[:240]}"))
    print(f"{results[-1][1]:4}  {name:44} {results[-1][2]}", flush=True)


@tool
def get_weather(city: str) -> str:
    """Return the current weather for a city."""
    return f"It is 21C and sunny in {city}."


@tool
def add(a: int, b: int) -> int:
    """Add two integers."""
    return a + b


class Answer(BaseModel):
    city: str
    temperature_c: int
    condition: Literal["sunny", "cloudy", "rainy"]


def chat_matrix(model):
    llm = ChatOpenAI(base_url=base + "/v1", api_key=key, model=model, timeout=args.timeout, max_retries=0, temperature=0)
    p = f"[{model}] "

    run(p + "invoke", lambda: repr(llm.invoke("Reply with the single word: pong").content[:30]))

    def stream():
        chunks = [c.content for c in llm.stream("Count from 1 to 5, comma separated.")]
        return f"chunks={len(chunks)} text={''.join(chunks)[:40]!r}"
    run(p + "stream", stream)

    def stream_usage():
        last = None
        for c in llm.stream("Say hi", stream_usage=True):
            last = c if last is None else last + c
        assert last is not None and last.usage_metadata, "no usage in stream"
        return f"usage={last.usage_metadata}"
    run(p + "stream usage", stream_usage)

    def multi_turn():
        first = llm.invoke([HumanMessage("My name is Ravi.")])
        return repr(llm.invoke([HumanMessage("My name is Ravi."), first, HumanMessage("What is my name? One word.")]).content[:30])
    run(p + "multi-turn", multi_turn)

    def tool_call():
        out = llm.bind_tools([get_weather]).invoke("What is the weather in Pune? Use the tool.")
        assert out.tool_calls, f"no tool_calls, content={out.content[:80]!r}"
        return out.tool_calls[0]["name"] + " " + json.dumps(out.tool_calls[0]["args"])
    run(p + "tool call", tool_call)

    def tool_round_trip():
        bound = llm.bind_tools([get_weather])
        q = HumanMessage("What is the weather in Pune? Use the tool, then answer in one sentence.")
        first = bound.invoke([q])
        assert first.tool_calls, "no tool call"
        return repr(bound.invoke([q, first, get_weather.invoke(first.tool_calls[0])]).content[:60])
    run(p + "tool round trip", tool_round_trip)

    run(p + "parallel tools", lambda: f"tool_calls={[c['name'] for c in llm.bind_tools([get_weather, add]).invoke('Call get_weather for Pune AND add 2 and 3. Call both tools.').tool_calls]}")
    for method in ("json_schema", "function_calling"):
        run(p + f"structured {method}", lambda m=method: repr(llm.with_structured_output(Answer, method=m).invoke("Pune is 21C and sunny. Extract.")))
    run(p + "json_mode", lambda: repr(llm.with_structured_output(None, method="json_mode").invoke('Return JSON {"ok": true} only.')))
    run(p + "async ainvoke", lambda: repr(asyncio.run(llm.ainvoke("Say ok")).content[:20]))
    run(p + f"batch x{args.batch} (parallel)", lambda: f"ok={len(llm.batch([f'Reply with the number {i}' for i in range(args.batch)], config={'max_concurrency': args.batch}))}")

    def react_agent():
        from langgraph.prebuilt import create_react_agent
        r = create_react_agent(llm, [get_weather, add]).invoke({"messages": [("user", "What is the weather in Pune, and what is 17+25? Use tools.")]})
        return f"steps={len(r['messages'])} tools={[m.name for m in r['messages'] if m.type == 'tool']} final={r['messages'][-1].content[:60]!r}"
    run(p + "langgraph react agent", react_agent)

    def react_stream():
        from langgraph.prebuilt import create_react_agent
        return f"events={sum(1 for _ in create_react_agent(llm, [add]).stream({'messages': [('user', 'What is 2+40? Use the tool.')]}, stream_mode='values'))}"
    run(p + "langgraph stream", react_stream)

    def responses_api():
        r = ChatOpenAI(base_url=base + "/v1", api_key=key, model=model, timeout=args.timeout, max_retries=0, use_responses_api=True).invoke("Reply with the single word: pong")
        return repr(r.text()[:30] if callable(getattr(r, "text", None)) else r.content)
    run(p + "responses api", responses_api)

    def raw_sdk_stream():
        import openai
        client = openai.OpenAI(base_url=base + "/v1", api_key=key, max_retries=0, timeout=args.timeout)
        events, usage, text = 0, None, ""
        for chunk in client.chat.completions.create(model=model, stream=True, stream_options={"include_usage": True},
                                                    messages=[{"role": "user", "content": "Count from 1 to 5."}]):
            events += 1
            usage = chunk.usage or usage
            if chunk.choices and chunk.choices[0].delta.content:
                text += chunk.choices[0].delta.content
        assert usage is not None, "no usage chunk"
        return f"events={events} usage={usage.total_tokens} text={text[:30]!r}"
    run(p + "openai sdk raw stream", raw_sdk_stream)

    def sdk_models():
        import openai
        ids = [m.id for m in openai.OpenAI(base_url=base + "/v1", api_key=key, max_retries=0).models.list()]
        assert model in ids, f"{model} not listed"
        return f"models={len(ids)}"
    run(p + "openai sdk models.list", sdk_models)

    if args.long:
        def long_output():
            t = time.time()
            out = llm.invoke("Write a detailed 2500-word essay about the history of the printing press.", max_tokens=6000)
            return f"chars={len(out.content)} secs={time.time() - t:.0f}"
        run(p + "long output max_tokens=6000", long_output)

        def long_stream():
            t, n = time.time(), 0
            for c in llm.stream("Write a detailed 2500-word essay about the history of the printing press.", max_tokens=6000):
                n += len(c.content)
            return f"chars={n} secs={time.time() - t:.0f}"
        run(p + "long stream max_tokens=6000", long_stream)
    if args.big:
        filler = ("lorem ipsum dolor sit amet " * 15000)[:400_000]
        run(p + "big context ~400KB", lambda: repr(llm.invoke(filler + "\n\nIgnore the text above. Reply: done").content[:20]))


def messages_matrix(model):
    p = f"[{model}] messages "
    try:
        import anthropic
    except ImportError:
        run(p + "sdk installed", lambda: (_ for _ in ()).throw(RuntimeError("pip install anthropic")))
        return
    client = anthropic.Anthropic(base_url=messages_base, api_key=key, max_retries=0, timeout=args.timeout)
    weather = {"name": "get_weather", "description": "Return the current weather for a city.",
               "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}

    run(p + "create", lambda: repr(client.messages.create(model=model, max_tokens=64, messages=[{"role": "user", "content": "Reply: pong"}]).content[0].text[:30]))

    def tools_round_trip():
        q = {"role": "user", "content": "What is the weather in Pune? Use the tool."}
        first = client.messages.create(model=model, max_tokens=512, tools=[weather], messages=[q],
                                       system=[{"type": "text", "text": "Use tools when asked.", "cache_control": {"type": "ephemeral"}}])
        use = next((b for b in first.content if b.type == "tool_use"), None)
        assert use is not None, f"no tool_use, stop_reason={first.stop_reason}"
        final = client.messages.create(model=model, max_tokens=256, tools=[weather], messages=[
            q, {"role": "assistant", "content": [b.model_dump(exclude_none=True) for b in first.content]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": use.id, "content": "21C and sunny"}]}])
        return f"tool={use.name} final={next((b.text for b in final.content if b.type == 'text'), '')[:50]!r}"
    run(p + "tools round trip", tools_round_trip)

    def stream():
        with client.messages.stream(model=model, max_tokens=128, messages=[{"role": "user", "content": "Count from 1 to 5."}]) as s:
            text = "".join(s.text_stream)
        return repr(text[:40])
    run(p + "stream", stream)

    def langchain_messages():
        from langchain_anthropic import ChatAnthropic
        llm = ChatAnthropic(base_url=messages_base, api_key=key, model=model, max_retries=0, timeout=args.timeout)
        out = llm.bind_tools([get_weather]).invoke("What is the weather in Pune? Use the tool.")
        assert out.tool_calls, "no tool_calls"
        return out.tool_calls[0]["name"]
    run(p + "langchain-anthropic tools", langchain_messages)


def embedding_matrix(model):
    p = f"[{model}] "
    emb = OpenAIEmbeddings(base_url=base + "/v1", api_key=key, model=model, max_retries=0)
    run(p + "embed_documents (token arrays)", lambda: f"vectors={len(emb.embed_documents(['alpha', 'beta']))} dims={len(emb.embed_query('alpha'))}")
    raw = OpenAIEmbeddings(base_url=base + "/v1", api_key=key, model=model, max_retries=0, check_embedding_ctx_length=False)
    run(p + "embed_documents (strings)", lambda: f"vectors={len(raw.embed_documents(['alpha', 'beta', 'gamma']))}")


for m in args.chat_model:
    chat_matrix(m)
for m in messages_models:
    messages_matrix(m)
for m in args.embedding_model:
    embedding_matrix(m)

failed = sum(1 for r in results if r[1] == "FAIL")
print(f"\nSUMMARY {len(results) - failed} pass / {len(results)}  base={base} messages_base={messages_base}")
sys.exit(min(failed, 100))
