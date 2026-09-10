#!/usr/bin/env python3
"""Verify separate local server and production-proxy processes; emit no secrets."""
import argparse
import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--state-dir", required=True)
args = parser.parse_args()
state = Path(args.state_dir)
observed = json.loads((state / "discovery.json").read_text())
assert observed["authenticated"]["status"] == "healthy"
names = sorted(tool["name"] for tool in observed["authenticated"]["tools"])
assert names == ["delete_issue", "read_issue", "write_issue"], names
assert observed["anonymous"]["http_status"] == 401
assert observed["forbidden"]["http_status"] == 403
assert observed["incomplete"]["http_status"] == 403
assert observed["incomplete"]["status"] != "healthy"
assert not observed["incomplete"].get("tools"), "partial catalog published"


def call(name):
    body = json.dumps({"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": name, "arguments": {}}}).encode()
    request = urllib.request.Request("http://127.0.0.1:54932", body, headers={"Content-Type": "application/json", "MCP-Protocol-Version": "2025-11-25", "Mcp-Session-Id": "fixture-session", "Authorization": "Bearer deliberately-wrong-caller-token"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


allowed, reply = call("read_issue")
assert allowed == 200 and "Synthetic fixture" in reply["result"]["content"][0]["text"]
denied, _ = call("write_issue")
new, _ = call("delete_issue")
assert denied == 403 and new == 403
(state / "policy.json").write_text("[]")
revoked, _ = call("read_issue")
assert revoked == 403
tls = ssl.create_default_context(cafile=str(state / "cert.pem"))
with urllib.request.urlopen("https://127.0.0.1:54931/stats", context=tls, timeout=5) as response:
    stats = json.load(response)
assert stats["calls"] == ["read_issue"], stats
report = {"result": "passed", "transport": "separate local HTTPS MCP process and production loopback proxy", "discovered_tools": names, "anonymous_http": 401, "forbidden_http": 403, "partial_page_http": 403, "partial_catalog_published": False, "selected_tool_http": allowed, "unselected_tool_http": denied, "new_tool_http": new, "revoked_tool_http": revoked, "upstream_tool_calls": stats["calls"], "boundary": "Transport and proxy proof; control-plane lease, enrollment and browser flow remain separate acceptance checks."}
(state / "result.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
