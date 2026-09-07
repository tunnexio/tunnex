#!/usr/bin/env python3
"""Pinned native engine + synthetic loopback provider; no paid calls or containers."""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request

binary = Path(os.environ["AI0_BIFROST_BINARY"])
assert hashlib.sha256(binary.read_bytes()).hexdigest() == "31ac451d83706069e580dd1dedf099aa518d1bc47c3c481d20f97203f799275e", "qualification binary digest mismatch"
prompt_marker = "AI0_PRIVATE_PROMPT_956598ebd5944b7eb23965e492e961cc"
response_marker = "AI0_PRIVATE_RESPONSE_b382987730af4250ac664e6e1e55b685"
arrivals = []
class Provider(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"data":[]}')
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert body["messages"][0]["content"] == prompt_marker
        arrivals.append(1)
        result = {"id": "metadata-fixture", "object": "chat.completion", "model": "openai/gpt-4o-mini",
                  "choices": [{"index": 0, "message": {"role": "assistant", "content": response_marker}, "finish_reason": "stop"}],
                  "usage": {"prompt_tokens": 4, "completion_tokens": 3, "total_tokens": 7}}
        raw = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

provider = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
threading.Thread(target=provider.serve_forever, daemon=True).start()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with tempfile.TemporaryDirectory(prefix="tunnex-ai-metadata-") as scratch:
    directory = Path(scratch)
    config = json.loads((Path(__file__).parent / "config.json").read_text())
    # Use plaintext fixture DB so absence is not hidden by encryption.
    config.pop("encryption_key", None)
    config["config_store"]["config"]["path"] = str(directory / "config.db")
    config["logs_store"]["config"]["path"] = str(directory / "logs.db")
    config["providers"]["openrouter"]["network_config"].update(base_url="http://127.0.0.1:"+str(provider.server_port), allow_private_network=True)
    config["governance"]["virtual_keys"] = [{"id": "metadata-agent", "name": "metadata-agent", "value": "sk-bf-ai-metadata-fixture", "is_active": True,
         "provider_configs": [{"provider": "openrouter", "allowed_models": ["openai/gpt-4o-mini"], "key_ids": ["openrouter-primary"], "weight": 1}]}]
    (directory / "config.json").write_text(json.dumps(config))
    with socket.socket() as port_socket:
        port_socket.bind(("127.0.0.1", 0))
        port = port_socket.getsockname()[1]
    base = "http://127.0.0.1:"+str(port)
    env = {"PATH": os.environ.get("PATH", ""), "BIFROST_ADMIN_USER": "metadata-admin", "BIFROST_ADMIN_PASSWORD": "metadata-password-fixture", "OPENROUTER_API_KEY": "metadata-provider-fixture"}
    with (directory / "runtime.log").open("wb") as log:
        process = subprocess.Popen([str(binary), "-host", "127.0.0.1", "-port", str(port), "-app-dir", scratch, "-log-level", "error"], env=env, stdout=log, stderr=log)
        try:
            for _ in range(150):
                assert process.poll() is None, "engine exited before readiness (log withheld)"
                try:
                    with opener.open(base+"/health", timeout=1) as response:
                        if response.status == 200:
                            break
                except Exception:
                    time.sleep(.1)
            else:
                raise AssertionError("engine readiness timeout")
            payload = json.dumps({"model": "openrouter/openai/gpt-4o-mini", "messages": [{"role": "user", "content": prompt_marker}], "max_tokens": 16}).encode()
            request = urllib.request.Request(base+"/v1/chat/completions", data=payload, headers={"Content-Type": "application/json", "X-Bf-Vk": "sk-bf-ai-metadata-fixture"})
            with opener.open(request, timeout=15) as response:
                result = json.load(response)
            assert result["choices"][0]["message"]["content"] == response_marker, "synthetic completion failed"
            authorization = "Basic "+base64.b64encode(b"metadata-admin:metadata-password-fixture").decode()
            for _ in range(100):
                request = urllib.request.Request(base+"/api/logs/stats?virtual_key_ids=metadata-agent", headers={"Authorization": authorization})
                with opener.open(request, timeout=3) as response:
                    stats = json.load(response)
                if stats.get("total_requests") == 1 and stats.get("total_tokens") == 7:
                    break
                time.sleep(.1)
            else:
                raise AssertionError("metadata aggregate did not retain one request / seven tokens")
            assert len(arrivals) == 1
        finally:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            provider.shutdown()
            provider.server_close()
    database = directory / "logs.db"
    assert database.is_file(), "persistent log database missing"
    with sqlite3.connect(database) as connection:
        dump = "\n".join(connection.iterdump())
    assert "metadata-agent" in dump, "persisted virtual-key attribution missing"
    for marker in (prompt_marker, response_marker):
        assert marker not in dump, "private content leaked to persisted logical records"
        for candidate in directory.glob("logs.db*"):
            assert marker.encode() not in candidate.read_bytes(), "private content leaked to raw log database/WAL bytes"
    print("PASS: one synthetic provider request; persisted scoped metadata and seven-token aggregate retained; unique prompt/response absent from logical and raw log database; content logging disabled")
