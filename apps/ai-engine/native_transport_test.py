"""Zero-spend private Bifrost extension test using synthetic local transports.

The caller builds the binary from the pinned source with build.py first. This
fixture uses no production credentials, external providers or paid inference.
"""
import base64
import http.client
import http.server
import json
import os
import pathlib
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

KEY = "fixture-provider-only"
ADMIN = "Basic " + base64.b64encode(b"fixture-admin:fixture-password").decode()
PROXY_AUTH = "Basic " + base64.b64encode(b"fixture-proxy:fixture-password").decode()
arrivals = []


class Provider(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        assert self.headers.get("Authorization") == "Bearer " + KEY
        assert self.path == "/v1/models"
        self.reply({"data": [{"id": "allowed"}, {"id": "draft-only"}]})

    def do_POST(self):
        assert self.headers.get("Authorization") == "Bearer " + KEY
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        payload = json.loads(body)
        arrivals.append((self.path, payload["model"]))
        if payload.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b'data: {"id":"fixture","choices":[{"index":0,"delta":{"content":"OK"}}]}\n\ndata: {"id":"fixture","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n')
            return
        self.reply({"id": "fixture", "object": "chat.completion", "model": payload["model"], "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "OK"}}], "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})

    def reply(self, payload):
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Proxy(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_CONNECT(self):
        if self.path != "provider.fixture:8080" or self.headers.get("Proxy-Authorization") != PROXY_AUTH:
            self.send_error(403)
            return
        with socket.create_connection(provider.server_address, timeout=3) as remote:
            self.send_response(200)
            self.end_headers()
            for sock in (self.connection, remote):
                sock.setblocking(False)
            until = time.monotonic() + 20
            while time.monotonic() < until:
                readable, _, _ = select.select((self.connection, remote), (), (), 1)
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    (remote if source is self.connection else self.connection).sendall(data)


def call(origin, method, path, payload=None, auth=True, vk=None):
    connection = http.client.HTTPConnection("127.0.0.1", origin, timeout=15)
    headers = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = ADMIN
    if vk:
        headers["X-Bf-Vk"] = vk
    connection.request(method, path, json.dumps(payload) if payload is not None else None, headers)
    response = connection.getresponse()
    raw = response.read(1 << 20)
    status = response.status
    connection.close()
    return status, raw


provider = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Provider)
proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
for server in (provider, proxy):
    threading.Thread(target=server.serve_forever, daemon=True).start()

with tempfile.TemporaryDirectory(prefix="tunnex-native-test-") as directory:
    root = pathlib.Path(directory)
    endpoint = "http://provider.fixture:8080"
    owned = "custom-" + str(uuid.uuid4())
    key_id = "tnx-managed-" + str(uuid.uuid4())
    virtual_key = "sk-bf-fixture-scoped-virtual-key"
    for name in ("prices.json", "params.json"):
        (root / name).write_text("{}")
    (root / "policy.json").write_text(json.dumps({"endpoints": [{"url": endpoint, "provider": "custom"}]}))
    config = {
        "encryption_key": "fixture-encryption-key-32-bytes-only",
        "client": {"enforce_auth_on_inference": True, "disable_content_logging": True, "enable_logging": False},
        "config_store": {"enabled": True, "type": "sqlite", "config": {"path": str(root / "config.db")}},
        "framework": {"pricing": {"pricing_url": (root / "prices.json").as_uri(), "model_parameters_url": (root / "params.json").as_uri(), "live_models_sync_interval": 0, "mcp_library_sync_interval": 0}},
        "governance": {
            "auth_config": {"is_enabled": True, "admin_username": "fixture-admin", "admin_password": "fixture-password", "disable_auth_on_inference": False},
            "virtual_keys": [{"id": "fixture-policy", "name": "fixture-policy", "value": virtual_key, "is_active": True, "provider_configs": [{"provider": owned, "allowed_models": ["allowed"], "key_ids": [key_id], "weight": 1}]}],
        },
        "providers": {owned: {
            "network_config": {"base_url": endpoint, "allow_private_network": True, "max_retries": 0},
            "proxy_config": {"type": "http", "url": "env.TUNNEX_AI_CUSTOM_PROXY_URL"},
            "custom_provider_config": {"base_provider_type": "openai", "is_key_less": False, "allowed_requests": {"list_models": True, "chat_completion": True, "chat_completion_stream": True}},
            "keys": [{"id": key_id, "name": key_id + "-r1", "value": KEY, "models": ["allowed"], "enabled": True, "weight": 1}],
        }},
    }
    (root / "config.json").write_text(json.dumps(config))
    (root / "config.json").chmod(0o600)
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    env = dict(os.environ, TUNNEX_AI_CUSTOM_ENDPOINTS_FILE=str(root / "policy.json"), TUNNEX_AI_CUSTOM_PROXY_URL=f"http://fixture-proxy:fixture-password@127.0.0.1:{proxy.server_address[1]}")
    with (root / "native.log").open("wb") as log:
        process = subprocess.Popen([sys.argv[1], "-host", "127.0.0.1", "-port", str(port), "-app-dir", directory, "-log-level", "error"], stdout=log, stderr=log, env=env)
    try:
        for _ in range(150):
            try:
                if call(port, "GET", "/health", auth=False)[0] == 200:
                    break
            except OSError:
                pass
            assert process.poll() is None, "native engine failed to start"
            time.sleep(.1)
        else:
            raise AssertionError("native engine readiness timed out")
        path = f"/api/providers/{owned}/keys/{key_id}"
        code, before = call(port, "GET", path)
        assert code == 200 and KEY.encode() not in before
        payload = {"provider": "custom", "model": "draft-only", "mode": "chat", "key_name": key_id + "-r1", "endpoint_url": endpoint}
        # Authentication, revision and endpoint mismatches have zero arrivals.
        expected_arrivals = len(arrivals)
        for changed, auth, want in [(payload, False, 401), ({**payload, "key_name": key_id + "-r2"}, True, 409), ({**payload, "endpoint_url": "https://other.fixture"}, True, 409), ({**payload, "api_key": "injected"}, True, 409)]:
            status, raw = call(port, "POST", path + "/test-connection", changed, auth=auth)
            # Unknown injected key is rejected before any provider request.
            assert status in ({400, 409} if "api_key" in changed else {want}), (status, want)
            assert KEY.encode() not in raw
        assert len(arrivals) == expected_arrivals
        status, raw = call(port, "POST", path + "/test-connection", payload)
        assert status == 200 and json.loads(raw)["status"] == "success", (status, raw)
        assert call(port, "GET", path)[1] == before, "saved test mutated serving key/model scope"
        assert KEY.encode() not in raw
        draft = {k: v for k, v in payload.items() if k != "key_name"}
        draft["api_key"] = KEY
        status, raw = call(port, "POST", "/api/tunnex/test-connection", draft)
        assert status == 200 and json.loads(raw)["status"] == "success", (status, raw)
        catalog = {"provider": "custom", "mode": "chat", "api_key": KEY, "endpoint_url": endpoint, "query": "", "limit": 50, "offset": 0}
        status, raw = call(port, "POST", "/api/tunnex/model-catalog", catalog)
        result = json.loads(raw)
        assert status == 200 and [row["id"] for row in result["items"]] == ["allowed", "draft-only"], (status, raw)
        expected_arrivals = len(arrivals)
        serving = {"model": owned + "/draft-only", "messages": [{"role": "user", "content": "OK"}], "max_tokens": 8}
        status,raw=call(port, "POST", "/v1/chat/completions", serving, auth=False, vk=virtual_key)
        assert status == 403, (status,raw)
        assert len(arrivals) == expected_arrivals, "unauthorized model reached provider"
        serving["model"] = owned + "/allowed"
        assert call(port, "POST", "/v1/chat/completions", serving, auth=False)[0] == 401
        for stream in (False, True):
            status, raw = call(port, "POST", "/v1/chat/completions", {**serving, "stream": stream}, auth=False, vk=virtual_key)
            assert status == 200 and (b"[DONE]" in raw if stream else json.loads(raw)["choices"][0]["message"]["content"] == "OK"), (status, raw)
            assert KEY.encode() not in raw
        assert call(port, "GET", path)[1] == before
        print("Native Bifrost: authenticated draft/catalog, saved-key scope preservation, VK denial, serving and streaming passed.")
    finally:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
for server in (provider, proxy):
    server.shutdown()
