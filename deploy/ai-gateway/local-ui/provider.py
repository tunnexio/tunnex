"""Zero-spend OpenAI-compatible UI fixture. No outbound calls or prompt logging."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
import os
import time
import uuid

KEY = os.environ.get("AI_FIXTURE_KEY", "")
if not KEY:
    raise RuntimeError("Local fixture credential is not configured")
MODELS = ["local-fixture-chat", "local-fixture-code", "local-fixture-embedding"]
RESPONSE = "Local fixture response. No external AI model was called. This simulated answer is for UI and workflow review."


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send_json(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def authorized(self):
        if not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + KEY):
            self.send_json(401, {"error": {"message": "Local fixture credential required", "type": "authentication_error"}})
            return False
        return True

    def do_GET(self):
        if self.path == "/health":
            return self.send_json(200, {"status": "ok", "fixture": True, "external_requests": False})
        if not self.authorized():
            return
        path = self.path.split("?", 1)[0]
        if path == "/v1/auth/key":
            return self.send_json(200, {"data": {"label": "Local UI fixture", "is_free_tier": True, "limit": None}})
        if path in ("/v1/models", "/models"):
            return self.send_json(200, {"object": "list", "data": [{"id": model, "name": model, "object": "model", "created": 0, "owned_by": "local-ui-fixture"} for model in MODELS]})
        self.send_json(404, {"error": {"message": "Fixture route unavailable"}})

    def do_POST(self):
        if not self.authorized():
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self.send_json(400, {"error": {"message": "Invalid fixture request"}})
        if size <= 0 or size > 262144:
            return self.send_json(400, {"error": {"message": "Invalid fixture request"}})
        try:
            body = json.loads(self.rfile.read(size))
        except (ValueError, TypeError):
            return self.send_json(400, {"error": {"message": "Invalid fixture request"}})
        if not isinstance(body, dict):
            return self.send_json(400, {"error": {"message": "Invalid fixture request"}})
        model = body.get("model", "")
        if model not in MODELS:
            return self.send_json(404, {"error": {"message": "Only local fixture models are available", "type": "invalid_request_error"}})
        path = self.path.split("?", 1)[0]
        if path in ("/v1/embeddings", "/embeddings"):
            if model != "local-fixture-embedding":
                return self.send_json(400, {"error": {"message": "This fixture model does not support embeddings"}})
            values = body.get("input", "")
            count = len(values) if isinstance(values, list) else 1
            return self.send_json(200, {"object": "list", "model": model, "data": [{"object": "embedding", "index": i, "embedding": [0.125, -0.25, 0.5, 0.0]} for i in range(count)], "usage": {"prompt_tokens": 8 * count, "total_tokens": 8 * count}})
        if path not in ("/v1/chat/completions", "/chat/completions", "/v1/completions", "/completions"):
            return self.send_json(404, {"error": {"message": "Fixture operation unavailable"}})
        if model == "local-fixture-embedding":
            return self.send_json(400, {"error": {"message": "This fixture model supports embeddings only"}})
        completion = path.endswith("/completions") and "/chat/" not in path
        request_id = "local-fixture-" + uuid.uuid4().hex
        usage = {"prompt_tokens": 8, "completion_tokens": 24, "total_tokens": 32}
        if not body.get("stream"):
            choice = {"index": 0, "finish_reason": "stop", "text": RESPONSE} if completion else {"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": RESPONSE}}
            return self.send_json(200, {"id": request_id, "object": "text_completion" if completion else "chat.completion", "created": int(time.time()), "model": model, "choices": [choice], "usage": usage})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            for chunk in ["Local fixture response. ", "No external AI model was called. ", "This simulated answer is for UI and workflow review."]:
                choice = {"index": 0, "text": chunk, "finish_reason": None} if completion else {"index": 0, "delta": {"content": chunk}, "finish_reason": None}
                self.wfile.write(("data: " + json.dumps({"id": request_id, "object": "text_completion" if completion else "chat.completion.chunk", "created": int(time.time()), "model": model, "choices": [choice]}) + "\n\n").encode())
                self.wfile.flush()
            choice = {"index": 0, "text": "", "finish_reason": "stop"} if completion else {"index": 0, "delta": {}, "finish_reason": "stop"}
            self.wfile.write(("data: " + json.dumps({"id": request_id, "object": "text_completion" if completion else "chat.completion.chunk", "created": int(time.time()), "model": model, "choices": [choice], "usage": usage}) + "\n\ndata: [DONE]\n\n").encode())
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass


ThreadingHTTPServer(("0.0.0.0", 8090), Handler).serve_forever()
