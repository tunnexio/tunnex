#!/usr/bin/env python3
"""Loopback-only MCP fixture. Synthetic credentials; no external tools or data."""
import argparse
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--cert", required=True)
parser.add_argument("--key", required=True)
parser.add_argument("--token-file", required=True)
parser.add_argument("--port", type=int, default=54931)
args = parser.parse_args()
token = Path(args.token_file).read_text().strip()
lock = threading.Lock()
counts = {"initialize": 0, "tools/list": 0, "tools/call": 0, "calls": []}
tools = [
    {"name": "read_issue", "description": "Read a synthetic issue.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "write_issue", "description": "Update a synthetic issue.", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "delete_issue", "description": "Delete a synthetic issue.", "inputSchema": {"type": "object", "properties": {}}},
]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # Never log authentication headers or request bodies.

    def reply(self, status, body=None, session=False):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if session:
            self.send_header("Mcp-Session-Id", "fixture-session")
        self.end_headers()
        if body is not None:
            self.wfile.write(json.dumps(body).encode())

    def do_GET(self):
        if self.path == "/stats":
            with lock:
                self.reply(200, counts)
        else:
            self.reply(404)

    def do_POST(self):
        if self.path not in ("/mcp", "/second-page-fails", "/denied"):
            return self.reply(404)
        if self.headers.get("Authorization") != "Bearer " + token:
            return self.reply(401, {"error": "fixture authentication required"})
        if self.path == "/denied":
            return self.reply(403, {"error": "fixture access denied"})
        size = int(self.headers.get("Content-Length", "0"))
        if size > 65536:
            return self.reply(413)
        try:
            request = json.loads(self.rfile.read(size))
        except (ValueError, UnicodeError):
            return self.reply(400)
        method = request.get("method")
        if method != "initialize" and (self.headers.get("Mcp-Session-Id") != "fixture-session" or self.headers.get("MCP-Protocol-Version") != "2025-11-25"):
            return self.reply(400, {"error": "fixture session or protocol missing"})
        with lock:
            if method in counts:
                counts[method] += 1
        if method == "initialize":
            result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}, "serverInfo": {"name": "local-mcp-fixture", "version": "1"}}
        elif method == "notifications/initialized":
            if "id" in request:
                return self.reply(400)
            return self.reply(202)
        elif method == "tools/list":
            cursor = request.get("params", {}).get("cursor")
            if cursor and self.path == "/second-page-fails":
                return self.reply(403, {"error": "fixture later-page refusal"})
            result = {"tools": tools[1:]} if cursor == "page-2" else {"tools": tools[:1], "nextCursor": "page-2"}
        elif method == "tools/call":
            name = request.get("params", {}).get("name")
            with lock:
                counts["calls"].append(name)
            result = {"content": [{"type": "text", "text": "Synthetic fixture result for " + str(name)}], "isError": False}
        else:
            return self.reply(400)
        self.reply(200, {"jsonrpc": "2.0", "id": request.get("id"), "result": result}, method == "initialize")


server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain(args.cert, args.key)
server.socket = tls.wrap_socket(server.socket, server_side=True)
print(f"Local MCP fixture listening at https://127.0.0.1:{args.port}/mcp", flush=True)
server.serve_forever()
