#!/usr/bin/env python3
"""Owned lab private HTTP/UDP service; no credentials or cloud calls."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json,socket,threading
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body=json.dumps({'service':'azure-s2s-owned-app','client_ip':self.client_address[0]}).encode()
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass
def udp():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',8081))
    while True:
        payload,peer=s.recvfrom(65535);s.sendto(payload,peer)
threading.Thread(target=udp,daemon=True).start()
ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()
