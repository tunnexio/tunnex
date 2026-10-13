#!/usr/bin/env python3
"""Owned local emulator HTTP fixture; no forwarding, storage, or request logs."""
import argparse
import hashlib
import ipaddress
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BYTES = 1024 * 1024
PATTERN = bytes(range(256))


def payload(length):
    return (PATTERN * ((length + 255) // 256))[:length]


def handler(marker):
    class Receiver(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, *_args):
            pass

        def reply(self, status, body, content_type='application/octet-stream'):
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('X-Payload-SHA256', hashlib.sha256(body).hexdigest())
            self.send_header('Connection', 'close')
            self.end_headers()
            self.close_connection = True
            self.wfile.write(body)

        def do_GET(self):
            if self.path == '/':
                self.reply(200, marker.encode('utf-8'), 'text/plain; charset=utf-8')
                return
            prefix = '/bytes/'
            size = self.path[len(prefix):] if self.path.startswith(prefix) else ''
            if not size.isascii() or not size.isdecimal() or len(size) > 7:
                self.reply(404, b'Unknown payload path')
                return
            length = int(size)
            if length > MAX_BYTES:
                self.reply(413, b'Payload exceeds 1 MiB')
                return
            self.reply(200, payload(length))

        def do_POST(self):
            if self.path != '/upload':
                self.reply(404, b'Unknown upload path')
                return
            sizes = self.headers.get_all('Content-Length', [])
            if self.headers.get('Transfer-Encoding') is not None or len(sizes) != 1:
                self.reply(400, b'One Content-Length required; chunked uploads unsupported')
                return
            size = sizes[0]
            if not size.isascii() or not size.isdecimal() or len(size) > 7:
                self.reply(400, b'Invalid Content-Length')
                return
            length = int(size)
            if length > MAX_BYTES:
                self.reply(413, b'Payload exceeds 1 MiB')
                return
            try:
                body = self.rfile.read(length)
            except (TimeoutError, OSError):
                self.reply(408, b'Upload timed out')
                return
            if len(body) != length:
                self.reply(400, b'Incomplete upload')
                return
            receipt = json.dumps({'received_length': length, 'received_sha256': hashlib.sha256(body).hexdigest()}, sort_keys=True).encode('ascii')
            self.reply(200, receipt, 'application/json')
    return Receiver


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--listen', required=True, help='Explicit owned IPv4:port; no wildcard bind')
    parser.add_argument('--marker', default='TUNNEX_OWNED_LOCAL_PAYLOAD_RECEIVER')
    args = parser.parse_args()
    try:
        address, port_text = args.listen.rsplit(':', 1)
        ip = ipaddress.IPv4Address(address)
        port = int(port_text)
        if ip.is_unspecified or ip.is_multicast or not 1 <= port <= 65535:
            raise ValueError('invalid bind')
    except ValueError:
        parser.error('--listen must name an explicit owned IPv4 address and port 1..65535')
    if len(args.marker.encode('utf-8')) > 4096:
        parser.error('--marker exceeds 4096 bytes')
    server = ThreadingHTTPServer((str(ip), port), handler(args.marker))
    server.daemon_threads = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
