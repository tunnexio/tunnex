#!/usr/bin/env python3
"""Owned lab private HTTP/UDP service; no credentials or cloud calls."""
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import socket
import threading

LARGE_BODY = b'0123456789abcdef' * 4096
MAX_SOURCES = 16
MAX_COUNT = 9007199254740991
udp_lock = threading.Lock()
udp_sources = {}
udp_counts = {'echo_count': 0, 'unrecognized_source_count': 0, 'source_capacity_exceeded_count': 0}


def record_udp_source(raw):
    address = ipaddress.ip_address(raw)
    allowed = address.version == 4 and (
        address in ipaddress.ip_network('10.233.10.0/24')
        or raw in ('10.232.1.4', '10.231.1.4')
        or address in ipaddress.ip_network('172.16.0.0/12'))
    with udp_lock:
        udp_counts['echo_count'] = min(MAX_COUNT, udp_counts['echo_count'] + 1)
        if not allowed:
            udp_counts['unrecognized_source_count'] = min(MAX_COUNT, udp_counts['unrecognized_source_count'] + 1)
        elif raw not in udp_sources and len(udp_sources) >= MAX_SOURCES:
            udp_counts['source_capacity_exceeded_count'] = min(MAX_COUNT, udp_counts['source_capacity_exceeded_count'] + 1)
        else:
            current = udp_sources.setdefault(raw, {'client_ip': raw, 'count': 0})
            current['count'] = min(MAX_COUNT, current['count'] + 1)
            current['last_observed_at'] = datetime.now(timezone.utc).isoformat()


def udp_source_metadata():
    with udp_lock:
        return {**udp_counts, 'source_counts': [dict(udp_sources[key]) for key in sorted(udp_sources)]}


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        if self.path == '/large':
            body = LARGE_BODY
        else:
            body = json.dumps({'service': 'azure-s2s-owned-app', 'client_ip': self.client_address[0],
                               'udp_source_metadata': udp_source_metadata()}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream' if self.path == '/large' else 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def udp():
    connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connection.bind(('0.0.0.0', 8081))
    while True:
        payload, peer = connection.recvfrom(65535)
        connection.sendto(payload, peer)
        record_udp_source(peer[0])


if __name__ == '__main__':
    threading.Thread(target=udp, daemon=True).start()
    ThreadingHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
