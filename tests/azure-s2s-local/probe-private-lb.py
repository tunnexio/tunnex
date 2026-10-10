#!/usr/bin/env python3
"""Owned LB HTTP observation only; run in the approved office DNS namespace."""
import argparse
from datetime import datetime, timezone
import http.client
import importlib.util
import json
import math
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

HOST = 'lbapp.azure-s2s.test'
TARGET = '10.231.1.10'
SOURCE = '10.233.10.2'
spec = importlib.util.spec_from_file_location('azure_packet_identity', Path(__file__).with_name('probe-packets.py'))
identity_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity_module)
observed_http_identity = identity_module.observed_http_identity

def stamp():
    return datetime.now(timezone.utc).isoformat()

def bounds(seconds, timeout):
    if not 1 <= seconds <= 60 or not math.isfinite(timeout) or not .2 <= timeout <= 2:
        raise ValueError('Bounded duration/timeout required')

def allowed_answers(answers):
    return bool(answers) and set(answers) == {TARGET}

def resolve(timeout):
    # Normal libc getaddrinfo in a bounded subprocess, using namespace DNS.
    code = "import json,socket; print(json.dumps(sorted({v[4][0] for v in socket.getaddrinfo('lbapp.azure-s2s.test',8080,0,socket.SOCK_STREAM)})))"
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, timeout=timeout, check=True)
    answers = json.loads(result.stdout)
    if not isinstance(answers, list) or not allowed_answers(answers):
        raise ValueError('Owned LB DNS answer required')
    return TARGET

def project(status, body):
    identity = observed_http_identity(body, SOURCE)
    return {**identity, 'http_status': status,
            'success': status == 200 and identity['owned_service_confirmed'] and identity['source_preservation'] == 'preserved'}

def socket_identity(connection, previous_port):
    reused = connection is not None and connection.sock is not None
    port = connection.sock.getsockname()[1] if reused else None
    return {'reused_existing_socket': reused, 'local_port': port,
            'same_local_port_as_previous_persistent': reused and port == previous_port}

def write_receipt(path, value):
    path = path.absolute()
    if any(p.is_symlink() for p in (path, *path.parents)) or not path.parent.is_dir():
        raise ValueError('Owned existing receipt directory required')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=15)
    parser.add_argument('--timeout', type=float, default=1)
    args = parser.parse_args()
    bounds(args.seconds, args.timeout)
    if args.receipt.exists() or any(p.is_symlink() for p in (args.receipt, *args.receipt.absolute().parents)):
        raise ValueError('New owned receipt required')
    check = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        check.bind((SOURCE, 0))
    finally:
        check.close()
    started = time.monotonic()
    end = started + args.seconds
    receipt = {'started_at': stamp(), 'hostname': HOST, 'expected_address': TARGET,
               'source_address': SOURCE, 'tcp_port': 8080, 'seconds': args.seconds,
               'scope': 'Actual DNS/HTTP observations only; no grant, capability or readiness inference',
               'samples': [], 'counters': {k: {'success': 0, 'failure': 0} for k in ('fresh_http', 'persistent_http')}}
    persistent = None
    previous_port = None
    def alarm_handler(_signum, _frame):
        raise TimeoutError('bounded operation')
    previous_handler = signal.signal(signal.SIGALRM, alarm_handler)
    try:
        while time.monotonic() < end:
            tick = time.monotonic()
            for kind in ('fresh_http', 'persistent_http'):
                remaining = end - time.monotonic()
                if remaining <= 0:
                    break
                budget = min(args.timeout, remaining)
                entry = {'kind': kind, 'observed_at': stamp(), 'success': False}
                if kind == 'persistent_http':
                    entry.update(socket_identity(persistent, previous_port))
                else:
                    entry.update(reused_existing_socket=False, local_port=None, same_local_port_as_previous_persistent=False)
                connection = None
                before = time.monotonic()
                signal.setitimer(signal.ITIMER_REAL, budget)
                try:
                    resolve(budget)
                    entry['dns_expected_answer_confirmed'] = True
                    reused = kind == 'persistent_http' and persistent is not None and persistent.sock is not None
                    connection = persistent if reused else http.client.HTTPConnection(TARGET, 8080, timeout=budget, source_address=(SOURCE, 0))
                    if kind == 'persistent_http':
                        persistent = connection
                    connection.request('GET', '/', headers={'Host': HOST, 'Connection': 'keep-alive'})
                    port = connection.sock.getsockname()[1]
                    # Preserve observed socket identity even if response reading
                    # times out across revoke/expiry and cleanup closes it.
                    entry.update(local_port=port, reused_existing_socket=reused,
                                 same_local_port_as_previous_persistent=(reused and port == previous_port))
                    response = connection.getresponse()
                    body = response.read(16385)
                    entry.update(project(response.status, body))
                    entry.update(http_version=response.version, local_port=port, server_closes_connection=response.will_close,
                                 reused_existing_socket=reused, same_local_port_as_previous_persistent=(reused and port == previous_port))
                    if kind == 'persistent_http':
                        previous_port = port
                except (OSError, ValueError, http.client.HTTPException, subprocess.SubprocessError):
                    entry['error_code'] = 'dns_or_http_failed'
                    if kind == 'persistent_http' and persistent:
                        persistent.close()
                        persistent = None
                        previous_port = None
                finally:
                    signal.setitimer(signal.ITIMER_REAL, 0)
                    if kind == 'fresh_http' and connection:
                        connection.close()
                entry['elapsed_seconds'] = round(time.monotonic() - before, 6)
                receipt['samples'].append(entry)
                receipt['counters'][kind]['success' if entry['success'] else 'failure'] += 1
            time.sleep(min(max(0, 1 - (time.monotonic() - tick)), max(0, end - time.monotonic())))
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if persistent:
            persistent.close()
    receipt.update(finished_at=stamp(), elapsed_seconds=round(time.monotonic() - started, 6))
    write_receipt(args.receipt, receipt)
    print(json.dumps({'receipt': str(args.receipt), 'counters': receipt['counters']}))

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError):
        raise SystemExit('Owned probe prerequisite/input failed; no success claim')
