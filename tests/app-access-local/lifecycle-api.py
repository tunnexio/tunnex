#!/usr/bin/env python3
"""Nonshipping owned local lifecycle API client; never logs credentials.

Callers choose explicit reviewed mutations and coordinate the protocol driver.
Recorded request-start and response-completion bracket the durable mutation;
response-completion is not labeled database commit. No automatic retries.
"""
import datetime
import http.client
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT / '.runtime'
PROJECT = 'tunnex-app-access-aa0-1003'


def private_json(path):
    path = Path(path)
    if path.is_symlink() or path.resolve(strict=True).parent != RUNTIME.resolve(strict=True) or path.stat().st_mode & 0o777 != 0o600:
        raise ValueError('owned private artifact required')
    return json.loads(path.read_text())


class OwnedClient:
    def __init__(self, control_file):
        subprocess.run([str(ROOT / 'ownership.py')], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.control = private_json(control_file)
        if self.control.get('cp_base_url') != 'http://127.0.0.1:15174':
            raise ValueError('exact owned control plane required')
        self.actor = str(uuid.UUID(self.control['user_id']))
        self.org = str(uuid.UUID(private_json(RUNTIME / 'aa8-direct-identity.json')['org_id']))
        self.cookie = '; '.join(cookie['Name'] + '=' + cookie['Value'] for cookie in self.control['cp_cookies'])
        if '\r' in self.cookie or '\n' in self.cookie:
            raise ValueError('invalid private cookie artifact')

    def request(self, method, path, body=None, *, label, before_send=None):
        if method not in {'GET', 'POST', 'PATCH', 'DELETE'} or not re.fullmatch(r'[a-z0-9_-]{1,60}', label):
            raise ValueError('explicit bounded lifecycle request required')
        scoped = '/api/v1/organizations/' + self.org + '/'
        if not path.startswith(scoped) and path != '/api/v1/auth/logout':
            raise ValueError('exact owned organization required')
        if '\r' in path or '\n' in path:
            raise ValueError('invalid local request')
        started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        mono_start = time.monotonic_ns()
        connection = http.client.HTTPConnection('127.0.0.1', 15174, timeout=15)
        try:
            if before_send is not None:
                before_send(started)
            connection.request(method, path, None if body is None else json.dumps(body),
                               {'Cookie': self.cookie, 'X-Tunnex-CSRF': '1', 'Content-Type': 'application/json'})
            response = connection.getresponse()
            raw = response.read(1024 * 1024 + 1)
            completed = datetime.datetime.now(datetime.timezone.utc).isoformat()
            mono_completed = time.monotonic_ns()
            if len(raw) > 1024 * 1024:
                raise ValueError('bounded response exceeded')
            try:
                decoded = json.loads(raw) if raw else None
            except ValueError:
                decoded = {'non_json_response': True}
            event = {'label': label, 'method': method, 'path': path, 'actor_user_id': self.actor,
                     'request_started_at': started, 'response_completed_at': completed,
                     'request_started_monotonic_ns': mono_start,
                     'response_completed_monotonic_ns': mono_completed,
                     'status': response.status, 'response': decoded,
                     'timing_scope': 'request-start and response-completion; no claimed commit timestamp'}
            evidence = RUNTIME / ('aa8-' + label + '-' + str(uuid.uuid4()) + '.json')
            with open(evidence, 'x', opener=lambda name, flags: os.open(name, flags, 0o600)) as out:
                json.dump(event, out, indent=2)
                out.flush()
                os.fsync(out.fileno())
            return response.status, decoded, evidence, event
        finally:
            connection.close()


def marker(trigger, evidence, event):
    """Only send after the corresponding real operation succeeds and is retained."""
    if event['method'] not in {'POST', 'PATCH', 'DELETE'} or event['status'] < 200 or event['status'] >= 300:
        raise ValueError('failed request cannot be labeled an authority mutation')
    return {'trigger': trigger, 'evidence_ref': str(evidence),
            'mutation_started_at': event['request_started_at'],
            'mutation_completed_at': event['response_completed_at']}
