#!/usr/bin/env python3
"""Nonshipping exact owned application lifecycle qualification; no DB writes."""
import argparse
import http.client
import socket
import ssl
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path('/Users/pawangupta/tunnex/tests/app-access-local')
CP = 'http://127.0.0.1:15174'
APP = '01a1024c-95f0-7819-8d70-33cde4c3ca1c'
ORG = '01a100fb-d59d-7adc-b21f-1275c4e4bc4d'

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def read_private(path):
    path = Path(path)
    if path.parent != ROOT / '.runtime' or '..' in path.parts:
        raise RuntimeError('Private owned artifact path required')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise RuntimeError('Private input refused')
    return json.loads(path.read_text())

def save_private(path, value):
    path = Path(path)
    if path.parent != ROOT / '.runtime' or '..' in path.parts:
        raise RuntimeError('Private owned output required')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(value, output, indent=2)
        output.flush()
        os.fsync(output.fileno())

class Client:
    def __init__(self, control):
        if control['cp_base_url'] != CP:
            raise RuntimeError('Owned CP endpoint refused')
        self.cookies = '; '.join(c['Name'] + '=' + c['Value'] for c in control['cp_cookies'])
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.evidence = []
    def call(self, method, suffix, body=None, expected=(200,)):
        if not suffix.startswith('/api/v1/organizations/' + ORG + '/'):
            raise RuntimeError('Owned tenant request refused')
        headers = {'Cookie': self.cookies, 'X-Tunnex-CSRF': '1'}
        data = None if body is None else json.dumps(body).encode()
        if data is not None:
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request(CP + suffix, data=data, headers=headers, method=method)
        started = time.time()
        try:
            response = self.opener.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status = response.code
            payload = response.read(1 << 20)
        result = json.loads(payload) if payload else None
        self.evidence.append({'method': method, 'path': suffix, 'status': status, 'started_unix': started, 'completed_unix': time.time(), 'error_code': result.get('error', {}).get('code') if isinstance(result, dict) else None})
        if status not in expected:
            raise RuntimeError('Product API status mismatch; retained safe evidence identifies request')
        return result

BASE = '/api/v1/organizations/' + ORG + '/app-access/applications/' + APP
FIELDS = ('name', 'description', 'icon', 'origin_url', 'gateway_id', 'public_hostname', 'idle_timeout_seconds', 'absolute_timeout_seconds', 'allowed_destination_cidrs')

def draft_input(application):
    value = {field: application['draft'][field] for field in FIELDS}
    value['expected_version'] = application['version']
    return value

def check(client, application):
    result = client.call('POST', BASE + '/checks', {'expected_version': application['version']}, (202,))
    deadline = time.monotonic() + 20
    while result['status'] in ('queued', 'running') and time.monotonic() < deadline:
        time.sleep(.5)
        result = client.call('GET', BASE + '/checks/' + result['id'])
    return result

def publish(client, application, checked):
    body = {'expected_version': application['version'], 'revision': application['draft']['revision'], 'digest': application['draft']['digest'], 'check_id': checked['id'], 'idempotency_key': str(uuid.uuid4())}
    operation = client.call('POST', BASE + '/publication-operations', body, (201,))
    deadline = time.monotonic() + 75
    while operation['status'] in ('queued', 'checking') and time.monotonic() < deadline:
        time.sleep(.5)
        operation = client.call('GET', BASE + '/publication-operations/' + operation['id'])
    if operation['status'] != 'activated':
        raise RuntimeError('Reviewed publication did not activate')
    state = client.call('GET', BASE + '/publication')
    if state['active']['revision'] != application['draft']['revision'] or state['active']['digest'] != application['draft']['digest']:
        raise RuntimeError('Active immutable revision mismatch')
    return state

def published_root(session_file):
    token = read_private(session_file)['app_session_token']
    hostname = 'payroll.apps.127.0.0.1.nip.io'
    context = ssl.create_default_context(cafile=str(ROOT / '.runtime/aa6-proxy/ca-cert.pem'))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    connection = http.client.HTTPSConnection(hostname, 443, context=context, timeout=10)
    raw = socket.create_connection(('127.0.0.1', 443), timeout=10)
    connection.sock = context.wrap_socket(raw, server_hostname=hostname)
    try:
        connection.request('GET', '/', headers={'Cookie': '__Host-tunnex_app_session=' + token})
        response = connection.getresponse()
        response.read(65536)
        if response.status != 200:
            raise RuntimeError('Published origin did not remain available through wrong draft CA')
        return response.status
    finally:
        connection.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--phase', choices=('failed-edit', 'wrong-ca', 'restore-publish', 'disable', 'reenable', 'rollback', 'archive'), required=True)
    parser.add_argument('--evidence-file', required=True)
    parser.add_argument('--session-file', default=str(ROOT / '.runtime/aa8-day2-session.json'))
    args = parser.parse_args()
    if os.environ.get('APP_ACCESS_OWNED_PROJECT') != 'tunnex-app-access-aa0-1003' or os.environ.get('APP_ACCESS_OWNED_CHECKOUT') != str(ROOT):
        raise RuntimeError('Owned context required')
    subprocess.run([str(ROOT / 'ownership.py')], check=True, stdout=subprocess.DEVNULL)
    control = read_private(ROOT / '.runtime/aa8-admin-control.json')
    client = Client(control)
    output = {'phase': args.phase, 'org_id': ORG, 'app_id': APP}
    try:
        application = client.call('GET', BASE)
        before = client.call('GET', BASE + '/publication')
        output['before'] = before
        if args.phase == 'failed-edit':
            save_private(ROOT / '.runtime/aa8-day2-baseline.json', application)
            body = draft_input(application)
            origin = urllib.parse.urlsplit(body['origin_url'])
            if origin.hostname != 'origin-app-fixture':
                raise RuntimeError('Owned origin required')
            body['origin_url'] = urllib.parse.urlunsplit((origin.scheme, 'origin-app-fixture:1', origin.path, origin.query, ''))
            edited = client.call('PATCH', BASE, body)
            failed = check(client, edited)
            if failed['status'] not in ('failed', 'expired'):
                raise RuntimeError('Unreachable draft did not fail check')
            client.call('POST', BASE + '/publication-operations', {'expected_version': edited['version'], 'revision': edited['draft']['revision'], 'digest': edited['draft']['digest'], 'check_id': failed['id'], 'idempotency_key': str(uuid.uuid4())}, (409,))
            after = client.call('GET', BASE + '/publication')
            if before['active'] != after['active']:
                raise RuntimeError('Failed reviewed edit changed active authority')
            output['failed_check'] = failed
        elif args.phase == 'wrong-ca':
            body = draft_input(application)
            old_ca = ROOT / '.runtime/origin/origin-ca-before-aa8.pem'
            if not old_ca.is_file() or old_ca.is_symlink() or old_ca.stat().st_size > 32768:
                raise RuntimeError('Retained public fixture CA refused')
            body['origin_ca_pem'] = old_ca.read_text()
            edited = client.call('PATCH', BASE, body)
            failed = check(client, edited)
            if failed['status'] != 'failed' or failed['tls_status'] != 'failed':
                raise RuntimeError('Wrong CA did not fail actual origin TLS')
            client.call('POST', BASE + '/publication-operations', {'expected_version': edited['version'], 'revision': edited['draft']['revision'], 'digest': edited['draft']['digest'], 'check_id': failed['id'], 'idempotency_key': str(uuid.uuid4())}, (409,))
            after = client.call('GET', BASE + '/publication')
            if before['active'] != after['active']:
                raise RuntimeError('Wrong CA changed active authority')
            output['failed_check'] = failed
            output['preserved_active_root_status'] = published_root(args.session_file)
        elif args.phase == 'restore-publish':
            original = read_private(ROOT / '.runtime/aa8-day2-baseline.json')
            body = draft_input(original)
            body['expected_version'] = application['version']
            body['origin_ca_pem'] = (ROOT / '.runtime/origin/origin-ca.pem').read_text()
            restored = client.call('PATCH', BASE, body)
            checked = check(client, restored)
            if checked['status'] != 'succeeded':
                raise RuntimeError('Restored reviewed origin failed')
            after = publish(client, restored, checked)
        elif args.phase == 'disable':
            after = client.call('POST', BASE + '/publication/disable', {'expected_application_version': before['application_version'], 'expected_authority_version': before['active']['authority_version']})
            if after['active']['state'] != 'disabled' or not after['active']['withdrawal_confirmed']:
                raise RuntimeError('Withdrawal not durably confirmed')
        elif args.phase == 'reenable':
            if before['active']['state'] != 'disabled':
                raise RuntimeError('Reenable requires reviewed disabled state')
            checked = check(client, application)
            if checked['status'] != 'succeeded':
                raise RuntimeError('Fresh reenable origin check failed')
            after = publish(client, application, checked)
        elif args.phase == 'rollback':
            original = read_private(ROOT / '.runtime/aa8-day2-baseline.json')
            revision = original['draft']['revision']
            if not any(r['revision'] == revision for r in before['rollback_revisions']):
                raise RuntimeError('Reviewed revision not retained as previously activated')
            rolled = client.call('POST', BASE + '/rollback-draft', {'expected_version': application['version'], 'revision': revision})
            if rolled['draft']['revision'] <= application['draft']['revision']:
                raise RuntimeError('Rollback was not a new immutable draft')
            checked = check(client, rolled)
            if checked['status'] != 'succeeded':
                raise RuntimeError('Fresh rollback check failed')
            after = publish(client, rolled, checked)
        else:
            if before['active']['state'] != 'disabled' or not before['active']['withdrawal_confirmed']:
                raise RuntimeError('Archive requires disabled confirmed withdrawal')
            client.call('DELETE', BASE + '?expected_version=' + str(application['version']), expected=(204,))
            archived = client.call('GET', BASE)
            if archived['state'] != 'archived':
                raise RuntimeError('Retained archive readback mismatch')
            after = client.call('GET', BASE + '/publication')
        output['after'] = after
        output['events'] = client.call('GET', '/api/v1/organizations/' + ORG + '/app-access/events?app_id=' + APP + '&limit=100')
        output['audits'] = client.call('GET', '/api/v1/organizations/' + ORG + '/audit-logs?target_type=app_access&target_id=' + APP + '&limit=100')
        if not output['audits'] or any(row.get('target_type') != 'app_access' or row.get('target_id') != APP for row in output['audits']):
            raise RuntimeError('Application configuration audit readback empty or incorrectly scoped')
        if any(row.get('app_id') != APP for row in output['events']['items']):
            raise RuntimeError('Application authority events incorrectly scoped')
        output['audit_scope'] = {'target_type': 'app_access', 'target_id': APP, 'includes_grant_audits': False}
        output['event_scope'] = {'app_id': APP, 'empty_allowed_for_configuration_only_phase': True}
        output['passed'] = True
    finally:
        output['requests'] = client.evidence
        save_private(args.evidence_file, output)
    print(json.dumps({'phase': args.phase, 'passed': True, 'evidence_file': args.evidence_file}))

if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Owned day-two qualification refused; inspect private evidence without printing credentials')
