#!/usr/bin/env python3
"""Reviewed Azure lab activation; normal owner API, no cloud commands.

Run on the enrolled peer after forwarding its normal API to localhost:48083.
Inputs: private ui-accounts.json, api-setup.json, and a separate PSK file.
Create leaves intent disabled. Enable is a separate, explicit CAS operation.
No credentials, PSKs, response bodies, or application content are printed.
"""
import argparse
import http.cookiejar
import ipaddress
import json
import os
import socket
import stat
import urllib.error
import urllib.request
import uuid

API = 'http://127.0.0.1:48083'


def private_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('input must be an owned private regular file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(262145)
        if len(data) > 262144:
            raise ValueError('private input exceeds limit')
        return data
    finally:
        os.close(fd)


def private_write(path, value):
    temporary = path + '.' + uuid.uuid4().hex
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Client:
    def __init__(self):
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, method, path, body=None, revision=None):
        headers = {'Origin': API, 'X-Tunnex-CSRF': '1'}
        if body is not None:
            headers['Content-Type'] = 'application/json'
        if revision is not None:
            headers['If-Match'] = '"' + str(int(revision)) + '"'
        request = urllib.request.Request(API + path, None if body is None else json.dumps(body).encode(), headers, method=method)
        try:
            with self.opener.open(request, timeout=30) as response:
                data = response.read(1048577)
                if len(data) > 1048576:
                    raise ValueError('API response exceeds limit')
                return json.loads(data) if data else None
        except urllib.error.HTTPError as error:
            raise ValueError('API request failed with HTTP ' + str(error.code)) from None
        except urllib.error.URLError:
            raise ValueError('API transport unavailable') from None


def configuration(psk):
    return {
        'profile_id': 'azure-active-active-bgp-ipv4-v1',
        'azure': {'gateway_sku': 'VpnGw1AZ', 'vpn_type': 'RouteBased', 'ike_version': 2,
                  'custom_policy': 'aes256-sha256-dh14-pfs2048',
                  'use_policy_based_traffic_selectors': False, 'nat_enabled': False},
        'mode': 'ipv4-bgp', 'customer_outside_address': '20.219.28.146',
        'local_prefixes': ['10.233.10.0/24'], 'remote_prefixes': ['10.231.0.0/16'],
        'tunnels': [dict(outside_address=outside, inside_cidr='169.254.10.1/32',
                         customer_inside_address='169.254.10.1', cloud_inside_address=inside, psk=psk)
                    for outside, inside in [('52.140.60.21', '169.254.21.2'), ('20.219.125.34', '169.254.22.2')]],
        'bgp': {'local_asn': 65000, 'remote_asn': 65515, 'router_id': '10.233.10.1', 'maximum_prefixes': 8}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['plan', 'create', 'enable', 'status'])
    parser.add_argument('--private-root', required=True)
    parser.add_argument('--psk-file')
    parser.add_argument('--application-address')
    parser.add_argument('--application-port', type=int, default=80)
    args = parser.parse_args()
    root = os.path.abspath(args.private_root)
    info = os.lstat(root)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('private root must be an owned private directory')
    if args.phase == 'plan':
        config = configuration('redacted')
        for tunnel in config['tunnels']:
            del tunnel['psk']
        print(json.dumps({'configuration': config, 'application_reachability': 'not_probed'}, sort_keys=True))
        return
    accounts = json.loads(private_read(root + '/ui-accounts.json'))
    setup = json.loads(private_read(root + '/api-setup.json'))
    # Match the normal local enrollment helper account schema.
    if isinstance(accounts, dict):
        accounts = accounts.get('accounts', list(accounts.values()))
    owner = next(a for a in accounts if a.get('email') == 'browser-owner@azure-s2s.local')
    client = Client()
    client.call('POST', '/api/v1/auth/login', {'email': owner['email'], 'password': owner['password']})
    client.call('GET', '/api/v1/auth/me')
    organizations = client.call('GET', '/api/v1/organizations')
    if isinstance(organizations, dict):
        organizations = organizations.get('organizations', [])
    if not any(o['id'] == setup['org_id'] and o['slug'] == 'azure-s2s-local' for o in organizations):
        raise ValueError('owned lab organization mismatch')
    for key in ['org_id', 'site_id', 'gateway_id']:
        uuid.UUID(setup[key])
    prefix = '/api/v1/organizations/' + setup['org_id'] + '/ipsec'
    state_path = root + '/azure-live-activation.json'
    if args.phase == 'create':
        if not args.psk_file:
            raise ValueError('create requires a private PSK file')
        psk = private_read(args.psk_file).decode().rstrip('\r\n')
        if not 8 <= len(psk) <= 64 or any(ord(c) < 32 or ord(c) == 127 for c in psk):
            raise ValueError('invalid private PSK input')
        config = configuration(psk)
        client.call('POST', prefix + '/configuration-check', config)
        if os.path.exists(state_path):
            raise ValueError('activation state already exists; inspect status before retrying')
        state = {'id': str(uuid.uuid4()), 'tunnel_ids': [str(uuid.uuid4()), str(uuid.uuid4())]}
        private_write(state_path, state)
        client.call('POST', prefix + '/connections', dict(state, name='Azure owned live active-active BGP',
                    site_id=setup['site_id'], gateway_node_id=setup['gateway_id'], configuration=config))
    state = json.loads(private_read(state_path))
    path = prefix + '/connections/' + str(uuid.UUID(state['id']))
    connection = client.call('GET', path)
    if connection['gateway_node_id'] != setup['gateway_id'] or connection['site_id'] != setup['site_id']:
        raise ValueError('activation connection binding mismatch')
    if args.phase == 'enable':
        connection = client.call('PUT', path + '/intent', {'intent': 'enabled'}, connection['desired_revision'])
    status = client.call('GET', path + '/status')
    status['tunnels'] = [{k: t.get(k) for k in ['id', 'slot', 'status', 'selected']} for t in status.get('tunnels', [])]
    if status.get('bgp'):
        bgp = status['bgp']
        status['bgp'] = {k: bgp.get(k) for k in ['version', 'sequence']}
        status['bgp']['peers'] = [{k: p.get(k) for k in ['slot', 'state', 'accepted_prefixes', 'installed_prefixes', 'rejected_prefixes']} for p in bgp.get('peers', [])]
        status['bgp']['routes'] = [{k: r.get(k) for k in ['prefix', 'slot']} for r in bgp.get('routes', [])]
    output = {'connection': {k: connection.get(k) for k in ['id', 'desired_revision', 'desired_intent', 'application_state', 'cleanup_state']},
              'runtime': {k: status.get(k) for k in ['observed_at', 'recovery_version', 'active_slot', 'selection_sequence', 'tunnels', 'bgp']},
              'application_reachability': 'not_probed'}
    if args.application_address:
        address = ipaddress.IPv4Address(args.application_address)
        if address not in ipaddress.IPv4Network('10.231.0.0/16') or not 1 <= args.application_port <= 65535:
            raise ValueError('application probe must use the owned remote prefix and valid port')
        try:
            with socket.create_connection((str(address), args.application_port), timeout=5):
                output['application_reachability'] = 'tcp_connected'
        except OSError:
            output['application_reachability'] = 'tcp_unavailable'
    print(json.dumps(output, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, StopIteration, OSError, UnicodeError):
        # Do not expose exceptions that could contain credentials or response content.
        print(json.dumps({'error': 'activation failed; inspect private inputs, API availability, and current desired revision'}))
        raise SystemExit(1)
