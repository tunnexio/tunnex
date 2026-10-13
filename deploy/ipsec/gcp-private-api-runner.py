#!/usr/bin/env python3
"""Explicitly invoked private normal API preparation through the owned bastion."""
import argparse
import ipaddress
import json
import os
import shlex
import stat
import subprocess
import sys
import unicodedata
import urllib.error
import urllib.request
import uuid

BASTION = 'cyberking9560@34.131.23.179'
ORG = '01a124e7-60c7-78ca-aa85-d3a5025d9764'
ROOT = '/home/cyberking9560/tn-gcps2s-20261010'
PROFILES = {'gcp-ha-bgp-ipv4-v1': ('ipv4-bgp', ['ha-0', 'ha-1'], '10.80.0.0/24'),
            'gcp-classic-static-ipv4-v1': ('ipv4-static', ['classic-0'], '10.81.0.0/24')}
GATEWAY_SSH = ['ssh', '-i', '/home/cyberking9560/.ssh/google_compute_engine',
               '-o', 'UserKnownHostsFile=/home/cyberking9560/.ssh/google_compute_known_hosts',
               '-o', 'HostKeyAlias=compute.1860325440445762510', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'CheckHostIP=no', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
               'cyberking9560@34.131.136.132']


def unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('duplicate JSON field')
        out[key] = value
    return out


def private_read(path, limit=128 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o600 or s.st_size > limit:
            raise ValueError('private file refused')
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise ValueError('private file refused')
        return data
    finally:
        os.close(fd)


def cookie_header(raw):
    cookies = []
    for line in raw.decode('utf-8').splitlines():
        if line.startswith('#HttpOnly_'):
            line = line[len('#HttpOnly_'):]
        elif not line or line.startswith('#'):
            continue
        columns = line.split('\t')
        if len(columns) != 7 or columns[0] not in ['127.0.0.1', 'localhost']:
            raise ValueError('scoped cookie refused')
        name, value = columns[5:]
        if not name or any(ch in name + value for ch in '\r\n;'):
            raise ValueError('cookie framing refused')
        cookies.append(name + '=' + value)
    if not cookies:
        raise ValueError('cookie absent')
    return '; '.join(cookies)


def nonzero_id(value):
    if not isinstance(value, str) or uuid.UUID(value).int == 0:
        raise ValueError('nonzero UUID required')


def payload(template, key_reader=private_read):
    if set(template) != {'id', 'name', 'site_id', 'gateway_node_id', 'tunnel_ids', 'configuration'}:
        raise ValueError('exact provider template required')
    for key in ['id', 'site_id', 'gateway_node_id']:
        nonzero_id(template[key])
    c = template['configuration']
    profile = c.get('profile_id')
    if profile not in PROFILES:
        raise ValueError('GCP profile required')
    mode, suffixes, remote = PROFILES[profile]
    expected = {'profile_id', 'mode', 'customer_outside_address', 'local_prefixes', 'remote_prefixes', 'tunnels'}
    if len(suffixes) == 2:
        expected.add('bgp')
    if set(c) != expected or c['mode'] != mode or c['customer_outside_address'] != '34.131.136.132' or c['local_prefixes'] != ['10.70.0.0/24'] or c['remote_prefixes'] != [remote]:
        raise ValueError('owned provider scope refused')
    if len(template['tunnel_ids']) != len(suffixes) or len(set(template['tunnel_ids'])) != len(suffixes) or len(c['tunnels']) != len(suffixes):
        raise ValueError('profile cardinality refused')
    for value in template['tunnel_ids']:
        nonzero_id(value)
    result = json.loads(json.dumps(template))
    for tunnel, suffix in zip(result['configuration']['tunnels'], suffixes):
        if set(tunnel) != {'outside_address', 'inside_cidr', 'customer_inside_address', 'cloud_inside_address'}:
            raise ValueError('secret-free tunnel template required')
        ipaddress.IPv4Address(tunnel['outside_address'])
        if len(suffixes) == 1 and any(tunnel[k] for k in ['inside_cidr', 'customer_inside_address', 'cloud_inside_address']):
            raise ValueError('Classic inside address refused')
        raw = key_reader(ROOT + '/tn-gcps2s-20261010-' + suffix + '.psk', 256)
        key = raw.decode('utf-8')
        # Original bytes are authoritative; ambiguous line framing must be corrected
        # in the creation source by the owner, never silently stripped here.
        if not 8 <= len(raw) <= 64 or not key.strip() or any(unicodedata.category(ch) == 'Cc' for ch in key):
            raise ValueError('raw PSK framing refused')
        tunnel['psk'] = key
    return result


def api(method, path, cookie, body):
    request = urllib.request.Request('http://127.0.0.1:48083/api/v1/organizations/' + ORG + path,
                                     data=json.dumps(body).encode(), method=method,
                                     headers={'Cookie': cookie, 'X-Tunnex-CSRF': '1', 'Content-Type': 'application/json'})
    # Never follow redirects carrying private authorization or PSKs.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=15) as response:
        if response.status not in [200, 201]:
            raise ValueError('normal API refused')
        raw = response.read(128 * 1024 + 1)
        if len(raw) > 128 * 1024:
            raise ValueError('bounded API response refused')
        return json.loads(raw, object_pairs_hook=unique)


def remote(packet):
    if set(packet) != {'action', 'cookie', 'input'} or not isinstance(packet['cookie'], str) or '\r' in packet['cookie'] or '\n' in packet['cookie']:
        raise ValueError('private request envelope refused')
    if packet['action'] == 'provider-create':
        data = payload(packet['input'])
        saved = api('POST', '/ipsec/connections', packet['cookie'], data)
        if saved.get('id') != data['id'] or saved.get('desired_intent') != 'disabled':
            raise ValueError('disabled save receipt refused')
        return {key: saved.get(key) for key in ['id', 'desired_revision', 'desired_intent', 'cleanup_state']}
    if packet['action'] != 'join-token' or packet['input'] != {'node_name': 'tn-gcps2s-20261010-gateway', 'enrols_kind': 'gateway'}:
        raise ValueError('exact gateway token input required')
    saved = api('POST', '/nodes/join-token', packet['cookie'], packet['input'])
    token = saved['join_token']
    if not isinstance(token, str) or not 16 <= len(token) <= 4096 or any(unicodedata.category(ch) == 'Cc' for ch in token):
        raise ValueError('private token framing refused')
    content = ('TUNNEX_JOIN_TOKEN=' + token + '\nTUNNEX_NODE_NAME=tn-gcps2s-20261010-gateway\n'
               'TUNNEX_API_URL=http://127.0.0.1:38083\nTUNNEX_AGENT_URL=https://127.0.0.1:38446\n'
               'TUNNEX_AGENT_SERVERNAME=tunnex-control\nTUNNEX_AGENT_HEALTH_ADDR=127.0.0.1:9091\n'
               'TUNNEX_NODE_STATE_DIR=/var/lib/tunnex-gcp-cloud-state\n').encode()
    writer = "import os,stat,sys; p='/var/lib/tunnex-gcp-cloud-preparation'; os.mkdir(p,0o700); s=os.lstat(p); assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700; fd=os.open(p+'/enrollment.env',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600); data=sys.stdin.buffer.read(8193); assert len(data)<=8192; os.write(fd,data); os.fsync(fd); os.close(fd)"
    proc = subprocess.run(GATEWAY_SSH + ['sudo python3 -c ' + shlex.quote(writer)], input=content,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    if proc.returncode:
        raise ValueError('private gateway token delivery refused; issued token not printed')
    return {'token_issued': True, 'private_gateway_env_delivered': True, 'gateway_started': False}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--remote', action='store_true')
    p.add_argument('--action', choices=['join-token', 'provider-create'])
    p.add_argument('--cookie-file')
    p.add_argument('--template')
    a = p.parse_args()
    if a.remote:
        raw = sys.stdin.buffer.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            raise ValueError('bounded request refused')
        print(json.dumps(remote(json.loads(raw, object_pairs_hook=unique))))
        return
    if not a.action or not a.cookie_file or (a.action == 'provider-create') != bool(a.template):
        p.error('action, private cookie and provider-only template required')
    item = json.loads(private_read(a.template), object_pairs_hook=unique) if a.template else {'node_name': 'tn-gcps2s-20261010-gateway', 'enrols_kind': 'gateway'}
    source = open(__file__, encoding='utf-8').read()
    # Only public source travels in argv; authorization and payload travel in stdin.
    command = 'python3 -c ' + shlex.quote(source) + ' --remote'
    packet = json.dumps({'action': a.action, 'cookie': cookie_header(private_read(a.cookie_file)), 'input': item}).encode()
    q = subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', BASTION, command],
                       input=packet, capture_output=True, timeout=45)
    if q.returncode:
        raise ValueError('private bastion operation refused')
    # Remote output has only enumerated public result keys.
    result = json.loads(q.stdout)
    allowed = {'id', 'desired_revision', 'desired_intent', 'cleanup_state'} if a.action == 'provider-create' else {'token_issued', 'private_gateway_env_delivered', 'gateway_started'}
    if not isinstance(result, dict) or set(result) != allowed:
        raise ValueError('public result projection refused')
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt):
        print('Private GCP operation refused; sensitive responses withheld.', file=sys.stderr)
        sys.exit(1)
