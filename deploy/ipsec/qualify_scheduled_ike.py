#!/usr/bin/env python3
"""Lab-only accelerated IKE scheduler qualification; never reads or changes PSKs.

Bootstrap and restoration use exact per-tunnel terminate/initiate because an IKE
rekey inherits its old peer configuration in strongSwan 6.1.0. Those operations
are excluded from the automatic scheduler observation window.
"""
import argparse
import datetime
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import socket
import struct
import select
import threading
import sys
import time
import uuid

import runtime_stop_proof as proof
from runtime_restore_runner import active_entry, tunnels_installed


class RekeyEvents:
    """Read only exact ike-rekey notifications from the live VICI socket."""
    def __init__(self, pid, uri):
        if not uri.startswith('unix:///') or '..' in uri.split('/'):
            raise ValueError('explicit absolute VICI Unix socket required')
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(5)
        self.socket.connect('/proc/%d/root%s' % (pid, uri[len('unix://'):]))
        payload = bytes([3, 9]) + b'ike-rekey'
        self.socket.sendall(struct.pack('!I', len(payload)) + payload)
        if self.frame() != bytes([5]):
            raise ValueError('VICI event registration not confirmed')
        self.events = []
        self.error = None
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.collect, daemon=True)
        self.thread.start()

    def exact(self, count):
        data = b''
        while len(data) < count:
            block = self.socket.recv(count-len(data))
            if not block:
                raise EOFError('VICI event socket closed')
            data += block
        return data

    def frame(self):
        size = struct.unpack('!I', self.exact(4))[0]
        if not 0 < size <= 1048576:
            raise ValueError('invalid VICI event size')
        return self.exact(size)

    def collect(self):
        try:
            while not self.stop.is_set():
                if not select.select([self.socket], [], [], 1)[0]:
                    continue
                frame = self.frame()
                if frame[:11] != bytes([7, 9]) + b'ike-rekey':
                    raise ValueError('unexpected VICI event')
                tree = decode_vici(frame[11:])
                for connection, event in tree.items():
                    self.events.append({'connection': connection,
                        'old_id': int(event['old']['uniqueid']), 'new_id': int(event['new']['uniqueid']),
                        'new_state': event['new']['state'], 'monotonic': time.monotonic(),
                        'utc': datetime.datetime.now(datetime.timezone.utc).isoformat()})
        except Exception as error:
            self.error = str(error)

    def close(self):
        self.stop.set()
        self.thread.join(timeout=7)
        self.socket.close()


def decode_vici(data):
    root = {}
    stack = [root]
    pos = 0
    while pos < len(data):
        kind = data[pos]
        pos += 1
        if kind in (1, 3, 4):
            size = data[pos]
            pos += 1
            key = data[pos:pos+size].decode()
            pos += size
        if kind == 1:
            child = {}
            stack[-1][key] = child
            stack.append(child)
        elif kind == 2:
            if len(stack) <= 1:
                raise ValueError('unbalanced VICI section')
            stack.pop()
        elif kind == 3:
            size = struct.unpack('!H', data[pos:pos+2])[0]
            pos += 2
            stack[-1][key] = data[pos:pos+size].decode()
            pos += size
        elif kind == 4:
            pass
        elif kind == 5:
            size = struct.unpack('!H', data[pos:pos+2])[0]
            pos += 2 + size
        elif kind != 6:
            raise ValueError('unknown VICI element')
    if len(stack) != 1 or pos != len(data):
        raise ValueError('incomplete VICI event')
    return root


def name(engine):
    b = engine['Binding']
    return 'tnx-ipsec-%s-d%d-c%d-s%d' % (uuid.UUID(engine['TunnelID']), b['DesiredRevision'], b['ConfigurationRevision'], engine['SecretRevision'])


def render(engines, intervals=None):
    chunks = ['connections {']
    for index, e in enumerate(engines):
        n = name(e)
        for field in ('LocalAddress', 'RemoteAddress', 'LocalIdentity', 'RemoteIdentity'):
            if ipaddress.ip_address(e[field]).version != 4:
                raise ValueError('IPv4 lab profile required')
        for field in ('LocalPrefixes', 'RemotePrefixes'):
            if not e[field] or any(ipaddress.ip_network(p, strict=True).version != 4 for p in e[field]):
                raise ValueError('invalid IPv4 selectors')
        if not 0 < e['XFRMID'] < 2**32 or not 0 <= e['ReqID'] < 2**32:
            raise ValueError('invalid kernel binding')
        t = intervals[index] if intervals else 28800
        chunks.extend(['  %s {' % n, '    version = 2', '    dpd_delay = 10s',
                       '    local_addrs = ' + e['LocalAddress'], '    remote_addrs = ' + e['RemoteAddress'],
                       '    proposals = aes256-sha256-modp2048', '    mobike = no',
                       '    rekey_time = %ds' % t, '    reauth_time = 0s'])
        if intervals:
            chunks.extend(['    rand_time = 0s', '    over_time = 2880s'])
        for side, field in [('local', 'LocalIdentity'), ('remote', 'RemoteIdentity')]:
            chunks.extend(['    %s {' % side, '      auth = psk', '      id = ' + e[field], '    }'])
        chunks.extend(['    children {', '      %s {' % n, '        mode = tunnel',
                       '        local_ts = ' + ', '.join(e['LocalPrefixes']),
                       '        remote_ts = ' + ', '.join(e['RemotePrefixes']),
                       '        esp_proposals = aes256-sha256-modp2048', '        start_action = none',
                       '        dpd_action = clear', '        close_action = none',
                       '        if_id_in = %d' % e['XFRMID'], '        if_id_out = %d' % e['XFRMID'],
                       '        life_time = 3600s', '        rekey_time = 3000s'])
        if e['ReqID']:
            chunks.append('        reqid = %d' % e['ReqID'])
        chunks.extend(['      }', '    }', '  }'])
    return '\n'.join(chunks + ['}', ''])


def sample(text, engines):
    result = {}
    for block in re.split(r'(?m)(?=^tnx-ipsec-)', text):
        lines = block.splitlines()
        if not lines:
            continue
        header = re.match(r'^(tnx-ipsec-[^:]+): #(\d+), ESTABLISHED,', lines[0])
        if not header:
            continue
        n, serial = header.group(1), int(header.group(2))
        timer = re.search(r'\brekeying in (\d+)s\b', block)
        if timer and tunnels_installed(block, {'Engines': [e for e in engines if name(e) == n]}):
            if n in {name(e) for e in engines}:
                result[n] = {'ike_serial': serial, 'remaining_seconds': int(timer.group(1))}
    return result


def authority_unchanged(m):
    identity = proof.inspect(m['container'])
    if (not identity['state']['Running'] or identity['state']['Pid'] != m['pid']
            or identity['state']['StartedAt'] != m['started']):
        raise ValueError('lab runtime changed; refusing stale configuration')
    proof.state_mount(identity, m['journal'])
    current = active_entry(proof.private_read(m['journal']))
    if current['DeliveryID'] != m['delivery'] or current['Engines'] != m['engines']:
        raise ValueError('CP delivery or engine configuration changed')


def swan(m, *args):
    return proof.command('docker', 'exec', '-e', 'STRONGSWAN_CONF=' + m['strongswan_conf'],
                         m['container'], m['swanctl'], *args, '--uri', m['vici'])


def verify_exact_configs(m):
    # swanctl --load-conns unloads names missing from its file. Dedicated two-
    # connection lab scope is mandatory; never erase coexistence configurations.
    text = swan(m, '--list-conns')
    names = re.findall(r'(?m)^([^\s:]+):', text)
    expected = [name(e) for e in m['engines']]
    if len(names) != len(expected) or set(names) != set(expected):
        raise ValueError('loaded connections are not exactly the two scoped lab tunnels')


def put_config(m, filename, text):
    path = '/run/tunnex-ipsec/' + m['run_id'] + '-' + filename + '.conf'
    # path is composed exclusively from UUID and fixed caller-owned labels.
    subprocess.run(['docker', 'exec', '-i', m['container'], '/bin/sh', '-c',
                    'umask 077; cat > ' + path], input=text, text=True, check=True, timeout=20)
    return path


def read_sample(m):
    return sample(swan(m, '--list-sas'), m['engines'])


def fresh_session(m, engine, max_seconds=None):
    authority_unchanged(m)
    n = name(engine)
    before = read_sample(m).get(n, {}).get('ike_serial')
    swan(m, '--terminate', '--ike', n, '--timeout', '20')
    swan(m, '--initiate', '--child', n, '--ike', n, '--timeout', '20')
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        observation = read_sample(m).get(n)
        if observation and observation['ike_serial'] != before:
            seconds = observation['remaining_seconds']
            if (max_seconds is not None and 0 < seconds <= max_seconds) or (max_seconds is None and seconds > 20000):
                return observation
        time.sleep(1)
    raise TimeoutError('fresh IKE session did not adopt expected timer')


def restore(m, directory):
    lock = os.open(directory / 'restore.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if (directory / 'restored.json').exists():
            return
        authority_unchanged(m)
        path = put_config(m, 'standard', render(m['engines']))
        verify_exact_configs(m)
        swan(m, '--load-conns', '--file', path)
        sessions = {}
        for engine in m['engines']:
            sessions[name(engine)] = fresh_session(m, engine)
        proof.private_write(directory / 'restored.json', {'standard_timers_verified': True, 'sessions': sessions})
        print('Original IKE configuration and fresh long-lived sessions restored.', flush=True)
    finally:
        os.close(lock)


def run(args):
    if os.geteuid() != 0:
        raise ValueError('Docker host root required')
    identity = proof.inspect(args.container)
    proof.state_mount(identity, args.journal)
    entry = active_entry(proof.private_read(args.journal))
    directory = Path(args.evidence_dir)
    info = directory.lstat()
    if info.st_uid != 0 or not directory.is_dir() or info.st_mode & 0o077:
        raise ValueError('private root-owned evidence directory required')
    directory = directory / ('ike-' + str(uuid.uuid4()))
    directory.mkdir(mode=0o700)
    m = {'container': identity['id'], 'engines': entry['Engines'], 'run_id': directory.name,
         'swanctl': args.swanctl, 'vici': args.vici, 'strongswan_conf': args.strongswan_conf,
         'watchdog_deadline': time.time() + 360, 'journal': str(Path(args.journal).resolve()),
         'delivery': entry['DeliveryID'], 'pid': identity['state']['Pid'], 'started': identity['state']['StartedAt']}
    verify_exact_configs(m)
    baseline = read_sample(m)
    if len(baseline) != 2 or any(v['remaining_seconds'] <= 300 for v in baseline.values()):
        raise ValueError('both established long-lived baseline sessions required')
    proof.private_write(directory / 'manifest.json', m)
    proof.private_write(directory / 'baseline.json', baseline)
    events = RekeyEvents(identity['state']['Pid'], m['vici'])
    log = open(directory / 'watchdog.log', 'x')
    os.chmod(directory / 'watchdog.log', 0o600)
    subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--watchdog', str(directory)],
                     stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    log.close()
    print('Evidence directory: ' + str(directory), flush=True)
    observations = []
    passed = False
    try:
        authority_unchanged(m)
        path = put_config(m, 'accelerated', render(m['engines'], [120, 150]))
        verify_exact_configs(m)
        swan(m, '--load-conns', '--file', path)
        seeded = {}
        for index, engine in enumerate(m['engines']):
            seeded[name(engine)] = {'sample': fresh_session(m, engine, [120, 150][index]),
                                    'seeded_monotonic': time.monotonic()}
        proof.private_write(directory / 'bootstrap-excluded.json', seeded)
        print('Short timer bootstrap verified; automatic observation begins. No rekey commands in observation.', flush=True)
        deadline = time.monotonic() + 220
        renewed = {}
        while time.monotonic() < deadline:
            now = time.monotonic()
            current = read_sample(m)
            if events.error:
                raise ValueError('VICI event monitor failed: ' + events.error)
            observations.append({'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'samples': current})
            for index, engine in enumerate(m['engines']):
                n = name(engine)
                item = current.get(n)
                old = seeded[n]
                elapsed = now - old['seeded_monotonic']
                if item and item['ike_serial'] != old['sample']['ike_serial']:
                    # Early ID replacement is not accepted as scheduled renewal.
                    if elapsed < [120, 150][index] - 10:
                        raise ValueError('IKE changed before expected timer; scheduled proof ambiguous')
                    if not 0 < item['remaining_seconds'] <= [120, 150][index]:
                        raise ValueError('renewed session timer differs from accelerated profile')
                    matching = [event for event in events.events if event['connection'] == n
                                and event['old_id'] == old['sample']['ike_serial']
                                and event['new_id'] == item['ike_serial']
                                and event['new_state'] == 'ESTABLISHED'
                                and event['monotonic'] >= old['seeded_monotonic']]
                    if matching:
                        renewed[n] = {'elapsed_seconds': elapsed, 'before': old['sample'], 'after': item, 'event': matching[-1]}
            if len(renewed) == 2:
                passed = True
                break
            time.sleep(2)
        proof.private_write(directory / 'observations.json', observations)
        proof.private_write(directory / 'scheduled-result.json', {'pass': passed, 'scope': 'accelerated-scheduled-IKE-rekey',
                                                                  'renewed': renewed, 'payload_verified': False})
        if not passed:
            raise TimeoutError('automatic IKE renewal not observed for both tunnels')
    finally:
        try:
            events.close()
            proof.private_write(directory / 'ike-rekey-events.json', events.events)
        finally:
            restore(m, directory)
    print('PASS: both automatic accelerated IKE renewals observed; original timers restored. Client continuity remains separate.', flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--watchdog')
    for field in ('container', 'journal', 'evidence-dir', 'swanctl', 'vici', 'strongswan-conf'):
        p.add_argument('--' + field)
    args = p.parse_args()
    if args.watchdog:
        directory = Path(args.watchdog)
        m = proof.private_read(directory / 'manifest.json')
        time.sleep(max(0, m['watchdog_deadline'] - time.time()))
        restore(m, directory)
    else:
        if any(getattr(args, k) is None for k in ('container', 'journal', 'evidence_dir', 'swanctl', 'vici', 'strongswan_conf')):
            p.error('all explicit lab target and daemon paths are required')
        run(args)


if __name__ == '__main__':
    main()
