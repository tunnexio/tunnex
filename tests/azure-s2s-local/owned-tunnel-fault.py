#!/usr/bin/env python3
"""Run on the owned peer host, outside gateway netns. No cloud commands.
Block one or both fixed Azure peers for a bounded interval; always remove the owned fault.
"""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import time

OWNER = 'azure-s2s-01a12505'
NETWORK = 'tunnex-azure-cloud'
TABLE = 'az_s2s_owned_fault'
PEERS = {1: '52.140.60.21', 2: '20.219.125.34'}

def emit(value):
    value['observed_at'] = datetime.now(timezone.utc).isoformat()
    print(json.dumps(value), flush=True)


def run(argv, data=None, allow_absent=False):
    result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
    if result.returncode and not allow_absent:
        raise ValueError('owned operation refused')
    if len(result.stdout) > 262144:
        raise ValueError('output bound exceeded')
    return result.returncode, result.stdout


def attest_fault_text(doc, text, local):
    if local is None:
        raise ValueError('current owned bridge identity required')
    local = str(ipaddress.IPv4Address(local))
    rows = doc['nftables']
    tables = [row['table'] for row in rows if 'table' in row]
    chains = [row['chain'] for row in rows if 'chain' in row]
    rules = [row['rule'] for row in rows if 'rule' in row]
    if any(len(row) != 1 or next(iter(row)) not in {'metainfo', 'table', 'chain', 'rule'} for row in rows):
        raise ValueError('foreign fault object refused')
    if len(tables) != 1 or len(chains) != 1 or len(rules) not in {4, 8}:
        raise ValueError('incomplete fault topology refused')
    table = dict(tables[0])
    table.pop('handle', None)
    comment = table.pop('comment', None)
    if table != {'family': 'inet', 'name': TABLE} or comment not in {None, OWNER}:
        raise ValueError('foreign fault table refused')
    chain = dict(chains[0])
    chain.pop('handle', None)
    if chain != {'family': 'inet', 'table': TABLE, 'name': 'forward', 'type': 'filter', 'hook': 'forward', 'prio': -300, 'policy': 'accept'}:
        raise ValueError('foreign fault chain refused')
    if any(rule.get('family') != 'inet' or rule.get('table') != TABLE or rule.get('chain') != 'forward' or set(rule) - {'family', 'table', 'chain', 'handle', 'expr'} for rule in rules):
        raise ValueError('foreign fault rule refused')
    # Match the COMPLETE independent textual ruleset. Only counter values and
    # the known raw=-300 priority rendering vary. Unknown text is never ignored.
    normalized = []
    for line in text.splitlines():
        line = ' '.join(line.split())
        if not line:
            continue
        line = re.sub(r'counter packets [0-9]+ bytes [0-9]+', 'counter', line)
        line = line.replace('priority raw;', 'priority -300;')
        normalized.append(line)
    for slots in ([1], [2], [1, 2]):
        expected = [f'table inet {TABLE} {{', f'comment "{OWNER}"', 'chain forward {', 'type filter hook forward priority -300; policy accept;']
        for slot in slots:
            peer = PEERS[slot]
            expected += [f'ip saddr {local} ip daddr {peer} udp dport {{ 500, 4500 }} counter drop',
                         f'ip saddr {peer} ip daddr {local} udp sport {{ 500, 4500 }} counter drop',
                         f'ip saddr {local} ip daddr {peer} ip protocol esp counter drop',
                         f'ip saddr {peer} ip daddr {local} ip protocol esp counter drop']
        expected += ['}', '}']
        if normalized == expected and len(rules) == 4 * len(slots):
            def match(protocol, field, right):
                return {'match': {'op': '==', 'left': {'payload': {'protocol': protocol, 'field': field}}, 'right': right}}
            expected_rules = []
            for slot in slots:
                peer = PEERS[slot]
                for source, destination, protocol, field, value in [
                    (local, peer, 'udp', 'dport', {'set': [500, 4500]}),
                    (peer, local, 'udp', 'sport', {'set': [500, 4500]}),
                    (local, peer, 'ip', 'protocol', 'esp'),
                    (peer, local, 'ip', 'protocol', 'esp')]:
                    expected_rules.append([match('ip', 'saddr', source), match('ip', 'daddr', destination),
                                           match(protocol, field, value), {'counter': {}}, {'drop': None}])
            for rule, expressions in zip(rules, expected_rules):
                actual = rule.get('expr')
                if not isinstance(actual, list) or len(actual) != 5 or set(actual[3]) != {'counter'}:
                    raise ValueError('foreign fault expressions refused')
                counts = actual[3]['counter']
                if not isinstance(counts, dict) or set(counts) != {'packets', 'bytes'} or any(type(v) is not int or not 0 <= v < 2**64 for v in counts.values()):
                    raise ValueError('invalid fault counter refused')
                clean = actual[:3] + [{'counter': {}}] + actual[4:]
                if clean != expressions:
                    raise ValueError('fault expression mismatch refused')
            return
    raise ValueError('fault text ownership or exact rules refused')


def fault_inventory(local=None):
    code, raw = run(['nft', '-j', 'list', 'table', 'inet', TABLE], allow_absent=True)
    if code:
        # A failed read is not proof of absence (permission/observer failure).
        _, tables_raw = run(['nft', '-j', 'list', 'tables'])
        inventory = json.loads(tables_raw)
        if any(row.get('table', {}).get('family') == 'inet' and row.get('table', {}).get('name') == TABLE for row in inventory['nftables']):
            raise ValueError('fault table read refused')
        return None
    doc = json.loads(raw)
    _, text = run(['nft', '-n', 'list', 'table', 'inet', TABLE])
    attest_fault_text(doc, text.decode(), local)
    return doc


def clear(local=None):
    if fault_inventory(local) is not None:
        run(['nft', 'delete', 'table', 'inet', TABLE])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['block', 'clear'])
    parser.add_argument('--container')
    parser.add_argument('--slot', choices=['1', '2', 'both'])
    parser.add_argument('--seconds', type=int, default=90)
    args = parser.parse_args()
    if socket.gethostname() != 'tunnex-peer':
        raise ValueError('owned peer hostname required')
    if os.geteuid() != 0:
        raise ValueError('owned host root required')
    if not args.container or (args.action == 'block' and (not args.slot or not 1 <= args.seconds <= 120)):
        raise ValueError('bounded fault input required')
    _, label = run(['docker', 'inspect', '--format', '{{index .Config.Labels "tunnex.owner"}}', args.container])
    if label.decode().strip() != OWNER:
        raise ValueError('foreign gateway refused')
    _, raw = run(['docker', 'inspect', '--format', '{{json .NetworkSettings.Networks}}', args.container])
    networks = json.loads(raw)
    if set(networks) != {NETWORK}:
        raise ValueError('isolated owned bridge required')
    local = str(ipaddress.IPv4Address(networks[NETWORK]['IPAddress']))
    if args.action == 'clear':
        clear(local)
        emit({'fault': 'cleared'})
        return
    slots = [1, 2] if args.slot == 'both' else [int(args.slot)]
    peers = [PEERS[slot] for slot in slots]
    if fault_inventory(local) is not None:
        raise ValueError('existing fault refused')
    script = f'add table inet {TABLE} {{ comment "{OWNER}"; }}\n'
    script += f'add chain inet {TABLE} forward {{ type filter hook forward priority -300; policy accept; }}\n'
    for peer in peers:
        script += f'add rule inet {TABLE} forward ip saddr {local} ip daddr {peer} udp dport {{ 500, 4500 }} counter drop\n'
        script += f'add rule inet {TABLE} forward ip saddr {peer} ip daddr {local} udp sport {{ 500, 4500 }} counter drop\n'
        script += f'add rule inet {TABLE} forward ip saddr {local} ip daddr {peer} ip protocol esp counter drop\n'
        script += f'add rule inet {TABLE} forward ip saddr {peer} ip daddr {local} ip protocol esp counter drop\n'
    script = script.encode()
    run(['nft', '--check', '-f', '-'], script)
    for sig in [signal.SIGINT, signal.SIGTERM]:
        signal.signal(sig, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        run(['nft', '-f', '-'], script)
        emit({'fault': 'blocked', 'slots': slots, 'peers': peers, 'seconds': args.seconds})
        time.sleep(args.seconds)
    finally:
        clear(local)
        emit({'fault': 'cleared'})


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, KeyError, TypeError, KeyboardInterrupt):
        emit({'error': 'owned_fault_refused_or_interrupted'})
        raise SystemExit(1)
