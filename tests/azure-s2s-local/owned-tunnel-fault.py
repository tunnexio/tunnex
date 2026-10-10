#!/usr/bin/env python3
"""Run on the owned peer host, outside gateway netns. No cloud commands.
Block one or both fixed Azure peers for a bounded interval; always remove the owned fault.
"""
import argparse
import ipaddress
import json
import os
import signal
import socket
import subprocess
import time

OWNER = 'azure-s2s-01a12505'
NETWORK = 'tunnex-azure-cloud'
TABLE = 'az_s2s_owned_fault'
PEERS = {1: '52.140.60.21', 2: '20.219.125.34'}


def run(argv, data=None, allow_absent=False):
    result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
    if result.returncode and not allow_absent:
        raise ValueError('owned operation refused')
    if len(result.stdout) > 262144:
        raise ValueError('output bound exceeded')
    return result.returncode, result.stdout


def fault_inventory():
    code, raw = run(['nft', '-j', 'list', 'table', 'inet', TABLE], allow_absent=True)
    if code:
        return None
    doc = json.loads(raw)
    tables = [row['table'] for row in doc['nftables'] if 'table' in row]
    if len(tables) != 1 or tables[0].get('comment') != OWNER or tables[0].get('family') != 'inet' or tables[0].get('name') != TABLE:
        raise ValueError('foreign fault table refused')
    return doc


def clear():
    if fault_inventory() is not None:
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
    if args.action == 'clear':
        clear()
        print(json.dumps({'fault': 'cleared'}))
        return
    if not args.container or not args.slot or not 1 <= args.seconds <= 120:
        raise ValueError('bounded fault input required')
    _, label = run(['docker', 'inspect', '--format', '{{index .Config.Labels "tunnex.owner"}}', args.container])
    if label.decode().strip() != OWNER:
        raise ValueError('foreign gateway refused')
    _, raw = run(['docker', 'inspect', '--format', '{{json .NetworkSettings.Networks}}', args.container])
    networks = json.loads(raw)
    if set(networks) != {NETWORK}:
        raise ValueError('isolated owned bridge required')
    local = str(ipaddress.IPv4Address(networks[NETWORK]['IPAddress']))
    slots = [1, 2] if args.slot == 'both' else [int(args.slot)]
    peers = [PEERS[slot] for slot in slots]
    if fault_inventory() is not None:
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
        print(json.dumps({'fault': 'blocked', 'slots': slots, 'peers': peers, 'seconds': args.seconds}), flush=True)
        time.sleep(args.seconds)
    finally:
        clear()
        print(json.dumps({'fault': 'cleared'}), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, KeyError, TypeError, KeyboardInterrupt):
        print(json.dumps({'error': 'owned_fault_refused_or_interrupted'}))
        raise SystemExit(1)
