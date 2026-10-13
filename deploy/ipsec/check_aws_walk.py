#!/usr/bin/env python3
"""Check completeness/integrity of a manually collected AWS walk; never certify it."""
import argparse
import json
import pathlib

from check_cloud_walk import check_walk

CHECKS = (
    'behind_host_tcp_udp', 'policy_allow_deny', 'bad_key_refusal',
    'return_route_failure', 'mtu_payload', 'tunnel_1_failure',
    'tunnel_2_failure', 'return_path_independence', 'both_tunnels_failure',
    'restart_recovery', 'host_reboot', 'protocol_rekey', 'maintenance_rotation', 'cleanup',
)


def check(document, root):
    return check_walk(document, root, profile='aws-static-ipv4-v1',
        environment='live-aws', checks_required=CHECKS,
        environment_error='live AWS evidence required')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('receipt', type=pathlib.Path)
    args = parser.parse_args()
    try:
        document = json.loads(args.receipt.read_text())
        errors = check(document, args.receipt.parent)
    except (ValueError, OSError):
        errors = ['cannot read receipt JSON']
    for error in errors:
        print(error)
    if not errors:
        print('Evidence complete and hashes match. Manual review still required; this does not certify AWS support.')
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
