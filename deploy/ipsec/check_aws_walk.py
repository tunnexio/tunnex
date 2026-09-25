#!/usr/bin/env python3
"""Check completeness/integrity of a manually collected AWS walk; never certify it."""
import argparse
import hashlib
import json
import pathlib
import re

CHECKS = (
    'behind_host_tcp_udp', 'policy_allow_deny', 'bad_key_refusal',
    'return_route_failure', 'mtu_payload', 'tunnel_1_failure',
    'tunnel_2_failure', 'return_path_independence', 'both_tunnels_failure',
    'restart_recovery', 'host_reboot', 'protocol_rekey', 'maintenance_rotation', 'cleanup',
)


def check(document, root):
    """Return static errors only: receipt content and credentials are never echoed."""
    errors = []
    if not isinstance(document, dict):
        return ['invalid receipt']
    if document.get('schema_version') != 1 or document.get('profile') != 'aws-static-ipv4-v1':
        errors.append('unsupported receipt schema/profile')
    if not isinstance(document.get('source_sha'), str) or not re.fullmatch(r'[0-9a-f]{40}', document['source_sha']):
        errors.append('missing source commit')
    if document.get('environment') != 'live-aws':
        errors.append('live AWS evidence required')
    checks = document.get('checks')
    if not isinstance(checks, dict) or set(checks) != set(CHECKS):
        return errors + ['required check set does not match']
    root = root.resolve()
    for name in CHECKS:
        entry = checks[name]
        if not isinstance(entry, dict) or entry.get('status') != 'pass':
            errors.append(name + ': pending or failed')
            continue
        artifacts = entry.get('artifacts')
        if not isinstance(artifacts, list) or not artifacts:
            errors.append(name + ': missing evidence')
            continue
        for artifact in artifacts:
            try:
                if not isinstance(artifact, dict):
                    raise ValueError()
                relative = artifact['path']
                digest = artifact['sha256']
                if not isinstance(relative, str) or not relative or pathlib.Path(relative).is_absolute():
                    raise ValueError()
                if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
                    raise ValueError()
                path = (root / relative).resolve()
                if not path.is_relative_to(root) or not path.is_file():
                    raise ValueError()
                if path.stat().st_size == 0:
                    raise ValueError()
                with path.open('rb') as stream:
                    actual = hashlib.file_digest(stream, 'sha256').hexdigest()
                if actual != digest:
                    raise ValueError()
            except (KeyError, TypeError, ValueError, OSError, RuntimeError):
                errors.append(name + ': invalid or changed evidence')
    return errors


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
