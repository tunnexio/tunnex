#!/usr/bin/env python3
"""Prepare private state for the isolated GCP lab; never read AWS lab secrets."""
import pathlib
import secrets
root = pathlib.Path(__file__).resolve().parent / '.runtime'
root.mkdir(mode=0o700, exist_ok=True)
(root / 'bin').mkdir(mode=0o700, exist_ok=True)
env = root / 'compose.env'
if not env.exists():
    with env.open('x') as stream:
        stream.write('GCP_DB_PASSWORD=' + secrets.token_hex(24) + '\n')
    env.chmod(0o600)
print('Private local GCP state prepared; credentials not printed.')
