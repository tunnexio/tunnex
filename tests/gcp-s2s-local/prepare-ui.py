#!/usr/bin/env python3
"""Seed only explicit owned local role fixtures; keep credentials private."""
import json
import os
import pathlib
import secrets
import subprocess
import tempfile
root = pathlib.Path(__file__).resolve().parents[2]
private = root / 'tests/gcp-s2s-local/.runtime'
accounts = private / 'ui-accounts.json'
if not accounts.exists():
    accounts.write_text(json.dumps({role: {'email': 'browser-'+role+'@gcp-s2s.local',
        'password': secrets.token_hex(24)} for role in ('owner','admin','member')}, indent=2))
    accounts.chmod(0o600)
values = dict(line.split('=',1) for line in (private / 'compose.env').read_text().splitlines())
env = os.environ.copy()
env['GOFLAGS'] = '-mod=readonly'
env['GCP_LOCAL_FIXTURE_DSN'] = 'postgres://gcps2s:'+values['GCP_DB_PASSWORD']+'@127.0.0.1:35440/gcps2s?sslmode=disable'
env['GCP_LOCAL_FIXTURE_ACCOUNTS'] = str(accounts)
with tempfile.TemporaryDirectory(prefix='.gcp-ui-fixture-', dir=root/'apps/api') as scratch:
    source = pathlib.Path(scratch)/'main.go'
    source.write_text((root/'tests/gcp-s2s-local/ui-fixture.go.txt').read_text())
    result = subprocess.run(['go','run',str(source)],cwd=root/'apps/api',env=env)
raise SystemExit(result.returncode)
