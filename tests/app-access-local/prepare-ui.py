#!/usr/bin/env python3
"""Verify normal native login for the separately seeded owned UI test account."""
import http.cookiejar
import json
from pathlib import Path
import subprocess
import urllib.request

root = Path(__file__).resolve().parent
subprocess.run([str(root / 'ownership.py')], check=True)
values = dict(line.split('=', 1) for line in (root / '.runtime' / 'ui-account.env').read_text().splitlines() if '=' in line)
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
request = urllib.request.Request('http://127.0.0.1:18083/api/v1/auth/login',
    data=json.dumps({'email': values['AA1_UI_EMAIL'], 'password': values['AA1_UI_PASSWORD']}).encode(),
    headers={'Content-Type': 'application/json'})
with client.open(request, timeout=15) as response:
    result = json.load(response)
if result.get('mfa_required') or result.get('user', {}).get('must_change_password'):
    raise SystemExit('Local UI test account requires an authentication gate')
print('Owned test account passed normal native login; credentials remain private.')
