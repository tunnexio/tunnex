#!/usr/bin/env python3
"""Generate fresh role inputs on the owned lab CP; never copy Mac credentials."""
import argparse
import json
from pathlib import Path
import secrets
import importlib.util
spec=importlib.util.spec_from_file_location('azure_enrollment',Path(__file__).with_name('enroll-local.py'))
lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--private-root',type=Path,required=True);args=p.parse_args()
path=args.private_root.resolve()/'ui-accounts.json'
if path.exists():
    if path.is_symlink() or path.stat().st_mode&0o077:raise SystemExit('Refuse unsafe existing private account file')
    print('Existing private owned fixture retained; no password reset or copy.')
else:
    accounts={role:{'email':'browser-'+role+'@azure-s2s.local','password':secrets.token_hex(24)} for role in ('owner','admin','member')}
    lab.private_write(path,json.dumps(accounts,indent=2));print('Fresh owned fixture passwords generated locally; values remain private.')
