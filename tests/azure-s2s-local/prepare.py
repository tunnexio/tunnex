#!/usr/bin/env python3
import os,secrets
from pathlib import Path
root=Path(__file__).resolve().parent
(root/'.runtime/bin').mkdir(parents=True,exist_ok=True)
p=root/'.env'
if not p.exists():
    p.write_text('AZURE_DB_PASSWORD='+secrets.token_urlsafe(32)+'\n')
    os.chmod(p,0o600)
print('Azure local private environment prepared')
