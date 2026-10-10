#!/usr/bin/env python3
"""Prepare private observer binding from independent inputs; never run/stage observations."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

IMAGE='9a49bc2ff93a900d68057edf6d6cc370cb9da9e7ca58825ad57d980122c724ae'
NODE='7dfb70a6f04fcacd20df7dfc0eace7277ccbe0a34793109ca68ef4ee9380d53b'
CONTAINER='c5bf93faf70a856fc115893429e6dc5fc901d231c55015796c53f66279d5b955'
OBSERVER='a55be0165ed8990906457efe0e1714971d7826516a9e579e6feebac329734d6a'

def private(path):
 path=Path(path)
 for parent in [path.parent,*path.parent.parents]:
  if parent.is_symlink():raise ValueError('private path')
 p=path.parent.stat();s=path.lstat()
 if p.st_uid!=os.getuid() or stat.S_IMODE(p.st_mode)!=0o700 or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o600 or not stat.S_ISREG(s.st_mode) or s.st_size>131072:raise ValueError('private input')
 return path.read_bytes()

def timestamp(value):
 if not isinstance(value,str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})',value):raise ValueError('timestamp')
 normalized=re.sub(r'\.(\d{1,9})',lambda m:'.'+m[1][:6].ljust(6,'0'),value)
 return datetime.fromisoformat(normalized.replace('Z','+00:00'))

def build(normal,attestation,immutable,mode,clock):
 if mode not in ('baseline','absence','post-limit'):raise ValueError('mode')
 for source in (normal,attestation):
  if not 0<=(clock-timestamp(source['observed_at'])).total_seconds()<=60:raise ValueError('fresh input')
 if attestation['container_id']!=CONTAINER or attestation['image_sha256']!=IMAGE or attestation['node_executable_sha256']!=NODE:raise ValueError('current owned image')
 n=normal['normal_connection'];b=attestation['binding']
 if b['connection_id'] not in [immutable.get(k,{}).get('id') for k in ('target','prior')]:raise ValueError('saved immutable connection')
 if n['profile_id']!='azure-active-active-bgp-ipv4-v1':raise ValueError('profile')
 for key in ('org_id','site_id','gateway_id','connection_id'):
  v=b[key]
  if not isinstance(v,str) or str(uuid.UUID(v))!=v:raise ValueError('identity')
 if n['id']!=b['connection_id']:raise ValueError('connection')
 # Separate independently attested normal immutable ownership, not inferred from API readiness.
 for key in ('org_id','site_id','gateway_id'):
  if immutable['setup'][key]!=b[key]:raise ValueError('normal ownership')
 for key in ('desired_revision','configuration_revision','maximum_prefixes'):
  if type(b[key])!=int or b[key]<1 or n[key]!=b[key]:raise ValueError('revision')
 if b['maximum_prefixes'] not in (1,8):raise ValueError('limit')
 expected=['10.231.0.0/16'] if b['maximum_prefixes']==8 else ['10.231.0.0/16','10.235.77.0/24']
 if n['remote_prefixes']!=expected:raise ValueError('allowlist')
 if mode=='absence':
  if n['desired_intent']!='disabled' or n['application_state']!='not_applied' or n['cleanup_state']=='pending' or attestation['journal_cleanup_desired_revision']!=b['desired_revision']:raise ValueError('disabled actual cleanup binding')
 elif n['desired_intent']!='enabled':raise ValueError('enabled binding')
 if mode=='baseline' and n['application_state']!='applied':raise ValueError('normal baseline')
 if mode=='post-limit' and (b['maximum_prefixes']!=1 or normal.get('runtime_observation')!='not_requested'):raise ValueError('postlimit immutable read only')
 for key in ('namespace_device','namespace_inode'):
  if type(b[key])!=int or b[key]<1:raise ValueError('namespace')
 allowed={'org_id','site_id','gateway_id','connection_id','desired_revision','configuration_revision','maximum_prefixes','namespace_device','namespace_inode'}
 if set(b)-allowed-{'historical_boot'} or not allowed<=set(b):raise ValueError('binding fields')
 result={k:b[k] for k in allowed};result.update(mode=mode,node_executable_sha256=NODE)
 if 'historical_boot' in b:
  h=b['historical_boot']
  if set(h)!={'proof_sha256','stopped_journal_sha256','root_attested_host_machine_id'} or any(not re.fullmatch('[0-9a-f]{64}',h[k]) for k in ('proof_sha256','stopped_journal_sha256')) or not re.fullmatch('[0-9a-f]{32}',h['root_attested_host_machine_id']):raise ValueError('historical pins')
  result['historical_boot']=h
 return result

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--normal',type=Path,required=True);p.add_argument('--attestation',type=Path,required=True);p.add_argument('--immutable',type=Path,required=True);p.add_argument('--observer-binary',type=Path,required=True);p.add_argument('--mode',choices=('baseline','absence','post-limit'),required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 try:
  # Binary is a reviewed executable artifact, never run by this preparation helper.
  if a.observer_binary.is_symlink() or not a.observer_binary.is_file() or hashlib.sha256(a.observer_binary.read_bytes()).hexdigest()!=OBSERVER:raise ValueError('observer hash')
  result=build(json.loads(private(a.normal)),json.loads(private(a.attestation)),json.loads(private(a.immutable)),a.mode,datetime.now(timezone.utc))
  parent=a.output.parent
  if parent.is_symlink() or parent.resolve()!=parent.absolute() or parent.stat().st_uid!=os.getuid() or stat.S_IMODE(parent.stat().st_mode)!=0o700:raise ValueError('private output')
  fd=os.open(a.output,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w') as f:json.dump(result,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
  print('observer_binding_prepared_no_observation')
 except (ValueError,KeyError,TypeError,OSError):raise SystemExit('observer_preparation_refused')
if __name__=='__main__':main()
