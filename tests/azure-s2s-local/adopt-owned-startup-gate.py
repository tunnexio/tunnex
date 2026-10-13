#!/usr/bin/env python3
"""One-time conversion of the exact owned plaintext gate; never releases it."""
import argparse
import importlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import uuid

spec=importlib.util.spec_from_file_location('gated',Path(__file__).with_name('assemble-gated-restoration.py'))
gated=importlib.util.module_from_spec(spec);spec.loader.exec_module(gated)

def marker(raw):
 match=re.fullmatch(rb'actual-owned-controlled-restart:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\n?',raw)
 if not match:raise ValueError('exact original marker required')
 value=match[1].decode();uuid.UUID(value)
 return value

def replace_gate(runner,gate,raw,identity,cid,recheck):
 run=marker(raw)
 temporary=gate.parent/('.gate-adoption-'+str(uuid.uuid4()))
 canonical=json.dumps({'Version':1,'SupervisorRun':run,'ContainerID':cid},separators=(',',':')).encode()+b'\n'
 runner.write_bytes(temporary,canonical)
 recheck();gated.same_gate(gate,raw,identity)
 os.replace(temporary,gate);runner.sync_directory(gate.parent)
 if gated.private_bytes(gate,8192)!=canonical:raise ValueError('canonical gate changed')

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--container',required=True);p.add_argument('--journal',type=Path,required=True)
 p.add_argument('--evidence-dir',type=Path,required=True);p.add_argument('--shared-dir',type=Path,required=True)
 a=p.parse_args();stage='gate_adoption_prerequisites'
 try:
  if os.geteuid()!=0 or socket.gethostname()!='tunnex-peer':raise ValueError('owned root host required')
  for path in (a.journal.parent,a.evidence_dir,a.shared_dir):gated.private_directory(path)
  for name in ('runtime_stop_proof.py','runtime_restore_runner.py'):
   path=a.shared_dir/name;info=path.lstat()
   if path.resolve()!=path or not path.is_file() or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('shared source ownership')
  sys.path.insert(0,str(a.shared_dir));runner=importlib.import_module('runtime_restore_runner');proof=runner.proof
  import fcntl
  fd=os.open(a.journal.parent/'.restoration-supervisor.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
  try:
   import stat
   info=os.fstat(fd)
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError('lock ownership')
   fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   before=json.loads(gated.private_bytes(a.evidence_dir/'before.json',1<<20))
   stopped=json.loads(gated.private_bytes(a.evidence_dir/'stopped.json',1<<20))
   old=gated.private_bytes(a.evidence_dir/'stopped-journal.json',16<<20)
   import hashlib
   if stopped['snapshot']!=before or stopped['stopped_journal_raw_sha256']!=hashlib.sha256(old).hexdigest():raise ValueError('stop proof binding')
   current=proof.inspect(a.container);cid=current['id']
   if not current['state']['Running'] or current['state']['Pid']<=0 or current['state']['Pid']==before['pid']:raise ValueError('fresh running process required')
   if cid!=before['container'] or not re.fullmatch('[0-9a-f]{64}',cid):raise ValueError('original CID required')
   if proof.command('docker','inspect','--format','{{index .Config.Labels "tunnex.owner"}}',cid)!=gated.OWNER:raise ValueError('owner required')
   if proof.state_mount(current,str(a.journal))!=before['state_mount']:raise ValueError('original mount required')
   if proof.command('docker','inspect','--format','{{.HostConfig.RestartPolicy.Name}}',cid)!='no':raise ValueError('automatic restart refused')
   journal=gated.private_bytes(a.journal,16<<20);runner.journal_entries_unchanged(old,journal)
   entries=[e for e in json.loads(old)['Payload']['Entries'] if e['Phase']!='retained_refusal']
   if len(entries)!=1 or entries[0]['Phase']!='applied' or entries[0].get('ContractVersion')!=3 or entries[0]['Allocation'].get('ProfileID')!='azure-active-active-bgp-ipv4-v1':raise ValueError('original Azure obligation required')
   delivery=str(uuid.UUID(entries[0]['DeliveryID']))
   if os.path.lexists(a.journal.parent/('restore-'+delivery+'.json')):raise ValueError('existing receipt refused')
   gate=a.journal.parent/'restoration-startup-gate';raw=gated.private_bytes(gate,8192);identity=gate.lstat();marker(raw)
   stage='preserve_original_gate'
   evidence=a.evidence_dir/('gate-adoption-'+str(uuid.uuid4()));evidence.mkdir(mode=0o700)
   runner.write_bytes(evidence/'original-gate',raw)
   def recheck():
    if proof.boot()!=before['boot'] or proof.inspect(cid)!=current or gated.private_bytes(a.journal,16<<20)!=journal:raise ValueError('actual identity changed')
    if proof.command('docker','inspect','--format','{{index .Config.Labels "tunnex.owner"}}',cid)!=gated.OWNER:raise ValueError('owner changed')
   stage='atomic_gate_conversion'
   replace_gate(runner,gate,raw,identity,cid,recheck)
   gated.event('canonical_gate_installed_still_present')
  finally:os.close(fd)
 except (OSError,ValueError,KeyError,TypeError,ImportError,subprocess.SubprocessError):
  print(json.dumps({'stage':stage,'error_code':'owned_gate_adoption_refused','observed_at':gated.stamp()}));return 1
 return 0
if __name__=='__main__':raise SystemExit(main())
