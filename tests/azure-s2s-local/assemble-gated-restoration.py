#!/usr/bin/env python3
"""Manual receipt installation for the already stopped/proved owned Azure runtime."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import uuid

OWNER='azure-s2s-01a12505'

def stamp():return datetime.now(timezone.utc).isoformat()
def private_directory(path):
 if not path.is_absolute() or path.resolve()!=path:raise ValueError('private directory path')
 info=path.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('private directory ownership')
 return info

def private_bytes(path,limit):
 if not path.is_absolute() or path.resolve()!=path:raise ValueError('private file path')
 before=path.lstat()
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  info=os.fstat(fd)
  if not os.path.samestat(before,info) or not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError('private file ownership')
  with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(limit+1)
  if len(raw)>limit or not os.path.samestat(info,path.lstat()):raise ValueError('private file changed or oversized')
  return raw
 finally:os.close(fd)

def same_gate(path,raw,identity):
 if not os.path.samestat(identity,path.lstat()) or private_bytes(path,8192)!=raw:raise ValueError('exact gate changed')

def install_receipt(runner,target,raw):
 temporary=target.parent/('.restore-'+str(uuid.uuid4())+'.tmp')
 runner.write_bytes(temporary,raw)
 # Same filesystem and atomic exclusive publication; no existing path replaced.
 os.link(temporary,target,follow_symlinks=False);runner.sync_directory(target.parent)
 if private_bytes(target,8192)!=raw:raise ValueError('installed receipt changed')
 temporary.unlink();runner.sync_directory(target.parent)

def event(stage):print(json.dumps({'stage':stage,'observed_at':stamp()}),flush=True)

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--container',required=True)
 p.add_argument('--journal',type=Path,required=True)
 p.add_argument('--evidence-dir',type=Path,required=True,help='Existing actual controlled stop proof directory; never created by this script')
 p.add_argument('--shared-dir',type=Path,required=True,help='Reviewed shared runtime_stop_proof.py and runtime_restore_runner.py')
 p.add_argument('--receipt-helper',type=Path,required=True)
 p.add_argument('--receipt-helper-sha256',required=True)
 a=p.parse_args();stage='prerequisites'
 try:
  if os.geteuid()!=0 or socket.gethostname()!='tunnex-peer':raise ValueError('owned host root required')
  private_directory(a.evidence_dir);private_directory(a.shared_dir);private_directory(a.journal.parent)
  for name in ('runtime_stop_proof.py','runtime_restore_runner.py'):
   path=a.shared_dir/name;info=path.lstat()
   if path.resolve()!=path or not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('shared source ownership')
  helper=a.receipt_helper;info=helper.lstat()
  if not helper.is_absolute() or helper.resolve()!=helper or not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or not os.access(helper,os.X_OK):raise ValueError('helper ownership')
  if not re.fullmatch('[0-9a-f]{64}',a.receipt_helper_sha256) or hashlib.sha256(helper.read_bytes()).hexdigest()!=a.receipt_helper_sha256:raise ValueError('reviewed helper digest')
  sys.path.insert(0,str(a.shared_dir));runner=importlib.import_module('runtime_restore_runner');proof=runner.proof
  lockfd=os.open(a.journal.parent/'.restoration-supervisor.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
  try:
   lockinfo=os.fstat(lockfd)
   if not stat.S_ISREG(lockinfo.st_mode) or lockinfo.st_uid!=0 or stat.S_IMODE(lockinfo.st_mode)!=0o600:raise ValueError('supervisor lock ownership')
   fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   stage='actual_stop_evidence'
   before_raw=private_bytes(a.evidence_dir/'before.json',1<<20)
   stopped_raw=private_bytes(a.evidence_dir/'stopped.json',1<<20)
   journal_raw=private_bytes(a.evidence_dir/'stopped-journal.json',16<<20)
   before=json.loads(before_raw);stopped=json.loads(stopped_raw)
   if stopped['snapshot']!=before or stopped['stopped_journal_raw_sha256']!=hashlib.sha256(journal_raw).hexdigest():raise ValueError('actual stop proof binding')
   current=proof.inspect(a.container);cid=current['id']
   if cid!=before['container'] or not re.fullmatch('[0-9a-f]{64}',cid):raise ValueError('same inspected container required')
   if proof.command('docker','inspect','--format','{{index .Config.Labels "tunnex.owner"}}',cid)!=OWNER:raise ValueError('owned runtime required')
   if proof.command('docker','inspect','--format','{{.HostConfig.RestartPolicy.Name}}',cid)!='no':raise ValueError('automatic restart policy refused')
   if proof.state_mount(current,str(a.journal))!=before['state_mount']:raise ValueError('exact original state mount required')
   stage='exact_gate_and_journal'
   gate=a.journal.parent/'restoration-startup-gate';gate_raw=private_bytes(gate,8192);gate_identity=gate.lstat();gate_value=json.loads(gate_raw)
   if set(gate_value)!={'Version','SupervisorRun','ContainerID'} or gate_value['Version']!=1 or not isinstance(gate_value['SupervisorRun'],str) or not gate_value['SupervisorRun'] or gate_value['ContainerID']!=cid:raise ValueError('gate owner mismatch')
   current_raw=private_bytes(a.journal,16<<20);runner.journal_entries_unchanged(journal_raw,current_raw)
   entries=[e for e in json.loads(journal_raw)['Payload']['Entries'] if e['Phase']!='retained_refusal']
   if len(entries)!=1 or entries[0]['Phase']!='applied' or entries[0].get('ContractVersion')!=3 or entries[0]['Allocation'].get('ProfileID')!='azure-active-active-bgp-ipv4-v1':raise ValueError('exact Azure AA BGP obligation required')
   entry=entries[0];delivery=str(uuid.UUID(entry['DeliveryID']))
   target=a.journal.parent/('restore-'+delivery+'.json')
   if os.path.lexists(target):raise ValueError('preexisting receipt refused')
   pid=current['state']['Pid'];ns=os.readlink('/proc/%d/ns/net'%pid)
   stage='fresh_runtime_observation'
   fresh=runner.observe_fresh_runtime(before,stopped_raw,journal_raw,current_raw,current,ns,gate,gate_raw,gate_identity)
   attempt=a.evidence_dir/('assemble-'+str(uuid.uuid4()));attempt.mkdir(mode=0o700)
   proof.private_write(attempt/'fresh-runtime.json',fresh)
   runner.write_bytes(attempt/'current-journal.json',current_raw)
   stage='receipt_assembly'
   command=[str(helper),'-journal',str(a.evidence_dir/'stopped-journal.json'),'-evidence',str(a.evidence_dir/'stopped.json'),'-boot',proof.boot(),'-namespace',ns,'-delivery',delivery,'-fresh-runtime',str(attempt/'fresh-runtime.json'),'-startup-gate',str(gate),'-current-journal',str(attempt/'current-journal.json'),'-out',str(attempt/'receipt.json')]
   result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
   if result.returncode!=0:raise ValueError('reviewed CLI refused actual proof')
   raw=private_bytes(attempt/'receipt.json',8192)
   stage='preinstall_identity'
   again=proof.inspect(cid)
   if again!=current or proof.boot()!=before['boot'] or private_bytes(a.journal,16<<20)!=current_raw:raise ValueError('runtime or journal changed before installation')
   runner.observe_fresh_runtime(before,stopped_raw,journal_raw,current_raw,again,ns,gate,gate_raw,gate_identity)
   same_gate(gate,gate_raw,gate_identity)
   stage='exclusive_receipt_install'
   install_receipt(runner,target,raw)
   event('receipt_installed')
   stage='exact_gate_release'
   if proof.inspect(cid)!=current or proof.boot()!=before['boot'] or private_bytes(a.journal,16<<20)!=current_raw:raise ValueError('runtime changed before gate release')
   same_gate(gate,gate_raw,gate_identity)
   gate.unlink();runner.sync_directory(gate.parent)
   proof.private_write(attempt/'result.json',{'stage':'exact_gate_released','observed_at':stamp(),'runtime_acceptance':'not_observed'})
   event('exact_gate_released')
  finally:os.close(lockfd)
 except (OSError,ValueError,KeyError,TypeError,ImportError,subprocess.SubprocessError):
  print(json.dumps({'stage':stage,'observed_at':stamp(),'error_code':'gated_restoration_refused','runtime_acceptance':'not_observed'}),flush=True)
  return 1
 return 0

if __name__=='__main__':raise SystemExit(main())
