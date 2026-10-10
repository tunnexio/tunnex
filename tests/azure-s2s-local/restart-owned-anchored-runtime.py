#!/usr/bin/env python3
"""Explicit controlled restart of the existing owned healthy Azure node and anchor."""
import argparse
from datetime import datetime,timezone
import fcntl
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import time
import uuid
spec=importlib.util.spec_from_file_location('gated',Path(__file__).with_name('assemble-gated-restoration.py'))
gated=importlib.util.module_from_spec(spec);spec.loader.exec_module(gated)

def evidence_parent(directory,private_root):
 if not private_root.is_absolute() or private_root.resolve()!=private_root or directory.parent!=private_root:raise ValueError('exact private evidence parent required')
 info=private_root.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=1000 or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('private API owner directory required')

def stable_runtime_identity(value):
 # Docker's Health log/counters may advance while the exact process remains alive.
 # Preserve every other State field, including unknown future fields, and all
 # inspected container/sandbox/mount ownership metadata.
 output=dict(value);output['state']={key:item for key,item in value['state'].items() if key!='Health'}
 return output

def same_runtime_identity(before,after):return stable_runtime_identity(before)==stable_runtime_identity(after)

def healthy(value,now):
 runtime=value['runtime'];observed=datetime.fromisoformat(runtime['observed_at'].replace('Z','+00:00'))
 if not 0 <= (now-observed).total_seconds() <=15:raise ValueError('stale health')
 if len(runtime['tunnels'])!=2 or any(t['status']!='up' for t in runtime['tunnels']):raise ValueError('tunnels unavailable')
 bgp=runtime['bgp']
 if len(bgp['peers'])!=2 or any(p['state']!='established' for p in bgp['peers']) or not any(r['prefix']=='10.231.0.0/16' for r in bgp['routes']):raise ValueError('routing unavailable')

def baseline(value):
 if value['source_address']!='10.233.10.2' or value['udp_payload_bytes']!=4096 or not value['tcp_large_requested']:raise ValueError('baseline scope')
 for key in ('fresh_tcp','existing_tcp','fresh_udp','existing_udp'):
  counter=value['counters'][key];samples=[s for s in value['samples'] if s['kind']==key]
  if counter['success']<5 or counter['failure']!=0 or not samples or not samples[-1]['success']:raise ValueError('baseline failed')
  if key.endswith('tcp') and any(s.get('source_preservation')!='preserved' or not s.get('large_same_socket') for s in samples):raise ValueError('TCP source or socket failed')
 ports=[s['local_port'] for s in value['samples'] if s['kind']=='existing_tcp']
 if len(set(ports))!=1:raise ValueError('existing TCP socket changed')

def archive_receipt(runner,entry,target,evidence):
 raw=gated.private_bytes(target,8192);identity=target.lstat();runner.validate_previous_receipt(entry,raw)
 runner.write_bytes(evidence/'previous-receipt.json',raw)
 if not os.path.samestat(identity,target.lstat()) or gated.private_bytes(target,8192)!=raw:raise ValueError('prior receipt changed')
 target.unlink();runner.sync_directory(target.parent)

INSTALLER_STAGES={'prerequisites','actual_stop_evidence','exact_gate_and_journal','fresh_runtime_observation','receipt_assembly','preinstall_identity','exclusive_receipt_install','exact_gate_release'}
def report_installer_refusal(raw):
 # Delegated diagnostics are data: only fixed whitelisted categories escape.
 if len(raw)>16384:return None
 for line in raw.splitlines():
  try:value=json.loads(line)
  except (ValueError,TypeError):continue
  if isinstance(value,dict) and value.get('stage') in INSTALLER_STAGES and value.get('error_code')=='gated_restoration_refused':
   return {'stage':'delegated_installer_refused','installer_stage':value['stage'],'error_code':'gated_restoration_refused','observed_at':gated.stamp(),'runtime_acceptance':'not_observed'}
 return None

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for key in ('container','anchor','journal','evidence-dir','shared-dir','private-root','lifecycle-helper','packet-helper','receipt-helper','receipt-helper-sha256'):p.add_argument('--'+key,required=True)
 a=p.parse_args();stage='preflight';lock=None
 try:
  if os.geteuid()!=0 or socket.gethostname()!='tunnex-peer':raise ValueError('owned root host required')
  journal=Path(a.journal);directory=Path(a.evidence_dir);shared=Path(a.shared_dir)
  gated.private_directory(journal.parent);evidence_parent(directory,Path(a.private_root));gated.private_directory(shared)
  if directory.name!='controlled-namespace-stop-2' or os.path.lexists(directory):raise ValueError('exclusive second proof directory required')
  for path in [shared/'runtime_stop_proof.py',shared/'runtime_restore_runner.py',Path(a.lifecycle_helper),Path(a.packet_helper)]:
   info=path.lstat()
   if not path.is_absolute() or path.resolve()!=path or not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('reviewed source ownership')
  helper=Path(a.receipt_helper);h=helper.lstat()
  if not helper.is_absolute() or helper.resolve()!=helper or not stat.S_ISREG(h.st_mode) or h.st_uid!=0 or h.st_mode&0o022 or not os.access(helper,os.X_OK):raise ValueError('reviewed binary ownership')
  if not re.fullmatch('[0-9a-f]{64}',a.receipt_helper_sha256) or hashlib.sha256(helper.read_bytes()).hexdigest()!=a.receipt_helper_sha256:raise ValueError('reviewed binary digest')
  sys.path.insert(0,str(shared));runner=importlib.import_module('runtime_restore_runner');proof=runner.proof
  def command(*args,timeout=60):return subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=timeout).stdout
  def owner(cid):
   if proof.command('docker','inspect','--format','{{index .Config.Labels "tunnex.owner"}}',cid)!=gated.OWNER:raise ValueError('owner refused')
   if proof.command('docker','inspect','--format','{{.HostConfig.RestartPolicy.Name}}',cid)!='no':raise ValueError('automatic restart refused')
  node=proof.inspect(a.container);anchor=proof.inspect(a.anchor);cid=node['id'];aid=anchor['id']
  if cid==aid:raise ValueError('distinct node and anchor required')
  for identity in (node,anchor):
   if not re.fullmatch('[0-9a-f]{64}',identity['id']) or not identity['state']['Running']:raise ValueError('running exact identities required')
   owner(identity['id'])
  if os.stat('/proc/%d/ns/net'%node['state']['Pid'])!=os.stat('/proc/%d/ns/net'%anchor['state']['Pid']):
   # Compare namespace identity, not full stat timestamps.
   n=os.stat('/proc/%d/ns/net'%node['state']['Pid']);b=os.stat('/proc/%d/ns/net'%anchor['state']['Pid'])
   if (n.st_dev,n.st_ino)!=(b.st_dev,b.st_ino):raise ValueError('shared namespace required')
  proof.state_mount(node,str(journal));gate=journal.parent/'restoration-startup-gate'
  if os.path.lexists(gate):raise ValueError('prior gate refused')
  lock=os.open(journal.parent/'.restoration-supervisor.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600);info=os.fstat(lock)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError('private lock required')
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  raw=gated.private_bytes(journal,16<<20);entries=[e for e in json.loads(raw)['Payload']['Entries'] if e['Phase']!='retained_refusal']
  if len(entries)!=1:raise ValueError('single obligation required')
  entry=entries[0]
  if entry['Phase']!='applied' or entry.get('ContractVersion')!=3 or entry['Allocation'].get('ProfileID')!='azure-active-active-bgp-ipv4-v1' or entry['Restoration']['Epoch']<1 or len(entry['Observed'])!=2:raise ValueError('restored Azure AA required')
  ns=os.readlink('/proc/%d/ns/net'%node['state']['Pid'])
  if entry['Allocation']['Namespace']!=ns or any(o['Namespace']!=ns for o in entry['Observed']):raise ValueError('current restored namespace required')
  target=journal.parent/('restore-'+str(uuid.UUID(entry['DeliveryID']))+'.json');runner.validate_previous_receipt(entry,gated.private_bytes(target,8192))
  directory.mkdir(mode=0o700)
  stage='real_client_baseline'
  # Exact owned LAN address attestation before deleting this fixed client namespace later.
  addresses=json.loads(command('ip','-n','azure-s2s-client','-j','address','show','dev','az-s2s-client'))
  if len(addresses)!=1 or not any(x.get('local')=='10.233.10.2' and x.get('prefixlen')==24 for x in addresses[0]['addr_info']):raise ValueError('owned client address required')
  links=json.loads(command('ip','-n','azure-s2s-client','-j','link','show'))
  if {link['ifname'] for link in links}!={'lo','az-s2s-client'}:raise ValueError('foreign client link refused')
  packet=directory/'baseline-packets.json'
  command('ip','netns','exec','azure-s2s-client','python3',a.packet_helper,'--source','10.233.10.2','--udp-bytes','4096','--tcp-large','--seconds','10','--timeout','1','--receipt',str(packet),timeout=25)
  baseline(json.loads(gated.private_bytes(packet,1<<20)))
  stage='normal_api_health'
  health=command('sudo','-u','#1000','--','python3',a.lifecycle_helper,'read','--private-root',a.private_root,timeout=30)
  healthy(json.loads(health),datetime.now(timezone.utc));runner.write_bytes(directory/'before-health.json',health)
  stage='live_journal_identity'
  current=gated.private_bytes(journal,16<<20);runner.journal_entries_unchanged(raw,current)
  stage='docker_process_identity'
  if not same_runtime_identity(node,proof.inspect(cid)) or not same_runtime_identity(anchor,proof.inspect(aid)):raise ValueError('runtime identity changed')
  gate_raw=json.dumps({'Version':1,'SupervisorRun':str(uuid.uuid4()),'ContainerID':cid},separators=(',',':')).encode()+b'\n'
  runner.write_bytes(gate,gate_raw);gate_identity=gate.lstat()
  before=proof.snapshot(cid,str(journal));proof.private_write(directory/'before.json',before)
  proof.private_write(directory/'anchor-before.json',anchor)
  stage='controlled_stop'
  gated.same_gate(gate,gate_raw,gate_identity)
  if proof.boot()!=before['boot'] or not same_runtime_identity(node,proof.inspect(cid)):raise ValueError('runtime changed before stop')
  gated.event('controlled_node_stop_started')
  command('docker','stop','--time','45',cid,timeout=55)
  owner(aid)
  if not same_runtime_identity(anchor,proof.inspect(aid)):raise ValueError('anchor changed before stop')
  command('ip','netns','delete','azure-s2s-client',timeout=10)
  command('docker','stop','--time','10',aid,timeout=20)
  stage='independent_stop_observation'
  # Bound the canonical host observer without changing its checks.
  command('python3',str(shared/'runtime_stop_proof.py'),'prove','--snapshot',str(directory/'before.json'),'--output',str(directory/'stopped.json'),timeout=50)
  stopped=json.loads(gated.private_bytes(directory/'stopped.json',1<<20))
  stopped_raw=gated.private_bytes(journal,16<<20)
  if hashlib.sha256(stopped_raw).hexdigest()!=stopped['stopped_journal_raw_sha256']:raise ValueError('stop journal changed')
  runner.write_bytes(directory/'stopped-journal.json',stopped_raw)
  stage='archive_consumed_receipt'
  stopped_entries=[e for e in json.loads(stopped_raw)['Payload']['Entries'] if e['Phase']!='retained_refusal']
  if len(stopped_entries)!=1:raise ValueError('stopped obligation changed')
  archive_receipt(runner,stopped_entries[0],target,directory)
  stage='same_identity_restart'
  gated.same_gate(gate,gate_raw,gate_identity)
  if proof.boot()!=before['boot']:raise ValueError('host boot changed')
  for identity in (cid,aid):owner(identity)
  command('docker','start',aid,timeout=30);pid=proof.inspect(aid)['state']['Pid']
  if pid<=0:raise ValueError('anchor not running')
  for args in [('ip','netns','add','azure-s2s-client'),('ip','link','add','az-s2s-lan','type','veth','peer','name','az-s2s-client'),('ip','link','set','az-s2s-client','netns','azure-s2s-client'),('ip','-n','azure-s2s-client','address','add','10.233.10.2/24','dev','az-s2s-client'),('ip','-n','azure-s2s-client','link','set','az-s2s-client','up'),('ip','-n','azure-s2s-client','link','set','lo','up'),('ip','-n','azure-s2s-client','route','add','default','via','10.233.10.1'),('ip','link','set','az-s2s-lan','netns',str(pid)),('nsenter','-t',str(pid),'-n','ip','address','add','10.233.10.1/24','dev','az-s2s-lan'),('nsenter','-t',str(pid),'-n','ip','link','set','az-s2s-lan','up')]:command(*args,timeout=10)
  command('docker','start',cid,timeout=30)
  gated.event('same_identities_started_gate_retained')
  # Delegate unchanged strict fresh observer/CLI/publication to reviewed manual installer.
  fcntl.flock(lock,fcntl.LOCK_UN);os.close(lock);lock=None
  stage='fresh_receipt_install'
  result=subprocess.run(['python3',str(Path(__file__).with_name('assemble-gated-restoration.py')),'--container',cid,'--journal',str(journal),'--evidence-dir',str(directory),'--shared-dir',str(shared),'--receipt-helper',a.receipt_helper,'--receipt-helper-sha256',a.receipt_helper_sha256],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45,check=False)
  if result.returncode!=0:
   diagnostic=report_installer_refusal(result.stdout)
   if diagnostic is not None:print(json.dumps(diagnostic),flush=True)
   raise ValueError('strict delegated installer refused; gate and proof retained')
  sys.stdout.buffer.write(result.stdout);sys.stdout.flush()
  gated.event('controlled_restart_receipt_complete_runtime_not_yet_observed')
 except (OSError,ValueError,KeyError,TypeError,ImportError,subprocess.SubprocessError):
  print(json.dumps({'stage':stage,'error_code':'controlled_restart_refused','observed_at':gated.stamp(),'runtime_acceptance':'not_observed'}));return 1
 finally:
  if lock is not None:os.close(lock)
 return 0
if __name__=='__main__':raise SystemExit(main())
