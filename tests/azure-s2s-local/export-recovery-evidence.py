#!/usr/bin/env python3
"""Export fixed owned packet receipts and optional fresh normal API readback only."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
import os
import re
import uuid
from pathlib import Path
import stat
import subprocess

FILES=('postboot-reenabled-packets.json','anchored-active-restart-cbdf882f-packets.json',
       'controlled-recovery-fd6eeaff-packets.json','controlled-healthy-restart-12cfccbb-packets.json')
KINDS=('fresh_tcp','existing_tcp','fresh_udp','existing_udp')


def read_private(path, owner=0):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as stream:
  info=os.fstat(stream.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=owner or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>2097152:raise ValueError('private receipt shape')
  return json.load(stream)


def number(value):
 if type(value) not in (int,float) or not math.isfinite(value) or not 0<=value<=100000:raise ValueError('bounded number')
 return value


def timestamp(value):
 # Python3.10 rejects RFC3339Nano; validate calendar/offset with at most six
 # fractional digits, but retain the original observed precision in evidence.
 if not isinstance(value,str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})',value):raise ValueError('timestamp shape')
 compatible=re.sub(r'(\.[0-9]{6})[0-9]{1,3}(?=Z|[+-])',r'\1',value).replace('Z','+00:00')
 try:
  parsed=datetime.fromisoformat(compatible)
  offset=value[-6:] if not value.endswith('Z') else None
  if parsed.tzinfo is None or offset is not None and (int(offset[1:3])>23 or int(offset[4:6])>59):raise ValueError('timestamp shape')
 except ValueError:raise ValueError('timestamp shape') from None
 return value


def packets(value):
 if value.get('source_address')!='10.233.10.2' or value.get('direction')!='forward' or value.get('service')!={'address':'10.231.1.4','tcp_port':8080,'udp_port':8081}:raise ValueError('owned packet binding')
 output={key:timestamp(value[key]) for key in ('started_at','packet_finished_at')}
 output.update(source_address='10.233.10.2',direction='forward',counters={},tcp_source_preservation_counts={})
 output['packet_run_elapsed_seconds']=number(value['packet_run_elapsed_seconds'])
 for kind in KINDS:
  raw=value['counters'][kind];counter={}
  for field in ('success','failure'):
   if type(raw[field])!=int or not 0<=raw[field]<=100000:raise ValueError('counter')
   counter[field]=raw[field]
  counter['maximum_observed_success_gap_seconds']=number(raw['maximum_observed_success_gap_seconds'])
  age=raw['seconds_since_last_success_at_run_end']
  counter['seconds_since_last_success_at_run_end']=None if age is None else number(age)
  output['counters'][kind]=counter
 samples=value['samples']
 if not isinstance(samples,list) or len(samples)>10000:raise ValueError('sample bound')
 counts={kind:{'success':0,'failure':0} for kind in KINDS}
 categories=('preserved','owned_lan_source_mismatch','nat_source_mismatch','unrecognized_source_mismatch','diagnostic_unknown')
 for sample in samples:
  kind=sample['kind']
  if kind not in KINDS or type(sample['success'])!=bool:raise ValueError('sample shape')
  counts[kind]['success' if sample['success'] else 'failure']+=1
  if kind.endswith('tcp'):
   category=sample.get('source_preservation','diagnostic_unknown')
   if category not in categories:raise ValueError('source category')
   output['tcp_source_preservation_counts'][category]=output['tcp_source_preservation_counts'].get(category,0)+1
 for kind in KINDS:
  if any(counts[kind][field]!=output['counters'][kind][field] for field in ('success','failure')):raise ValueError('counter/sample mismatch')
 return output


def integer(value,low=0,high=9223372036854775807):
 if type(value)!=int or not low<=value<=high:raise ValueError('bounded lifecycle integer')
 return value


def hex_digest(value):
 if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}',value):raise ValueError('identity/hash shape')
 return value


def boot_id(value):
 if not isinstance(value,str) or str(uuid.UUID(value))!=value:raise ValueError('boot identity')
 return value


def stop_snapshot(value):
 if value.get('version')!=1:raise ValueError('snapshot version')
 result={'version':1,'container':hex_digest(value['container']),'boot':boot_id(value['boot']),
         'pid':integer(value['pid'],1),'started':timestamp(value['started']),
         'observed_ns':integer(value['observed_ns'],1),
         'namespace':{key:integer(value['namespace'][key],1) for key in ('device','inode')}}
 for key in ('journal_entries_sha256','journal_raw_sha256'):result[key]=hex_digest(value[key])
 return result


def stopped_proof(value):
 required=['exact-stopped-runtime','empty-cgroup','no-namespace-holders-two-passes']
 if value.get('version')!=1 or value.get('kind')!='supervisor-confirmed-runtime-stop' or value.get('checks')!=required:raise ValueError('stop proof shape')
 snapshot=stop_snapshot(value['snapshot']);event=value['termination']
 if event.get('action')!='die' or event.get('container')!=snapshot['container']:raise ValueError('termination binding')
 event_ns=integer(event['time_ns'],1);verified=integer(value['verified_ns'],1)
 if not snapshot['observed_ns']<=event_ns<=verified:raise ValueError('termination ordering')
 return {'version':1,'kind':value['kind'],'snapshot':snapshot,'checks':required,
         'termination':{'container':snapshot['container'],'action':'die','time_ns':event_ns},
         'verified_ns':verified,'stopped_journal_raw_sha256':hex_digest(value['stopped_journal_raw_sha256'])}


def fresh_runtime(value):
 if value.get('version')!=1 or value.get('kind')!='supervisor-confirmed-fresh-runtime':raise ValueError('fresh runtime kind')
 ns=value['namespace']
 if not isinstance(ns,str) or not re.fullmatch(r'net:\[[1-9][0-9]{0,19}\]',ns):raise ValueError('namespace identity')
 result={'version':1,'kind':value['kind'],'container':hex_digest(value['container']),
         'boot':boot_id(value['boot']),'namespace':ns,'started_at':timestamp(value['started_at'])}
 for key in ('pid','pid_start_ticks','startup_gate_device','startup_gate_inode'):result[key]=integer(value[key],1)
 for key in ('stop_evidence_sha256','stopped_journal_sha256','current_journal_sha256','startup_gate_sha256'):result[key]=hex_digest(value[key])
 return result


def root_evidence_directory(path):
 info=path.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700 or path.absolute()!=path.resolve():raise ValueError('root evidence directory')


def controlled_restart(root):
 directory=root/'controlled-namespace-stop-2'
 if not directory.exists():return {'availability':'missing'}
 root_evidence_directory(directory)
 before=stop_snapshot(read_private(directory/'before.json'))
 stopped=stopped_proof(read_private(directory/'stopped.json'))
 if before!=stopped['snapshot']:raise ValueError('snapshot/proof binding')
 attempts=[]
 for path in directory.iterdir():
  if path.name.startswith('assemble-'):
   suffix=path.name[len('assemble-'):]
   if str(uuid.UUID(suffix))!=suffix:raise ValueError('attempt identity')
   root_evidence_directory(path);attempts.append(path)
 if len(attempts)>100:raise ValueError('attempt bound')
 accepted=[];missing=0
 for path in attempts:
  if not (path/'result.json').exists():missing+=1;continue
  result=read_private(path/'result.json')
  if result.get('stage')!='exact_gate_released' or result.get('runtime_acceptance')!='not_observed':raise ValueError('gate result shape')
  fresh=fresh_runtime(read_private(path/'fresh-runtime.json'))
  if fresh['container']!=before['container'] or fresh['boot']!=before['boot'] or fresh['pid']==before['pid'] or fresh['started_at']==before['started']:raise ValueError('fresh runtime binding')
  if fresh['stopped_journal_sha256']!=stopped['stopped_journal_raw_sha256']:raise ValueError('stopped journal hash binding')
  accepted.append({'fresh_runtime':fresh,'gate_release':{'stage':'exact_gate_released','observed_at':timestamp(result['observed_at']),'runtime_acceptance':'not_observed'}})
 if len(accepted)!=1:raise ValueError('expected exactly one accepted gate result')
 return {'availability':'observed','snapshot':before,'stop_proof':stopped,
         'accepted_installation':accepted[0],'attempts_without_result':missing,
         'initial_install_refusal':{'availability':'not_saved','cause':'unclassified'},
         'scope':'Stop and exact gate-release observations only; no zero-outage or old LAN socket continuity proof'}


def private_root(root):
 info=root.lstat()
 if os.geteuid()!=0 or not stat.S_ISDIR(info.st_mode) or info.st_uid!=1000 or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('root observer requires UID1000 private root')
 # Reject symlink ancestors before passing the same exact path to sudo.
 if root.absolute()!=root.resolve():raise ValueError('private root path')
 return root.resolve()


def current_read_command(root):
 return ['sudo','-u','#1000','--','python3',str(Path(__file__).resolve().with_name('lifecycle-live.py')),'read','--private-root',str(root)]


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--private-root',required=True,type=Path)
 parser.add_argument('--output',required=True,type=Path)
 parser.add_argument('--initial-refusal',required=True,type=Path,help='Packaged unchanged genuine-reboot-recovery.json; SHA only')
 parser.add_argument('--read-current',action='store_true',help='Execute lifecycle-live.py read against fixed localhost normal API; never changes intent')
 args=parser.parse_args();root=private_root(args.private_root)
 result={'exported_at':datetime.now(timezone.utc).isoformat(),'scope':'Historical packet observations and optional fresh normal API status; no restoration authorization or production readiness claim','historical_packet_receipts':{},'current_status':{'availability':'not_requested'},'warm_restart_summary':{'availability':'not_projected_without_verified_schema'},'cleanup_revision_5_receipt':{'availability':'not_saved'},'enable_revision_6_receipt':{'availability':'not_saved'}}
 for name in FILES:
  path=root/name
  if not path.exists():result['historical_packet_receipts'][name]={'availability':'missing'};continue
  result['historical_packet_receipts'][name]={'availability':'observed','observations':packets(read_private(path))}
 result['controlled_restart']=controlled_restart(root)
 initial=args.initial_refusal
 if initial.name!='genuine-reboot-recovery.json' or initial.is_symlink() or not initial.is_file() or initial.stat().st_size>2097152:raise ValueError('initial receipt shape')
 result['initial_refusal_receipt']={'path':'docs/evidence/azure-s2s-20261010/genuine-reboot-recovery.json','sha256':hashlib.sha256(initial.read_bytes()).hexdigest(),'preserved':True}
 if args.read_current:
  run=subprocess.run(current_read_command(root),capture_output=True,text=True,timeout=40)
  if run.returncode:result['current_status']={'availability':'read_failed'}
  else:
   # Independently re-project the reader output; never copy unknown nested fields.
   value=json.loads(run.stdout)
   if value.get('phase')!='read' or value.get('cas_request_sent') is not False:raise ValueError('read-only receipt')
   spec=importlib.util.spec_from_file_location('recovery_lifecycle',Path(__file__).with_name('lifecycle-live.py'))
   lifecycle=importlib.util.module_from_spec(spec);spec.loader.exec_module(lifecycle)
   setup=read_private(root/'api-setup.json',1000);allocation=read_private(root/'azure-live-activation.json',1000)
   # The child omits binding IDs after validation; restore only owned inputs.
   bound={**value['connection'],'org_id':setup['org_id'],'site_id':setup['site_id'],'gateway_node_id':setup['gateway_id']}
   connection=lifecycle.connection_projection(bound,setup,allocation['id'])
   runtime=lifecycle.runtime_projection(value['runtime'],allocation['tunnel_ids'])
   if 'bgp' in runtime:
    runtime['bgp']['route_count']=len(runtime['bgp'].pop('routes'))
   result['current_status']={'availability':'fresh_normal_api_read','observed_at':timestamp(value['observed_at']),'connection':connection,'runtime':runtime,'application_reachability':'not_measured_by_status_read'}
 fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as stream:json.dump(result,stream,indent=2);stream.write('\n')
 print('Typed recovery evidence exported; historical observations remain separate from current status.')


if __name__=='__main__':
 try:main()
 except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired):raise SystemExit('Recovery export refused: missing prerequisite or unexpected receipt shape')
