#!/usr/bin/env python3
"""Export fixed owned packet receipts and optional fresh normal API readback only."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import stat
import subprocess

FILES=('postboot-reenabled-packets.json','anchored-active-restart-cbdf882f-packets.json')
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
 if not isinstance(value,str) or len(value)>64:raise ValueError('timestamp')
 parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
 if parsed.tzinfo is None:raise ValueError('timestamp timezone')
 return parsed.isoformat()


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
