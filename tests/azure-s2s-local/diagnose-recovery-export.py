#!/usr/bin/env python3
"""Fixed-stage diagnosis only: no receipt values, bodies, journals or raw errors."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess

spec=importlib.util.spec_from_file_location('safe_recovery_export',Path(__file__).with_name('export-recovery-evidence.py'))
export=importlib.util.module_from_spec(spec);spec.loader.exec_module(export)
FIELDS={'source_address','direction','service','address','tcp_port','udp_port','started_at','packet_finished_at','packet_run_elapsed_seconds','counters','samples','kind','success','failure','maximum_observed_success_gap_seconds','seconds_since_last_success_at_run_end','source_preservation','version','container','boot','pid','started','observed_ns','namespace','device','inode','journal_raw_sha256','journal_entries_sha256','snapshot','termination','action','time_ns','verified_ns','checks','stopped_journal_raw_sha256','started_at','pid_start_ticks','startup_gate_device','startup_gate_inode','stop_evidence_sha256','stopped_journal_sha256','current_journal_sha256','startup_gate_sha256','stage','runtime_acceptance','observed_at'}|set(export.KINDS)


class ShapeFailure(ValueError):
 def __init__(self,path,category):self.path=path;self.category=category


def field(value,key,path,types):
 if not isinstance(value,dict):raise ShapeFailure(path,'expected_object')
 if key not in value:raise ShapeFailure(path+'.'+key,'missing_required_field')
 result=value[key]
 if type(result) not in types:raise ShapeFailure(path+'.'+key,'unexpected_type')
 return result


def packet_shape(value):
 for key in ('source_address','direction','started_at','packet_finished_at'):field(value,key,'packet',(str,))
 field(value,'packet_run_elapsed_seconds','packet',(int,float))
 service=field(value,'service','packet',(dict,))
 for key,types in [('address',(str,)),('tcp_port',(int,)),('udp_port',(int,))]:field(service,key,'packet.service',types)
 counters=field(value,'counters','packet',(dict,))
 for kind in export.KINDS:
  counter=field(counters,kind,'packet.counters',(dict,))
  for key,types in [('success',(int,)),('failure',(int,)),('maximum_observed_success_gap_seconds',(int,float)),('seconds_since_last_success_at_run_end',(int,float,type(None)))]:field(counter,key,'packet.counters.'+kind,types)
 samples=field(value,'samples','packet',(list,))
 if len(samples)>10000:raise ShapeFailure('packet.samples','bound_refused')
 for sample in samples:
  field(sample,'kind','packet.samples.item',(str,));field(sample,'success','packet.samples.item',(bool,))


def diagnostic(error):
 if isinstance(error,ShapeFailure):return {'category':error.category,'field_path':error.path}
 if isinstance(error,KeyError):
  key=error.args[0] if error.args else None
  return {'category':'missing_required_field','field':key if isinstance(key,str) and key in FIELDS else 'unrecognized_field'}
 if isinstance(error,FileNotFoundError):return {'category':'missing_file'}
 if isinstance(error,PermissionError):return {'category':'filesystem_permission_refused'}
 if isinstance(error,subprocess.TimeoutExpired):return {'category':'bounded_read_timeout'}
 if isinstance(error,OSError):return {'category':'filesystem_refused'}
 if isinstance(error,TypeError):return {'category':'unexpected_type'}
 return {'category':'strict_projection_or_ownership_refused'}


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--private-root',required=True,type=Path)
 parser.add_argument('--initial-refusal',required=True,type=Path)
 parser.add_argument('--read-current',action='store_true')
 args=parser.parse_args()
 def check(stage,operation):
  try:operation();output={'stage':stage,'result':'pass'}
  except (ValueError,KeyError,TypeError,OSError,subprocess.TimeoutExpired) as error:output={'stage':stage,'result':'refused',**diagnostic(error)}
  print(json.dumps(output,sort_keys=True),flush=True)
  return output['result']=='pass'
 if not check('private_root',lambda:export.private_root(args.private_root)):return
 root=args.private_root.resolve()
 for name in export.FILES:
  path=root/name
  if not path.exists():print(json.dumps({'stage':name,'result':'missing_optional_receipt'}));continue
  holder={}
  if check(name+':read_private',lambda:holder.update(value=export.read_private(path))):
   if check(name+':required_fields',lambda:packet_shape(holder['value'])):check(name+':strict_projection',lambda:export.packets(holder['value']))
 check('controlled-namespace-stop-2:strict_projection',lambda:export.controlled_restart(root))
 def initial():
  path=args.initial_refusal
  if path.name!='genuine-reboot-recovery.json' or path.is_symlink() or not path.is_file() or path.stat().st_size>2097152:raise ValueError('initial receipt shape')
  path.read_bytes() # No contents, digest or filesystem path emitted by diagnosis.
 check('initial_refusal:presence',initial)
 if args.read_current:
  def current():
   run=subprocess.run(export.current_read_command(root),capture_output=True,text=True,timeout=40)
   if run.returncode:raise ValueError('normal read refused')
   value=json.loads(run.stdout)
   if value.get('phase')!='read' or value.get('cas_request_sent') is not False:raise ValueError('not read only')
  check('normal_api:uid1000_read',current)


if __name__=='__main__':main()
