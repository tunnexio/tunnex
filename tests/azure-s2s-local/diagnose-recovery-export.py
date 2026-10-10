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
 known={'snapshot version','identity/hash shape','boot identity','timestamp','timestamp shape','timestamp timezone','bounded lifecycle integer','stop proof shape','termination binding','termination ordering','fresh runtime kind','namespace identity','root evidence directory','snapshot/proof binding','attempt identity','attempt bound','gate result shape','fresh runtime binding','stopped journal hash binding','expected exactly one accepted gate result','private receipt shape','root observer requires UID1000 private root','private root path'}
 if isinstance(error,ValueError) and str(error) in known:return {'category':'strict_validation_refused','validation':str(error).replace(' ','_').replace('/','_')}
 return {'category':'strict_projection_or_ownership_refused'}


def lifecycle_fields(value,prefix,check,fresh=False):
 checks=[('container',export.hex_digest),('boot',export.boot_id),
         ('pid',lambda value:export.integer(value,1)),
         ('started_at' if fresh else 'started',export.timestamp)]
 if fresh:
  checks += [(key,export.hex_digest) for key in ('stop_evidence_sha256','stopped_journal_sha256','current_journal_sha256','startup_gate_sha256')]
  checks += [(key,lambda value:export.integer(value,1)) for key in ('pid_start_ticks','startup_gate_device','startup_gate_inode')]
 else:
  checks += [('observed_ns',lambda value:export.integer(value,1))]
  checks += [(key,export.hex_digest) for key in ('journal_raw_sha256','journal_entries_sha256')]
 for key,validator in checks:
  check(prefix+':field:'+key,lambda key=key,validator=validator:validator(value[key]))


def controlled_stages(root,check):
 directory=root/'controlled-namespace-stop-2'
 if not directory.exists():print(json.dumps({'stage':'controlled:directory','result':'missing_optional_receipt'}));return
 if not check('controlled:directory_ownership',lambda:export.root_evidence_directory(directory)):return
 values={}
 for name,projector in [('before.json',export.stop_snapshot),('stopped.json',export.stopped_proof)]:
  holder={}
  if check('controlled:'+name+':read_private',lambda:holder.update(value=export.read_private(directory/name))):
   if name=='before.json':lifecycle_fields(holder['value'],'controlled:before.json',check)
   elif isinstance(holder['value'].get('snapshot'),dict):lifecycle_fields(holder['value']['snapshot'],'controlled:stopped.json:snapshot',check)
   check('controlled:'+name+':projection',lambda:values.update({name:projector(holder['value'])}))
 if len(values)==2:
  def binding():
   if values['before.json']!=values['stopped.json']['snapshot']:raise ValueError('snapshot/proof binding')
  check('controlled:snapshot_proof_binding',binding)
 attempts=[]
 for path in directory.iterdir():
  if path.name.startswith('assemble-'):
   def identity():
    import uuid
    suffix=path.name[len('assemble-'):]
    if str(uuid.UUID(suffix))!=suffix:raise ValueError('attempt identity')
   if not check('controlled:attempt_identity',identity):continue
   if check('controlled:attempt_directory_ownership',lambda:export.root_evidence_directory(path)):attempts.append(path)
 if len(attempts)>100:check('controlled:attempt_count_bound',lambda:(_ for _ in ()).throw(ValueError('attempt bound')));return
 accepted=0
 for path in sorted(attempts):
  # Never emit the path or UUID. Labels identify only accepted fixed stage names.
  if not (path/'result.json').exists():print(json.dumps({'stage':'controlled:attempt_result','result':'missing_result'}));continue
  result={};fresh={}
  if check('controlled:result.json:read_private',lambda:result.update(value=export.read_private(path/'result.json'))):
   def result_shape():
    value=result['value']
    if value.get('stage')!='exact_gate_released' or value.get('runtime_acceptance')!='not_observed':raise ValueError('gate result shape')
    export.timestamp(value['observed_at'])
   if check('controlled:result.json:shape',result_shape):accepted+=1
  if check('controlled:fresh-runtime.json:read_private',lambda:fresh.update(value=export.read_private(path/'fresh-runtime.json'))):
   lifecycle_fields(fresh['value'],'controlled:fresh-runtime.json',check,fresh=True)
   if check('controlled:fresh-runtime.json:projection',lambda:fresh.update(projected=export.fresh_runtime(fresh['value']))) and len(values)==2:
    def fresh_binding():
     before=values['before.json'];value=fresh['projected']
     if value['container']!=before['container'] or value['boot']!=before['boot'] or value['pid']==before['pid'] or value['started_at']==before['started']:raise ValueError('fresh runtime binding')
    check('controlled:fresh_runtime_binding',fresh_binding)
    def hash_binding():
     if fresh['projected']['stopped_journal_sha256']!=values['stopped.json']['stopped_journal_raw_sha256']:raise ValueError('stopped journal hash binding')
    check('controlled:stopped_journal_hash_binding',hash_binding)
 def result_count():
  if accepted!=1:raise ValueError('expected exactly one accepted gate result')
 check('controlled:accepted_result_count',result_count)


def child_failure(stdout):
 output={'category':'normal_api_read_refused'}
 try:
  if len(stdout)>16384:return output
  value=json.loads(stdout)
  stages={'arguments','private_root','private_inputs','normal_owner_login','owned_organization','fresh_connection_revision','fresh_cleanup_readback','typed_runtime_status','receipt'}
  if value.get('error')!='lifecycle_failed':return output
  if value.get('stage') in stages:output['child_stage']=value['stage']
  if value.get('category') in ('api','input_or_response_shape'):output['child_category']=value['category']
  if type(value.get('http_status'))==int and value['http_status'] in (400,401,403,404,409,429,500,502,503,504):output['http_status']=value['http_status']
 except (ValueError,TypeError,AttributeError):pass
 return output


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
 controlled_stages(root,check)
 check('controlled:final_strict_projection',lambda:export.controlled_restart(root))
 def initial():
  path=args.initial_refusal
  if path.name!='genuine-reboot-recovery.json' or path.is_symlink() or not path.is_file() or path.stat().st_size>2097152:raise ValueError('initial receipt shape')
  path.read_bytes() # No contents, digest or filesystem path emitted by diagnosis.
 check('initial_refusal:presence',initial)
 if args.read_current:
  def current():
   run=subprocess.run(export.current_read_command(root),capture_output=True,text=True,timeout=40)
   if run.returncode:
    print(json.dumps({'stage':'normal_api:uid1000_read','result':'refused',**child_failure(run.stdout)},sort_keys=True));return
   value=json.loads(run.stdout)
   if value.get('phase')!='read' or value.get('cas_request_sent') is not False:raise ValueError('not read only')
   print(json.dumps({'stage':'normal_api:uid1000_read','result':'pass'}))
  try:current()
  except (ValueError,KeyError,TypeError,OSError,subprocess.TimeoutExpired) as error:
   print(json.dumps({'stage':'normal_api:uid1000_read','result':'refused',**diagnostic(error)},sort_keys=True))


if __name__=='__main__':main()
