#!/usr/bin/env python3
"""Run on bastion16 only after review. Samples real nonce responses; never injects faults.
Each sample invokes the approved v5 nonce probe, which independently validates
existing target identity/body/log and captures gateway NFT/CHILD before+after.
This is sequential HTTP traffic, not an established streaming TCP transfer test.
"""
import argparse,hashlib,json,os,pathlib,stat,subprocess,time
p=argparse.ArgumentParser();p.add_argument('--execute',action='store_true');p.add_argument('--probe-source',type=pathlib.Path,required=True);p.add_argument('--gateway-container',required=True);p.add_argument('--run-directory',type=pathlib.Path,required=True);p.add_argument('--samples',type=int,default=36);p.add_argument('--cadence',type=float,default=10);a=p.parse_args()
assert len(a.gateway_container)==64 and all(c in '0123456789abcdef' for c in a.gateway_container)
assert 3<=a.samples<=180 and 5<=a.cadence<=30
if not a.execute:
 print(json.dumps({'source_only':True,'samples':a.samples,'cadence_seconds':a.cadence,'sequential_requests':True,'fault_injected_by_sampler':False,'established_stream_tested':False}));raise SystemExit
assert pathlib.Path('/home/ubuntu/tunnex-bgp-vgw-eic-20261008').is_dir()
st=a.probe_source.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and not st.st_mode&0o022
expected='d3f7c32885dfe6a8f351edf50020683c4b1fe381e557d5738da7ee9110aff1cb'
assert hashlib.sha256(a.probe_source.read_bytes()).hexdigest()==expected
os.umask(0o077);a.run_directory.mkdir(mode=0o700)
def save(name,obj):
 with (a.run_directory/name).open('x') as f:json.dump(obj,f,indent=2);f.flush();os.fsync(f.fileno())
 fd=os.open(a.run_directory,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
start=time.monotonic();save('intent.json',{'wall_started':time.time(),'monotonic_started':start,'gateway':a.gateway_container,'probe_sha256':expected,'cadence':a.cadence,'samples':a.samples,'scope':'fresh independent target nonce per request; no faults or timer changes'})
rows=[];fatal=False
for n in range(a.samples):
 scheduled=start+n*a.cadence
 if time.monotonic()<scheduled:time.sleep(scheduled-time.monotonic())
 began=time.monotonic();wall=time.time()
 try:
  result=subprocess.run(['python3',str(a.probe_source),'--execute','--gateway-container',a.gateway_container,'--expect','allow'],capture_output=True,text=True,timeout=120)
 except subprocess.TimeoutExpired:
  save('sample-%03d.json'%n,{'index':n,'started_monotonic':began,'ended_monotonic':time.monotonic(),'infrastructure_error':True,'probe_timeout':True,'success':False,'traffic_failure':False});fatal=True;break
 ended=time.monotonic();status=None
 for line in result.stdout.splitlines():
  try:obj=json.loads(line)
  except json.JSONDecodeError:continue
  if isinstance(obj,dict) and 'receipt' in obj:status=obj
 row={'index':n,'started_monotonic':began,'ended_monotonic':ended,'wall_started':wall,'duration_seconds':ended-began,'schedule_lag_seconds':max(0,began-scheduled),'exit':result.returncode,'probe_summary':status,'success':False,'traffic_failure':False}
 if status:
  path=pathlib.Path(status['receipt']);assert path.parent==pathlib.Path('/home/ubuntu/tunnex-bgp-vgw-eic-20261008') and path.name=='nonce-'+status['nonce']+'-result.json'
  raw=path.read_bytes();r=json.loads(raw);probe=r['probe'];row.update({'receipt':str(path),'receipt_sha256':hashlib.sha256(raw).hexdigest(),'nonce':status['nonce'],'http_output':probe['stdout'],'curl_exit':probe['exit'],'success':bool(r['passed'] and probe['exit']==0 and len(r['matched'])==1),'traffic_failure':probe['exit']==28 and probe['stdout']=='HTTP=000\n' and not r['matched']})
  if not row['success'] and not row['traffic_failure']:row['infrastructure_error']=True;fatal=True
 # SSH errors, failed target control or uncertain outcomes never count as downtime.
 else:row['infrastructure_error']=True;row['stderr']=result.stderr[-2000:];fatal=True
 save('sample-%03d.json'%n,row);rows.append(row)
 if fatal:break
streak=maximum=0;windows=[];opened=None
for row in rows:
 if row['traffic_failure']:
  streak+=1;maximum=max(maximum,streak)
  if opened is None:opened=row
 elif row['success']:
  if opened is not None:
   windows.append({'first_failed_request':opened['index'],'first_healthy_recovery_request':row['index'],'observed_failure_to_recovery_seconds':row['ended_monotonic']-opened['started_monotonic'],'interpretation':'sampled request interval; not exact fault onset or continuous stream downtime'})
   opened=None
  streak=0
 else:streak=0
baseline=0
for row in rows:
 if not row['success']:break
 baseline+=1
save('summary.json',{'samples_completed':len(rows),'steady_baseline_successes':baseline,'successes':sum(r['success'] for r in rows),'confirmed_timeouts':sum(r['traffic_failure'] for r in rows),'max_consecutive_failures':maximum,'recovered_failure_windows':windows,'unrecovered_failure_first_request':None if opened is None else opened['index'],'infrastructure_error':fatal,'fault_control_external':True,'counter_route_correlation':'refer to each immutable nonce before/after NFT and CHILD snapshots; counter churn requires expression binding','existing_tcp_transfer_behavior_tested':False})
print(json.dumps({'run_directory':str(a.run_directory),'samples_completed':len(rows),'infrastructure_error':fatal}))
