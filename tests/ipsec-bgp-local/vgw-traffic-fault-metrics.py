#!/usr/bin/env python3
"""Offline-only correlation of immutable sampler and actual fault receipts.
Does not inject faults, run probes, or accept route/session state as traffic success.
"""
import argparse,datetime,hashlib,json,os,pathlib,stat
p=argparse.ArgumentParser();p.add_argument('--measurement',type=pathlib.Path,required=True);p.add_argument('--fault-begin',type=pathlib.Path,required=True);p.add_argument('--fault-restore',type=pathlib.Path,required=True);p.add_argument('--pins',type=pathlib.Path,required=True);p.add_argument('--fixture-control',type=pathlib.Path,required=True);p.add_argument('--worker-before',type=pathlib.Path,required=True);p.add_argument('--worker-after',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
def load(path):
 s=path.lstat();assert stat.S_ISREG(s.st_mode) and not s.st_mode&0o022;raw=path.read_bytes();return json.loads(raw),hashlib.sha256(raw).hexdigest()
m,msha=load(a.measurement);begin,bsha=load(a.fault_begin);restore,rsha=load(a.fault_restore);pin,psha=load(a.pins)
assert pin['root_reviewed'] is True
wb,wbsha=load(a.worker_before);wa,washa=load(a.worker_after);assert wb['exit']==wa['exit']==0 and wb['stdout']==wa['stdout']
identity_lines=wb['stdout'].splitlines();assert len(identity_lines)==4
head=identity_lines[0].split();assert len(head)==4 and head[0]==pin['gateway_id'] and head[1]==pin['image'] and head[2].isdigit() and int(head[2])>0
assert identity_lines[1]==pin['namespace']
assert identity_lines[2].split()==[pin['node_sha256'],'/proc/1/exe'] and identity_lines[3].split()==[pin['cert_sha256'],'/state/cert.pem']
assert m['before']['exit']==m['after']['exit']==0 and m['before']['stdout'].startswith(pin['gateway_id']+' true\n') and m['after']['stdout'].startswith(pin['gateway_id']+' true\n')
assert begin['identity']==restore['identity'] and begin['identity']['container']==pin['gateway_id'] and begin['identity']['namespace']==pin['namespace'] and begin['identity']['node_sha256']==pin['node_sha256']
assert restore['foreign_rules_preserved'] is True and restore['owned_fault_rules_absent'] is True
skew=pin['maximum_verified_clock_skew_seconds'];assert isinstance(skew,(int,float)) and 0<=skew<=1
assert pin['clock_skew_evidence_sha256'] and len(pin['clock_skew_evidence_sha256'])==64
started=datetime.datetime.fromisoformat(begin['at']).timestamp();injection_started=datetime.datetime.fromisoformat(begin.get('injection_started_at',begin['at'])).timestamp();ended=datetime.datetime.fromisoformat(restore['at']).timestamp();assert injection_started<=started<=ended
rows=m['measurement']['rows'];assert rows and all(rows[i]['started']<=rows[i+1]['started']for i in range(len(rows)-1))
control,csha=load(a.fixture_control);assert control['control']['exit']==0
fixtures={r['nonce']:r for r in control['fixtures']};assert len(fixtures)==len(control['fixtures'])==len(rows) and len({r['nonce']for r in rows})==len(rows)
assert control['control']['stdout']==control['fixtures'][0]['body']
verified=[]
assert m['measurement']['client_result_path'] and isinstance(m['measurement']['client_result_path'],str)
for row in rows:
 assert row['ended']>=row['started']
 if row['success']:assert row['exit']==0 and row['target_matches']==1 and row['stdout']==fixtures[row['nonce']]['body']+'HTTP=200\n'
 assert isinstance(row['exit'],int) and 0<=row['exit']<=255
 if row['success']:row['failure_class']=None
 elif row['exit']==28 and row['stdout']=='HTTP=000\n' and row['target_matches']==0:row['failure_class']='curl_timeout'
 elif row['exit']==7 and row['stdout']=='HTTP=000\n' and row['target_matches']==0:row['failure_class']='curl_connect_failure'
 elif row['exit']==255:row['failure_class']='execution_uncertain'
 elif row['exit']==0:row['failure_class']='http_or_body_or_correlation_failure'
 else:row['failure_class']='other_curl_error'
 if row['confirmed_timeout']:assert row['exit']==28 and row['stdout']=='HTTP=000\n' and row['target_matches']==0
 verified.append(row)
baseline=[r for r in verified if r['wall']+(r['ended']-r['started'])<injection_started-skew]
fault=[r for r in verified if r['wall']>=started+skew and r['wall']+(r['ended']-r['started'])<=ended-skew]
after=[r for r in verified if r['wall']>=ended+skew]
injection_fault=[r for r in verified if r['wall']>=injection_started+skew and r['wall']+(r['ended']-r['started'])<=ended-skew]
first_injection_failure=next((r for r in injection_fault if not r['success'] and r['failure_class']!='execution_uncertain'),None)
first_failure=next((r for r in fault if not r['success'] and r['failure_class']!='execution_uncertain'),None)
survivor=next((r for r in fault if r['success'] and (first_failure is None or r['started']>first_failure['started'])),None)
injection_survivor=next((r for r in fault if r['success'] and (first_injection_failure is None or r['started']>first_injection_failure['started'])),None)
restoration=next((r for r in after if r['success']),None)
result={'source_only_offline_metrics':True,'input_sha256':{'measurement':msha,'fault_begin':bsha,'fault_restore':rsha,'pins':psha,'worker_before':wbsha,'worker_after':washa,'fixture_control':csha},'gateway_id':pin['gateway_id'],'verified_clock_skew_seconds':skew,'baseline_samples':len(baseline),'baseline_all_healthy':bool(baseline) and all(r['success']for r in baseline),'steady_baseline_qualified':len(baseline)>=15 and all(r['success']for r in baseline),'minimum_steady_baseline_samples':15,'fully_inside_fault_samples':len(fault),'injection_started_at':begin.get('injection_started_at',begin['at']),'full_fault_started_at':begin['at'],'partial_injection_window_seconds':started-injection_started,'first_injection_failed_request':None if first_injection_failure is None else first_injection_failure['index'],'sampled_injection_failure_to_survivor_seconds':None if injection_survivor is None or first_injection_failure is None else injection_survivor['ended']-first_injection_failure['started'],'fault_timeouts':sum(r['failure_class']=='curl_timeout'for r in fault),'fault_connect_failures':sum(r['failure_class']=='curl_connect_failure'for r in fault),'fault_failure_classes':{kind:sum(r['failure_class']==kind for r in fault)for kind in ['curl_timeout','curl_connect_failure','http_or_body_or_correlation_failure','other_curl_error','execution_uncertain']},'first_failure_class':None if first_failure is None else first_failure['failure_class'],'first_failed_request':None if first_failure is None else first_failure['index'],'first_healthy_during_full_fault':None if survivor is None else survivor['index'],'fault_sustained_successes':sum(r['success']for r in fault),'survivor_failover_censored':survivor is None,'sampled_failure_to_survivor_seconds':None if survivor is None or first_failure is None else survivor['ended']-first_failure['started'],'first_healthy_after_restore':None if restoration is None else restoration['index'],'restoration_censored':restoration is None,'post_restore_samples':len(after),'post_restore_all_healthy':bool(after)and all(r['success']for r in after),'interpretation':'request interval bound, not exact outage; excludes event-boundary overlapping samples using independently verified clock skew','existing_tcp_connection_survival_tested':False,'customer_zero_downtime_claimed':False}
os.umask(0o077)
with a.output.open('x')as f:json.dump(result,f,indent=2);f.flush();os.fsync(f.fileno())
fd=os.open(a.output.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd);print(json.dumps({'output':str(a.output),'fault_timeouts':result['fault_timeouts'],'survivor_failover_censored':result['survivor_failover_censored']}))
