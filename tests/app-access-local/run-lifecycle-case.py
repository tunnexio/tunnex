#!/usr/bin/env python3
"""One actual local mutation and five-protocol measurement. No automatic retries."""
import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('owned_api',ROOT/'lifecycle-api.py')
api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)


def execute(case,session_file,control_file,driver_path):
    state=api.private_json(ROOT/'.runtime/aa8-lifecycle-state.json')
    control=api.private_json(control_file)
    if control.get('user_id') not in {state['direct_user_id'],state.get('group_user_id')} or control.get('org_id')!=state['org_id'] or control.get('app_id')!=state['app_id']:
        raise ValueError('exact synthetic authority tuple required')
    own=api.OwnedClient(control_file)
    admin=api.OwnedClient(ROOT/'.runtime/aa8-admin-control.json')
    base='/api/v1/organizations/'+state['org_id']
    if case in {'grant-revoke','grant-disable','grant-expiry'}:
        status,grants,_,_=admin.request('GET',base+'/app-access/grants?app_id='+state['app_id']+'&limit=100',label=case+'-version')
        if status!=200:raise ValueError('fresh grant version unavailable')
        grant=next(item for item in grants['items'] if item['id']==state['direct_grant_id'])
        if not grant['enabled'] or grant['revoked_at'] is not None:raise ValueError('baseline grant unavailable')
    evidence_path=ROOT/'.runtime'/('aa8-'+case+'-protocols-'+str(time.time_ns())+'.json')
    env=dict(os.environ,APP_ACCESS_OWNED_PROJECT=api.PROJECT,APP_ACCESS_OWNED_CHECKOUT=str(ROOT))
    driver=subprocess.Popen([str(driver_path),'--session-file',str(session_file)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
    observations=[];mutation_ref=None;feature_changed=False;licence_changed=False;outage_resource=None;outage_recovery=None
    def entitlement(state_value):
        directory=ROOT/'.runtime/aa6-proxy';readback=directory/'entitlement-readback.json'
        version=(json.loads(readback.read_text())['version'] if readback.exists() else 0)+1
        started=datetime.datetime.now(datetime.timezone.utc).isoformat()
        temp=directory/('entitlement-control-'+str(time.time_ns())+'.tmp')
        with open(temp,'x',opener=lambda name,flags:os.open(name,flags,0o600)) as out:json.dump({'version':version,'state':state_value},out);out.flush();os.fsync(out.fileno())
        os.replace(temp,directory/'entitlement-control.json')
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            if readback.exists():
                result=json.loads(readback.read_text())
                if result.get('version')==version and result.get('state')==state_value and result.get('app_access_available')==(state_value=='valid'):
                    completed=datetime.datetime.now(datetime.timezone.utc).isoformat();ref=ROOT/'.runtime'/('aa8-entitlement-'+str(time.time_ns())+'.json')
                    with open(ref,'x',opener=lambda name,flags:os.open(name,flags,0o600)) as out:json.dump({'request_started_at':started,'readback_completed_at':completed,'actual_manager_readback':result},out);out.flush();os.fsync(out.fileno())
                    return ref,{'trigger':'licence-loss','evidence_ref':str(ref),'mutation_started_at':started,'mutation_completed_at':completed}
            time.sleep(.02)
        raise ValueError('actual entitlement readback unavailable')
    try:
        for line in driver.stdout:
            item=json.loads(line);observations.append(item)
            if item.get('state')=='ready':
                if case=='proxy_shutdown':
                    started=datetime.datetime.now(datetime.timezone.utc).isoformat()
                    subprocess.run([str(ROOT/'run-proxy-fixture.sh'),'--stop'],check=True,stdout=subprocess.DEVNULL)
                    completed=datetime.datetime.now(datetime.timezone.utc).isoformat();mutation_ref=ROOT/'.runtime'/('aa8-proxy-shutdown-'+str(time.time_ns())+'.json')
                    with open(mutation_ref,'x',opener=lambda name,flags:os.open(name,flags,0o600)) as out:json.dump({'guarded_command':'run-proxy-fixture.sh --stop','started_at':started,'completed_at':completed,'recovery_owner':'root after measurement'},out);out.flush();os.fsync(out.fileno())
                    driver.stdin.write(json.dumps({'trigger':case,'evidence_ref':str(mutation_ref),'mutation_started_at':started,'mutation_completed_at':completed})+'\n');driver.stdin.flush()
                    continue
                elif case in {'cp_pause','redis_pause','gateway_stop'}:
                    name={'cp_pause':'tunnex-app-access-aa1-browser-fixture-1003','redis_pause':'tunnex-app-access-aa0-1003-redis-1','gateway_stop':'tunnex-app-access-aa0-1003-gateway-1'}[case]
                    inspect=json.loads(subprocess.check_output([str(ROOT/'docker-local.sh'),'inspect',name],text=True))[0]
                    labels=inspect['Config']['Labels'];resource=inspect['Id']
                    if labels.get('com.docker.compose.project')!=api.PROJECT or labels.get('com.docker.compose.project.working_dir')!=str(ROOT) or not inspect['State']['Running']:raise ValueError('owned outage resource mismatch')
                    expected='aa1-browser' if case=='cp_pause' else None
                    if expected and labels.get('app-access.fixture')!=expected:raise ValueError('owned fixture mismatch')
                    if case!='cp_pause' and labels.get('com.docker.compose.service')!=('redis' if case=='redis_pause' else 'gateway'):raise ValueError('owned service mismatch')
                    started=datetime.datetime.now(datetime.timezone.utc).isoformat();outage_resource=resource;outage_recovery='start' if case=='gateway_stop' else 'unpause'
                    command=['stop','--time','1',resource] if case=='gateway_stop' else ['pause',resource]
                    subprocess.run([str(ROOT/'docker-local.sh')]+command,check=True,stdout=subprocess.DEVNULL)
                    current=json.loads(subprocess.check_output([str(ROOT/'docker-local.sh'),'inspect',resource],text=True))[0]['State']
                    if (case=='gateway_stop' and current['Running']) or (case!='gateway_stop' and not current['Paused']):raise ValueError('actual outage readback failed')
                    completed=datetime.datetime.now(datetime.timezone.utc).isoformat();mutation_ref=ROOT/'.runtime'/('aa8-'+case+'-'+str(time.time_ns())+'.json')
                    with open(mutation_ref,'x',opener=lambda name,flags:os.open(name,flags,0o600)) as out:json.dump({'resource_id':resource,'started_at':started,'completed_at':completed,'actual_state':current},out);out.flush();os.fsync(out.fileno())
                    driver.stdin.write(json.dumps({'trigger':case,'evidence_ref':str(mutation_ref),'mutation_started_at':started,'mutation_completed_at':completed})+'\n');driver.stdin.flush()
                    continue
                elif case=='licence-loss':
                    licence_changed=True
                    mutation_ref,measured_marker=entitlement('lapsed')
                    driver.stdin.write(json.dumps(measured_marker)+'\n');driver.stdin.flush()
                    continue
                elif case=='publication-disable':
                    code,publication,_,_=admin.request('GET',base+'/app-access/applications/'+state['app_id']+'/publication',label='publication-disable-version')
                    if code!=200 or publication.get('active',{}).get('state')!='active':raise ValueError('active publication unavailable')
                    client=admin;method='POST';path=base+'/app-access/applications/'+state['app_id']+'/publication/disable';body={'expected_application_version':publication['application_version'],'expected_authority_version':publication['active']['authority_version']}
                elif case=='feature-disable':
                    code,settings,_,_=admin.request('GET',base+'/app-access/settings',label='feature-version')
                    if code!=200 or not settings['enabled']:raise ValueError('feature baseline unavailable')
                    client=admin;method='PATCH';path=base+'/app-access/settings';body={'enabled':False,'expected_version':settings['version']}
                elif case=='grant-revoke':
                    client=admin;method='POST';path=base+'/app-access/grants/'+grant['id']+'/revoke';body={'expected_version':grant['version']}
                elif case in {'grant-disable','grant-expiry'}:
                    client=admin;method='PATCH';path=base+'/app-access/grants/'+grant['id'];body={'enabled':case=='grant-expiry','starts_at':grant['starts_at'],'expires_at':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=3)).isoformat() if case=='grant-expiry' else grant['expires_at'],'expected_version':grant['version']}
                elif case=='self-session':
                    client=own;method='DELETE';path=base+'/app-access/my-sessions/'+control['session_id'];body=None
                elif case=='admin-session':
                    client=admin;method='DELETE';path=base+'/app-access/applications/'+state['app_id']+'/sessions/'+control['session_id'];body=None
                elif case=='parent-logout':
                    client=own;method='POST';path='/api/v1/auth/logout';body=None
                elif case=='group-remove':
                    if control['user_id']!=state.get('group_user_id'):raise ValueError('group-only synthetic user required')
                    client=admin;method='DELETE';path=base+'/groups/'+state['group_id']+'/members/'+state['group_user_id'];body=None
                elif case=='user-deactivate':
                    client=admin;method='POST';path=base+'/members/'+control['user_id']+'/deactivate';body=None
                else:raise ValueError('unsupported reviewed lifecycle case')
                def mutation_started(started):
                    driver.stdin.write(json.dumps({'phase':'mutation_started','mutation_started_at':started})+'\n');driver.stdin.flush()
                status,result,mutation_ref,event=client.request(method,path,body,label=case+'-mutation',before_send=mutation_started if case=='publication-disable' else None)
                measured_marker=api.marker(case,mutation_ref,event)
                feature_changed=case=='feature-disable'
                if case=='grant-expiry':
                    expires=datetime.datetime.fromisoformat(result['expires_at'].replace('Z','+00:00'))
                    while datetime.datetime.now(datetime.timezone.utc)<expires:
                        time.sleep(min(0.02,max(0,(expires-datetime.datetime.now(datetime.timezone.utc)).total_seconds())))
                    expiry_event={'trigger':'grant-expiry','persisted_expires_at':result['expires_at'],'window_mutation_evidence':str(mutation_ref),'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'time_boundary':'actual API-returned exclusive expiry; not the earlier PATCH response'}
                    expiry_ref=ROOT/'.runtime'/('aa8-grant-expiry-boundary-'+str(time.time_ns())+'.json')
                    with open(expiry_ref,'x',opener=lambda name,flags:os.open(name,flags,0o600)) as out:json.dump(expiry_event,out,indent=2);out.flush();os.fsync(out.fileno())
                    measured_marker={'trigger':case,'evidence_ref':str(expiry_ref),'mutation_started_at':expires.isoformat(),'mutation_completed_at':expiry_event['observed_at'],'persisted_expires_at':result['expires_at']}
                driver.stdin.write(json.dumps(measured_marker)+'\n');driver.stdin.flush()
            print(json.dumps({'case':case,'state':item.get('state'),'passed':item.get('passed')}),flush=True)
        code=driver.wait(timeout=20)
        if feature_changed or licence_changed:
            for label,path in [('feature-off-events',base+'/app-access/events?app_id='+state['app_id']+'&limit=100'),('feature-off-app-audit',base+'/audit-logs?target_type=app_access&target_id='+state['app_id']+'&limit=100'),('feature-off-settings-audit',base+'/audit-logs?target_type=app_access&target_id='+state['org_id']+'&limit=100')]:
                history_status,_,history_ref,_=admin.request('GET',path,label=label if feature_changed else label.replace('feature-off','licence-off'))
                observations.append({'history':label,'status':history_status,'evidence_ref':str(history_ref)})
                if history_status!=200:raise ValueError('off-state owner history unavailable')
        measured=next((x for x in observations if x.get('state')=='measured'),None)
        success=code==0 and measured is not None and measured.get('passed') is True
        report={'case':case,'driver_exit':code,'passed':success,'mutation_evidence':str(mutation_ref) if mutation_ref else None,'observations':observations}
        with open(evidence_path,'x',opener=lambda name,flags:os.open(name,flags,0o600)) as out:json.dump(report,out,indent=2);out.flush();os.fsync(out.fileno())
        print(json.dumps({'case':case,'passed':success,'evidence':str(evidence_path)}),flush=True)
        return 0 if success else 1
    finally:
        if driver.poll() is None:driver.terminate();driver.wait(timeout=10)
        if outage_resource:
            subprocess.run([str(ROOT/'docker-local.sh'),outage_recovery,outage_resource],check=True,stdout=subprocess.DEVNULL)
        if licence_changed:entitlement('valid')
        if feature_changed:
            status,settings,_,_=admin.request('GET',base+'/app-access/settings',label='feature-restore-version')
            if status!=200:raise ValueError('feature restoration version unavailable')
            status,_,_,_=admin.request('PATCH',base+'/app-access/settings',{'enabled':True,'expected_version':settings['version']},label='feature-restore')
            if status!=200:raise ValueError('feature restoration failed')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case',required=True,choices=['grant-revoke','grant-disable','grant-expiry','self-session','admin-session','parent-logout','group-remove','user-deactivate','feature-disable','licence-loss','cp_pause','redis_pause','gateway_stop','publication-disable','proxy_shutdown'])
    parser.add_argument('--session-file',type=Path,default=ROOT/'.runtime/aa8-stream-session.json')
    parser.add_argument('--control-file',type=Path,default=ROOT/'.runtime/aa8-direct-control.json')
    parser.add_argument('--driver',type=Path,default=Path('/private/tmp/aa8-stream-driver'))
    args=parser.parse_args()
    try:raise SystemExit(execute(args.case,args.session_file,args.control_file,args.driver))
    except (ValueError,OSError,subprocess.SubprocessError):raise SystemExit('Owned lifecycle measurement refused; private evidence must establish any completed mutation')
