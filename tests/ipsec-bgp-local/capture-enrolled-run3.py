#!/usr/bin/env python3
"""Read-only baseline capture AFTER normal rev4 Apply and exact PID1 pause; never pauses/releases a runtime."""
import hashlib,json,os,pathlib,subprocess
from enrolled_approval import reviewed_run,selected_applied
os.umask(0o077)
r=pathlib.Path(__file__).resolve().parent;shared=r/'.runtime';rt,approval,index=reviewed_run(shared,shared/'enrolled-repeat-20261008-3');assert index==3
d=[str(r/'docker-local.sh')];old=approval['old_container_id']
def out(*args):return subprocess.check_output(d+list(args))
def read(*args):return out('exec',old,*args)
def save(name,data):
 path=rt/name;assert not path.exists(),'Prior baseline must be retained';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:os.write(fd,data);os.fsync(fd)
 finally:os.close(fd)
def store(name,value):save(name,(json.dumps(value,indent=2)+'\n').encode())
g=json.loads(out('inspect',old))[0];assert g['Id']==old and g['State']['Running']and g['Image']=='sha256:84c9dfdffbe27cc5a6992bceb2863d3b045d2fbdaf6b3339a7d7a5cdffba5c98' and g['Config']['Labels']['com.docker.compose.project']=='tunnexs2sbgplocal1007'
assert any(line.startswith('State:')and 'T ('in line for line in read('cat','/proc/1/status').decode().splitlines()),'Caller must pause exact PID1 only after normal Applied readiness'
actual=read('sha256sum','/proc/1/exe').decode().split()[0];assert actual=='d8d9ad44e704ccdeee876c8f76923feac9daa335724dab4a5fc4e9b0149775fb'
raw=read('cat','/state/ipsec/journal.json');journal=json.loads(raw);entry=selected_applied(journal['Payload']['Entries']);assert entry['DeliveryID']!='65171908-b2af-40fe-9203-a02d2281f4c3'and entry['Engines'][0]['Binding']['DesiredRevision']==4 and journal['Payload']['OwnerID']=='01a115fb-f7d4-794f-80b6-84f507a94152'
assert entry['BGPProcess']['Stage']=='ready'and entry['BGPRoutes']and entry['BGPRoutes']['Stage']=='completed','Actual fresh managed-session Apply checkpoint required'
canonical='/state/ipsec/restore-'+entry['DeliveryID']+'.json';assert subprocess.run(d+['exec',old,'test','-e',canonical],stdout=subprocess.DEVNULL).returncode==1,'Fresh delivery canonical receipt unexpectedly exists'
assert subprocess.run(d+['exec',old,'test','-e','/state/ipsec/restoration-startup-gate'],stdout=subprocess.DEVNULL).returncode==1
ns=read('readlink','/proc/1/ns/net').decode().strip();state=[m for m in g['Mounts']if m['Destination']=='/state'];assert len(state)==1 and state[0]['Type']=='volume'and state[0]['Name']=='tunnexs2sbgplocal1007_gateway_state'and state[0]['RW']
layout={'container_id':old,'namespace':ns,'image':g['Image'],'state_mount':state,'networks':g['NetworkSettings']['Networks'],'host_config':g['HostConfig'],'config':{k:g['Config'][k]for k in ['Entrypoint','Cmd','Healthcheck']},'journal_sha256':hashlib.sha256(raw).hexdigest(),'before_gate_exists':False,'all_mounts':g['Mounts'],'environment_equality_sha256':hashlib.sha256(json.dumps(sorted(g['Config']['Env'])).encode()).hexdigest(),'actual_executable_sha256':actual}
query="select json_build_object('id',id,'org_id',org_id,'cert_serial',cert_serial,'cert_key_fingerprint',cert_key_fingerprint,'cert_not_after',cert_not_after,'status',status) from nodes where id='01a115fb-f7d4-794f-80b6-84f507a94152';"
node=json.loads(out('exec','tunnexs2sbgplocal1007-postgres-1','psql','-U','bgplocal','-d','bgplocal','-At','-c',query));volume=json.loads(out('volume','inspect',state[0]['Name']))[0]
cert={'container_id':old,'certificate_pem_sha256':hashlib.sha256(read('cat','/state/cert.pem')).hexdigest(),'private_key_recorded':False}
assert read('cat','/state/ipsec/journal.json')==raw
save('enrolled-restoration-before-journal.json',raw);store('enrolled-restoration-before-layout-v3.json',layout);store('enrolled-restoration-before-gateway.json',{'container_id':old,'node':node,'volume':volume,'actual_executable_sha256':actual,'namespace':ns});store('enrolled-restoration-before-cert.json',cert)
non={}
for name in ['tunnexs2sbgplocal1007-api-1','tunnexs2sbgplocal1007-postgres-1','tunnexs2sbgplocal1007-redis-1','tunnexs2sbgpintegrated1007-peer','tunnexs2sbgpintegrated1007-client','tunnexs2sbgpintegrated1007-target']:
 item=json.loads(out('inspect',name))[0];assert item['State']['Running'];non[name]=item['Id']
store('nongateway-before.json',non)
subprocess.run(['python3',str(r/'license-proof.py'),'--output',str(rt/'enrolled-restoration-final-before-license.json')],check=True,stdout=subprocess.DEVNULL)
assert read('cat','/state/ipsec/journal.json')==raw
print(json.dumps({'run':3,'old_container':old,'namespace':ns,'active_delivery_id':entry['DeliveryID'],'retained_entries':sum(e['Phase']=='retained_refusal'for e in journal['Payload']['Entries']),'baseline_sha256':layout['journal_sha256'],'runtime_mutated':False}))
