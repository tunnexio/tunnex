#!/usr/bin/env python3
"""Exact owned cloud refresh proposal. Default only validates and prints safe diff."""
import argparse,copy,hashlib,json,os,pathlib,subprocess,time
os.umask(0o077)
assert os.geteuid()==0,'Run sudo python3 on owned Linux host'
p=argparse.ArgumentParser();p.add_argument('role',choices=['api','gateway']);p.add_argument('--execute',action='store_true');a=p.parse_args()
r=pathlib.Path('/home/ubuntu/tunnex-bgp-lab');b=r/'refresh-max-prefix-before';dest=r/'builds/max-prefix-21169a9f/bin';old=json.loads((b/(a.role+'-inspect.json')).read_text());cid=old['Id'];current=json.loads(subprocess.check_output(['docker','inspect',cid]))[0]
assert current['Id']==cid and current['Config']['Labels'].get('tunnex.lab')=='tunnex-bgp-20261007'and current['State']['Running'];assert current['Config']==old['Config']and current['HostConfig']==old['HostConfig'];assert sorted(current['Mounts'],key=lambda x:x['Destination'])==sorted(old['Mounts'],key=lambda x:x['Destination'])
state=json.loads((r/'state.json').read_text());assert state[a.role]==cid
hashes={'api':'30de107bd8d56d83f18e6bd327c9beab866c16c6d455624543d5bfbe54f76c90','gateway':'b659a3a54528575f44afb28aa1e2c09508fdc6ef313d1ebe43b7f937cc5f1145'};binary=dest/('tunnex-api'if a.role=='api'else'tunnex-node');assert binary.is_file()and not binary.is_symlink()and hashlib.sha256(binary.read_bytes()).hexdigest()==hashes[a.role]
pg=state['postgres'];aggregate=subprocess.check_output(['docker','exec',pg,'psql','-U','bgpcloud','-d','bgpcloud','-At','-v','ON_ERROR_STOP=1','-c','SELECT count(*) FROM ipsec_connections; SELECT count(*) FROM ipsec_runtime_deliveries;'],text=True).strip();assert aggregate=='0\n0','New cloud duties require trusted lifecycle review'
g=json.loads((b/'gateway-inspect.json').read_text());volume=next(x['Source']for x in g['Mounts']if x['Destination']=='/state');assert not (pathlib.Path(volume)/'ipsec/journal.json').exists()
config=copy.deepcopy(old['Config']);config.pop('Hostname',None);host=copy.deepcopy(old['HostConfig']);
# Actual owned Engine creation observed exactly null->false normalization.
if host.get('OomKillDisable')is None:host['OomKillDisable']=False
binds=host.get('Binds')or[];mounts=host.get('Mounts')or[]
found_binds=[x for x in binds if x.split(':')[1]=='/binaries'];found_mounts=[x for x in mounts if x.get('Target')=='/binaries'];assert len(found_binds)+len(found_mounts)==1,'Ambiguous binaries mount'
if found_binds:
 parts=found_binds[0].split(':');assert len(parts)==3 and parts[2]=='ro';host['Binds']=[str(dest)+':/binaries:ro'if x==found_binds[0]else x for x in binds]
else:
 mount=found_mounts[0];assert mount['Type']=='bind'and mount['ReadOnly']is True and mount['Source']=='/home/ubuntu/tunnex-bgp-lab/context/bin';mount['Source']=str(dest)
if a.role=='gateway':config['Image']='sha256:868b425d65ef30b6f0c221c834e8925079d658281e89380ead59a929021c50a2'
image=json.loads(subprocess.check_output(['docker','image','inspect',config['Image']]))[0];config['Labels']={**(image['Config'].get('Labels')or{}),**old['Config']['Labels']}
networks={}
for name,n in old['NetworkSettings']['Networks'].items():
 assert n['IPAddress']and n['IPAMConfig']['IPv4Address']==n['IPAddress'];networks[name]={k:n[k]for k in ['IPAMConfig','Links','Aliases','DriverOpts','GwPriority','MacAddress']if n.get(k)is not None}
payload={**config,'HostConfig':host,'NetworkingConfig':{'EndpointsConfig':networks}};path=b/(a.role+'-create-approved-private.json');raw=json.dumps(payload,sort_keys=True).encode()
if not path.exists():
 with path.open('xb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
else:assert path.read_bytes()==raw
print(json.dumps({'role':a.role,'old_id':cid,'new_name':old['Name'].lstrip('/'),'image':config['Image'],'approved_changes':['new image for gateway only','new read-only binaries source','new generated hostname/container ID'],'preserved':['private env','command and entrypoint','full HostConfig except binaries bind','state volumes','network IPAM aliases/MAC','ports'],'payload_sha256':hashlib.sha256(raw).hexdigest(),'execute':a.execute}),flush=True)
if not a.execute:raise SystemExit(0)
assert not (b/(a.role+'-refresh-result.json')).exists()
pending=b/(a.role+'-refresh-pending.json');assert not pending.exists(),'Existing pending action requires exact manual inspection; never repeat stop/create'
def checkpoint(data):
 with pending.open('w')as f:f.write(json.dumps(data,indent=2)+'\n');f.flush();os.fsync(f.fileno())
 fd=os.open(b,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
with pending.open('x')as f:f.write(json.dumps({'old_id':cid,'role':a.role,'payload_sha256':hashlib.sha256(raw).hexdigest(),'stage':'before-stop','new_id':None})+'\n');f.flush();os.fsync(f.fileno())
fd=os.open(b,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
if a.role=='gateway':
 subprocess.run(['curl','--fail','--silent','http://127.0.0.1:18383/healthz'],stdout=subprocess.DEVNULL,check=True)
 proof=json.loads((b/'api-postrefresh-preservation.json').read_text());assert proof['migration_version']==217 and proof['migration_dirty']is False and proof['node_certificate_preserved']is True and proof['license_preserved']is True and proof['api_healthy']is True
 assert proof['new_api_id']==json.loads((b/'api-refresh-result.json').read_text())['new_id']
assert current['State']['Running']
subprocess.run(['docker','stop','--time','20',cid],check=True,stdout=subprocess.DEVNULL)
checkpoint({'old_id':cid,'role':a.role,'stage':'old-stopped','new_id':None})
for network in old['NetworkSettings']['Networks']:
 subprocess.run(['docker','network','disconnect',network,cid],check=True)
subprocess.run(['docker','rename',cid,old['Name'].lstrip('/')+'-retained-'+cid[:12]],check=True)
name=old['Name'].lstrip('/');res=subprocess.check_output(['curl','--fail-with-body','--silent','--unix-socket','/var/run/docker.sock','-H','Content-Type: application/json','-X','POST','http://localhost/v1.47/containers/create?name='+name,'--data-binary','@'+str(path)]);new=json.loads(res)['Id'];checkpoint({'old_id':cid,'role':a.role,'stage':'created-not-started','new_id':new})
n=json.loads(subprocess.check_output(['docker','inspect',new]))[0];assert not n['State']['Running']
actual=copy.deepcopy(n['Config']);expected=copy.deepcopy(config)
for key in ['Hostname','Image']:
 actual.pop(key,None);expected.pop(key,None)
assert actual==expected,'Created Config differs; retain pending container without start'
assert n['Image']==image['Id'] and n['HostConfig']==host,'Created image/HostConfig differs'
expected_mounts=copy.deepcopy(old['Mounts'])
for mount in expected_mounts:
 if mount['Destination']=='/binaries':mount['Source']=str(dest)
assert sorted(n['Mounts'],key=lambda x:x['Destination'])==sorted(expected_mounts,key=lambda x:x['Destination'])
assert set(n['NetworkSettings']['Networks'])==set(networks)
for name,wanted in networks.items():
 actual=n['NetworkSettings']['Networks'][name]
 for key in ['IPAMConfig','Aliases','MacAddress']:
  assert actual.get(key)==wanted.get(key),(name,key)
 inspected=json.loads(subprocess.check_output(['docker','network','inspect',name]))[0];assert inspected['Id']==old['NetworkSettings']['Networks'][name]['NetworkID']
 assert actual['NetworkID']in('',inspected['Id'])
 if actual['NetworkID']=='':assert actual['EndpointID']==''and actual['IPAddress']==''
checkpoint({'old_id':cid,'role':a.role,'stage':'prestart-readback-passed','new_id':new})
subprocess.run(['docker','start',new],check=True,stdout=subprocess.DEVNULL)
started=json.loads(subprocess.check_output(['docker','inspect',new]))[0];assert started['State']['Running']
for name,wanted in networks.items():
 actual=started['NetworkSettings']['Networks'][name];assert actual['NetworkID']==old['NetworkSettings']['Networks'][name]['NetworkID']and actual['IPAddress']==wanted['IPAMConfig']['IPv4Address']
 for key in ['IPAMConfig','Aliases','MacAddress']:assert actual.get(key)==wanted.get(key),(name,key)
checkpoint({'old_id':cid,'role':a.role,'stage':'started-network-readback-passed','new_id':new})
result={'old_id':cid,'new_id':new,'role':a.role,'payload_sha256':hashlib.sha256(raw).hexdigest(),'old_retained':True,'post_start_qualification_pending':True}
with (b/(a.role+'-refresh-result.json')).open('x')as f:f.write(json.dumps(result,indent=2)+'\n');f.flush();os.fsync(f.fileno())
print(json.dumps(result))
