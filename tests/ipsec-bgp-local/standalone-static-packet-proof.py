#!/usr/bin/env python3
"""Read normal static API status and probe an already owned echo target. No setup."""
import argparse,datetime,hashlib,http.cookiejar,json,os,pathlib,re,stat,subprocess,urllib.request
from enrolled_approval import reviewed_run
os.umask(0o077)
p=argparse.ArgumentParser(description=__doc__);p.add_argument('expectation',choices=['allow','deny']);p.add_argument('--name',required=True);p.add_argument('--state',type=pathlib.Path,required=True);p.add_argument('--topology',type=pathlib.Path,required=True);p.add_argument('--selected-slot',type=int,choices=[1,2]);a=p.parse_args()
r=pathlib.Path(__file__).resolve().parent;private=r/'.runtime/story9-static';assert a.name and all(c.isalnum()or c=='-'for c in a.name);receipt=private/('packet-proof-'+a.name+'.json');assert not receipt.exists(),'Retain previous packet evidence'
def read(path):
 assert path.absolute().parent==private and stat.S_ISREG(path.lstat().st_mode)and stat.S_IMODE(path.lstat().st_mode)==0o600 and path.lstat().st_uid==os.getuid();return json.loads(path.read_text())
c=read(private/'api.json');s=read(a.state);top=read(a.topology);assert c['base_url']=='http://127.0.0.1:18283'and c['fixture_name']=='Static regression qualification'and c['local_prefix']=='10.10.0.0/24'and c['target_prefix']=='10.32.0.2/32'and c['port']==18080
assert top['scenario']=='static'and top['project']=='tunnexs2sbgpstatic1008';base=json.loads((r/'.runtime/integrated-topology.json').read_text());run,approval,index=reviewed_run(r/'.runtime',r/'.runtime/enrolled-repeat-20261008-3');assert index==3;finish=json.loads((run/'enrolled-restoration-finish.json').read_text());assert finish['worker_released']and finish['new_container_id']==top['gateway_id']==base['gateway_id'];assert top['shared_client']==base['containers']['client']and top['networks']['outer']==base['networks']['outer']
docker=[str(r/'docker-local.sh')]
def inspect(kind,name):return json.loads(subprocess.check_output(docker+[kind,'inspect',name]))[0]
def out(cid,*args):return subprocess.check_output(docker+['exec',cid]+list(args),text=True)
gateway=top['gateway_id'];client=top['shared_client'];target=top['containers']['target'];peer=top['containers']['peer']
for role,cid in [('gateway',gateway),('client',client),('target',target),('peer',peer)]:
 m=inspect('container',cid);assert m['Id']==cid and m['State']['Running'];expected='tunnexs2sbgplocal1007'if role=='gateway'else(base['project']if role=='client'else top['project']);label='com.docker.compose.project'if role=='gateway'else'tunnex.bgp.integrated';assert m['Config']['Labels'].get(label)==expected
assert inspect('container',gateway)['Image']==approval['image'];assert out(gateway,'sha256sum','/proc/1/exe').split()[0]==approval['binary_sha256'];assert inspect('container',target)['NetworkSettings']['Networks'][top['project']+'-lan']['IPAddress']=='10.32.0.2'
for role,nid in top['networks'].items():
 n=inspect('network',nid);assert n['Id']==nid and n['Internal'];assert n['Labels'].get('tunnex.bgp.integrated')==(base['project']if role=='outer'else top['project'])
probe='/test/packet-probe-nonce-run3-before-disable';assert out(client,'sha256sum',probe).split()[0]=='cfc5e7cf31ad3f7f04d8a6bfb2ead8769e40afa67ea7a76d6430f9e6a8122d07';target_sha='08cf3e98dcf26c0bcb66a01db7b14863e5b219550c968d1ed5e83aeb2abc1dce';assert top['target_probe_sha256']==target_sha and out(target,'sha256sum','/test/packet-probe').split()[0]==target_sha
servers=[]
for line in out(target,'ps','-eo','pid,comm').splitlines()[1:]:
 words=line.split()
 if len(words)==2 and words[1]=='packet-probe':servers.append(words[0])
assert len(servers)==1;server_pid=servers[0];assert out(target,'sha256sum','/proc/'+server_pid+'/exe').split()[0]==target_sha;assert out(target,'cat','/proc/'+server_pid+'/cmdline').replace('\x00',' ').strip()=='/test/packet-probe server 10.32.0.2:18080'
server_stat=out(target,'cat','/proc/'+server_pid+'/stat');server_start=server_stat[server_stat.rindex(') ')+2:].split()[19]
cl=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(path,body=None):
 request=urllib.request.Request(c['base_url']+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','Origin':c['base_url'],'X-Tunnex-CSRF':'1'})
 with cl.open(request,timeout=15)as response:return json.loads(response.read())
login=api('/api/v1/auth/login',{'email':c['email'],'password':c['password']});assert not login.get('mfa_required');connection=s['connection_id'];path='/api/v1/organizations/'+c['organization_id']+'/ipsec/connections/'+connection;provider=api(path)
assert provider['id']==connection and provider['name']==c['provider_connection_name']and provider['site_id']==(s.get('site_id')or c['site_id'])and provider['gateway_node_id']==c['gateway_id']and not provider['deleted_at'];configuration=api(path+'/configuration');cfg=configuration['configuration'];assert cfg['mode']=='ipv4-static'and cfg['local_prefixes']==['10.10.0.0/24']and cfg['remote_prefixes']==['10.32.0.0/24']and len(cfg['tunnels'])==2;assert len(s['tunnel_ids'])==2 and len(set(s['tunnel_ids']))==2
status=api(path+'/status');selected=sorted(t['slot']for t in status['tunnels']if t.get('selected'));assert len(selected)<=1;assert sorted(t['id']for t in status['tunnels'])==sorted(s['tunnel_ids']);assert api('/api/v1/organizations/'+c['organization_id']+'/zero-trust-mode')['mode']=='enforcing'
if a.selected_slot is not None:assert selected==[a.selected_slot]
def snapshot():
 return {'routes':json.loads(out(gateway,'ip','-j','-4','route','show','table','main')),'managed_vici_sas':out(gateway,'env','STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf','/opt/tunnex-ipsec/sbin/swanctl','--list-sas','--uri','unix:///run/tunnex-ipsec/charon.vici')}
before=snapshot();result=out(client,probe,'client','10.32.0.2:18080','10.10.0.2',a.expectation).strip();after=snapshot()
if a.expectation=='allow':assert re.fullmatch(r'OWNED_FORWARDED_TARGET_ALLOWED nonce=[0-9a-f]{64} response_sha256=[0-9a-f]{64}',result)
else:assert result=='OWNED_FORWARDED_TARGET_DENIED'
assert out(target,'sha256sum','/proc/'+server_pid+'/exe').split()[0]==target_sha;after_stat=out(target,'cat','/proc/'+server_pid+'/stat');assert after_stat[after_stat.rindex(') ')+2:].split()[19]==server_start;provider_after=api(path);assert provider_after['desired_revision']==provider['desired_revision']and provider_after['desired_intent']==provider['desired_intent']
proof={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'expectation':a.expectation,'result':result,'connection_id':connection,'mode':'ipv4-static','configuration':configuration,'zero_trust_mode':'enforcing','desired_intent':provider['desired_intent'],'desired_revision':provider['desired_revision'],'selected_slots':selected,'status_before':status,'status_after':api(path+'/status'),'gateway_id':gateway,'gateway_binary_sha256':approval['binary_sha256'],'client_id':client,'target_id':target,'peer_id':peer,'target_server_pid':server_pid,'target_server_start_ticks':server_start,'target_binary_sha256':target_sha,'probe_binary_sha256':'cfc5e7cf31ad3f7f04d8a6bfb2ead8769e40afa67ea7a76d6430f9e6a8122d07','before':before,'after':after,'activation_performed_by_probe':False,'provisioning_performed':False,'daemon_restart_performed':False}
fd=os.open(receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w')as f:f.write(json.dumps(proof,indent=2)+'\n');f.flush();os.fsync(f.fileno())
print(json.dumps({'receipt':str(receipt),'expectation':a.expectation,'result':result,'connection_id':connection,'selected_slots':selected}))
