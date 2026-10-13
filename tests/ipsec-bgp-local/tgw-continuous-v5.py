#!/usr/bin/env python3
"""Run ONLY on designated bastion after root confirms ZT convergence.
Dedicated real physical-ENI namespace nonce echo; no process restart.
"""
import argparse,base64,hashlib,json,os,pathlib,secrets,shlex,subprocess,time
ap=argparse.ArgumentParser();ap.add_argument('--execute',action='store_true');ap.add_argument('--gateway-container',required=True);ap.add_argument('--count',type=int,default=120);ap.add_argument('--expect',choices=['allow'],default='allow');a=ap.parse_args()
assert 15<=a.count<=300
assert a.gateway_container=='b8baa489a1a6e24020676d75703db1ef28118178e97d38c9a00914dab2c20cad'
assert a.gateway_container and all(c in '0123456789abcdef' for c in a.gateway_container) and len(a.gateway_container)==64
key='/home/ubuntu/tunnex-bgp-20261007/lab-key';base=pathlib.Path('/home/ubuntu/tunnex-bgp-tgw-20261008');knownbase=pathlib.Path('/home/ubuntu/tunnex-bgp-vgw-eic-20261008');os.umask(0o077)
def run(cmd):
 r=subprocess.run(cmd,capture_output=True,timeout=35);return {'exit':r.returncode,'stdout':r.stdout.decode(),'stderr':r.stderr.decode()}
def ssh(host,command,options=[]):return run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10','-i',key,*options,host,command])
client_opts=['-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(knownbase/'client_known_hosts'),'-o','ProxyCommand=ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -i '+key+' -W %h:%p ubuntu@13.63.169.255']
target_opts=['-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(knownbase/'known_hosts'),'-o','ProxyCommand=aws ec2-instance-connect open-tunnel --instance-id i-0cd8ee7ba1e099092 --instance-connect-endpoint-id eice-01f10d84c64fdf3a1 --remote-port 22 --max-tunnel-duration 120']
nonce=secrets.token_hex(32);uri='/?nonce='+nonce
if not a.execute:print(json.dumps({'source_only':True,'expect':a.expect,'uri_template':'/?nonce=<fresh64hex>','target':'10.86.1.10:8080','correlation':'exact source10.84.3.10 URI in independent EIC journal, plus actual CHILD/NFT counter snapshots'}));raise SystemExit
assert pathlib.Path('/home/ubuntu').is_dir() and base.is_dir()
def save(name,obj):
 with open(base/name,'x') as f:json.dump(obj,f);f.flush();os.fsync(f.fileno())
 fd=os.open(base,os.O_RDONLY);os.fsync(fd);os.close(fd)
started=int(time.time());stem='continuous-'+nonce
save(stem+'-intent.json',{'nonce':nonce,'uri':uri,'expected':a.expect,'gateway_container':a.gateway_container,'started':started})
identity_code="import json,os,pathlib,subprocess,hashlib; p=4752; main=subprocess.check_output(['systemctl','show','tunnex-bgp-tgw-nonce-20261008.service','-p','MainPID','--value']).decode().strip(); assert main==str(p); stat=pathlib.Path('/proc/'+str(p)+'/stat').read_text(); ns=os.stat('/proc/'+str(p)+'/ns/net').st_ino; assert ns==os.stat('/var/run/netns/tnx-tgw-target-20261008').st_ino; print(json.dumps({'pid':p,'start':stat.rsplit(')',1)[1].split()[19],'exe':os.readlink('/proc/'+str(p)+'/exe'),'cmdline':pathlib.Path('/proc/'+str(p)+'/cmdline').read_bytes().decode(),'namespace':ns,'code_sha256':hashlib.sha256(pathlib.Path('/opt/tunnex-bgp-tgw-20261008/nonce-server.py').read_bytes()).hexdigest()},sort_keys=True))"
identity_command='sudo -n python3 -c '+shlex.quote(identity_code)
identity_before=ssh('ubuntu@10.85.1.10',identity_command,target_opts);save(stem+'-service-identity-before.json',identity_before);assert identity_before['exit']==0
identity=json.loads(identity_before['stdout']);assert identity['pid']==4752;assert identity['exe']=='/usr/bin/python3.12' and identity['start']=='6600428' and identity['code_sha256']=='9c673b73ddb16d195366b54fa1d8d30fb1a8c81d5e2c800f7d59a84653dfecc6'
expected={'nonce':nonce,'sha256':hashlib.sha256(nonce.encode()).hexdigest(),'target':'10.86.1.10'}
control=ssh('ubuntu@10.85.1.10','sudo -n ip netns exec tnx-tgw-target-20261008 curl --noproxy "*" --fail --max-time 5 -s '+shlex.quote('http://10.86.1.10:8080'+uri),target_opts)
assert control['exit']==0 and json.loads(control['stdout'])==expected
save(stem+'-control.json',{'control':control,'expected':expected})
worker_command='sudo -n docker inspect --format '+shlex.quote('{{.Id}} {{.Image}} {{.State.Pid}} {{.State.StartedAt}}')+' '+a.gateway_container+'; sudo -n docker exec '+a.gateway_container+' readlink /proc/1/ns/net; sudo -n docker exec '+a.gateway_container+' sha256sum /proc/1/exe /state/cert.pem'
worker_before=ssh('ubuntu@13.63.169.255',worker_command);save(stem+'-worker-before.json',worker_before);assert worker_before['exit']==0
lines=worker_before['stdout'].splitlines();assert len(lines)==4 and lines[0].split()==[a.gateway_container,'sha256:868b425d65ef30b6f0c221c834e8925079d658281e89380ead59a929021c50a2','919715','2026-10-08T09:07:52.444078218Z']
assert lines[1]=='net:[4026532947]' and lines[2].split()==['b85a470bfa46fb8d03487381c58d1be004aa5adc3fad6a1e50d9a575b72e6d76','/proc/1/exe'] and lines[3].split()==['eef07a8865a43de26d8dafbc26e26327cf9d850adc3fd65112baf776d452ea8d','/state/cert.pem']
client_code="import json,subprocess; q=lambda *a:json.loads(subprocess.check_output(a)); r=q('ip','-j','-4','route','get','10.86.1.10');l=q('ip','-j','link','show','dev','ens6');a=q('ip','-j','-4','address','show','dev','ens6');assert len(r)==len(l)==len(a)==1 and r[0]['dev']=='ens6' and r[0]['prefsrc']=='10.84.3.10' and r[0]['gateway']=='10.84.3.1';assert l[0]['ifindex']==3 and l[0]['address']=='06:ff:d1:a1:5e:2b' and l[0]['link_type']=='ether' and 'UP' in l[0]['flags'];assert any(x['local']=='10.84.3.10' and x['prefixlen']==24 for x in a[0]['addr_info']);print(json.dumps({'route':r,'link':l,'address':a},sort_keys=True))"
client_command='sudo -n ip netns exec tnx-tgw-client-20261008 python3 -c '+shlex.quote(client_code)
client_before=ssh('ubuntu@10.84.2.10',client_command,client_opts);save(stem+'-client-before.json',client_before);assert client_before['exit']==0
command='sudo -n docker inspect --format "{{.Id}} {{.State.Running}}" '+a.gateway_container+'; sudo -n docker exec '+a.gateway_container+' nft -j list ruleset; sudo -n docker exec -e STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf '+a.gateway_container+' /opt/tunnex-ipsec/sbin/swanctl --list-sas --uri unix:///run/tunnex-ipsec/charon.vici'
before=ssh('ubuntu@13.63.169.255',command);save(stem+'-before.json',before);assert before['exit']==0 and before['stdout'].startswith(a.gateway_container+' true\n')
client_file='/var/tmp/tunnex-tgw-continuous-'+nonce+'.jsonl'
client_code=r"""
import json,os,secrets,subprocess,time,hashlib,sys
os.umask(0o077);path=sys.argv[1];count=int(sys.argv[2]);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w')as f:
 for i in range(count):
  n=secrets.token_hex(32);wall=time.time();mono=time.monotonic();result=subprocess.run(['curl','--noproxy','*','--connect-timeout','1','--max-time','2','--silent','--show-error','--write-out','HTTP=%{http_code}\n','http://10.86.1.10:8080/?nonce='+n],capture_output=True,text=True,timeout=5)
  row={'index':i,'nonce':n,'wall':wall,'monotonic':mono,'duration':time.monotonic()-mono,'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr};f.write(json.dumps(row)+'\n');f.flush();os.fsync(f.fileno());time.sleep(max(0,1-(time.monotonic()-mono)))
print(path)
"""
client_text='sudo -n ip netns exec tnx-tgw-client-20261008 timeout -k 3 '+str(a.count*3+15)+' python3 -c '+shlex.quote(client_code)+' '+shlex.quote(client_file)+' '+str(a.count)
save(stem+'-client-intent.json',{'path':client_file,'count':a.count,'command_sha256':hashlib.sha256(client_text.encode()).hexdigest(),'no_api_writes':True,'no_reconnect_claim':False})
try:
 p=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10','-i',key,*client_opts,'ubuntu@10.84.2.10',client_text],capture_output=True,timeout=a.count*3+50)
 execution={'exit':p.returncode,'stdout':p.stdout.decode(),'stderr':p.stderr.decode()}
except subprocess.TimeoutExpired as e:
 execution={'exit':None,'timeout':True,'stdout':(e.stdout or b'').decode(),'stderr':(e.stderr or b'').decode(),'remote_bound_applies':True}
save(stem+'-client-execution.json',execution)
raw=ssh('ubuntu@10.84.2.10','sudo -n stat -c %u:%a '+shlex.quote(client_file)+'; sudo -n cat '+shlex.quote(client_file),client_opts);save(stem+'-client-raw.json',raw);assert raw['exit']==0 and raw['stdout'].startswith('0:600\n');rows=[json.loads(line)for line in raw['stdout'].splitlines()[1:]];save(stem+'-client-rows.json',rows)
after=ssh('ubuntu@13.63.169.255',command);save(stem+'-after.json',after);assert after['exit']==0 and after['stdout'].startswith(a.gateway_container+' true\n')
worker_after=ssh('ubuntu@13.63.169.255',worker_command);save(stem+'-worker-after.json',worker_after);assert worker_after['exit']==0 and worker_after['stdout']==worker_before['stdout']
client_after=ssh('ubuntu@10.84.2.10',client_command,client_opts);save(stem+'-client-after.json',client_after);assert client_after['exit']==0 and json.loads(client_after['stdout'])==json.loads(client_before['stdout'])
identity_after=ssh('ubuntu@10.85.1.10',identity_command,target_opts);save(stem+'-service-identity-after.json',identity_after);assert identity_after['exit']==0 and json.loads(identity_after['stdout'])==identity
control_after=ssh('ubuntu@10.85.1.10','sudo -n ip netns exec tnx-tgw-target-20261008 curl --noproxy "*" --fail --max-time 5 -s '+shlex.quote('http://10.86.1.10:8080'+uri),target_opts);save(stem+'-control-after.json',control_after);assert control_after['exit']==0 and json.loads(control_after['stdout'])==expected
log=ssh('ubuntu@10.85.1.10','sudo -n journalctl -u tunnex-bgp-tgw-nonce-20261008.service --since @'+str(started)+' --no-pager -o cat',target_opts);save(stem+'-target-log-raw.json',log);assert log['exit']==0
correlated=[]
for index,row in enumerate(rows):
 assert row['index']==index and len(row['nonce'])==64 and all(c in '0123456789abcdef'for c in row['nonce'])
 route='/?nonce='+row['nonce'];matches=[line for line in log['stdout'].splitlines()if '10.84.3.10 - 'in line and '"GET '+route+' HTTP/1.1" 200'in line]
 good=False
 if row['exit']==0 and row['stdout'].endswith('HTTP=200\n'):
  body=json.loads(row['stdout'].rsplit('HTTP=',1)[0]);good=body=={'nonce':row['nonce'],'sha256':hashlib.sha256(row['nonce'].encode()).hexdigest(),'target':'10.86.1.10'}and len(matches)==1
 correlated.append({**row,'target_matches':matches,'verified_success':good,'verified_timeout':row['exit']==28 and row['stdout']=='HTTP=000\n'and not matches})
save(stem+'-correlated-rows.json',correlated);assert execution['exit']==0 and len(rows)==a.count and len({r['nonce']for r in rows})==len(rows)
save(stem+'-result.json',{'rows':len(rows),'verified_successes':sum(r['verified_success']for r in correlated),'timeouts':sum(r['verified_timeout']for r in correlated),'counter_and_fault_clock_review_required':True,'independent_fresh_connections':True,'existing_stream':False,'no_api_writes':True,'unclassified_rows':sum(not r['verified_success']and not r['verified_timeout']for r in correlated),'scope':'actual real physical TGW namespaces; pernonce response and independent targetlog'})
print(json.dumps({'receipt':str(base/(stem+'-result.json')),'rows':len(rows),'successes':sum(r['verified_success']for r in correlated)}))
