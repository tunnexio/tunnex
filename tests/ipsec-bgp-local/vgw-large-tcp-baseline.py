#!/usr/bin/env python3
"""Run ONLY on designated bastion after root confirms ZT convergence.
Additive fresh served fixture response; no service restart or echo-server claim.
"""
import argparse,base64,hashlib,json,os,pathlib,secrets,shlex,subprocess,time
ap=argparse.ArgumentParser();ap.add_argument('--execute',action='store_true');ap.add_argument('--gateway-container',required=True);a=ap.parse_args()
assert a.gateway_container and all(c in '0123456789abcdef' for c in a.gateway_container) and len(a.gateway_container)==64
key='/home/ubuntu/tunnex-bgp-20261007/lab-key';base=pathlib.Path('/home/ubuntu/tunnex-bgp-vgw-eic-20261008');os.umask(0o077)
def run(cmd):
 r=subprocess.run(cmd,capture_output=True,timeout=35);return {'exit':r.returncode,'stdout':r.stdout.decode(),'stderr':r.stderr.decode()}
def ssh(host,command,options=[]):return run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10','-i',key,*options,host,command])
client_opts=['-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(base/'client_known_hosts'),'-o','ProxyCommand=ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -i '+key+' -W %h:%p ubuntu@13.63.169.255']
target_opts=['-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(base/'known_hosts'),'-o','ProxyCommand=aws ec2-instance-connect open-tunnel --instance-id i-0cd8ee7ba1e099092 --instance-connect-endpoint-id eice-01f10d84c64fdf3a1 --remote-port 22 --max-tunnel-duration 120']
nonce=secrets.token_hex(32);stem='large-tcp-'+nonce;uri='/tunnex-bgp-acceptance-large/'+nonce+'.bin?nonce='+nonce
if not a.execute:
 print(json.dumps({'source_only':True,'size_bytes':4194304,'gateway_container':a.gateway_container,'scope':'customer84.2.10 download from actual target85.1.10:8080; existing normal TCP grant required','DF_ICMP':'pending normal ICMP grant; no ping interpretation'}));raise SystemExit
assert pathlib.Path('/home/ubuntu').is_dir() and base.is_dir()
def save(name,obj):
 with open(base/name,'x') as f:json.dump(obj,f);f.flush();os.fsync(f.fileno())
 fd=os.open(base,os.O_RDONLY);os.fsync(fd);os.close(fd)
started=int(time.time());save(stem+'-intent.json',{'nonce':nonce,'uri':uri,'size':4194304,'gateway_container':a.gateway_container,'started':started,'helper_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()})
identity_code="import json,os,pathlib,subprocess; p=1353; main=subprocess.check_output(['systemctl','show','tunnex-bgp-target.service','-p','MainPID','--value']).decode().strip(); assert main==str(p); stat=pathlib.Path('/proc/'+str(p)+'/stat').read_text(); print(json.dumps({'pid':p,'start':stat.rsplit(')',1)[1].split()[19],'exe':os.readlink('/proc/'+str(p)+'/exe'),'cmdline':pathlib.Path('/proc/'+str(p)+'/cmdline').read_bytes().decode(),'cwd':os.readlink('/proc/'+str(p)+'/cwd'),'http_code_sha256':__import__('hashlib').sha256(pathlib.Path('/usr/lib/python3.12/http/server.py').read_bytes()).hexdigest()},sort_keys=True))"
identity_command='sudo -n python3 -c '+shlex.quote(identity_code)
identity_before=ssh('ubuntu@10.85.1.10',identity_command,target_opts);assert identity_before['exit']==0
identity=json.loads(identity_before['stdout']);assert identity['exe']=='/usr/bin/python3.12' and identity['cmdline']=='/usr/bin/python3\x00-m\x00http.server\x008080\x00--bind\x000.0.0.0\x00' and identity['cwd']=='/opt/tunnex-bgp-lab' and identity['http_code_sha256']=='6ef28116c245a8e5e7f2d57f17607b7df706fd86110cf1c5a2b8416151b41248'
save(stem+'-service-identity-before.json',identity_before)
block=hashlib.sha256(nonce.encode()).digest();expected_sha=hashlib.sha256(block*(4194304//32)).hexdigest()
code="""import os,pathlib,hashlib,json
root=pathlib.Path('/opt/tunnex-bgp-lab');assert pathlib.Path('/proc/1353/cwd').resolve()==root and root.stat().st_uid==0 and root.stat().st_mode&0o777==0o755
p=root/'tunnex-bgp-acceptance-large'
try:p.mkdir(mode=0o755)
except FileExistsError:pass
assert not p.is_symlink() and p.stat().st_uid==0 and p.stat().st_mode&0o777==0o755
nonce=%r;data=hashlib.sha256(nonce.encode()).digest()*(4194304//32)
fd=os.open(p/(nonce+'.bin'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
print(json.dumps({'sha256':hashlib.sha256(data).hexdigest(),'size':len(data)}))
"""%nonce
fixture=ssh('ubuntu@10.85.1.10','sudo -n python3 -c '+shlex.quote(code),target_opts);save(stem+'-fixture.json',fixture);assert fixture['exit']==0 and json.loads(fixture['stdout'])=={'sha256':expected_sha,'size':4194304}
def transfer_code(url):
 return "import subprocess,hashlib,json,time; t=time.monotonic(); r=subprocess.run(['curl','--noproxy','*','--fail','--connect-timeout','3','--max-time','25','--silent','--show-error',%r],capture_output=True,timeout=28); print(json.dumps({'exit':r.returncode,'bytes':len(r.stdout),'sha256':hashlib.sha256(r.stdout).hexdigest(),'seconds':time.monotonic()-t,'stderr':r.stderr.decode()})); raise SystemExit(r.returncode)"%url
control=ssh('ubuntu@10.85.1.10','python3 -c '+shlex.quote(transfer_code('http://127.0.0.1:8080'+uri)),target_opts);save(stem+'-control.json',control);assert control['exit']==0 and json.loads(control['stdout'])['sha256']==expected_sha and json.loads(control['stdout'])['bytes']==4194304
# Explicit argv per command avoids masking an earlier failed read behind a later exit status.
def gateway_snapshot():
 commands=[['docker','inspect','--format','{{.Id}} {{.State.Running}}',a.gateway_container],['docker','exec',a.gateway_container,'ip','-j','-d','link','show'],['docker','exec',a.gateway_container,'ip','-j','route','show','table','all'],['docker','exec',a.gateway_container,'nft','-j','list','ruleset'],['docker','exec','-e','STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf',a.gateway_container,'/opt/tunnex-ipsec/sbin/swanctl','--list-sas','--uri','unix:///run/tunnex-ipsec/charon.vici'],['docker','exec',a.gateway_container,'sha256sum','/state/cert.pem']]
 rows=[]
 for argv in commands:
  r=ssh('ubuntu@13.63.169.255','sudo -n '+shlex.join(argv));rows.append({'argv':argv,'result':r});assert r['exit']==0
 assert rows[0]['result']['stdout']==a.gateway_container+' true\n'
 return rows
before=gateway_snapshot();save(stem+'-before.json',before)
client_identity=ssh('ubuntu@10.84.2.10','hostname; ip -j address show; ip -j route get 10.85.1.10',client_opts);save(stem+'-client-identity.json',client_identity);assert client_identity['exit']==0
route=ssh('ubuntu@10.84.2.10','ip -j route get 10.85.1.10',client_opts);save(stem+'-client-route.json',route);assert route['exit']==0
rows=json.loads(route['stdout']);assert len(rows)==1 and rows[0].get('prefsrc')=='10.84.2.10' and rows[0].get('dev')=='ens5'
probe=ssh('ubuntu@10.84.2.10','python3 -c '+shlex.quote(transfer_code('http://10.85.1.10:8080'+uri)),client_opts);save(stem+'-probe.json',probe)
after=gateway_snapshot();save(stem+'-after.json',after);assert before[-1]['result']['stdout']==after[-1]['result']['stdout']
identity_after=ssh('ubuntu@10.85.1.10',identity_command,target_opts);save(stem+'-service-identity-after.json',identity_after);assert identity_after['exit']==0 and identity_after['stdout']==identity_before['stdout']
log=ssh('ubuntu@10.85.1.10','sudo -n journalctl -u tunnex-bgp-target.service --since @'+str(started)+' --no-pager -o cat',target_opts);save(stem+'-target-log.json',log);assert log['exit']==0
matched=[x for x in log['stdout'].splitlines() if '10.84.2.10 - ' in x and '"GET '+uri+' HTTP/1.1" 200' in x]
result=json.loads(probe['stdout']) if probe['exit']==0 else None
passed=bool(result and result['exit']==0 and result['bytes']==4194304 and result['sha256']==expected_sha and len(matched)==1)
save(stem+'-result.json',{'passed':passed,'transfer':result,'expected_sha256':expected_sha,'target_matches':matched,'counter_suite_NATT_MTU_review_required':True,'scope':'actual customer download baseline only; not bidirectional MSS/DF/PMTUD qualification','DF_ICMP':'pending normal ICMP grant'})
print(json.dumps({'passed':passed,'receipt':str(base/(stem+'-result.json'))}));assert passed
