#!/usr/bin/env python3
"""Run ONLY on designated bastion after root confirms ZT convergence.
Additive fresh served fixture response; no service restart or echo-server claim.
"""
import argparse,base64,hashlib,json,os,pathlib,secrets,shlex,subprocess,time
ap=argparse.ArgumentParser();ap.add_argument('--execute',action='store_true');ap.add_argument('--gateway-container',required=True);ap.add_argument('--expect',choices=['allow','deny'],required=True);a=ap.parse_args()
assert a.gateway_container and all(c in '0123456789abcdef' for c in a.gateway_container) and len(a.gateway_container)==64
key='/home/ubuntu/tunnex-bgp-20261007/lab-key';base=pathlib.Path('/home/ubuntu/tunnex-bgp-vgw-eic-20261008');os.umask(0o077)
def run(cmd):
 r=subprocess.run(cmd,capture_output=True,timeout=35);return {'exit':r.returncode,'stdout':r.stdout.decode(),'stderr':r.stderr.decode()}
def ssh(host,command,options=[]):return run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10','-i',key,*options,host,command])
client_opts=['-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(base/'client_known_hosts'),'-o','ProxyCommand=ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -i '+key+' -W %h:%p ubuntu@13.63.169.255']
target_opts=['-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(base/'known_hosts'),'-o','ProxyCommand=aws ec2-instance-connect open-tunnel --instance-id i-0cd8ee7ba1e099092 --instance-connect-endpoint-id eice-01f10d84c64fdf3a1 --remote-port 22 --max-tunnel-duration 120']
nonce=secrets.token_hex(32);uri='/tunnex-bgp-acceptance-nonces/'+nonce+'.json?nonce='+nonce
if not a.execute:print(json.dumps({'source_only':True,'expect':a.expect,'uri_template':'/tunnex-bgp-acceptance-nonces/<fresh64hex>.json?nonce=<fresh64hex>','target':'10.85.1.10:8080','correlation':'exact source10.84.2.10 URI in independent EIC journal, plus actual CHILD/NFT counter snapshots'}));raise SystemExit
assert pathlib.Path('/home/ubuntu').is_dir() and base.is_dir()
def save(name,obj):
 with open(base/name,'x') as f:json.dump(obj,f);f.flush();os.fsync(f.fileno())
 fd=os.open(base,os.O_RDONLY);os.fsync(fd);os.close(fd)
started=int(time.time());stem='nonce-'+nonce
save(stem+'-intent.json',{'nonce':nonce,'uri':uri,'expected':a.expect,'gateway_container':a.gateway_container,'started':started})
identity_code="import json,os,pathlib,subprocess; p=1353; main=subprocess.check_output(['systemctl','show','tunnex-bgp-target.service','-p','MainPID','--value']).decode().strip(); assert main==str(p); stat=pathlib.Path('/proc/'+str(p)+'/stat').read_text(); print(json.dumps({'pid':p,'start':stat.rsplit(')',1)[1].split()[19],'exe':os.readlink('/proc/'+str(p)+'/exe'),'cmdline':pathlib.Path('/proc/'+str(p)+'/cmdline').read_bytes().decode(),'cwd':os.readlink('/proc/'+str(p)+'/cwd')},sort_keys=True))"
identity_command='sudo -n python3 -c '+shlex.quote(identity_code)
identity_before=ssh('ubuntu@10.85.1.10',identity_command,target_opts);assert identity_before['exit']==0
identity=json.loads(identity_before['stdout']);assert identity['exe']=='/usr/bin/python3.12' and identity['cmdline']=='/usr/bin/python3\x00-m\x00http.server\x008080\x00--bind\x000.0.0.0\x00' and identity['cwd']=='/opt/tunnex-bgp-lab'
save(stem+'-service-identity-before.json',identity_before)
body=json.dumps({'nonce':nonce,'target':'10.85.1.10','scope':'fresh owned served acceptance fixture'},sort_keys=True,separators=(',',':'))+'\n'
body_sha=hashlib.sha256(body.encode()).hexdigest()
code="""import os,pathlib,hashlib,json
root=pathlib.Path('/opt/tunnex-bgp-lab');assert pathlib.Path('/proc/1353/cwd').resolve()==root and root.stat().st_uid==0 and root.stat().st_mode&0o777==0o755
p=root/'tunnex-bgp-acceptance-nonces'
try:p.mkdir(mode=0o755)
except FileExistsError:pass
assert not p.is_symlink() and p.stat().st_uid==0 and p.stat().st_mode&0o777==0o755
name=%r;body=%r
fd=os.open(p/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
with os.fdopen(fd,'w') as f:f.write(body);f.flush();os.fsync(f.fileno())
fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
print(hashlib.sha256(body.encode()).hexdigest())
"""%(nonce+'.json',body)
encoded=base64.b64encode(code.encode()).decode()
fixture=ssh('ubuntu@10.85.1.10','sudo -n python3 -c '+shlex.quote('import base64;exec(base64.b64decode('+repr(encoded)+'))'),target_opts)
assert fixture['exit']==0 and fixture['stdout'].strip()==body_sha
control=ssh('ubuntu@10.85.1.10','curl --noproxy "*" --fail --max-time 5 -s '+shlex.quote('http://127.0.0.1:8080'+uri),target_opts)
assert control['exit']==0 and control['stdout']==body
save(stem+'-fixture-control.json',{'fixture':fixture,'control':control,'body_sha256':body_sha,'body':body})
command='sudo -n docker inspect --format "{{.Id}} {{.State.Running}}" '+a.gateway_container+'; sudo -n docker exec '+a.gateway_container+' nft -j list ruleset; sudo -n docker exec -e STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf '+a.gateway_container+' /opt/tunnex-ipsec/sbin/swanctl --list-sas --uri unix:///run/tunnex-ipsec/charon.vici'
before=ssh('ubuntu@13.63.169.255',command);save(stem+'-before.json',before);assert before['exit']==0 and before['stdout'].startswith(a.gateway_container+' true\n')
probe=ssh('ubuntu@10.84.2.10','curl --noproxy "*" --connect-timeout 3 --max-time 5 --silent --show-error --write-out "HTTP=%{http_code}\\n" "http://10.85.1.10:8080'+uri+'"',client_opts)
after=ssh('ubuntu@13.63.169.255',command);save(stem+'-after.json',after);assert after['exit']==0 and after['stdout'].startswith(a.gateway_container+' true\n')
identity_after=ssh('ubuntu@10.85.1.10',identity_command,target_opts);assert identity_after['exit']==0 and identity_after['stdout']==identity_before['stdout']
save(stem+'-service-identity-after.json',identity_after)
log=ssh('ubuntu@10.85.1.10','sudo -n journalctl -u tunnex-bgp-target.service --since @'+str(started)+' --no-pager -o cat',target_opts);assert log['exit']==0
matched=[line for line in log['stdout'].splitlines() if '10.84.2.10 - ' in line and '"GET '+uri+' HTTP/1.1" 200' in line]
passed=(probe['exit']==0 and probe['stdout']==body+'HTTP=200\n' and len(matched)==1) if a.expect=='allow' else (probe['exit']==28 and probe['stdout']=='HTTP=000\n' and not matched)
save(stem+'-result.json',{'probe':probe,'after':after,'target_log':log,'matched':matched,'passed':passed,'scope':'actual fresh served fixture body through private VPN; exact nonce/body hash and independently correlated target log','expected_body_sha256':body_sha,'counter_review_required':True})
print(json.dumps({'nonce':nonce,'passed':passed,'target_matches':len(matched),'receipt':str(base/(stem+'-result.json'))}));assert passed
