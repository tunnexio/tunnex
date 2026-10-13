#!/usr/bin/env python3
"""Run ONLY on designated bastion after root confirms ZT convergence.
Sleeping restored namespace denial only; no product authority or guard-counter claim.
"""
import argparse,base64,hashlib,json,os,pathlib,secrets,shlex,subprocess,time
ap=argparse.ArgumentParser();ap.add_argument('--execute',action='store_true');ap.add_argument('--gateway-container',required=True);ap.add_argument('--expect',choices=['deny'],required=True);ap.add_argument('--pins',required=True);a=ap.parse_args()
assert a.gateway_container and all(c in '0123456789abcdef' for c in a.gateway_container) and len(a.gateway_container)==64
key='/home/ubuntu/tunnex-bgp-20261007/lab-key';base=pathlib.Path('/home/ubuntu/tunnex-bgp-vgw-eic-20261008');os.umask(0o077)
def run(cmd):
 r=subprocess.run(cmd,capture_output=True,timeout=35);return {'exit':r.returncode,'stdout':r.stdout.decode(),'stderr':r.stderr.decode()}
def ssh(host,command,options=[]):return run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10','-i',key,*options,host,command])
client_opts=['-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(base/'client_known_hosts'),'-o','ProxyCommand=ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -i '+key+' -W %h:%p ubuntu@13.63.169.255']
target_opts=['-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(base/'known_hosts'),'-o','ProxyCommand=aws ec2-instance-connect open-tunnel --instance-id i-0cd8ee7ba1e099092 --instance-connect-endpoint-id eice-01f10d84c64fdf3a1 --remote-port 22 --max-tunnel-duration 120']
nonce=secrets.token_hex(32);uri='/tunnex-bgp-acceptance-nonces/'+nonce+'.json?nonce='+nonce
if not a.execute:print(json.dumps({'source_only':True,'expect':a.expect,'uri_template':'/tunnex-bgp-acceptance-nonces/<fresh64hex>.json?nonce=<fresh64hex>','target':'10.85.1.10:8080','correlation':'curl exit28 HTTP000, independent target control, exact sleeping namespace census before/after'}));raise SystemExit
assert pathlib.Path('/home/ubuntu').is_dir() and base.is_dir()
def save(name,obj):
 with open(base/name,'x') as f:json.dump(obj,f);f.flush();os.fsync(f.fileno())
 fd=os.open(base,os.O_RDONLY);os.fsync(fd);os.close(fd)
import stat
st=pathlib.Path(a.pins).lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600
pin=json.loads(pathlib.Path(a.pins).read_text());assert pin['root_reviewed'] is True and pin['gate_expected'] is True and pin['gateway_id']==a.gateway_container
started=int(time.time());stem='pre-release-nonce-'+nonce
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
observer_source="import json,subprocess,hashlib,os\npin=PIN_LITERAL\ncid=pin['gateway_id'];assert len(cid)==64 and all(c in '0123456789abcdef' for c in cid)\nassert cid!='382b1763ae4bd0fa21a871839af4be0d9c0c8e37dc7d57c85a68172cfff6be06'\nd=json.loads(subprocess.check_output(['docker','inspect',cid]))[0]\nassert d['Id']==cid and d['State']['Running'] and d['Image']==pin['image'] and d['Config']['Labels']['tunnex.lab']=='tunnex-bgp-20261007'\ndef ex(*args):return subprocess.check_output(['docker','exec',cid,*args],text=True)\nns=ex('readlink','/proc/1/ns/net').strip();assert ns==pin['namespace'] and ns!='net:[4026532807]'\nassert ex('sha256sum',pin['node_path']).split()[0]==pin['node_sha256']\nassert ex('sha256sum','/state/cert.pem').split()[0]==pin['cert_sha256']\nprocesses=ex('ps','-eo','pid,comm');rows=[r.split() for r in processes.splitlines()[1:]]\nassert not any(r[-1] in ['tunnex-node','charon','bgpd','zebra'] for r in rows)\nassert ex('readlink','/proc/1/exe').strip() in ['/bin/busybox','/bin/sh']\nassert subprocess.run(['docker','exec',cid,'test','-e','/run/enrolled-restoration-release'],stdout=subprocess.DEVNULL).returncode==1\ngate=ex('cat','/state/ipsec/restoration-startup-gate');assert gate==pin['gate_content']\nroutes=json.loads(ex('ip','-j','-4','route','show','table','all'));assert not any(r.get('dst')=='10.85.0.0/16' for r in routes)\nassert json.loads(ex('ip','-j','xfrm','state'))==[] and json.loads(ex('ip','-j','xfrm','policy'))==[]\nnft=json.loads(ex('nft','-j','list','ruleset'));assert not any(r.get('table',{}).get('name')=='tunnex_ipsec' for r in nft['nftables'])\nprint(json.dumps({'cid':cid,'namespace':ns,'image':d['Image'],'started_at':d['State']['StartedAt'],'host_pid':d['State']['Pid'],'pid1_stat':ex('cat','/proc/1/stat'),'processes':processes,'gate_sha256':hashlib.sha256(gate.encode()).hexdigest(),'release_absent':True,'xfrm_states':[],'xfrm_policies':[],'routes':routes,'nft':nft,'worker_started':False,'node_sha256':pin['node_sha256'],'cert_sha256':pin['cert_sha256']}))\n"
observer_source=observer_source.replace('PIN_LITERAL',repr(pin))
command='sudo -n python3 -c '+shlex.quote('import base64;exec(base64.b64decode('+repr(base64.b64encode(observer_source.encode()).decode())+'))')
before=ssh('ubuntu@13.63.169.255',command);save(stem+'-before.json',before);assert before['exit']==0
before_census=json.loads(before['stdout'])
probe=ssh('ubuntu@10.84.2.10','curl --noproxy "*" --connect-timeout 3 --max-time 5 --silent --show-error --write-out "HTTP=%{http_code}\\n" "http://10.85.1.10:8080'+uri+'"',client_opts)
after=ssh('ubuntu@13.63.169.255',command);save(stem+'-after.json',after);assert after['exit']==0
after_census=json.loads(after['stdout'])
for field in ['cid','namespace','image','started_at','host_pid','gate_sha256','release_absent','worker_started','node_sha256','cert_sha256']:
 assert before_census[field]==after_census[field]
assert before_census['pid1_stat'].rsplit(')',1)[1].split()[19]==after_census['pid1_stat'].rsplit(')',1)[1].split()[19]
identity_after=ssh('ubuntu@10.85.1.10',identity_command,target_opts);assert identity_after['exit']==0 and identity_after['stdout']==identity_before['stdout']
save(stem+'-service-identity-after.json',identity_after)
log=ssh('ubuntu@10.85.1.10','sudo -n journalctl -u tunnex-bgp-target.service --since @'+str(started)+' --no-pager -o cat',target_opts);assert log['exit']==0
matched=[line for line in log['stdout'].splitlines() if '10.84.2.10 - ' in line and '"GET '+uri+' HTTP/1.1" 200' in line]
passed=probe['exit']==28 and probe['stdout']=='HTTP=000\n' and not matched
save(stem+'-result.json',{'probe':probe,'after':after,'target_log':log,'matched':matched,'passed':passed,'scope':'fresh restored sleeping namespace has no authority; real client timeout with independently healthy target and exact before/after empty transport census','expected_body_sha256':body_sha,'counter_review_required':False,'product_guard_drop_counter_claimed':False,'worker_started':False,'before_census':before_census,'after_census':after_census})
print(json.dumps({'nonce':nonce,'passed':passed,'target_matches':len(matched),'receipt':str(base/(stem+'-result.json'))}));assert passed
