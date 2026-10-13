#!/usr/bin/env python3
"""Run ONLY on designated bastion after root confirms ZT convergence.
Sleeping restored namespace denial only; no product authority or guard-counter claim.
"""
import argparse,base64,hashlib,json,os,pathlib,secrets,shlex,subprocess,time
def validate_receipt_metadata(raw_set, raw_journal, receipts, pin):
 import uuid
 assert hashlib.sha256(raw_set).hexdigest()==pin['receipt_set_sha256'] and hashlib.sha256(raw_journal).hexdigest()==pin['journal_sha256']
 bundle=json.loads(raw_set);journal=json.loads(raw_journal)
 ids=pin['expected_deliveries'];assert ids and len(ids)<=256 and ids==sorted(set(ids))
 assert all(str(uuid.UUID(id))==id and uuid.UUID(id).int for id in ids)
 active=[e for e in journal['Payload']['Entries'] if e['Phase']!='retained_refusal']
 assert len(active)==len(ids) and sorted(e['DeliveryID'] for e in active)==ids and all(e['Phase']=='applied'for e in active)
 assert set(receipts)==set(ids)==set(bundle['Receipts'])
 assert bundle['OwnerID']==journal['Payload']['OwnerID']==pin['owner_id'] and bundle['Namespace']==pin['namespace']
 assert bundle['JournalSHA']==pin['journal_sha256'] and bundle['EvidenceDigest']==pin['evidence_digest']
 entries={e['DeliveryID']:e for e in active}
 for id,raw in receipts.items():
  assert hashlib.sha256(raw).hexdigest()==bundle['Receipts'][id]
  r=json.loads(raw);assert r['EntryDigest']==hashlib.sha256(json.dumps(entries[id],separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
  assert r['Version']==1 and r['OwnerID']==pin['owner_id'] and r['DeliveryID']==id and r['Namespace']==pin['namespace'] and r['EvidenceDigest']==pin['evidence_digest'] and r['Termination']=='supervisor-confirmed-runtime-stop'
 return {'receipt_set_sha256':pin['receipt_set_sha256'],'journal_sha256':pin['journal_sha256'],'installed_delivery_ids':ids,'receipt_sha256':bundle['Receipts']}

ap=argparse.ArgumentParser();ap.add_argument('--execute',action='store_true');ap.add_argument('--gateway-container',required=True);ap.add_argument('--expect',choices=['deny'],required=True);ap.add_argument('--pins',required=True);a=ap.parse_args()
assert a.gateway_container and all(c in '0123456789abcdef' for c in a.gateway_container) and len(a.gateway_container)==64
key='/home/ubuntu/tunnex-bgp-20261007/lab-key';base=pathlib.Path('/home/ubuntu/tunnex-bgp-vgw-eic-20261008');os.umask(0o077)
def run(cmd):
 r=subprocess.run(cmd,capture_output=True,timeout=35);return {'exit':r.returncode,'stdout':r.stdout.decode(),'stderr':r.stderr.decode()}
def ssh(host,command,options=[]):return run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10','-i',key,*options,host,command])
client_opts=['-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(base/'client_known_hosts'),'-o','ProxyCommand=ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -i '+key+' -W %h:%p ubuntu@13.63.169.255']
target_opts=['-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(base/'known_hosts'),'-o','ProxyCommand=aws ec2-instance-connect open-tunnel --instance-id i-0cd8ee7ba1e099092 --instance-connect-endpoint-id eice-01f10d84c64fdf3a1 --remote-port 22 --max-tunnel-duration 120']
nonce=secrets.token_hex(32);uri='/tunnex-bgp-acceptance-nonces/'+nonce+'.json?nonce='+nonce
if not a.execute:print(json.dumps({'source_only':True,'expect':a.expect,'uri_template':'/tunnex-bgp-acceptance-nonces/<fresh64hex>.json?nonce=<fresh64hex>','target':'10.85.1.10:8080','correlation':'curl exit7/28 HTTP000, independent target control, exact sleeping namespace census before/after'}));raise SystemExit
assert pathlib.Path('/home/ubuntu').is_dir() and base.is_dir()
def save(name,obj):
 with open(base/name,'x') as f:json.dump(obj,f);f.flush();os.fsync(f.fileno())
 fd=os.open(base,os.O_RDONLY);os.fsync(fd);os.close(fd)
import stat
st=pathlib.Path(a.pins).lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o600
pin=json.loads(pathlib.Path(a.pins).read_text());assert pin['node_sha256']=='fd3fd0fe6b1985c18f6182286a80b24f463bae93a5fce208ea996e830db67cb6' and pin['namespace'] not in ['net:[4026532947]','net:[4026532946]','net:[4026532813]'] and not pin['gateway_id'].startswith(('0faef89','3b3ed48'));assert pin['root_reviewed'] is True and pin['gate_expected'] is True and pin['gateway_id']==a.gateway_container
started=int(time.time());stem='pre-release-nonce-'+nonce
save(stem+'-intent.json',{'nonce':nonce,'uri':uri,'expected':a.expect,'gateway_container':a.gateway_container,'started':started})
identity_code="import json,os,pathlib,subprocess; p=1353; main=subprocess.check_output(['systemctl','show','tunnex-bgp-target.service','-p','MainPID','--value']).decode().strip(); assert main==str(p); stat=pathlib.Path('/proc/'+str(p)+'/stat').read_text(); print(json.dumps({'pid':p,'start':stat.rsplit(')',1)[1].split()[19],'exe':os.readlink('/proc/'+str(p)+'/exe'),'cmdline':pathlib.Path('/proc/'+str(p)+'/cmdline').read_bytes().decode(),'cwd':os.readlink('/proc/'+str(p)+'/cwd')},sort_keys=True))"
identity_command='sudo -n python3 -c '+shlex.quote(identity_code)
identity_before=ssh('ubuntu@10.85.1.10',identity_command,target_opts);assert identity_before['exit']==0
identity=json.loads(identity_before['stdout']);assert identity['pid']==1353 and identity['start']=='5629';assert identity['exe']=='/usr/bin/python3.12' and identity['cmdline']=='/usr/bin/python3\x00-m\x00http.server\x008080\x00--bind\x000.0.0.0\x00' and identity['cwd']=='/opt/tunnex-bgp-lab'
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
observer_source="import json,subprocess,hashlib,os,stat\npin=PIN_LITERAL\ncid=pin['gateway_id'];assert len(cid)==64 and all(c in '0123456789abcdef' for c in cid)\nassert cid!='382b1763ae4bd0fa21a871839af4be0d9c0c8e37dc7d57c85a68172cfff6be06'\nd=json.loads(subprocess.check_output(['docker','inspect',cid]))[0]\nassert d['Id']==cid and d['State']['Running'] and d['Image']==pin['image'] and d['Config']['Labels']['tunnex.lab']=='tunnex-bgp-20261007'\ndef ex(*args):return subprocess.check_output(['docker','exec',cid,*args],text=True)\nns=ex('readlink','/proc/1/ns/net').strip();assert ns==pin['namespace'] and ns!='net:[4026532807]'\nassert ex('sha256sum',pin['node_path']).split()[0]==pin['node_sha256']\nassert ex('sha256sum','/state/cert.pem').split()[0]==pin['cert_sha256']\nprocesses=ex('ps','-eo','pid,comm');rows=[r.split() for r in processes.splitlines()[1:]]\nassert not any(r[-1] in ['tunnex-node','charon','bgpd','zebra'] for r in rows)\nassert ex('readlink','/proc/1/exe').strip() in ['/bin/busybox','/bin/sh']\nassert subprocess.run(['docker','exec',cid,'test','-e','/run/enrolled-restoration-release'],stdout=subprocess.DEVNULL).returncode==1\ngate_fields=ex('stat','-c','%d %i %u %a %F','/state/ipsec/restoration-startup-gate').strip().split(' ',4);assert gate_fields[2:]==['0','600','regular file'];gate_stat={'dev':int(gate_fields[0]),'inode':int(gate_fields[1]),'uid':0,'mode':384};assert gate_stat==pin['gate_identity']\ngate=ex('cat','/state/ipsec/restoration-startup-gate');assert gate==pin['gate_content']\nroutes=json.loads(ex('ip','-j','-4','route','show','table','all'));assert not any(r.get('dst') in ['10.85.0.0/16','10.86.0.0/16'] for r in routes)\nstate_raw=ex('ip','-j','xfrm','state');policy_raw=ex('ip','-j','xfrm','policy');assert (json.loads(state_raw) if state_raw.strip() else [])==[] and (json.loads(policy_raw) if policy_raw.strip() else [])==[]\nnft=json.loads(ex('nft','-j','list','ruleset'));assert not any(r.get('table',{}).get('name')=='tunnex_ipsec' for r in nft['nftables'])\nprint(json.dumps({'cid':cid,'namespace':ns,'image':d['Image'],'started_at':d['State']['StartedAt'],'host_pid':d['State']['Pid'],'pid1_stat':ex('cat','/proc/1/stat'),'processes':processes,'gate_sha256':hashlib.sha256(gate.encode()).hexdigest(),'gate_identity':gate_stat,'release_absent':True,'xfrm_states':[],'xfrm_policies':[],'routes':routes,'nft':nft,'worker_started':False,'node_sha256':pin['node_sha256'],'cert_sha256':pin['cert_sha256']}))\n"
observer_source=observer_source.replace('assert json.loads(ex(\'ip\',\'-j\',\'xfrm\',\'state\'))==[] and json.loads(ex(\'ip\',\'-j\',\'xfrm\',\'policy\'))==[]', 'xfrm_states=empty_xfrm_census(ex(\'ip\',\'-j\',\'xfrm\',\'state\'));xfrm_policies=empty_xfrm_census(ex(\'ip\',\'-j\',\'xfrm\',\'policy\'))')
observer_source="def empty_xfrm_census(raw):\n if not isinstance(raw,str): raise ValueError('XFRM output type')\n if not raw.strip(): return []\n value=json.loads(raw)\n if type(value) is not list or value: raise ValueError('XFRM census not empty')\n return []\n"+observer_source
import inspect
receipt_observer="""
import pathlib
def private_read(path,limit):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd);assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_size<=limit
  with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(limit+1)
  assert len(raw)<=limit;return raw
 finally:os.close(fd)
state=[m for m in d['Mounts']if m['Destination']=='/state'];assert len(state)==1
state_root=pathlib.Path(state[0]['Source']);assert state_root.is_absolute()
raw_set=private_read(pin['receipt_set_path'],1048576)
raw_journal=private_read(state_root/'ipsec/journal.json',4194304)
receipt_meta=validate_receipt_metadata(raw_set,raw_journal,{id:private_read(state_root/('ipsec/restore-'+id+'.json'),1048576)for id in pin['expected_deliveries']},pin)
"""
observer_source=observer_source.replace("routes=json.loads(ex('ip'",receipt_observer+"routes=json.loads(ex('ip'",1)
observer_source=observer_source.replace("'worker_started':False,'node_sha256'","'receipt_metadata':receipt_meta,'worker_started':False,'node_sha256'",1)
observer_source="import hashlib,json\n"+inspect.getsource(validate_receipt_metadata)+observer_source

observer_source=observer_source.replace('PIN_LITERAL',repr(pin))
command='sudo -n python3 -c '+shlex.quote('import base64;exec(base64.b64decode('+repr(base64.b64encode(observer_source.encode()).decode())+'))')
before=ssh('ubuntu@13.63.169.255',command);save(stem+'-before.json',before);assert before['exit']==0
before_census=json.loads(before['stdout'])
client_proof_source="import subprocess,json\nr=json.loads(subprocess.check_output(['ip','-j','-4','route','get','10.85.1.10']))\nassert len(r)==1 and r[0]['dst']=='10.85.1.10' and r[0].get('prefsrc')=='10.84.2.10' and not r[0].get('flags',[])\ndev=r[0]['dev'];links=json.loads(subprocess.check_output(['ip','-j','link','show','dev',dev]));assert len(links)==1 and links[0]['ifindex']>0 and 'UP'in links[0]['flags'] and links[0]['link_type']=='ether'\nips=json.loads(subprocess.check_output(['ip','-j','-4','address','show','dev',dev]));assert len(ips)==1 and any(x.get('local')=='10.84.2.10'and x.get('scope')=='global'for x in ips[0]['addr_info'])\nprint(json.dumps({'route':r,'links':links,'addresses':ips},sort_keys=True))\n"
client_proof_command='python3 -c '+shlex.quote('import base64;exec(base64.b64decode('+repr(base64.b64encode(client_proof_source.encode()).decode())+'))')
client_before=ssh('ubuntu@10.84.2.10',client_proof_command,client_opts);save(stem+'-client-route-before.json',client_before);assert client_before['exit']==0
probe=ssh('ubuntu@10.84.2.10','curl --noproxy "*" --connect-timeout 3 --max-time 5 --silent --show-error --write-out "HTTP=%{http_code}\\n" "http://10.85.1.10:8080'+uri+'"',client_opts)
save(stem+'-probe.json',probe)
after=ssh('ubuntu@13.63.169.255',command);save(stem+'-after.json',after);assert after['exit']==0
after_census=json.loads(after['stdout'])
for field in ['cid','namespace','image','started_at','host_pid','gate_sha256','gate_identity','release_absent','worker_started','node_sha256','cert_sha256','receipt_metadata']:
 assert before_census[field]==after_census[field]
assert before_census['pid1_stat'].rsplit(')',1)[1].split()[19]==after_census['pid1_stat'].rsplit(')',1)[1].split()[19]
client_after=ssh('ubuntu@10.84.2.10',client_proof_command,client_opts);save(stem+'-client-route-after.json',client_after);assert client_after['exit']==0
client_shapes=[json.loads(client_before['stdout']),json.loads(client_after['stdout'])]
for shape in client_shapes:
 for row in shape['addresses']:
  for ip in row['addr_info']:
   for lifetime_field in ['preferred_life_time','valid_life_time']:
    if lifetime_field in ip and isinstance(ip[lifetime_field],int):assert ip[lifetime_field]>0;ip.pop(lifetime_field)
assert client_shapes[0]==client_shapes[1]
identity_after=ssh('ubuntu@10.85.1.10',identity_command,target_opts)
save(stem+'-service-identity-after.json',identity_after)
assert identity_after['exit']==0 and json.loads(identity_after['stdout'])==identity
control_after=ssh('ubuntu@10.85.1.10','curl --noproxy "*" --fail --max-time 5 -s '+shlex.quote('http://127.0.0.1:8080'+uri),target_opts)
save(stem+'-fixture-control-after.json',control_after)
assert control_after['exit']==0 and control_after['stdout']==body
log=ssh('ubuntu@10.85.1.10','sudo -n journalctl -u tunnex-bgp-target.service --since @'+str(started)+' --no-pager -o cat',target_opts);assert log['exit']==0
matched=[line for line in log['stdout'].splitlines() if '10.84.2.10 - ' in line and '"GET '+uri+' HTTP/1.1" 200' in line]
passed=probe['exit'] in [7,28] and probe['stdout']=='HTTP=000\n' and not matched
save(stem+'-result.json',{'probe':probe,'after':after,'target_log':log,'matched':matched,'passed':passed,'scope':'fresh restored sleeping namespace has no authority; real client timeout with independently healthy target and exact before/after empty transport census','expected_body_sha256':body_sha,'client_before':client_before,'client_after':client_after,'denial_exit_class':'connect_refused' if probe['exit']==7 else 'connect_timeout','counter_review_required':False,'product_guard_drop_counter_claimed':False,'worker_started':False,'before_census':before_census,'after_census':after_census})
print(json.dumps({'nonce':nonce,'passed':passed,'target_matches':len(matched),'receipt':str(base/(stem+'-result.json'))}));assert passed
