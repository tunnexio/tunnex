#!/usr/bin/env python3
"""Read-only post-release customer worker audit. Run on owned gateway13 via16.
No release, journal writes, kernel mutations, faults or application probes.
"""
import signal
import argparse,hashlib,http.cookiejar,json,os,pathlib,re,stat,subprocess,time,urllib.request
ap=argparse.ArgumentParser();ap.add_argument('--pins',type=pathlib.Path,required=True);ap.add_argument('--container',required=True);ap.add_argument('--namespace',required=True);ap.add_argument('--node-sha256',required=True);ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
assert os.geteuid()==0 and re.fullmatch('[0-9a-f]{64}',a.container) and re.fullmatch('net:\\[[0-9]+\\]',a.namespace) and re.fullmatch('[0-9a-f]{64}',a.node_sha256)
assert a.pins.parent==pathlib.Path('/home/ubuntu/tunnex-bgp-lab')or a.pins.parent.parent==pathlib.Path('/home/ubuntu/tunnex-bgp-lab')
ps=a.pins.lstat();assert stat.S_ISREG(ps.st_mode)and ps.st_uid==0 and stat.S_IMODE(ps.st_mode)==0o600
pin=json.loads(a.pins.read_bytes());assert pin['root_reviewed']is True and pin['gateway_id']==a.container and pin['namespace']==a.namespace and pin['node_sha256']==a.node_sha256=='296065d03c4e1f6b69f27708ab9a33d09f77004817bb5f57c10d622c3f30e75c'
assert pin['source_snapshot_sha256']=='4674c202643ef54f7239bd1c54af7fd78248b446e743da61b3ef229efc91ec1e'and pin['build_receipt_sha256']=='6ac029070ad8ccf9174b9744c7291c1834798a5bebadb114b90c444cc30ab6e6'
assert pin['namespace']!='net:[4026532816]'and pin['gateway_id']!='9795025b979ce4155300987d296a20378cbd91585f4f749b6204e658016e5c89'
assert a.output.parent==pathlib.Path('/home/ubuntu/tunnex-bgp-lab') and a.output.name.startswith('customer-post-release-')
def private_read(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd);assert stat.S_ISREG(st.st_mode)and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_size<=4194304
  with os.fdopen(os.dup(fd),'rb')as f:return f.read(4194305)
 finally:os.close(fd)
def run(argv):
 r=subprocess.run(argv,capture_output=True,text=True,timeout=8)
 assert r.returncode==0,(argv[:3],r.stderr[:256]);assert len(r.stdout.encode())<=1048576;return r.stdout
cid=a.container
def ex(*argv):return run(['docker','exec',cid,*argv])
def identity():
 d=json.loads(run(['docker','inspect',cid]))[0];assert d['State']['Running'] and d['Config']['Labels'].get('tunnex.lab')=='tunnex-bgp-20261007' and d['Image']=='sha256:868b425d65ef30b6f0c221c834e8925079d658281e89380ead59a929021c50a2'
 assert d['Image']==pin['image'] and d['State']['Pid']==pin['host_pid'] and d['State']['StartedAt']==pin['started_at']
 ns=ex('readlink','/proc/1/ns/net').strip();node=ex('sha256sum','/proc/1/exe').split()[0];assert ns==a.namespace and node==a.node_sha256
 return {'cid':cid,'image':d['Image'],'host_pid':d['State']['Pid'],'namespace':ns,'node_sha256':node,'startticks':ex('cat','/proc/1/stat').rsplit(')',1)[1].split()[19],'cert_sha256':ex('sha256sum','/state/cert.pem').split()[0],'api_sha256':run(['sha256sum',str(pathlib.Path(next(m['Source'] for m in d['Mounts'] if m['Destination']=='/binaries'))/'tunnex-api')]).split()[0]}
# Output reservation happens before reads; failures preserve a private attempt.
os.umask(0o077);fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);result={'started':time.time(),'observer_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'scope':'read-only native/normal API projection, no packet gate'}
def deadline(signum,frame):raise TimeoutError('Bounded120s observer deadline')
signal.signal(signal.SIGALRM,deadline);signal.alarm(120)
try:
 result['before']=identity();assert result['before']['cert_sha256']=='eef07a8865a43de26d8dafbc26e26327cf9d850adc3fd65112baf776d452ea8d' and result['before']['api_sha256']=='30de107bd8d56d83f18e6bd327c9beab866c16c6d455624543d5bfbe54f76c90';result['processes']=ex('ps','-eo','pid,comm');result['routes']=json.loads(ex('ip','-j','-4','route','show','table','all'));result['links']=json.loads(ex('ip','-j','-d','link','show'));result['nft']=json.loads(ex('nft','-j','list','table','inet','tunnex_ipsec'))
 result['xfrm_states_nokeys']=ex('ip','-s','xfrm','state','list','nokeys');result['xfrm_policies']=ex('ip','-s','xfrm','policy')
 result['sas']=ex('env','STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf','/opt/tunnex-ipsec/sbin/swanctl','--list-sas','--uri','unix:///run/tunnex-ipsec/charon.vici')

 d=json.loads(run(['docker','inspect',cid]))[0];state=[m for m in d['Mounts']if m['Destination']=='/state'];binary=[m for m in d['Mounts']if m['Destination']=='/binaries'];assert len(state)==len(binary)==1
 build=private_read(pathlib.Path(binary[0]['Source']).parent/'build-receipt.json');assert hashlib.sha256(build).hexdigest()==pin['build_receipt_sha256'];proof=json.loads(build);assert proof['binary_sha256']==a.node_sha256 and proof['source_snapshot_sha256']==pin['source_snapshot_sha256']
 raw=private_read(pathlib.Path(state[0]['Source'])/'ipsec/journal.json');journal=json.loads(raw);entries=[e for e in journal['Payload']['Entries']if e['Phase']!='retained_refusal']
 ids={'44e340c8-1111-4c1b-8a79-368e1b628ba9','ac42d648-b9a2-443e-a84d-fa855d0dafb4'};assert len(entries)==2 and {e['DeliveryID']for e in entries}==ids and journal['Payload']['OwnerID']=='01a1161a-9529-7478-b62f-a27f25222aa0'
 result['journal_sha256']=hashlib.sha256(raw).hexdigest();result['runtime_entries']=[];result['bgp']={}
 for entry in entries:
  assert entry['Phase']=='applied'and entry['ContractVersion']==3 and entry['Allocation']['Namespace']==a.namespace
  proc=entry.get('BGPProcess');result['runtime_entries'].append({k:entry.get(k)for k in ['DeliveryID','Phase','Allocation','Observed','BGPRoutes']})
  if proc is not None:
   assert proc['Namespace']==a.namespace and proc['Directory']=='/state/ipsec/bgp-'+entry['DeliveryID']+'-g'+str(proc['Generation'])
   result['bgp'][entry['DeliveryID']]={'process':proc,'summary':json.loads(ex('/opt/tunnex-bgp/vtysh','--vty_socket',proc['Directory'],'-d','bgpd','-c','show bgp summary json')),'rib':json.loads(ex('/opt/tunnex-bgp/vtysh','--vty_socket',proc['Directory'],'-d','bgpd','-c','show bgp ipv4 unicast json'))}
 # Journal is duty evidence, never lease/grant authority. Actual NFT element
 # expiry and normal-policy projections below are separately labelled facts.
 result['authority_observation']={'journal_serializes_lease_or_grants':False,'cp_permit_request_performed':False,'fresh_cp_permit_outcome_observed':False,'nft_sets':[x['set']for x in result['nft']['nftables']if 'set'in x]}
 p=pathlib.Path('/home/ubuntu/tunnex-bgp-lab/normal-api/credentials.json');st=p.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600
 assert p.parent.lstat().st_uid==0 and stat.S_IMODE(p.parent.lstat().st_mode)==0o700; c=json.loads(private_read(p));base=c['base_url'];cl=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
 def api(path,body=None):
  req=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','Origin':base,'X-Tunnex-CSRF':'1'})
  with cl.open(req,timeout=10) as response:return json.loads(response.read(1048577))
 login=api('/api/v1/auth/login',{'email':c['email'],'password':c['password']});assert not login.get('mfa_required')
 root='/api/v1/organizations/01a1161a-906c-7074-9e80-dd318fc2c1eb'
 result['providers']={}
 for id in ['9d9f98e2-cd96-456d-b020-a5a79f688040','8856b1c4-ae98-418b-bfd5-664cde5210c3']:
  connection=root+'/ipsec/connections/'+id;v=api(connection);assert v['id']==id and v['desired_intent']=='enabled'and v['desired_revision']==2 and v['gateway_node_id']=='01a1161a-9529-7478-b62f-a27f25222aa0'
  result['providers'][id]={'provider':{k:v.get(k)for k in ['id','desired_revision','desired_intent','gateway_node_id','site_id']},'status':api(connection+'/status')}
 result['normal_policy_rules']=api(root+'/policies');result['normal_resources']=api(root+'/resources');result['zero_trust_mode']=api(root+'/zero-trust-mode');result['eligibility']=api(root+'/ipsec/eligibility?site_id=01a119e8-fb58-72d9-bbd2-8de0fe7bfd1e&gateway_node_id=01a1161a-9529-7478-b62f-a27f25222aa0')
 result['after']=identity();assert result['before']==result['after'];result['completed']=True
except BaseException as error:result['completed']=False;result['error_type']=type(error).__name__;raise
finally:
 signal.alarm(0)
 with os.fdopen(fd,'w') as f:json.dump(result,f);f.flush();os.fsync(f.fileno())
 directory=os.open(a.output.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(directory);os.close(directory)
print(json.dumps({'receipt':str(a.output),'completed':result['completed'],'providers':result.get('providers'),'eligibility':result.get('eligibility')}))
