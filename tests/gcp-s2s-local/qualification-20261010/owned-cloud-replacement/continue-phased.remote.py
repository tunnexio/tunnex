"""Owned deployment orchestration only. Never creates runtime authority/proofs."""
import os,sys,stat,json,hashlib,subprocess,re,time
OLD='dc81baef1c4924007b39224fd4f9b14bef94e734c2138257b12bfdc46abd8294'
OLDIMAGE='sha256:ccde530ca3e815ee169ed258ab6a95ad20de4089f8e4abf6b0f20440a7d62102'
IMAGE='sha256:347bcb66318aa1b8ef1e949c6f57e28506e56a1497f2f4ae15b9ab74b8fed4c6'
SOURCE='4143d866ab97386411ff1ac4705aaa0e4579bcf6'
ROOT='/var/lib/tunnex-gcp-replacement-4143d866-20261010'
STATE='/var/lib/tunnex-gcp-s2s-cloud-20261010'
ENV='/var/lib/tunnex-gcp-s2s-launch-20261010/node-wgctrl.env'
NAME='tunnex-gcp-cloud-gateway-4143d866-20261010'
BOOT='9617762e-19db-4a21-bdee-909dfb31e501';NS='net:[4026531840]'
def run(*a,timeout=30):
 return subprocess.check_output(a,text=True,timeout=timeout).strip()
def h(b):return hashlib.sha256(b).hexdigest()
def directory(p):
 s=os.lstat(p);assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700
 return s
def read(p,limit):
 parent=directory(os.path.dirname(p));df=os.open(os.path.dirname(p),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  ds=os.fstat(df);assert (ds.st_dev,ds.st_ino)==(parent.st_dev,parent.st_ino) and ds.st_uid==0 and stat.S_IMODE(ds.st_mode)==0o700
  fd=os.open(os.path.basename(p),os.O_RDONLY|os.O_NOFOLLOW,dir_fd=df)
  try:
   s=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and 0<s.st_size<=limit
   b=os.read(fd,limit+1);t=os.fstat(fd);assert len(b)==s.st_size and (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)==(t.st_dev,t.st_ino,t.st_size,t.st_mtime_ns)
   return b,{'device':s.st_dev,'inode':s.st_ino,'size':s.st_size,'mtime_ns':s.st_mtime_ns,'sha256':h(b)}
  finally:os.close(fd)
 finally:os.close(df)
def write(name,b):
 directory(ROOT);fd=os.open(ROOT+'/'+name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  n=0
  while n<len(b):n+=os.write(fd,b[n:])
  os.fsync(fd)
 finally:os.close(fd)
 return h(b)
def receipt(name,obj):return write(name,(json.dumps(obj,sort_keys=True)+'\n').encode())
def load(name,digest):
 b,_=read(ROOT+'/'+name,16*1024*1024);assert h(b)==digest;return json.loads(b)
def public_env():
 b,meta=read(ENV,16384);v={}
 for row in b.decode().splitlines():
  k,sep,val=row.partition('=');assert sep and k not in v and '\x00' not in val;v[k]=val
 expected=PUBLIC_ENV
 assert set(v)==set(expected)|{'TUNNEX_JOIN_TOKEN'}
 for k,val in expected.items():assert v[k]==val
 t=v['TUNNEX_JOIN_TOKEN'];assert 1<=len(t)<=8192 and not any(c.isspace() or ord(c)<32 or ord(c)==127 for c in t)
 return meta

def inspect(c):return json.loads(run('docker','inspect',c))[0]
def identity():
 directory(STATE);out={}
 for n in ('cert.pem','key.pem','ca.pem'):
  # Read checks ownership/stability privately; content is never returned or written.
  _,out[n]=read(STATE+'/'+n,1024*1024);out[n].pop('sha256')
 return out

def journal():
 b,m=read(STATE+'/ipsec/journal.json',16*1024*1024);p=json.loads(b)['Payload']
 assert len(p['Entries'])==2
 expected={'80c20667-8d84-4dd8-8e51-ae4a10445cbb':3,'b79d7eda-fafe-41cf-af2c-4115d4ef32c6':4}
 assert {e['Allocation']['ConnectionID']:e['ContractVersion'] for e in p['Entries']}==expected
 projection=[{k:e[k] for k in ('ContractVersion','DeliveryID','OwnershipDigest','Allocation','Engines')} for e in p['Entries']]
 return {'metadata':m,'version':p['Version'],'owner':p['OwnerID'],'sequence':p['Sequence'],'immutable_digest':h(json.dumps(projection,sort_keys=True).encode()),'phase':[e['Phase'] for e in p['Entries']]}
def binding():
 assert run('cat','/proc/sys/kernel/random/boot_id')==BOOT and run('readlink','/proc/self/ns/net')==NS
 assert run('sysctl','-n','net.ipv4.ip_forward')=='1'
 links=json.loads(run('ip','-j','link','show','ens4'));assert len(links)==1
 l=links[0];assert l['ifindex']==2 and l['mtu']==1460 and 'UP'in l['flags'] and l['link_type']=='ether'
 aa=json.loads(run('ip','-j','addr','show','ens4'));assert any(a.get('local')=='10.70.0.2' and a.get('prefixlen')==32 for a in aa[0]['addr_info'])
 routes=json.loads(run('ip','-j','route','show','table','main'));r=[x for x in routes if x.get('dst')=='10.70.0.0/24'];assert len(r)==1
 r=r[0];assert (r.get('gateway'),r.get('prefsrc'),r.get('dev'),str(r.get('protocol')),r.get('metric'))==('10.70.0.1','10.70.0.2','ens4','242',50000)
 owned=[];retained=[]
 for row in routes:
  # Exact known controller routes only; every other route remains protected.
  classic=row.get('dst')=='10.81.0.0/24' and row.get('dev')=='txe936e4aecebb' and str(row.get('protocol'))=='242' and row.get('metric')==50001 and row.get('scope')=='link' and set(row)<= {'dst','dev','protocol','metric','scope','flags'} and row.get('flags',[])==[]
  if classic:owned.append(row)
  else:retained.append(row)
 return {'boot':BOOT,'namespace':NS,'retained_main_routes_sha256':h(json.dumps(retained,sort_keys=True).encode()),'owned_main_routes':owned,'identity':identity(),'environment':public_env(),'journal':journal()}
def oldshape(i,running):
 assert i['Id']==OLD and i['Image']==OLDIMAGE and i['State']['Running']==running and not i['State']['OOMKilled']
 assert i['HostConfig']['NetworkMode']=='host' and i['HostConfig']['RestartPolicy']['Name']=='no' and i['Config']['StopTimeout']==45
 assert i['Config']['Labels'].get('tunnex.owned')=='gcp-s2s-cloud-20261010'
 assert not i['HostConfig']['Privileged'] and 'SYS_ADMIN' not in (i['HostConfig'].get('CapAdd') or [])
 assert any(m['Source']==STATE and m['Destination']=='/var/lib/tunnex-node' and m['RW'] for m in i['Mounts'])
 assert run('docker','image','inspect','--format','{{.Id}}',IMAGE)==IMAGE
 assert not run('docker','ps','-aq','--filter','name=^'+NAME+'$')
def native(running):
 # Raw nft is strictly key-free, privately retained. Never reads raw XFRM states.
 if running:raw=run('docker','exec',OLD,'nft','-j','list','ruleset')
 else:raw=run('docker','run','--name','tunnex-gcp-replacement-read-'+str(time.time_ns()),'--network','host','--read-only','--cap-drop','ALL','--cap-add','NET_ADMIN','--label','tunnex.owned=gcp-s2s-cloud-20261010','--entrypoint','nft',IMAGE,'-j','list','ruleset')
 json.loads(raw);sad=run('ip','xfrm','state','count');assert re.fullmatch(r'SAD count [0-9]+',sad)
 processes=[]
 for pid in os.listdir('/proc'):
  if not pid.isdigit():continue
  try:comm=open('/proc/'+pid+'/comm').read().strip()
  except (FileNotFoundError,ProcessLookupError,PermissionError):continue
  if comm in ('charon','charon-systemd','bgpd','zebra'):processes.append({'pid':int(pid),'comm':comm})
 return raw,{'sad_count':int(sad.split()[-1]),'managed_processes':processes,'nft_sha256':h(raw.encode())}
phase=sys.argv[1]
if sys.flags.optimize:raise RuntimeError('optimized Python refused')
assert os.geteuid()==0
if phase=='continue-create-start':
 stopped=load('stopped.json',sys.argv[2]);reviewed_policy=sys.argv[3]
 assert re.fullmatch('[0-9a-f]{64}',reviewed_policy)
 before=load('before.json',stopped['before_sha256']);assert reviewed_policy==before['accepted_policy_evidence_sha256']
 assert sys.argv[2]=='102919b5f2ee2f9af4fee6a1ea02aa2c252bfacef3f683c50d3fcdabea97a307' and stopped['before_sha256']=='607948f94dcf7db53e341904ffc7f8aa8962ddad11470d1a6c05ed1f213fad15'
 assert stopped['exit_code']==0 and not stopped['running'] and not stopped['oom_killed'] and not stopped['readback_errors'] and stopped['immutable_journal_matches']
 # Original false is preserved. The only permitted continuation is the exact
 # independently observed normal WG cleanup, never a rebaseline of foreign state.
 assert stopped['retained_binding_matches'] is False
 assert all(stopped['binding'][k]==before['binding'][k] for k in ('boot','namespace','identity','environment'))
 routes=json.loads(run('ip','-j','route','show','table','main'))
 owned=stopped['binding']['owned_main_routes'];assert [r for r in routes if r in owned]==owned
 retained=[r for r in routes if r not in owned]
 assert h(json.dumps(retained,sort_keys=True).encode())=='d42d0673ad344a3a4465d1fa558723e09c32932b0aa1476d0187523bda1b4181'==stopped['binding']['retained_main_routes_sha256']
 wg={'dst':'10.99.0.0/24','dev':'wg0','protocol':'kernel','scope':'link','prefsrc':'10.99.0.1','flags':[]}
 assert not any(r.get('dev')=='wg0' for r in routes) and not any(l['ifname']=='wg0' for l in json.loads(run('ip','-j','link','show')))
 reconstructed=retained[:3]+[wg]+retained[3:]
 assert h(json.dumps(reconstructed,sort_keys=True).encode())=='9fd6abfe521a1a3a1e7dd8a6c266f7fadabb89cf31a94d1187b29afdbbf033d9'==before['binding']['retained_main_routes_sha256']
 # Source-only causal evidence SHA identifies the preserved independent capture;
 # it is observational provenance, never a new runtime/reset/cleanup receipt.
 continuation={'before_sha256':stopped['before_sha256'],'stop_sha256':sys.argv[2],'causal_capture_sha256':'c6590433c90e8b98e3a9f88fb4ddc6e347fbbd0c7b352ab0b9cc6e01087d1f10','original_retained_binding_matches':False,'exact_owned_wg_route_removal_proven':True,'foreign_lan_default_routes_preserved':True,'scope':'deployment observation only; no node authority'}
 i=inspect(OLD);oldshape(i,False);assert i['State']['ExitCode']==0
 current=binding();prior=stopped['binding'];assert all(current[k]==prior[k] for k in ('identity','environment','boot','namespace','retained_main_routes_sha256'))
 assert all(current['journal'][k]==prior['journal'][k] for k in ('owner','version','immutable_digest')) and current['journal']['sequence']>=prior['journal']['sequence'],'stopped immutable binding drift'
 # Root stages this exact reviewed observational ELF; it is not a node proof.
 verifier=ROOT+'/gcp-poststop-guard';vf=os.open(verifier,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  vs=os.fstat(vf);assert stat.S_ISREG(vs.st_mode) and vs.st_uid==0 and stat.S_IMODE(vs.st_mode)==0o700 and vs.st_nlink==1 and 0<vs.st_size<32*1024*1024
  vb=b''
  while len(vb)<vs.st_size:vb+=os.read(vf,min(65536,vs.st_size-len(vb)))
  vt=os.fstat(vf);assert (vs.st_dev,vs.st_ino,vs.st_size,vs.st_mtime_ns)==(vt.st_dev,vt.st_ino,vt.st_size,vt.st_mtime_ns) and h(vb)=='62215f47601e225d9ed8a6ae98a5bc90e34c2dafa1e1808cf5fef02eee7b8047'
 finally:os.close(vf)
 # One fresh complete reader snapshot, stable journal+namespace+links around it.
 jb,jmeta=read(STATE+'/ipsec/journal.json',16*1024*1024);jp=json.loads(jb)['Payload']
 expected=[g for g in jp['Guards'] if g['Namespace']==NS];assert len(expected)==1
 expected=expected[0];links=json.loads(run('ip','-j','link','show'));ns_before=run('readlink','/proc/self/ns/net')
 raw,n=native(False);assert n['sad_count']==0 and not n['managed_processes'],'unresolved old duty'
 nft=json.loads(raw);guard=[]
 for obj in nft['nftables']:
  assert isinstance(obj,dict) and len(obj)==1
  kind,value=next(iter(obj.items()))
  if kind=='metainfo':guard.append(obj);continue
  if isinstance(value,dict) and value.get('family')=='inet' and (value.get('table')=='tunnex_ipsec' or (kind=='table' and value.get('name')=='tunnex_ipsec')):guard.append(obj)
 links_after=json.loads(run('ip','-j','link','show'));ja,_=read(STATE+'/ipsec/journal.json',16*1024*1024);ns_after=run('readlink','/proc/self/ns/net')
 assert jb==ja and links==links_after and ns_before==ns_after==NS
 # Protect all other host objects. Strip ONLY typed native traffic counter values;
 # unknown object/rule structure remains exact. No expiry/member normalization here.
 def retained_objects(raw):
  result=[]
  for obj in json.loads(raw)['nftables']:
   assert isinstance(obj,dict) and len(obj)==1
   kind,value=next(iter(obj.items()))
   if kind=='metainfo':continue
   if isinstance(value,dict) and value.get('family')=='inet' and (value.get('table')=='tunnex_ipsec' or (kind=='table' and value.get('name')=='tunnex_ipsec')):continue
   if kind=='rule':
    assert isinstance(value.get('expr'),list)
    for expression in value['expr']:
     if isinstance(expression,dict) and 'counter' in expression:
      assert len(expression)==1 and isinstance(expression['counter'],dict) and set(expression['counter'])=={'packets','bytes'} and all(type(v)is int and v>=0 for v in expression['counter'].values())
      expression['counter']={'packets':0,'bytes':0}
   result.append(obj)
  return result
 br,_=read(ROOT+'/before-nft.json',4*1024*1024);assert h(br)==before['native']['nft_sha256']
 prior_objects=retained_objects(br);actual_objects=retained_objects(raw)
 # Match the complete previously captured 20 base objects, not names alone.
 assert len(prior_objects)==20 and h(json.dumps(prior_objects,sort_keys=True).encode())=='b9f2cef2eec1a98de43e2d70fdbb4fa7db4f355c12b9188b44b6925f8b588460'
 for obj in prior_objects:
  kind,value=next(iter(obj.items()));assert value.get('family')in ('ip','ip6') and (value.get('table')=='tunnex' or (kind=='table'and value.get('name')=='tunnex'))
 assert actual_objects==[],'unexpected host object after exact source-proven WG teardown'
 continuation['exact_owned_wg_table_teardown_proven']=True
 receipt('continuation-observation.json',continuation)
 cap={'qualifier_source':SOURCE,'reader_image':IMAGE,'reader_sha256':'7156559ea0d2d062a40af33952eb412833a191cb7179e9ad9efe8b146a563d7f','namespace_before':ns_before,'namespace_after':ns_after,'guard_identity_stable':True,'expected_guard':{k:expected[k] for k in ('ExpectedJSON','Digest','Revision','Namespace')},'actual_guard':{'nftables':guard},'links':[{'Name':l['ifname'],'Index':l['ifindex']} for l in links],'journal_sha256':h(jb)}
 # Image reader bytes must independently match, not just a claimed input field.
 actual_reader=run('docker','run','--name','tunnex-gcp-reader-id-'+str(time.time_ns()),'--network','none','--read-only','--cap-drop','ALL','--label','tunnex.owned=gcp-s2s-cloud-20261010','--entrypoint','sha256sum',IMAGE,'/usr/sbin/nft').split()[0];assert actual_reader==cap['reader_sha256']
 payload=(json.dumps(cap,sort_keys=True)+'\n').encode();write('fresh-guard-capture.json',payload)
 # Reopen exact bound executable immediately before execution and keep descriptor.
 ef=os.open(verifier,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  es=os.fstat(ef);assert (es.st_dev,es.st_ino,es.st_size,es.st_mtime_ns)==(vs.st_dev,vs.st_ino,vs.st_size,vs.st_mtime_ns)
  verified=subprocess.run(['/proc/self/fd/'+str(ef)],input=payload,capture_output=True,pass_fds=(ef,),check=True,timeout=10)
 finally:os.close(ef)
 proof=json.loads(verified.stdout);assert proof['capture_sha256']==h(payload) and proof['owned_table_prefix_refusal_verified'] is True and proof['permit_sets_actually_empty'] is True
 receipt('fresh-owned-prefix-verification.json',proof)
 assert run('readlink','/proc/self/ns/net')==NS and run('curl','--fail','--silent','http://127.0.0.1:38083/healthz')
 assert binding()==current,'binding drift during verification'
 cid=run(*CREATE);assert re.fullmatch('[0-9a-f]{64}',cid)
 d=receipt('created.json',{'container_id':cid,'image':IMAGE,'stopped_sha256':sys.argv[2],'fresh_guard_capture_sha256':h(payload),'current_policy_evidence_sha256':reviewed_policy,'scope':'normal startup requested; no readiness claim'})
 run('docker','start',cid)
 print(json.dumps({'phase':phase,'container_id':cid,'created_receipt_sha256':d,'status':'normal same-identity startup; independently verify readiness'}))
else:raise ValueError('unsupported phase')
