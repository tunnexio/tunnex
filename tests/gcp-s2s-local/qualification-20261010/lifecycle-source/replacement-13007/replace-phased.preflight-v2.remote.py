"""Owned deployment orchestration only. Never creates runtime authority/proofs."""
import os,sys,stat,json,hashlib,subprocess,re,time
OLD='75ecbfbcfc4d4bf1d2fd62a4d5fc7bada5cea4ff94d1efb9322b23886995e8e9'
OLDIMAGE='sha256:c91e82d7d6a411234aa1340af606071cede90bef8f9bc61171a4807b8788e272'
IMAGE='sha256:9a051bbdc9eed316bfabf2914e26a1c5f454927665902b0c7e0d2ded8a5374d7'
SOURCE='13007c405cece2ab3a1a790b1b539980479336a3'
WG_OBJECTS_SHA='PENDING_FRESH_SOURCE_REVIEWED_WG_OBJECTS_SHA'
ROOT='/var/lib/tunnex-gcp-replacement-13007c40-20261010-1'
STATE='/var/lib/tunnex-gcp-s2s-cloud-20261010'
ENV='/var/lib/tunnex-gcp-s2s-launch-20261010/node-wgctrl.env'
NAME='tunnex-gcp-cloud-gateway-13007c40-20261010'
BOOT='9617762e-19db-4a21-bdee-909dfb31e501';NS='net:[4026531840]'
PUBLIC_ENV={'TUNNEX_AGENT_HEALTH_ADDR': '127.0.0.1:9091', 'TUNNEX_AGENT_SERVERNAME': 'tunnex-control', 'TUNNEX_AGENT_URL': 'https://127.0.0.1:38446', 'TUNNEX_API_URL': 'http://127.0.0.1:38083', 'TUNNEX_NODE_ENDPOINT': '34.131.136.132:51820', 'TUNNEX_NODE_NAME': 'tn-gcps2s-20261010-gateway', 'TUNNEX_NODE_STATE_DIR': '/var/lib/tunnex-node', 'TUNNEX_WG_INTERFACE': 'wg0', 'TUNNEX_WG_BACKEND': 'wgctrl'}
CREATE=['docker', 'create', '--name', 'tunnex-gcp-cloud-gateway-13007c40-20261010', '--label', 'tunnex.owned=gcp-s2s-cloud-20261010', '--label', 'org.opencontainers.image.revision=13007c405cece2ab3a1a790b1b539980479336a3', '--network', 'host', '--restart', 'no', '--stop-timeout', '45', '--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW', '--device', '/dev/net/tun:/dev/net/tun', '--mount', 'type=bind,source=/var/lib/tunnex-gcp-s2s-cloud-20261010,target=/var/lib/tunnex-node', '--tmpfs', '/run:rw,nosuid,nodev,mode=755', '--env-file', '/var/lib/tunnex-gcp-s2s-launch-20261010/node-wgctrl.env', 'sha256:9a051bbdc9eed316bfabf2914e26a1c5f454927665902b0c7e0d2ded8a5374d7']
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
def require_exact_topology(before,after):
 if before!=after:raise ValueError('complete topology drift; no teardown allowance')
def observational_topology():
 routes_main=json.loads(run('ip','-j','-4','route','show','table','main'))
 routes_all=json.loads(run('ip','-j','-4','route','show','table','all'))
 routes6_all=json.loads(run('ip','-j','-6','route','show','table','all'))
 links=json.loads(run('ip','-j','link','show'))
 assert all(isinstance(v,list) and all(isinstance(x,dict)for x in v)for v in (routes_main,routes_all,routes6_all,links))
 wg=[l for l in links if l.get('ifname')=='wg0'];assert len(wg)<=1
 wgmode=json.loads(run('ip','-j','-d','link','show','wg0')) if wg else []
 wgaddr=json.loads(run('ip','-j','addr','show','wg0')) if wg else []
 if wg:
  assert len(wgmode)==len(wgaddr)==1 and wgmode[0]['linkinfo']['info_kind']=='wireguard' and wgmode[0]['ifindex']==wg[0]['ifindex']==wgaddr[0]['ifindex']
  assert wgaddr[0]['addr_info'] and all(a.get('family')=='inet' and a.get('local')=='10.99.0.1' and a.get('prefixlen')==24 for a in wgaddr[0]['addr_info'])
 return {'fresh_wg_addresses':wgaddr,'fresh_wg_mode':wgmode,'main_routes':routes_main,'all_ipv4_routes':routes_all,'all_ipv6_routes':routes6_all,'links':links,'observed_wg0_links':wg,'scope':'key-free observation only; no authority/adoption/teardown allowance'}
def reviewed_shutdown_topology(before,after):
 # Close leaves controller-owned XFRM routes intact; only wgctrl's exact
 # source-created interface and its kernel address routes may disappear.
 wg=before['observed_wg0_links'];assert len(wg)==1 and wg[0]['ifname']=='wg0'
 index=wg[0]['ifindex'];assert type(index)is int and index>0
 mode=before['fresh_wg_mode'];assert len(mode)==1 and mode[0]['ifindex']==index and mode[0]['ifname']=='wg0' and mode[0]['linkinfo']['info_kind']=='wireguard'
 assert all(mode[0].get(k)==v for k,v in wg[0].items())
 assert after['observed_wg0_links']==[]
 removed={}
 for field in ('main_routes','all_ipv4_routes','all_ipv6_routes','links'):
  old=[json.dumps(x,sort_keys=True)for x in before[field]];new=[json.dumps(x,sort_keys=True)for x in after[field]]
  assert len(set(old))==len(old) and len(set(new))==len(new) and set(new)<=set(old),'foreign/new/duplicate topology'
  gone=[json.loads(x)for x in old if x not in new]
  if field=='links':assert gone==wg and not any(l.get('ifindex')==index or l.get('ifname')=='wg0'for l in after[field])
  else:
   for r in gone:
    assert r.get('dev')=='wg0' and str(r.get('protocol'))in ('kernel','2')
    if field=='all_ipv6_routes':
     assert r.get('dst')=='ff00::/8' and str(r.get('table'))in ('local','255') and str(r.get('type'))in ('multicast','5') and r.get('metric')==256 and r.get('scope')in ('global','0') and r.get('pref')=='medium' and r.get('flags',[])==[]
     assert set(r)<= {'dst','dev','table','protocol','type','scope','metric','pref','flags'}
     continue
    assert set(r)<= {'dst','dev','table','protocol','type','scope','prefsrc','flags'} and r.get('flags',[])==[]
    assert r.get('dst')in ('10.99.0.0/24','10.99.0.1','10.99.0.255') and r.get('prefsrc')=='10.99.0.1'
    assert str(r.get('table','254'))in ('main','local','254','255')
    if r['dst']=='10.99.0.0/24':assert str(r.get('table','254'))in ('main','254') and r.get('type','unicast')in ('unicast','1') and r.get('scope')in ('link','253')
    else:
     assert str(r.get('table','254'))in ('local','255')
     assert (r.get('type'),r.get('scope'))in ((('local'if r['dst']=='10.99.0.1'else'broadcast'),('host'if r['dst']=='10.99.0.1'else'link')),(('2'if r['dst']=='10.99.0.1'else'3'),('254'if r['dst']=='10.99.0.1'else'253')))
  removed[field]=gone
 return removed
def oldshape(i,running):
 assert i['Config']['Labels'].get('org.opencontainers.image.revision')=='f1dd3a2605fb03e542f02a93599ab906662ffc2b'
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
if phase=='preflight':
 policy_sha=sys.argv[2];assert re.fullmatch('[0-9a-f]{64}',policy_sha)
 assert not os.path.lexists(ROOT);os.mkdir(ROOT,0o700)
 i=inspect(OLD);oldshape(i,True);b=binding();topology=observational_topology();raw,n=native(True)
 assert run('cat','/proc/sys/kernel/random/boot_id')==BOOT and run('readlink','/proc/self/ns/net')==NS
 after=binding();assert all(after[k]==b[k]for k in ('identity','environment','boot','namespace','retained_main_routes_sha256')) and all(after['journal'][k]==b['journal'][k]for k in ('owner','version','immutable_digest'))
 write('before-nft.json',raw.encode());d=receipt('before.json',{'binding':b,'topology':topology,'native':n,'accepted_policy_evidence_sha256':policy_sha,'source':SOURCE,'old':OLD,'new_image':IMAGE,'scope':'observational deployment baseline; no authority'})
 print(json.dumps({'phase':phase,'receipt_sha256':d,'native':n}))
elif phase=='stop':
 before=load('before.json',sys.argv[2]);require_exact_topology(before['topology'],observational_topology());i=inspect(OLD);oldshape(i,True);b=binding()
 prior=before['binding'];assert all(b[k]==prior[k] for k in ('boot','namespace','retained_main_routes_sha256','identity','environment'))
 assert all(b['journal'][k]==prior['journal'][k] for k in ('version','owner','immutable_digest')) and b['journal']['sequence']>=prior['journal']['sequence'],'preflight binding drift; do not stop'
 outcome={'before_sha256':sys.argv[2],'stop_attempted':True,'scope':'actual deployment stop/readback; NOT absence/guard/restoration proof'}
 errors=[]
 try:run('docker','stop','--time','45',OLD,timeout=50);outcome['stop_command_exit']=0
 except Exception as e:errors.append({'stage':'docker_stop','error_type':type(e).__name__,'returncode':getattr(e,'returncode',None)})
 for label,action in [('inspect',lambda:inspect(OLD)),('native',lambda:native(False)),('binding',binding),('topology',observational_topology)]:
  try:
   result=action()
   if label=='inspect':outcome['exit_code']=result['State']['ExitCode'];outcome['running']=result['State']['Running'];outcome['oom_killed']=result['State']['OOMKilled'];outcome['finished_at']=result['State']['FinishedAt']
   elif label=='native':raw,n=result;write('stopped-nft.json',raw.encode());outcome['native']=n
   elif label=='binding':outcome['binding']=result
   else:outcome['topology']=result
  except Exception as e:errors.append({'stage':label,'error_type':type(e).__name__,'returncode':getattr(e,'returncode',None)})
 outcome['readback_errors']=errors
 if 'binding'in outcome:
  after=outcome['binding'];outcome['retained_binding_matches']=all(after[k]==b[k] for k in ('identity','environment','boot','namespace'))
  try:outcome['shutdown_topology_delta']=reviewed_shutdown_topology(before['topology'],outcome['topology'])
  except Exception as e:outcome['readback_errors'].append({'stage':'shutdown_topology','error_type':type(e).__name__})
  outcome['immutable_journal_matches']=all(after['journal'][k]==b['journal'][k] for k in ('owner','version','immutable_digest')) and after['journal']['sequence']>=b['journal']['sequence']
 d=receipt('stopped.json',outcome)
 print(json.dumps({'phase':phase,'receipt_sha256':d,'exit_code':outcome.get('exit_code'),'readback_errors':errors,'native':outcome.get('native'),'create_start':'REQUIRES SEPARATE ROOT REVIEW; no automatic continuation'}))
elif phase=='create-start':
 stopped=load('stopped.json',sys.argv[2]);reviewed_policy=sys.argv[3]
 assert re.fullmatch('[0-9a-f]{64}',reviewed_policy)
 before=load('before.json',stopped['before_sha256']);assert reviewed_policy==before['accepted_policy_evidence_sha256']
 reviewed_shutdown_topology(before['topology'],stopped['topology'])
 require_exact_topology(stopped['topology'],observational_topology())
 assert stopped['retained_binding_matches'] and stopped['exit_code']==0 and not stopped['running'] and not stopped['oom_killed'] and not stopped['readback_errors'] and stopped['immutable_journal_matches']
 i=inspect(OLD);oldshape(i,False);assert i['State']['ExitCode']==0
 current=binding();prior=stopped['binding'];assert all(current[k]==prior[k] for k in ('identity','environment','boot','namespace','retained_main_routes_sha256'))
 assert all(current['journal'][k]==prior['journal'][k] for k in ('owner','version','immutable_digest')) and current['journal']['sequence']>=prior['journal']['sequence'],'stopped immutable binding drift'
 # Root stages this exact reviewed observational ELF; it is not a node proof.
 verifier=ROOT+'/gcp-poststop-guard';vf=os.open(verifier,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  vs=os.fstat(vf);assert stat.S_ISREG(vs.st_mode) and vs.st_uid==0 and stat.S_IMODE(vs.st_mode)==0o700 and vs.st_nlink==1 and 0<vs.st_size<32*1024*1024
  vb=b''
  while len(vb)<vs.st_size:vb+=os.read(vf,min(65536,vs.st_size-len(vb)))
  vt=os.fstat(vf);assert (vs.st_dev,vs.st_ino,vs.st_size,vs.st_mtime_ns)==(vt.st_dev,vt.st_ino,vt.st_size,vt.st_mtime_ns) and h(vb)=='PENDING_REVIEWED_QUALIFIER_HASH'
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
 br,_=read(ROOT+'/before-nft.json',4*1024*1024)
 oldobjects=retained_objects(br);newobjects=retained_objects(raw)
 def wg_owned(o):
  kind,value=next(iter(o.items()))
  return isinstance(value,dict) and value.get('family')in ('ip','ip6') and (value.get('table')=='tunnex' or (kind=='table'and value.get('name')=='tunnex'))
 wgobjects=[o for o in oldobjects if wg_owned(o)]
 assert h(json.dumps(wgobjects,sort_keys=True).encode())==WG_OBJECTS_SHA,'unreviewed source-owned WG table shape'
 assert {next(iter(o.values()))['family']for o in wgobjects if next(iter(o))=='table'}=={'ip','ip6'}
 assert not any(wg_owned(o)for o in newobjects)
 assert [o for o in oldobjects if not wg_owned(o)]==newobjects,'foreign/base host objects changed'
 # Full exact owned WG table snapshot is recorded, never partial object admission.
 receipt('observed-wg-table-close.json',{'before_objects_sha256':h(json.dumps(wgobjects,sort_keys=True).encode()),'objects_removed':len(wgobjects),'scope':'source-owned egress Close observation only; not runtime authority'})
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
 require_exact_topology(stopped['topology'],observational_topology())
 cid=run(*CREATE);assert re.fullmatch('[0-9a-f]{64}',cid)
 d=receipt('created.json',{'container_id':cid,'image':IMAGE,'stopped_sha256':sys.argv[2],'fresh_guard_capture_sha256':h(payload),'current_policy_evidence_sha256':reviewed_policy,'scope':'normal startup requested; no readiness claim'})
 ni=inspect(cid);assert ni['Id']==cid and ni['Image']==IMAGE and not ni['State']['Running']
 assert ni['Config']['Labels'].get('org.opencontainers.image.revision')==SOURCE and ni['Config']['Labels'].get('tunnex.owned')=='gcp-s2s-cloud-20261010'
 nh=ni['HostConfig'];assert nh['NetworkMode']=='host' and nh['RestartPolicy']['Name']=='no' and not nh['Privileged'] and ni['Config']['StopTimeout']==45
 assert set(nh.get('CapAdd')or[])=={'NET_ADMIN','NET_RAW'} and not nh.get('CapDrop')
 assert any(m['Source']==STATE and m['Destination']=='/var/lib/tunnex-node'and m['RW']for m in ni['Mounts'])
 ne={};
 for row in ni['Config']['Env']:
  key,sep,value=row.partition('=');assert sep and key not in ne;ne[key]=value
 assert all(ne.get(k)==v for k,v in PUBLIC_ENV.items())
 public_env()
 run('docker','start',cid)
 print(json.dumps({'phase':phase,'container_id':cid,'created_receipt_sha256':d,'status':'normal same-identity startup; independently verify readiness'}))
else:raise ValueError('unsupported phase')
