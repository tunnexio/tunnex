#!/usr/bin/env python3
"""Owned Linux cloud restart. Default READONLY; stages require explicit --execute.
No journal mutation; genuine host observer and source-pinned receipt/release only.
Run on owned gateway host, not bastion. Private artifacts never printed.
"""
import argparse,copy,hashlib,http.client,io,json,os,pathlib,socket,stat,subprocess,tarfile,time,urllib.parse
OLD='382b1763ae4bd0fa21a871839af4be0d9c0c8e37dc7d57c85a68172cfff6be06'
NS='net:[4026532807]'
IMAGE='sha256:868b425d65ef30b6f0c221c834e8925079d658281e89380ead59a929021c50a2'
NODE='b659a3a54528575f44afb28aa1e2c09508fdc6ef313d1ebe43b7f937cc5f1145'
DELIVERY='44e340c8-1111-4c1b-8a79-368e1b628ba9'
OBSERVER='eb0cf334663c713f7075cd8e41e46c1f44c2345faa15841710d937b3789d01f3'
CLI='1b393d1f78f609ed8ef26fb403582908ec2fe1a6aef1e82dc155230ff8866f61'
GATE=b'owned enrolled restoration supervisor blocks Apply until genuine new namespace receipt durable\n'
NAME='tunnex-bgp-20261007-gateway-trusted-restart-1'
STAGING='tunnex-bgp-20261007-restoration-staging-1'
WRAPPER='while [ ! -f /run/enrolled-restoration-release ]; do sleep 1; done; '
D=['docker','--host','unix:///var/run/docker.sock']
def call(*args):return subprocess.check_output(D+list(args))
def inspect(cid):return json.loads(call('inspect',cid))[0]
def sha(b):return hashlib.sha256(b).hexdigest()
def private(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);s=os.fstat(fd)
 assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=8<<20
 with os.fdopen(fd,'rb')as f:return f.read()
def syncdir(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
def publish(path,b):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(b);f.flush();os.fsync(f.fileno())
 syncdir(path.parent)
def save(name,obj):publish(run/name,json.dumps(obj,sort_keys=True,indent=2).encode()+b'\n')
def load(name):return json.loads(private(run/name))
def execout(cid,*args):return call('exec',cid,*args)
def namespace(cid):return execout(cid,'readlink','/proc/1/ns/net').decode().strip()
def unchanged_layout(g,b,networks=True):
 assert g['Id']==OLD and g['Image']==IMAGE and g['Config']==b['Config']and g['HostConfig']==b['HostConfig']
 assert sorted(g['Mounts'],key=lambda x:x['Destination'])==sorted(b['Mounts'],key=lambda x:x['Destination'])
 if networks:assert g['NetworkSettings']['Networks']==b['NetworkSettings']['Networks']
def cloud_command(g):
 assert g['Config']['Entrypoint']==['/bin/sh']and len(g['Config']['Cmd'])==2 and g['Config']['Cmd'][0]=='-ec'
 command=g['Config']['Cmd'][1];assert isinstance(command,str)and command and WRAPPER not in command
 return command
def publication_contract(g):
 bindings=g['HostConfig']['PortBindings'];assert set(bindings)=={'500/udp','4500/udp','9091/tcp'}
 for key,port in [('500/udp','500'),('4500/udp','4500'),('9091/tcp','19393')]:
  assert bindings[key]and all(x['HostPort']==port and set(x)=={'HostIp','HostPort'}for x in bindings[key])
 return copy.deepcopy(bindings)
def original_network(g):
 endpoints=g['NetworkSettings']['Networks'];assert len(endpoints)==1
 endpoint=next(iter(endpoints.values()));net=json.loads(call('network','inspect',endpoint['NetworkID']))[0]
 assert net['Driver']=='bridge'and not net['Internal']and net.get('Options',{}).get('com.docker.network.bridge.gateway_mode_ipv4','nat')=='nat'
 assert endpoint['IPAddress']=='172.30.88.2'
 return net
def current_old():
 g=inspect(OLD);assert g['State']['Running']and g['Image']==IMAGE and g['Config']['Labels'].get('tunnex.lab')=='tunnex-bgp-20261007'
 assert namespace(OLD)==NS and execout(OLD,'sha256sum','/proc/1/exe').decode().split()[0]==NODE
 cloud_command(g);publication_contract(g);original_network(g)
 return g
def state_path(g):
 m=[m for m in g['Mounts']if m['Destination']=='/state'];assert len(m)==1 and m[0]['RW']
 p=pathlib.Path(m[0]['Source']);assert p.resolve()==p and p.is_dir();return p
def state_hashes(p):
 result={}
 for f in sorted(p.rglob('*')):
  relative=f.relative_to(p)
  if relative.parts[0]=='ipsec':continue
  assert not f.is_symlink()
  if f.is_file():result[str(relative)]=sha(f.read_bytes())
 return result
def active(raw):
 j=json.loads(raw);entries=j['Payload']['Entries'];a=[e for e in entries if e['Phase']!='retained_refusal']
 assert len(a)==1 and a[0]['DeliveryID']==DELIVERY and a[0]['Phase']=='applied'and a[0]['ContractVersion']==3
 assert a[0]['BGPProcess']['Stage']=='ready' and a[0]['BGPRoutes']['Stage']=='completed'
 return a[0]
def lan_routes(cid):
 routes=json.loads(execout(cid,'ip','-j','-4','route','show','table','all'))
 result=[r for r in routes if r.get('dst')in ('10.84.2.0/24','10.84.3.0/24')]
 assert {r['dst']for r in result}=={'10.84.2.0/24','10.84.3.0/24'},'Both actual customer LAN routes required'
 for r in result:
  assert set(r)<=set(['dst','gateway','dev','protocol','metric','prefsrc','flags','table'])
  assert r['gateway']=='172.30.88.1'and r['dev']=='eth0'and r.get('flags',[])==[] and r.get('table','main')in ('main',254)
  assert r.get('protocol','boot')in ('boot','static')and r.get('prefsrc','172.30.88.2')=='172.30.88.2'
  if r['dst']=='10.84.3.0/24':assert r.get('metric')==51084 and r.get('protocol')=='static'
 assert len({r['dst']for r in result})==len(result)
 return result,routes
def host_preservation():
 allrows=json.loads(subprocess.check_output(['ip','-j','-4','route','show','table','all']))
 owned=[r for r in allrows if r.get('dst')=='10.86.0.0/16']
 assert len(owned)==1 and owned[0].get('gateway')=='172.30.88.2'and owned[0].get('protocol')in (242,'242')and owned[0].get('metric')==51086
 firewall=subprocess.check_output(['iptables','-S','DOCKER-USER']).decode()
 assert '10.84.3.10/32'in firewall and '10.86.1.10/32'in firewall and '--dport 8080'in firewall
 return {'tgw_host_route':owned,'docker_user_rules':firewall}
def tool(path,digest):
 st=path.lstat();assert stat.S_ISREG(st.st_mode)and st.st_uid==0 and st.st_mode&0o022==0 and sha(path.read_bytes())==digest
 return path.read_bytes()
def other_runtime():
 result={}
 for name in ['tunnex-bgp-20261007-api','tunnex-bgp-20261007-postgres','tunnex-bgp-20261007-redis']:
  g=inspect(name);assert g['State']['Running']and g['Config']['Labels'].get('tunnex.lab')=='tunnex-bgp-20261007'
  result[name]={'id':g['Id'],'image':g['Image'],'Config':g['Config'],'HostConfig':g['HostConfig'],'Mounts':g['Mounts']}
 assert result['tunnex-bgp-20261007-api']['id']=='e9d54f9986706e8cf7c915426276b0f9ca760a975792225df57bf16afceeb25b'
 return result
def cp_binding():
 sql="SELECT json_build_object('connection',c.id,'intent',c.desired_intent,'revision',c.desired_revision,'node',n.id,'certificate_serial',n.cert_serial,'delivery',d.id,'profile',d.manifest->>'profile_id') FROM ipsec_connections c JOIN nodes n ON n.id=c.gateway_node_id AND n.org_id=c.org_id JOIN ipsec_runtime_deliveries d ON d.connection_id=c.id AND d.id='44e340c8-1111-4c1b-8a79-368e1b628ba9' WHERE c.id='9d9f98e2-cd96-456d-b020-a5a79f688040';"
 r=json.loads(call('exec','tunnex-bgp-20261007-postgres','psql','-U','bgpcloud','-d','bgpcloud','-At','-v','ON_ERROR_STOP=1','-c',sql))
 assert r['intent']=='enabled'and r['revision']==2 and r['delivery']==DELIVERY and r['profile']=='aws-bgp-ipv4-v1'and r['certificate_serial']
 return r
class Engine(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(30);self.sock.connect('/var/run/docker.sock')
def api(method,path,obj):
 c=Engine('localhost');c.request(method,'/v1.47'+path,json.dumps(obj),{'Content-Type':'application/json'});r=c.getresponse();b=r.read();c.close();assert r.status in (200,201,204),'Engine operation refused; inspect pending, never blindly repeat'
 return json.loads(b)if b else None
def frozen(b):
 g=inspect(OLD);unchanged_layout(g,b);assert g['State']['Running']and g['State']['Pid']==b['State']['Pid']and g['State']['StartedAt']==b['State']['StartedAt']
 status=pathlib.Path('/proc/'+str(g['State']['Pid'])+'/status').read_text();assert any(x.startswith('State:')and 'T ('in x for x in status.splitlines())
 p=state_path(g);assert sha(private(p/'ipsec/journal.json'))==load('baseline.json')['journal_sha256'];return g,p
def fresh_worker(b,pre):
 n=inspect(pre['new']);assert n['State']['Running']and n['Image']==IMAGE and n['Config']==pre['actual_config']and n['HostConfig']==pre['host_config']and n['Mounts']==pre['mounts']
 assert namespace(pre['new'])==pre['namespace']!=NS
 assert execout(pre['new'],'sha256sum','/state/ipsec/journal.json').decode().split()[0]==load('baseline.json')['journal_sha256']
 assert all(x not in execout(pre['new'],'ps','-eo','comm').decode().splitlines()for x in ['tunnex-node','charon','bgpd','zebra'])
 assert execout(pre['new'],'ip','xfrm','state').strip()==b''
 assert subprocess.run(D+['exec',pre['new'],'test','-e','/run/enrolled-restoration-release'],stdout=subprocess.DEVNULL).returncode==1
 assert state_hashes(state_path(n))==load('baseline.json')['state_hashes'];return n
p=argparse.ArgumentParser();p.add_argument('stage',choices=['preflight','capture','preallocate','stop','install','release']);p.add_argument('--run',type=pathlib.Path,required=True);p.add_argument('--observer',type=pathlib.Path);p.add_argument('--cli',type=pathlib.Path);p.add_argument('--release',type=pathlib.Path);p.add_argument('--release-sha');p.add_argument('--execute',action='store_true');a=p.parse_args();os.umask(0o077);assert os.geteuid()==0
run=a.run;assert run.is_absolute()and run.parent==pathlib.Path('/home/ubuntu/tunnex-bgp-lab')and run.name=='cloud-enrolled-restart-21169a9f'
if a.stage=='preflight':
 g=current_old();s=state_path(g);raw=private(s/'ipsec/journal.json');active(raw);routes,_=lan_routes(OLD);other_runtime();cp_binding()
 print(json.dumps({'read_only':True,'old':OLD,'namespace':NS,'delivery':DELIVERY,'journal_sha256_unfrozen':sha(raw),'owned_lan_routes':routes,'requires_frozen_capture':True}));raise SystemExit
if not a.execute:print(json.dumps({'source_only':True,'stage':a.stage,'old':OLD,'delivery':DELIVERY,'run':str(run)}));raise SystemExit
if a.stage=='capture':
 assert not run.exists();run.mkdir(mode=0o700);syncdir(run.parent);g=current_old();paused=False
 try:
  subprocess.run(D+['kill','--signal','STOP',OLD],check=True,stdout=subprocess.DEVNULL);paused=True
  for _ in range(30):
   st=pathlib.Path('/proc/'+str(g['State']['Pid'])+'/status').read_text()
   if any(x.startswith('State:')and 'T ('in x for x in st.splitlines()):break
   time.sleep(.05)
  else:raise RuntimeError('pause refused')
  now=inspect(OLD);unchanged_layout(now,g);assert now['State']['Pid']==g['State']['Pid'];s=state_path(g);raw=private(s/'ipsec/journal.json');active(raw);routes,allroutes=lan_routes(OLD)
  assert not(s/'ipsec/restoration-startup-gate').exists()and not(s/('ipsec/restore-'+DELIVERY+'.json')).exists()
  save('namespace-link-census.json',json.loads(execout(OLD,'ip','-j','link','show')));save('namespace-address-census.json',json.loads(execout(OLD,'ip','-j','address','show')));save('namespace-nft-census.json',json.loads(execout(OLD,'nft','-j','list','ruleset')));save('inspect-private.json',g);save('host-preservation.json',host_preservation());save('host-route-census.json',json.loads(subprocess.check_output(['ip','-j','-4','route','show','table','all'])));save('other-runtime-private.json',other_runtime());save('cp-binding.json',cp_binding());publish(run/'journal-frozen.json',raw)
  save('baseline.json',{'old':OLD,'namespace':NS,'delivery':DELIVERY,'journal_sha256':sha(raw),'state_hashes':state_hashes(s),'lan_routes':routes,'all_routes':allroutes,'node_sha256':NODE,'image':IMAGE,'helper_sha256':sha(pathlib.Path(__file__).read_bytes())})
 except BaseException:
  if paused:subprocess.run(D+['kill','--signal','CONT',OLD],check=True,stdout=subprocess.DEVNULL)
  raise
 print('Frozen capture durable; old exact PID1 remains STOPPED; next action reviewed preallocation or exact CONT abort');raise SystemExit
b=load('inspect-private.json');base=load('baseline.json');assert base['old']==OLD and base['delivery']==DELIVERY
assert sha(pathlib.Path(__file__).read_bytes())==base['helper_sha256'],'Helper changed after capture'
assert host_preservation()==load('host-preservation.json'),'Owned host route/firewall changed'
assert other_runtime()==load('other-runtime-private.json')and cp_binding()==load('cp-binding.json'),'CP/certificate/other runtime differs'
if a.stage=='preallocate':
 g,s=frozen(b);assert not(run/'preallocated.json').exists();save('preallocate-pending.json',{'old':OLD,'journal_sha256':base['journal_sha256']})
 assert subprocess.run(D+['inspect',NAME],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0
 assert subprocess.run(D+['network','inspect',STAGING],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0
 sid=call('network','create','--internal','--opt','com.docker.network.bridge.gateway_mode_ipv4=routed','--label','tunnex.lab=tunnex-bgp-20261007','--label','tunnex.restoration=cloud-enrolled-21169a9f',STAGING).decode().strip()
 c=copy.deepcopy(g['Config']);c['Hostname']='';c['Cmd']=['-ec',WRAPPER+cloud_command(g)];h=copy.deepcopy(g['HostConfig']);h['NetworkMode']=STAGING
 # Routed staging defers bindings while preserving every original UDP/TCP publication.
 assert h['PortBindings']==publication_contract(g)
 payload={**c,'HostConfig':h};save('create-private.json',payload);new=api('POST','/containers/create?'+urllib.parse.urlencode({'name':NAME}),payload)['Id'];save('created.json',{'new':new,'staging_id':sid})
 n=inspect(new);assert not n['State']['Running'];assert n['HostConfig']==h and n['Image']==IMAGE
 for k,v in c.items():
  if k not in ('Hostname','Image'):assert n['Config'].get(k)==v,'Created config mismatch: '+k
 assert sorted(n['Mounts'],key=lambda x:x['Destination'])==sorted(g['Mounts'],key=lambda x:x['Destination'])
 call('start',new);n=inspect(new);ns=namespace(new);assert ns!=NS
 staged=json.loads(call('network','inspect',sid))[0];assert staged['Internal']and staged['Options']['com.docker.network.bridge.gateway_mode_ipv4']=='routed'
 assert n['HostConfig']['PortBindings']==g['HostConfig']['PortBindings']
 assert all(not binding.get('HostPort')for rows in n['NetworkSettings']['Ports'].values()for binding in (rows or [])),'Staging unexpectedly published original ports'
 pre={'new':new,'namespace':ns,'staging_id':sid,'actual_config':n['Config'],'host_config':n['HostConfig'],'mounts':n['Mounts']};fresh_worker(b,pre);save('preallocated.json',pre);print('New distinct sleeping namespace durable; no worker started');raise SystemExit
pre=load('preallocated.json')
if a.stage=='stop':
 g,s=frozen(b);fresh_worker(b,pre);assert a.observer;tool(a.observer,OBSERVER)
 save('stop-pending.json',{'old':OLD,'new':pre['new'],'journal_sha256':base['journal_sha256'],'observer_sha256':OBSERVER})
 publish(s/'ipsec/restoration-startup-gate',GATE)
 subprocess.run(['python3',str(a.observer),'snapshot','--container',OLD,'--journal',str(s/'ipsec/journal.json'),'--state-destination','/state','--output',str(run/'snapshot.json')],check=True)
 frozen(b);call('kill','--signal','KILL',OLD);call('wait',OLD)
 subprocess.run(['python3',str(a.observer),'prove','--snapshot',str(run/'snapshot.json'),'--output',str(run/'stop-proof.json')],check=True)
 assert private(s/'ipsec/journal.json')==private(run/'journal-frozen.json');save('stopped.json',{'old':OLD,'new':pre['new'],'proof_sha256':sha(private(run/'stop-proof.json'))});print('Genuine stop proof durable; gate retained');raise SystemExit
stopped=load('stopped.json');proof=load('stop-proof.json');assert proof['snapshot']['container']==OLD and proof['checks']==['exact-stopped-runtime','empty-cgroup','no-namespace-holders-two-passes']and proof['stopped_journal_raw_sha256']==base['journal_sha256']
o=inspect(OLD);unchanged_layout(o,b,False);assert not o['State']['Running']and o['State']['Pid']==0
n=fresh_worker(b,pre);s=state_path(n);assert private(s/'ipsec/restoration-startup-gate')==GATE
if a.stage=='install':
 assert a.cli;tool(a.cli,CLI);save('install-pending.json',{'old':OLD,'new':pre['new'],'cli_sha256':CLI})
 assert set(n['NetworkSettings']['Networks'])=={STAGING};call('network','disconnect',pre['staging_id'],pre['new']);assert namespace(pre['new'])==pre['namespace']
 # Original physical attachment order is determined from original routes/address readback, not dictionary order.
 assert len(b['NetworkSettings']['Networks'])==1,'More than one cloud endpoint needs explicit reviewed ordinal mapping'
 for name,endpoint in b['NetworkSettings']['Networks'].items():
  actual=inspect(OLD)['NetworkSettings']['Networks'][name];assert actual['NetworkID']==endpoint['NetworkID']and actual.get('IPAMConfig')==endpoint.get('IPAMConfig')and actual.get('Aliases')==endpoint.get('Aliases')
  assert actual.get('IPAddress')in ('',endpoint['IPAddress'])
  if actual.get('IPAddress')=='':assert all(actual.get(k,'')==''for k in ['MacAddress','Gateway','EndpointID','GlobalIPv6Address','IPv6Gateway'])
  call('network','disconnect',name,OLD)
  ep={k:endpoint[k]for k in ['IPAMConfig','Aliases','MacAddress','Links','DriverOpts','GwPriority']if endpoint.get(k)is not None};ep['IPAMConfig']=copy.deepcopy(endpoint.get('IPAMConfig')or{});ep['IPAMConfig']['IPv4Address']=endpoint['IPAddress']
  api('POST','/networks/'+endpoint['NetworkID']+'/connect',{'Container':pre['new'],'EndpointConfig':ep})
  got=inspect(pre['new'])['NetworkSettings']['Networks'][name]
  for k in ['NetworkID','IPAddress','MacAddress','Aliases','IPAMConfig']:assert got.get(k)==endpoint.get(k),'Endpoint mismatch: '+k
 assert inspect(pre['new'])['NetworkSettings']['Ports']==b['NetworkSettings']['Ports'],'Original UDP/TCP publications not activated exactly'
 for route in base['lan_routes']:
  existing=json.loads(execout(pre['new'],'ip','-j','-4','route','show','table','all'));assert not any(r.get('dst')==route['dst']for r in existing)
  save('route-pending-'+route['dst'].split('/')[0]+'.json',route)
  args=['ip','-4','route','add',route['dst'],'via',route['gateway'],'dev',route['dev'],'proto',str(route.get('protocol','boot'))]
  if 'metric'in route:args+=['metric',str(route['metric'])]
  if 'prefsrc'in route:args+=['src',route['prefsrc']]
  execout(pre['new'],*args)
 got,_=lan_routes(pre['new']);assert sorted(got,key=lambda r:r['dst'])==sorted(base['lan_routes'],key=lambda r:r['dst'])
 assert namespace(pre['new'])==pre['namespace'];assert private(s/'ipsec/journal.json')==private(run/'journal-frozen.json')
 temp='/tmp/cloud-enrolled-restoration';execout(pre['new'],'mkdir','-m','700',temp);stream=io.BytesIO()
 with tarfile.open(fileobj=stream,mode='w')as t:
  for name,raw,mode in [('receipt',a.cli.read_bytes(),0o700),('journal.json',private(run/'journal-frozen.json'),0o600),('proof.json',private(run/'stop-proof.json'),0o600)]:
   e=tarfile.TarInfo(name);e.uid=e.gid=0;e.mode=mode;e.size=len(raw);t.addfile(e,io.BytesIO(raw))
 subprocess.run(D+['exec','-i',pre['new'],'tar','-xf','-','-C',temp],input=stream.getvalue(),check=True)
 canonical=s/('ipsec/restore-'+DELIVERY+'.json');assert not canonical.exists()
 boot=execout(pre['new'],'cat','/proc/sys/kernel/random/boot_id').decode().strip()
 execout(pre['new'],'env','TMPDIR='+temp,temp+'/receipt','--journal',temp+'/journal.json','--evidence',temp+'/proof.json','--boot',boot,'--namespace',pre['namespace'],'--out','/state/ipsec/restore-'+DELIVERY+'.json')
 raw=private(canonical);r=json.loads(raw);assert r['DeliveryID']==DELIVERY and r['Namespace']==pre['namespace'];assert sha(private(s/'ipsec/journal.json'))==base['journal_sha256'];publish(run/'receipt.json',raw);save('installed.json',{'new':pre['new'],'namespace':pre['namespace'],'receipt_sha256':sha(raw),'journal_sha256':base['journal_sha256']});print('Genuine receipt and exact LAN routes installed; worker remains sleeping');raise SystemExit
if a.stage=='release':
 installed=load('installed.json');assert installed['new']==pre['new'];assert a.release and a.release_sha=='b3c2ec306d80c49f5735772a1dbf3ec92fb06b248dca6c82ee70c63d702ced17';tool(a.release,a.release_sha)
 assert sha(private(s/('ipsec/restore-'+DELIVERY+'.json')))==installed['receipt_sha256'];got,_=lan_routes(pre['new']);assert sorted(got,key=lambda r:r['dst'])==sorted(base['lan_routes'],key=lambda r:r['dst'])
 save('release-pending.json',{'new':pre['new'],'release_sha256':a.release_sha,'receipt_sha256':installed['receipt_sha256']})
 stream=io.BytesIO()
 with tarfile.open(fileobj=stream,mode='w')as t:
  raw=a.release.read_bytes();e=tarfile.TarInfo('release');e.uid=e.gid=0;e.mode=0o700;e.size=len(raw);t.addfile(e,io.BytesIO(raw))
 subprocess.run(D+['exec','-i',pre['new'],'tar','-xf','-','-C','/tmp/cloud-enrolled-restoration'],input=stream.getvalue(),check=True)
 execout(pre['new'],'/tmp/cloud-enrolled-restoration/release','--delivery',DELIVERY,'--namespace',pre['namespace'],'--journal-sha',base['journal_sha256'],'--receipt-sha',installed['receipt_sha256'])
 save('released.json',{'new':pre['new'],'namespace':pre['namespace'],'worker_released':True,'product_recovery_acceptance':'pending','state_json_unmodified':True,'old_retained':True});print('Worker released; actual CP lease/native recovery/packet proof required separately')
