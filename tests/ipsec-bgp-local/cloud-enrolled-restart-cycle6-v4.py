#!/usr/bin/env python3
"""Owned Linux cloud restart. Default READONLY; stages require explicit --execute.
No journal mutation; genuine host observer and source-pinned receipt/release only.
Run on owned gateway host, not bastion. Private artifacts never printed.
"""
import argparse,copy,hashlib,ipaddress,http.client,io,json,os,pathlib,socket,stat,subprocess,tarfile,time,urllib.parse
OLD='b8baa489a1a6e24020676d75703db1ef28118178e97d38c9a00914dab2c20cad'
NS='net:[4026532947]'
IMAGE='sha256:868b425d65ef30b6f0c221c834e8925079d658281e89380ead59a929021c50a2'
NODE='b85a470bfa46fb8d03487381c58d1be004aa5adc3fad6a1e50d9a575b72e6d76'
DELIVERY='44e340c8-1111-4c1b-8a79-368e1b628ba9'
NEW_NODE='879118210d5fa4906e95a1c56034851cb3ba8d813fdd23ccb044a072b134922f'
NEW_SOURCE='8faa7c782194073c298324f535de3a46b431f32ec049975d3474f5ecbcf65dba'
OLD_BIN_DIR='/home/ubuntu/tunnex-bgp-lab/builds/customer-continuity-mtu-608968c4/bin'
NEW_BIN_DIR='/home/ubuntu/tunnex-bgp-lab/builds/cloud-failover-fix-8faa7c78/bin'
NEW_RECEIPT_SHA='1c3632d7311c893afcd12855e48dee3a11492dce48fa2e97df9e84af30a15deb'
OBSERVER='8994f624a75210c1f0f1359708c75ba80c95ca523a6bb69c8b1bb3396dec27c6'
OBSERVER_PROVENANCE='root-reviewed canonical unique Destination enumeration only; all mount literal fields unchanged'
CLI='1b393d1f78f609ed8ef26fb403582908ec2fe1a6aef1e82dc155230ff8866f61'
GATE=b'owned enrolled restoration supervisor blocks Apply until genuine new namespace receipt durable\n'
NAME='tunnex-bgp-20261007-gateway-trusted-restart-6'
STAGING='tunnex-bgp-20261007-restoration-staging-6'
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
 with os.fdopen(fd,'wb')as f:
  identity=os.fstat(f.fileno());f.write(b);f.flush();os.fsync(f.fileno())
 syncdir(path.parent)
 return {'device':identity.st_dev,'inode':identity.st_ino,'uid':identity.st_uid,'mode':stat.S_IMODE(identity.st_mode)}
def save(name,obj):publish(run/name,json.dumps(obj,sort_keys=True,indent=2).encode()+b'\n')
def load(name):return json.loads(private(run/name))
def execout(cid,*args):return call('exec',cid,*args)
def namespace(cid):return execout(cid,'readlink','/proc/1/ns/net').decode().strip()
def canonical_mounts(rows):
 assert isinstance(rows,list)
 seen=set()
 for row in rows:
  assert isinstance(row,dict)and isinstance(row.get('Destination'),str)
  dst=row['Destination'];assert dst.startswith('/')and not dst.startswith('//')and '..'not in pathlib.PurePosixPath(dst).parts and str(pathlib.PurePosixPath(dst))==dst and dst not in seen
  seen.add(dst)
 # Docker enumerates mountpoints from a map. Normalize enumeration only;
 # every complete literal tuple field stays present and compared unchanged.
 return sorted(copy.deepcopy(rows),key=lambda row:row['Destination'])
def unchanged_layout(g,b,networks=True):
 assert g['Id']==OLD and g['Image']==IMAGE and g['Config']==b['Config']and g['HostConfig']==b['HostConfig']
 assert canonical_mounts(g['Mounts'])==canonical_mounts(b['Mounts'])
 if networks:assert g['NetworkSettings']['Networks']==b['NetworkSettings']['Networks']
def has_prior_restoration(entry,current_boot):
 import uuid
 restoration=entry.get('Restoration')
 if restoration is None:return False
 assert type(restoration)is dict and set(restoration)=={'BootID','Epoch','Retired'},'Unknown restoration checkpoint shape'
 boot=restoration['BootID'];assert str(uuid.UUID(boot))==boot and uuid.UUID(boot).int and boot==current_boot
 epoch=restoration['Epoch'];history=restoration['Retired']
 assert type(epoch)is int and 0<=epoch<=16 and (history is None or type(history)is list)
 history=[]if history is None else history
 assert epoch==len(history),'Restoration epoch/history mismatch'
 if not history:return False
 assert all(type(h)is dict and type(h.get('Entry'))is dict and h['Entry'].get('Restoration')is None and h['Entry'].get('ResetCleanup')is None and h['Entry'].get('Phase')=='applied' for h in history)
 last=history[-1];assert last['NewBootID']==current_boot and last['NewNamespace']==entry['Allocation']['Namespace'] and last['NewGeneration']==entry['Allocation']['Generation']
 assert type(last['EvidenceDigest'])is str and len(last['EvidenceDigest'])==64 and all(c in '0123456789abcdef'for c in last['EvidenceDigest'])
 return True
def prior_receipt_proof(entry,raw,namespace):
 history=entry['Restoration']['Retired'];assert history and history[-1]['EvidenceDigest']==sha(raw)
 r=json.loads(raw);assert r['DeliveryID']==DELIVERY and r['Namespace']==namespace
 return {'sha256':sha(raw),'namespace':namespace,'delivery':DELIVERY}
def cloud_command(g):
 assert g['Config']['Entrypoint']==['/bin/sh']and len(g['Config']['Cmd'])==2 and g['Config']['Cmd'][0]=='-ec'
 command=g['Config']['Cmd'][1];assert isinstance(command,str) and command.startswith(WRAPPER) and command.count(WRAPPER)==1
 return command[len(WRAPPER):]
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
def inventory(directory):
 p=pathlib.Path(directory);assert p.resolve()==p and p.is_dir();st=p.stat();assert st.st_uid==0 and st.st_mode&0o022==0
 if directory==NEW_BIN_DIR:assert stat.S_IMODE(st.st_mode)==0o700
 result={}
 for f in sorted(p.iterdir()):
  st=f.lstat();assert stat.S_ISREG(st.st_mode)and st.st_uid==0 and st.st_mode&0o022==0
  result[f.name]={'sha256':sha(f.read_bytes()),'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'device':st.st_dev,'inode':st.st_ino}
 return result
def upgrade_inventory(old,new):
 assert old['tunnex-node']['sha256']==NODE and {k:new['tunnex-node'][k]for k in ['sha256','mode','uid']}=={'sha256':NEW_NODE,'mode':0o700,'uid':0}
 assert set(new)==set(old)and 'tunnex-node'in new
 for name,metadata in new.items():
  if name!='tunnex-node':assert {k:metadata[k]for k in ['sha256','mode','uid']}=={k:old[name][k]for k in ['sha256','mode','uid']},'Other binary changed: '+name
 return True
def replacement_host_config(g):
 h=copy.deepcopy(g['HostConfig']);assert h.get('Binds')is None
 targets=[m for m in h['Mounts']if m.get('Target')=='/binaries'];assert len(targets)==1
 m=targets[0];assert m=={'Type':'bind','Source':OLD_BIN_DIR,'Target':'/binaries','ReadOnly':True}
 m['Source']=NEW_BIN_DIR
 return h
def creation_host_config(g):
 h=replacement_host_config(g)
 # Actual Engine create inspect canonicalizes null default to false. This
 # changes only the replacement requested/default representation; the old
 # original HostConfig remains null and is still compared byte-for-byte.
 if h.get('OomKillDisable')is None:h['OomKillDisable']=False
 return h
def replacement_mounts(g):
 mounts=copy.deepcopy(g['Mounts']);targets=[m for m in mounts if m['Destination']=='/binaries'];assert len(targets)==1
 m=targets[0];assert m['Type']=='bind'and m['Source']==OLD_BIN_DIR and m['RW']is False and m['Propagation']=='rprivate'
 m['Source']=NEW_BIN_DIR;return mounts
def validate_candidate_receipt(raw,node,source,receipt_sha,old_node):
 assert all(type(x)is str and len(x)==64 and x!='0'*64 and all(c in '0123456789abcdef'for c in x)for x in (node,source,receipt_sha,old_node))
 assert node!=old_node and source!='be457a19097a64bb17f0e196eef868a5a7265e6b0bf1c15d745d238618e4fb46'
 assert hashlib.sha256(raw).hexdigest()==receipt_sha
 proof=json.loads(raw)
 assert proof['binary_sha256']==node and proof['source_snapshot_sha256']==source and proof['prior_node_sha256']==old_node
 assert proof['unit_suites_passed']is True and proof['source_before_after_equal']is True and proof['toolchain']=='go version go1.26.8 darwin/arm64'
 assert proof['GOOS']=='linux' and proof['GOARCH']=='amd64' and proof['CGO_ENABLED']=='0'
 assert proof['build_arguments']==['build','-trimpath','-buildvcs=false','./cmd/agent']
 return {'node_sha256':node,'source_snapshot_sha256':source,'build_receipt_sha256':receipt_sha,'prior_node_sha256':old_node,'tests_passed':True}
def new_artifact(g):
 replacement_host_config(g);replacement_mounts(g)
 receipt=pathlib.Path(NEW_BIN_DIR).parent/'build-receipt.json';raw=private(receipt);assert sha(raw)==NEW_RECEIPT_SHA
 validate_candidate_receipt(raw,NEW_NODE,NEW_SOURCE,NEW_RECEIPT_SHA,NODE)
 old=inventory(OLD_BIN_DIR);new=inventory(NEW_BIN_DIR);upgrade_inventory(old,new)
 return {'old_proof_node_sha256':NODE,'new_worker_node_sha256':NEW_NODE,'new_worker_source_sha256':NEW_SOURCE,'new_build_receipt_sha256':NEW_RECEIPT_SHA,'old_binary_inventory':old,'new_binary_inventory':new,'old_binary_mount':OLD_BIN_DIR,'new_binary_mount':NEW_BIN_DIR}
def current_old():
 g=inspect(OLD);assert g['State']['Running']and g['Image']==IMAGE and g['Config']['Labels'].get('tunnex.lab')=='tunnex-bgp-20261007'
 assert namespace(OLD)==NS and execout(OLD,'sha256sum','/proc/1/exe').decode().split()[0]==NODE
 cloud_command(g);assert execout(OLD,'test','-f','/run/enrolled-restoration-release')==b'';publication_contract(g);original_network(g)
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
def active_entries(raw):
 j=json.loads(raw);entries=j['Payload']['Entries'];assert 0<len(entries)<=256
 rows=[e for e in entries if e['Phase']!='retained_refusal'];assert rows and len(rows)==len({e['DeliveryID']for e in rows})
 cp=cp_binding();expected={r['delivery']:r for r in cp};assert set(expected)=={e['DeliveryID']for e in rows}
 for e in rows:
  r=expected[e['DeliveryID']];assert e['Phase']=='applied' and e['ContractVersion']==3 and e['Allocation']['Namespace']==NS
  assert e['Engines'][0]['Binding']['GatewayID']==r['node'] and e['Engines'][0]['Binding']['ConnectionID']==r['connection']
  assert e['BGPProcess']['Stage']=='ready' and e['BGPRoutes']['Stage']=='completed'
 return sorted(rows,key=lambda e:e['DeliveryID'])
def active(raw):
 rows=active_entries(raw);return next(e for e in rows if e['DeliveryID']==DELIVERY)
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
  result[name]={'id':g['Id'],'image':g['Image'],'Config':g['Config'],'HostConfig':g['HostConfig'],'Mounts':canonical_mounts(g['Mounts'])}
 assert result['tunnex-bgp-20261007-api']['id']=='e9d54f9986706e8cf7c915426276b0f9ca760a975792225df57bf16afceeb25b'
 return result
def cp_binding():
 sql="SELECT coalesce(json_agg(x ORDER BY connection),'[]'::json) FROM (SELECT c.id AS connection,c.desired_intent AS intent,c.desired_revision AS revision,n.id AS node,n.cert_serial AS certificate_serial,d.id AS delivery,d.manifest->>'profile_id' AS profile FROM ipsec_connections c JOIN nodes n ON n.id=c.gateway_node_id AND n.org_id=c.org_id JOIN ipsec_runtime_deliveries d ON d.connection_id=c.id AND d.desired_revision=c.desired_revision AND d.kind='apply' AND d.node_id=n.id AND d.org_id=c.org_id AND d.certificate_serial=n.cert_serial WHERE c.id IN ('9d9f98e2-cd96-456d-b020-a5a79f688040','8856b1c4-ae98-418b-bfd5-664cde5210c3') AND c.desired_intent='enabled')x;"
 rows=json.loads(call('exec','tunnex-bgp-20261007-postgres','psql','-U','bgpcloud','-d','bgpcloud','-At','-v','ON_ERROR_STOP=1','-c',sql))
 assert len(rows)==2 and len({r['delivery']for r in rows})==2 and len({r['node']for r in rows})==1 and len({r['certificate_serial']for r in rows})==1
 assert {r['connection']for r in rows}=={'9d9f98e2-cd96-456d-b020-a5a79f688040','8856b1c4-ae98-418b-bfd5-664cde5210c3'}
 assert all(r['intent']=='enabled'and r['revision']==2 and r['profile']=='aws-bgp-ipv4-v1'and r['certificate_serial']for r in rows)
 assert any(r['delivery']==DELIVERY for r in rows)
 expected_raw=private(pathlib.Path(pin['normal_binding_path']));assert sha(expected_raw)==pin['normal_binding_sha256'];expected=json.loads(expected_raw);assert rows==expected['bindings'] and expected['gateway_id']==rows[0]['node']
 assert expected['normal_manifest_deliveries']==sorted(r['delivery']for r in rows)
 return rows
def link_proof(links,addresses,old_links,old_addresses,epoch=None):
 def selected(rows):
  matching=[r for r in rows if r.get('ifname')=='eth0'];assert len(matching)==1
  return matching[0]
 old=selected(old_links);new=selected(links)
 for link in [old,new]:
  assert isinstance(link['ifindex'],int)and link['ifindex']>0 and link['operstate']=='UP'and {'UP','LOWER_UP'}<=set(link['flags'])
  assert link['link_type']=='ether'and link['linkinfo']['info_kind']=='veth'
 assert new['mtu']==old['mtu']
 if epoch is None:assert new['address']==old['address']
 else:assert new['address']==epoch['MacAddress'] and new['ifindex']==epoch['bound_ifindex']
 def assigned(rows):
  r=selected(rows);ips=[x for x in r['addr_info']if x.get('family')=='inet'];assert len(ips)==1
  ip=ips[0];assert ip['local']=='172.30.88.2'and ip['prefixlen']==24 and ip['scope']=='global'
  return {k:ip.get(k)for k in ['family','local','prefixlen','broadcast','scope','label']}
 assert assigned(addresses)==assigned(old_addresses)
 # A fresh namespace can legitimately assign a different ifindex. Capture and
 # bind its actual current positive index; never adopt the old epoch index.
 return {'old_ifindex':old['ifindex'],'current_ifindex':new['ifindex'],'mac':new['address'],'mtu':new['mtu'],'address':assigned(addresses)}
def routeget_proof(rows,outside):
 assert len(rows)==1;r=rows[0]
 assert ipaddress.ip_network(r['dst'],strict=False)==ipaddress.ip_network(outside+'/32')
 assert r['dev']=='eth0'and r['gateway']=='172.30.88.1'and r.get('flags',[])==[]
 sources=[r[k]for k in ['from','prefsrc','src']if k in r];assert sources and all(x=='172.30.88.2'for x in sources)
 assert r.get('table','main')in ('main',254)and r.get('type','unicast')=='unicast'
 return r
def endpoint_epoch_proof(old_endpoints,new_endpoints,cid):
 assert set(old_endpoints)==set(new_endpoints) and len(new_endpoints)==1
 name=next(iter(old_endpoints));old=old_endpoints[name];new=new_endpoints[name]
 for key in ['NetworkID','IPAddress','IPAMConfig','Aliases','Links','DriverOpts','GwPriority','Gateway','IPPrefixLen','GlobalIPv6Address','GlobalIPv6PrefixLen','IPv6Gateway']:
  assert old.get(key)==new.get(key),'Endpoint mismatch: '+key
 assert new['IPAddress']=='172.30.88.2' and new['EndpointID']
 mac=new['MacAddress'];parts=mac.split(':');assert len(parts)==6 and all(len(x)==2 and all(c in '0123456789abcdef'for c in x)for x in parts) and int(parts[0],16)&1==0 and mac!='00:00:00:00:00:00'
 assert new['DNSNames']==[NAME,'gateway',cid[:12]]
 return copy.deepcopy(new)
def physical_underlay(cid):
 current=inspect(cid);epoch=endpoint_epoch_proof(load('inspect-private.json')['NetworkSettings']['Networks'],current['NetworkSettings']['Networks'],cid)
 links=json.loads(execout(cid,'ip','-d','-j','link','show'));addresses=json.loads(execout(cid,'ip','-j','address','show'))
 matches=[r for r in links if r.get('ifname')=='eth0'];assert len(matches)==1;epoch['bound_ifindex']=matches[0]['ifindex']
 bound=link_proof(links,addresses,load('namespace-link-census.json'),load('namespace-address-census.json'),epoch)
 routes={outside:routeget_proof(json.loads(execout(cid,'ip','-j','-4','route','get',outside,'from','172.30.88.2')),outside)for outside in ['13.50.7.159','51.20.220.141']}
 after=link_proof(json.loads(execout(cid,'ip','-d','-j','link','show')),json.loads(execout(cid,'ip','-j','address','show')),load('namespace-link-census.json'),load('namespace-address-census.json'),epoch)
 assert after==bound and inspect(cid)['NetworkSettings']['Networks']==current['NetworkSettings']['Networks'],'Current endpoint/underlay changed during readback'
 return {'link':bound,'endpoint':epoch,'requested_endpoint':load('inspect-private.json')['NetworkSettings']['Networks'],'outside_routes':routes}
def gate_proof(actual,recorded,raw,journal_sha):
 assert recorded['old']==OLD and recorded['journal_sha256']==journal_sha
 assert set(actual)=={'device','inode','uid','mode'}and actual==recorded['identity']
 assert isinstance(actual['device'],int)and actual['device']>0 and isinstance(actual['inode'],int)and actual['inode']>0
 assert actual['uid']==0 and actual['mode']==0o600 and raw==GATE
 return True
def abort_allowed(g,b,journal_sha,state_now,state_before,kill_intent,stop_proof):
 assert not kill_intent and not stop_proof,'No automatic abort after KILL intent/proof'
 unchanged_layout(g,b);assert g['State']['Running']and g['State']['Pid']==b['State']['Pid']and g['State']['StartedAt']==b['State']['StartedAt']
 assert journal_sha==base['journal_sha256']and state_now==state_before
 return True
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
 n=inspect(pre['new']);assert n['State']['Running']and n['Image']==IMAGE and n['Config']==pre['actual_config']and n['HostConfig']==pre['host_config']and canonical_mounts(n['Mounts'])==canonical_mounts(pre['mounts'])
 assert namespace(pre['new'])==pre['namespace']!=NS
 assert execout(pre['new'],'sha256sum','/binaries/tunnex-node').decode().split()[0]==NEW_NODE,'Mounted new worker differs'
 assert execout(pre['new'],'sha256sum','/state/ipsec/journal.json').decode().split()[0]==load('baseline.json')['journal_sha256']
 assert all(x not in execout(pre['new'],'ps','-eo','comm').decode().splitlines()for x in ['tunnex-node','charon','bgpd','zebra'])
 assert execout(pre['new'],'ip','xfrm','state').strip()==b''
 assert subprocess.run(D+['exec',pre['new'],'test','-e','/run/enrolled-restoration-release'],stdout=subprocess.DEVNULL).returncode==1
 assert state_hashes(state_path(n))==load('baseline.json')['state_hashes'];return n
p=argparse.ArgumentParser();p.add_argument('stage',choices=['preflight','capture','preallocate','stop','install','release','abort']);p.add_argument('--run',type=pathlib.Path,required=True);p.add_argument('--pins',type=pathlib.Path,required=True);p.add_argument('--observer',type=pathlib.Path);p.add_argument('--cli',type=pathlib.Path);p.add_argument('--release',type=pathlib.Path);p.add_argument('--release-sha');p.add_argument('--execute',action='store_true');a=p.parse_args();os.umask(0o077);assert os.geteuid()==0
pin=json.loads(private(a.pins));assert pin['root_reviewed'] is True
OLD=pin['old_id'];assert len(OLD)==64 and OLD=='b8baa489a1a6e24020676d75703db1ef28118178e97d38c9a00914dab2c20cad' and all(x in '0123456789abcdef'for x in OLD)
NS=pin['old_namespace'];assert NS=='net:[4026532947]'
NODE=pin['old_node_sha256'];assert NODE=='b85a470bfa46fb8d03487381c58d1be004aa5adc3fad6a1e50d9a575b72e6d76'
OLD_BIN_DIR=pin['old_bin_dir'];NEW_BIN_DIR=pin['new_bin_dir'];assert pathlib.Path(OLD_BIN_DIR).parent.parent==pathlib.Path('/home/ubuntu/tunnex-bgp-lab/builds') and pathlib.Path(OLD_BIN_DIR).name=='bin' and NEW_BIN_DIR!=OLD_BIN_DIR
assert pathlib.Path(NEW_BIN_DIR).parent.parent==pathlib.Path('/home/ubuntu/tunnex-bgp-lab/builds') and pathlib.Path(NEW_BIN_DIR).name=='bin'
NEW_NODE=pin['new_node_sha256'];NEW_SOURCE=pin['new_source_sha256'];NEW_RECEIPT_SHA=pin['new_receipt_sha256'];CLI=pin['cli_sha256']
assert CLI=='b6a9016e79656f0de4e5401eb01252c96847ba73e2b2f9763f7fed043f352d98'
assert all(len(x)==64 and all(c in '0123456789abcdef'for c in x)for x in [NEW_NODE,NEW_SOURCE,NEW_RECEIPT_SHA,CLI]) and NEW_NODE!=NODE
run=a.run;assert run.is_absolute()and run.parent==pathlib.Path('/home/ubuntu/tunnex-bgp-lab')and run.name=='cloud-enrolled-restart-21169a9f-cycle6-v4'
if a.stage=='preflight':
 g=current_old();s=state_path(g);raw=private(s/'ipsec/journal.json');active(raw);routes,_=lan_routes(OLD);other_runtime();cp_binding();new_artifact(g)
 print(json.dumps({'read_only':True,'old':OLD,'namespace':NS,'delivery':DELIVERY,'journal_sha256_unfrozen':sha(raw),'owned_lan_routes':routes,'requires_frozen_capture':True,'old_proof_node_sha256':NODE,'new_worker_node_sha256':NEW_NODE,'new_binary_mount_source':NEW_BIN_DIR}));raise SystemExit
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
  assert not(s/'ipsec/restoration-startup-gate').exists()
  prior_map={}
  for entry in active_entries(raw):
   id=entry['DeliveryID'];canonical=s/('ipsec/restore-'+id+'.json')
   if has_prior_restoration(entry,pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()):
    prior=private(canonical);r=json.loads(prior);assert r['DeliveryID']==id and r['Namespace']==NS and entry['Restoration']['Retired'][-1]['EvidenceDigest']==sha(prior)
    publish(run/('prior-receipt-'+id+'.json'),prior);prior_map[id]=sha(prior)
   else:assert not os.path.lexists(canonical);prior_map[id]=None
  assert prior_map==pin['prior_receipt_sha256'],'Unknown prior canonical receipt state'
  save('prior-receipt-map.json',prior_map)
  save('namespace-link-census.json',json.loads(execout(OLD,'ip','-d','-j','link','show')));save('namespace-address-census.json',json.loads(execout(OLD,'ip','-j','address','show')));save('namespace-nft-census.json',json.loads(execout(OLD,'nft','-j','list','ruleset')));save('inspect-private.json',g);save('new-worker-artifact.json',new_artifact(g));save('host-preservation.json',host_preservation());save('host-route-census.json',json.loads(subprocess.check_output(['ip','-j','-4','route','show','table','all'])));save('other-runtime-private.json',other_runtime());save('cp-binding.json',cp_binding());publish(run/'journal-frozen.json',raw)
  save('baseline.json',{'old':OLD,'namespace':NS,'delivery':DELIVERY,'journal_sha256':sha(raw),'state_hashes':state_hashes(s),'lan_routes':routes,'all_routes':allroutes,'node_sha256':NODE,'image':IMAGE,'helper_sha256':sha(pathlib.Path(__file__).read_bytes())})
 except BaseException:
  if paused:subprocess.run(D+['kill','--signal','CONT',OLD],check=True,stdout=subprocess.DEVNULL)
  raise
 print('Frozen capture durable; old exact PID1 remains STOPPED; next action reviewed preallocation or exact CONT abort');raise SystemExit
b=load('inspect-private.json');base=load('baseline.json');assert base['old']==OLD and base['delivery']==DELIVERY
assert sha(pathlib.Path(__file__).read_bytes())==base['helper_sha256'],'Helper changed after capture'
if a.stage=='abort':
 assert inventory(OLD_BIN_DIR)==load('new-worker-artifact.json')['old_binary_inventory'],'Old proof source changed'
else:assert new_artifact(b)==load('new-worker-artifact.json'),'New artifact or old proof source changed'
assert host_preservation()==load('host-preservation.json'),'Owned host route/firewall changed'
assert other_runtime()==load('other-runtime-private.json')and cp_binding()==load('cp-binding.json'),'CP/certificate/other runtime differs'
if a.stage=='preallocate':
 g,s=frozen(b);assert not(run/'preallocated.json').exists();save('preallocate-pending.json',{'old':OLD,'journal_sha256':base['journal_sha256']})
 assert subprocess.run(D+['inspect',NAME],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0
 assert subprocess.run(D+['network','inspect',STAGING],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0
 sid=call('network','create','--internal','--opt','com.docker.network.bridge.gateway_mode_ipv4=routed','--label','tunnex.lab=tunnex-bgp-20261007','--label','tunnex.restoration=cloud-enrolled-21169a9f',STAGING).decode().strip()
 c=copy.deepcopy(g['Config']);c['Hostname']='';c['Cmd']=['-ec',WRAPPER+cloud_command(g)];h=creation_host_config(g);h['NetworkMode']=STAGING
 # Routed staging defers bindings while preserving every original UDP/TCP publication.
 assert h['PortBindings']==publication_contract(g)
 payload={**c,'HostConfig':h};save('create-private.json',payload);new=api('POST','/containers/create?'+urllib.parse.urlencode({'name':NAME}),payload)['Id'];save('created.json',{'new':new,'staging_id':sid})
 n=inspect(new);assert not n['State']['Running'];assert n['HostConfig']==h and n['Image']==IMAGE
 for k,v in c.items():
  if k not in ('Hostname','Image'):assert n['Config'].get(k)==v,'Created config mismatch: '+k
 assert canonical_mounts(n['Mounts'])==canonical_mounts(replacement_mounts(g))
 call('start',new);n=inspect(new);ns=namespace(new);assert ns!=NS
 staged=json.loads(call('network','inspect',sid))[0];assert staged['Internal']and staged['Options']['com.docker.network.bridge.gateway_mode_ipv4']=='routed'
 assert n['HostConfig']['PortBindings']==g['HostConfig']['PortBindings']
 assert all(not binding.get('HostPort')for rows in n['NetworkSettings']['Ports'].values()for binding in (rows or [])),'Staging unexpectedly published original ports'
 pre={'new':new,'namespace':ns,'staging_id':sid,'actual_config':n['Config'],'host_config':n['HostConfig'],'mounts':n['Mounts']};fresh_worker(b,pre);save('preallocated.json',pre);print('New distinct sleeping namespace durable; no worker started');raise SystemExit
if a.stage=='abort':
 g,pstate=frozen(b)
 abort_allowed(g,b,sha(private(pstate/'ipsec/journal.json')),state_hashes(pstate),base['state_hashes'],(run/'kill-intent.json').exists(),(run/'stop-proof.json').exists()or(run/'stopped.json').exists())
 assert namespace(OLD)==NS and execout(OLD,'sha256sum','/proc/1/exe').decode().split()[0]==NODE
 save('abort-pending.json',{'old':OLD,'pid':g['State']['Pid'],'started_at':g['State']['StartedAt'],'journal_sha256':base['journal_sha256']})
 gate=pstate/'ipsec/restoration-startup-gate'
 if gate.exists():
  recorded=load('gate-published.json');st=gate.lstat()
  actual={'device':st.st_dev,'inode':st.st_ino,'uid':st.st_uid,'mode':stat.S_IMODE(st.st_mode)}
  assert stat.S_ISREG(st.st_mode);gate_proof(actual,recorded,private(gate),base['journal_sha256'])
  frozen(b);assert gate.lstat().st_ino==actual['inode'];gate.unlink();syncdir(gate.parent)
 else:assert not(run/'gate-published.json').exists(),'Recorded gate disappeared; refuse abort'
 frozen(b);call('kill','--signal','CONT',OLD)
 save('aborted.json',{'old':OLD,'old_resumed':True,'journal_unmodified':True,'new_sleeping_fixture_not_removed':True});print('Exact paused old runtime resumed; journal unchanged; inspect any sleeping fixture separately');raise SystemExit
pre=load('preallocated.json')
if a.stage=='stop':
 g,s=frozen(b);fresh_worker(b,pre);assert a.observer;tool(a.observer,OBSERVER)
 prior_map=load('prior-receipt-map.json');assert prior_map==pin['prior_receipt_sha256']
 for id,h in prior_map.items():
  canonical=s/('ipsec/restore-'+id+'.json')
  if h is None:assert not os.path.lexists(canonical)
  else:assert sha(private(canonical))==h
 save('stop-pending.json',{'old':OLD,'new':pre['new'],'journal_sha256':base['journal_sha256'],'observer_sha256':OBSERVER})
 identity=publish(s/'ipsec/restoration-startup-gate',GATE);save('gate-published.json',{'identity':identity,'old':OLD,'journal_sha256':base['journal_sha256']})
 subprocess.run(['python3',str(a.observer),'snapshot','--container',OLD,'--journal',str(s/'ipsec/journal.json'),'--state-destination','/state','--output',str(run/'snapshot.json')],check=True)
 frozen(b);save('kill-intent.json',{'old':OLD,'pid':g['State']['Pid'],'started_at':g['State']['StartedAt'],'journal_sha256':base['journal_sha256']});call('kill','--signal','KILL',OLD);call('wait',OLD)
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
  endpoint_epoch_proof({name:endpoint},{name:got},pre['new'])
 assert inspect(pre['new'])['NetworkSettings']['Ports']==b['NetworkSettings']['Ports'],'Original UDP/TCP publications not activated exactly'
 save('physical-underlay-proof.json',physical_underlay(pre['new']))
 for route in base['lan_routes']:
  existing=json.loads(execout(pre['new'],'ip','-j','-4','route','show','table','all'));assert not any(r.get('dst')==route['dst']for r in existing)
  save('route-pending-'+route['dst'].split('/')[0]+'.json',route)
  args=['ip','-4','route','add',route['dst'],'via',route['gateway'],'dev',route['dev'],'proto',str(route.get('protocol','boot'))]
  if 'metric'in route:args+=['metric',str(route['metric'])]
  if 'prefsrc'in route:args+=['src',route['prefsrc']]
  execout(pre['new'],*args)
 got,_=lan_routes(pre['new']);assert sorted(got,key=lambda r:r['dst'])==sorted(base['lan_routes'],key=lambda r:r['dst']);assert physical_underlay(pre['new'])==load('physical-underlay-proof.json')
 assert namespace(pre['new'])==pre['namespace'];assert private(s/'ipsec/journal.json')==private(run/'journal-frozen.json')
 temp='/tmp/cloud-enrolled-restoration';execout(pre['new'],'mkdir','-m','700',temp);stream=io.BytesIO()
 with tarfile.open(fileobj=stream,mode='w')as t:
  for name,raw,mode in [('receipt',a.cli.read_bytes(),0o700),('journal.json',private(run/'journal-frozen.json'),0o600),('proof.json',private(run/'stop-proof.json'),0o600)]:
   e=tarfile.TarInfo(name);e.uid=e.gid=0;e.mode=mode;e.size=len(raw);t.addfile(e,io.BytesIO(raw))
 subprocess.run(D+['exec','-i',pre['new'],'tar','-xf','-','-C',temp],input=stream.getvalue(),check=True)
 entries=active_entries(private(run/'journal-frozen.json'));prior_map=load('prior-receipt-map.json');assert set(prior_map)=={e['DeliveryID']for e in entries}
 boot=execout(pre['new'],'cat','/proc/sys/kernel/random/boot_id').decode().strip();receipt_hashes={}
 save('receipt-install-pending.json',{'deliveries':sorted(prior_map),'journal_sha256':base['journal_sha256'],'new':pre['new']})
 for entry in entries:
  id=entry['DeliveryID'];canonical=s/('ipsec/restore-'+id+'.json');prior_sha=prior_map[id]
  if prior_sha is None:assert not os.path.lexists(canonical)
  else:
   prior=private(canonical);assert sha(prior)==prior_sha and prior==private(run/('prior-receipt-'+id+'.json'))
   archive=canonical.parent/('restore-history-'+OLD+'-'+id+'.json');assert not os.path.lexists(archive);publish(archive,prior);canonical.unlink();syncdir(canonical.parent)
  execout(pre['new'],'env','TMPDIR='+temp,temp+'/receipt','--journal',temp+'/journal.json','--evidence',temp+'/proof.json','--boot',boot,'--namespace',pre['namespace'],'--delivery',id,'--out','/state/ipsec/restore-'+id+'.json')
  raw=private(canonical);r=json.loads(raw);assert r['DeliveryID']==id and r['Namespace']==pre['namespace'] and r['EvidenceDigest']==sha(private(run/'stop-proof.json'))
  receipt_hashes[id]=sha(raw);publish(run/('receipt-'+id+'.json'),raw)
 assert sha(private(s/'ipsec/journal.json'))==base['journal_sha256']
 receiptset={'OwnerID':json.loads(private(run/'journal-frozen.json'))['Payload']['OwnerID'],'Namespace':pre['namespace'],'JournalSHA':base['journal_sha256'],'EvidenceDigest':sha(private(run/'stop-proof.json')),'Receipts':receipt_hashes}
 save('receipt-set.json',receiptset);save('installed.json',{'new':pre['new'],'namespace':pre['namespace'],'receipt_set_sha256':sha(private(run/'receipt-set.json')),'journal_sha256':base['journal_sha256'],'deliveries':sorted(receipt_hashes)})
 print('Complete genuine per-delivery receipt set installed; worker remains sleeping');raise SystemExit
if a.stage=='release':
 installed=load('installed.json');assert installed['new']==pre['new'];assert a.release and a.release_sha=='e1eefdf8701a4b7601473a6408c5dc2323933a62cf33e1354133bb41eabc9687';tool(a.release,a.release_sha)
 receiptset=load('receipt-set.json');assert sorted(receiptset['Receipts'])==installed['deliveries'] and sha(private(run/'receipt-set.json'))==installed['receipt_set_sha256'];assert all(sha(private(s/('ipsec/restore-'+id+'.json')))==h for id,h in receiptset['Receipts'].items());got,_=lan_routes(pre['new']);assert sorted(got,key=lambda r:r['dst'])==sorted(base['lan_routes'],key=lambda r:r['dst']);assert physical_underlay(pre['new'])==load('physical-underlay-proof.json')
 save('release-pending.json',{'new':pre['new'],'release_sha256':a.release_sha,'receipt_set_sha256':installed['receipt_set_sha256']})
 stream=io.BytesIO()
 with tarfile.open(fileobj=stream,mode='w')as t:
  for name,raw,mode in [('release',a.release.read_bytes(),0o700),('receipt-set.json',private(run/'receipt-set.json'),0o600)]:
   e=tarfile.TarInfo(name);e.uid=e.gid=0;e.mode=mode;e.size=len(raw);t.addfile(e,io.BytesIO(raw))
 subprocess.run(D+['exec','-i',pre['new'],'tar','-xf','-','-C','/tmp/cloud-enrolled-restoration'],input=stream.getvalue(),check=True)
 execout(pre['new'],'/tmp/cloud-enrolled-restoration/release','--receipt-set','/tmp/cloud-enrolled-restoration/receipt-set.json','--receipt-set-sha',installed['receipt_set_sha256'],'--namespace',pre['namespace'],'--journal-sha',base['journal_sha256'])
 save('released.json',{'old_proof_node_sha256':NODE,'new_worker_node_sha256':NEW_NODE,'new_worker_source_sha256':NEW_SOURCE,'new_binary_mount_source':NEW_BIN_DIR,'new':pre['new'],'namespace':pre['namespace'],'worker_released':True,'product_recovery_acceptance':'pending','state_json_unmodified':True,'old_retained':True});print('Worker released; actual CP lease/native recovery/packet proof required separately')
