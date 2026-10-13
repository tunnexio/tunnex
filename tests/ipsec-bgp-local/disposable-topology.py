#!/usr/bin/env python3
"""Prepare only independently owned limit/static packet fixtures; never start IPsec/BGP or change CP intent."""
import argparse,hashlib,io,ipaddress,json,os,pathlib,subprocess,tarfile
os.umask(0o077)
p=argparse.ArgumentParser();p.add_argument('--scenario',choices=['limits','static'],required=True);p.add_argument('--state',type=pathlib.Path,required=True);p.add_argument('--enrolled-refresh',type=pathlib.Path);a=p.parse_args()
r=pathlib.Path(__file__).resolve().parent;d=[str(r/'docker-local.sh')];base=json.loads((r/'.runtime/integrated-topology.json').read_text());project='tunnexs2sbgp'+('limits'if a.scenario=='limits'else'static')+'1008';label='tunnex.bgp.integrated'
image='sha256:84c9dfdffbe27cc5a6992bceb2863d3b045d2fbdaf6b3339a7d7a5cdffba5c98';outer=base['networks']['outer'];gw=base['gateway_id'];subnet='10.30.0.0/24'if a.scenario=='limits'else'10.32.0.0/24';octet=30 if a.scenario=='limits' else 32;peerip='198.19.241.'+('30'if a.scenario=='limits'else'31');outside=['13.50.7.160','51.20.220.142']if a.scenario=='limits'else['13.50.7.161','51.20.220.143']
refresh=None
if a.enrolled_refresh is not None:
 from enrolled_approval import reviewed_run
 run,approval,index=reviewed_run(r/'.runtime',a.enrolled_refresh);assert index==3
 refresh=json.loads((run/'enrolled-restoration-finish.json').read_text());pre=json.loads((run/'enrolled-preallocation.json').read_text())
 assert refresh['worker_released'] and refresh['same_node_certificate_scale'] and refresh['retained_old_stopped'] and refresh['old_container_id']==approval['old_container_id'] and refresh['new_container_id']==gw==pre['new_container_id']
 assert pre['mounted_node_sha256']==approval['binary_sha256']and pre['image']==approval['image']
 image=approval['image']
else:assert gw=='eddbe7f90cd5684a6c51a14c4d8ccc8263ba02efed73301075bcda311e949a2a'
def out(*args):return subprocess.check_output(d+list(args),text=True).strip()
def inspect(kind,name):return json.loads(out(kind,'inspect',name))[0]
def absent(*args):return subprocess.run(d+list(args),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0
assert not a.state.exists(),'Retain prior setup; no implicit repeat/adoption'
network=inspect('network',outer);assert network['Id']==outer and network['Labels'].get(label)==base['project'] and [x['Subnet']for x in network['IPAM']['Config']]==['198.19.241.0/24']
g=inspect('container',gw);assert g['Id']==gw and g['State']['Running'] and g['Image']==image and g['Config']['Labels']['com.docker.compose.project']=='tunnexs2sbgplocal1007'
assert g['NetworkSettings']['Networks'][network['Name']]['IPAddress']=='198.19.241.10'
expected_binary=approval['binary_sha256']if refresh else'd8d9ad44e704ccdeee876c8f76923feac9daa335724dab4a5fc4e9b0149775fb'
assert out('exec',gw,'sha256sum','/proc/1/exe').split()[0]==expected_binary,'Unreviewed serving binary'
assert inspect('image',image)['Architecture']=='arm64'
def physical(cid,dev,source,prefixlen=24):
 links=json.loads(out('exec',cid,'ip','-j','-d','link','show','dev',dev));addresses=json.loads(out('exec',cid,'ip','-j','addr','show','dev',dev))
 assert len(links)==len(addresses)==1 and 'UP'in links[0]['flags'] and links[0]['link_type']=='ether' and links[0].get('linkinfo',{}).get('info_kind')=='veth' and len(links[0]['address'].split(':'))==6
 assert any(x.get('family')=='inet' and x.get('local')==source and x.get('prefixlen')==prefixlen for x in addresses[0]['addr_info'])
 return {'ifindex':links[0]['ifindex'],'ifname':dev,'source':source,'hardware_address':links[0]['address']}
gateway_interface=physical(gw,'eth1','198.19.241.10')
gateway_public=physical(gw,'eth1','13.63.169.255',32);assert gateway_public['ifindex']==gateway_interface['ifindex'] and gateway_public['hardware_address']==gateway_interface['hardware_address']
resolved=json.loads(out('exec',gw,'ip','-j','-4','route','get',peerip,'from','198.19.241.10'));assert len(resolved)==1 and resolved[0].get('dev')=='eth1' and resolved[0].get('from')=='198.19.241.10' and not resolved[0].get('flags') and not resolved[0].get('gateway')
client=inspect('container',base['containers']['client']);assert client['Config']['Labels'].get(label)==base['project'] and client['State']['Running']
assert absent('network','inspect',project+'-lan') and absent('inspect',project+'-peer') and absent('inspect',project+'-target')
for cid,endpoint in network['Containers'].items():assert endpoint['IPv4Address'].split('/')[0]!=peerip,'Outer peer address occupied'
for nid in out('network','ls','-q').splitlines():
 n=inspect('network',nid)
 for cfg in n['IPAM'].get('Config')or[]:
  if cfg.get('Subnet'):
   foreign=ipaddress.ip_network(cfg['Subnet']);assert foreign.version!=4 or not any(foreign.overlaps(ipaddress.ip_network(cidr)) for cidr in ([subnet,'10.31.0.0/24'] if a.scenario=='limits' else [subnet])),'LAN overlaps existing network'
for cid in network['Containers']:
 addresses=json.loads(out('exec',cid,'ip','-j','addr','show'))
 assert not any(x.get('local') in outside for link in addresses for x in link.get('addr_info',[])),'Outside alias already assigned'
for address in outside:
 rows=json.loads(out('exec',gw,'ip','-j','-4','route','show','exact',address+'/32'));assert rows==[],'Existing gateway outside route refused'
if a.scenario=='static':assert json.loads(out('exec',client['Id'],'ip','-j','-4','route','show','exact','10.32.0.0/24'))==[],'Client static route already exists'
client_interface=physical(client['Id'],'eth0','10.10.0.2')
state={'project':project,'scenario':a.scenario,'image':image,'gateway_id':gw,'networks':{'outer':outer},'containers':{},'outside':outside,'shared_client':client['Id'],'activation_performed':False,'daemons_started':False,'gateway_interface':gateway_interface,'client_interface':client_interface,'route_obligations':[]}
def save():a.state.parent.mkdir(mode=0o700,parents=True,exist_ok=True);a.state.write_text(json.dumps(state,indent=2)+'\n');os.chmod(a.state,0o600)
save()
state['networks']['lan']=out('network','create','--internal','--driver','bridge','--subnet',subnet,'--gateway',f'10.{octet}.0.254','--label',label+'='+project,project+'-lan');save()
args=['create','--name',project+'-peer','--label',label+'='+project,'--label','com.docker.compose.project='+project,'--network',outer,'--ip',peerip,'--cap-drop','ALL','--cap-add','NET_ADMIN','--cap-add','NET_RAW','--cap-add','NET_BIND_SERVICE','--cap-add','SETUID','--cap-add','SETGID','--sysctl','net.ipv4.ip_forward=1','--read-only','--security-opt','no-new-privileges','--tmpfs','/run:rw,nosuid,nodev,size=16m','--tmpfs','/test:rw,exec,nosuid,nodev,size=32m','--tmpfs','/var/tmp/frr:rw,nosuid,nodev,size=8m','--pids-limit','128','--entrypoint','/bin/sh',image,'-c','sleep 86400']
state['containers']['peer']=out(*args);save();peer=state['containers']['peer'];out('start',peer)
# Starting with only the outer endpoint fixes its native interface role before LAN attachment.
peer_outer=physical(peer,'eth0',peerip)
out('network','connect','--ip',f'10.{octet}.0.1',state['networks']['lan'],peer)
assert physical(peer,'eth0',peerip)==peer_outer
peer_lan=physical(peer,'eth1',f'10.{octet}.0.1');assert peer_lan['ifindex']!=peer_outer['ifindex']
state['peer_interfaces']={'outer':peer_outer,'lan':peer_lan};save()
resolved=json.loads(out('exec',peer,'ip','-j','-4','route','get','198.19.241.10','from',peerip));assert len(resolved)==1 and resolved[0].get('dev')=='eth0' and resolved[0].get('from')==peerip and not resolved[0].get('gateway') and not resolved[0].get('flags')
for address in outside:out('exec',peer,'ip','addr','add',address+'/32','dev','eth0')
if a.scenario=='limits':out('exec',peer,'ip','addr','add','10.31.0.1/24','dev','eth1')
def planned_route(cid,destination,via,dev,metric,preferred_source=None):
 obligation={'container_id':cid,'destination':destination,'gateway':via,'dev':dev,'table':254,'protocol':'static','metric':metric,'state':'pending'}
 if preferred_source is not None:
  source_interface=physical(cid,dev,preferred_source,32);obligation['preferred_source']=preferred_source;obligation['source_interface']=source_interface
 state['route_obligations'].append(obligation);save()
 args=['exec',cid,'ip','route','add',destination,'via',via,'dev',dev,'table','254','proto','static','metric',str(metric)]
 if preferred_source is not None:args+=['src',preferred_source]
 out(*args)
 rows=json.loads(out('exec',cid,'ip','-j','-4','route','show','table','main','exact',destination))
 assert len(rows)==1 and str(ipaddress.ip_network(rows[0].get('dst','invalid')))==destination and rows[0].get('gateway')==via and rows[0].get('dev')==dev and rows[0].get('protocol')=='static' and rows[0].get('metric')==metric and not rows[0].get('flags') and rows[0].get('type','unicast')=='unicast' and rows[0].get('table',254)in [254,'main'] and not any(x in rows[0] for x in ['nexthops','nhid','encap','encap_type'])
 if preferred_source is not None:
  assert rows[0].get('prefsrc')==preferred_source
  resolved=json.loads(out('exec',cid,'ip','-j','-4','route','get',str(ipaddress.ip_network(destination).network_address)));assert len(resolved)==1 and resolved[0].get('dev')==dev and resolved[0].get('gateway')==via and resolved[0].get('prefsrc')==preferred_source and not resolved[0].get('flags')
  obligation['source_route_readback']=resolved[0]
 obligation['state']='installed';obligation['readback']=rows[0];save()
planned_route(peer,'13.63.169.255/32','198.19.241.10','eth0',51030 if a.scenario=='limits' else 51032,outside[0])
for address in outside:planned_route(gw,address+'/32',peerip,'eth1',51030 if a.scenario=='limits' else 51032,'13.63.169.255')
if a.scenario=='static':
 target=out('create','--name',project+'-target','--label',label+'='+project,'--label','com.docker.compose.project='+project,'--network',state['networks']['lan'],'--ip','10.32.0.2','--cap-drop','ALL','--cap-add','NET_ADMIN','--read-only','--security-opt','no-new-privileges','--tmpfs','/test:rw,exec,nosuid,nodev,size=16m','--pids-limit','64','--entrypoint','/bin/sh',image,'-c','sleep 86400');state['containers']['target']=target;save();out('start',target)
 out('exec',target,'ip','route','add','10.10.0.0/24','via','10.32.0.1');planned_route(client['Id'],'10.32.0.0/24','10.10.0.1','eth0',51032)
 binary=(r/'.runtime/bin/packet-probe').read_bytes();stream=io.BytesIO()
 with tarfile.open(fileobj=stream,mode='w')as archive:
  entry=tarfile.TarInfo('packet-probe');entry.size=len(binary);entry.mode=0o700;entry.uid=entry.gid=0;archive.addfile(entry,io.BytesIO(binary))
 subprocess.run(d+['exec','-i',target,'tar','-xf','-','-C','/test'],input=stream.getvalue(),check=True)
 out('exec','-d',target,'/test/packet-probe','server','10.32.0.2:18080');state['target_probe_sha256']=hashlib.sha256(binary).hexdigest()
state['readback']={'peer_links':json.loads(out('exec',peer,'ip','-j','-d','link','show')),'peer_addresses':json.loads(out('exec',peer,'ip','-j','addr','show')),'peer_routes':json.loads(out('exec',peer,'ip','-j','-4','route','show')),'gateway_added_routes':[json.loads(out('exec',gw,'ip','-j','-4','route','show','exact',x+'/32'))for x in outside]};save()
print(json.dumps({'project':project,'state':str(a.state),'containers':state['containers'],'daemons_started':False,'activation_performed':False}))
