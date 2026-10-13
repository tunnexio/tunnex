#!/usr/bin/env python3
"""Prepare owned packet topology only: no IPsec/BGP daemons or CP activation."""
import hashlib,json,os,pathlib,subprocess,ipaddress
os.umask(0o077)
root=pathlib.Path(__file__).resolve().parent;repo=root.parent.parent
subprocess.run([str(root/'ownership.py')],check=True)
docker=[str(root/'docker-local.sh')];project='tunnexs2sbgpintegrated1007';label='tunnex.bgp.integrated';marker=root/'.runtime/integrated-topology.json'
image='sha256:6f97edac6ae8ce1cf05ed9c5b98aa014c7d85185f2774f828b51026473771d7f'
def out(*args):return subprocess.check_output(docker+list(args),text=True).strip()
def inspect(kind,name):
 p=subprocess.run(docker+[kind,'inspect',name],capture_output=True,text=True)
 return json.loads(p.stdout)[0]if p.returncode==0 else None
state=json.loads(marker.read_text())if marker.exists()else {'checkout':str(repo),'project':project,'image':image,'networks':{},'containers':{}}
assert state['checkout']==str(repo)and state['image']==image
assert inspect('image',image)['Architecture']=='arm64','Native package image mismatch'
gw=inspect('container','tunnexs2sbgplocal1007-gateway-1');assert gw and gw['Config']['Labels']['com.docker.compose.project']=='tunnexs2sbgplocal1007'
if state.get('gateway_id'):assert state['gateway_id']==gw['Id'],'Serving gateway identity changed; inspect exact new ownership before reconnect'
state['gateway_id']=gw['Id']
networks={'outer':'198.19.241.0/24','local':'10.10.0.0/24','remote':'10.20.0.0/24'}
# Validate all owned names and overlapping foreign network IPAM before mutations.
for role,cidr in networks.items():
 name=project+'-'+role;current=inspect('network',name);prior=state['networks'].get(role)
 if current:assert prior and current['Id']==prior and current['Labels'].get(label)==project,'Unrecorded/foreign network collision'
 else:assert not prior,'Recorded network disappeared'
for role in ['peer','client','target']:
 current=inspect('container',project+'-'+role);prior=state['containers'].get(role)
 if current:assert prior and current['Id']==prior and current['Config']['Labels'].get(label)==project,'Unrecorded/foreign container collision'
 else:assert not prior,'Recorded container disappeared'
for nid in out('network','ls','-q').splitlines():
 n=inspect('network',nid)
 if n['Labels'].get(label)==project:continue
 for cfg in (n['IPAM'].get('Config')or[]):
  if cfg.get('Subnet'):
   foreign=ipaddress.ip_network(cfg['Subnet'])
   for cidr in networks.values():assert not(foreign.version==4 and foreign.overlaps(ipaddress.ip_network(cidr))),'Foreign network overlaps fixture CIDR'
def save():marker.write_text(json.dumps(state,indent=2)+'\n')
for role,cidr in networks.items():
 if role not in state['networks']:
  # Bridge gateway .254 avoids conflicting with actual product gateway/peer .1.
  net=ipaddress.ip_network(cidr);state['networks'][role]=out('network','create','--internal','--driver','bridge','--subnet',cidr,'--gateway',str(net.network_address+254),'--label',label+'='+project,project+'-'+role);save()
for role,net,addr in [('peer','outer','198.19.241.20'),('client','local','10.10.0.2'),('target','remote','10.20.0.2')]:
 if role not in state['containers']:
  args=['create','--name',project+'-'+role,'--label',label+'='+project,'--label','com.docker.compose.project='+project,'--network',project+'-'+net,'--ip',addr,'--cap-drop','ALL','--cap-add','NET_ADMIN','--read-only','--security-opt','no-new-privileges','--tmpfs','/run:rw,nosuid,nodev,size=16m','--tmpfs','/test:rw,exec,nosuid,nodev,size=32m','--tmpfs','/var/tmp/frr:rw,nosuid,nodev,size=8m','--pids-limit','128','--entrypoint','/bin/sh']
  if role=='peer':args+=['--cap-add','NET_RAW','--cap-add','NET_BIND_SERVICE','--cap-add','SETUID','--cap-add','SETGID','--sysctl','net.ipv4.ip_forward=1']
  state['containers'][role]=out(*args,image,'-c','sleep 86400');save()
 for_container=inspect('container',state['containers'][role])
 if not for_container['State']['Running']:out('start',state['containers'][role])
def connect(cid,role,addr):
 c=inspect('container',cid);name=project+'-'+role
 if name in c['NetworkSettings']['Networks']:assert c['NetworkSettings']['Networks'][name]['IPAddress']==addr
 else:out('network','connect','--ip',addr,name,cid)
connect(state['containers']['peer'],'remote','10.20.0.1')
connect(gw['Id'],'outer','198.19.241.10');connect(gw['Id'],'local','10.10.0.1')
out('exec',state['containers']['peer'],'ip','address','replace','198.19.241.21/24','dev','eth0')
out('exec',state['containers']['client'],'ip','route','replace','10.20.0.0/24','via','10.10.0.1')
out('exec',state['containers']['target'],'ip','route','replace','10.10.0.0/24','via','10.20.0.1')
state['activation_performed']=False;state['daemons_started']=False;save()
print(json.dumps({'project':project,'networks':state['networks'],'containers':state['containers'],'gateway_id':gw['Id'],'activation_performed':False,'daemons_started':False},indent=2))
