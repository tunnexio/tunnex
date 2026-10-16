"""Owned internal-network qualification. No host mounts, published ports or cloud."""
import argparse,hashlib,json,pathlib,re,secrets,string,subprocess,tempfile,time
a=argparse.ArgumentParser();a.add_argument("--binary",type=pathlib.Path,default=pathlib.Path("/private/tmp/docker-host-native.test"));a.add_argument("--negative-rule",action="store_true");a.add_argument("--docker-host");a.add_argument("--image",required=True);options=a.parse_args()
class ExpectedProbeRefusal(Exception):pass
project='tunnexdockerhost'+secrets.token_hex(4);network=project+'-private'
nets={};spec={'private':'198.19.240.0/24','left':'10.10.0.0/24','right':'10.20.0.0/24'}
primary={'gateway':'private','peer':'private','client':'left','server':'right'}
image=None
tools_image=image
observer_id=None
def role_image(role):return image if role in ['gateway','peer'] else tools_image
endpoint=options.docker_host or subprocess.check_output(['docker','context','inspect','--format','{{.Endpoints.docker.Host}}'],text=True).strip()
assert endpoint.startswith('unix://'),'Local Unix Docker endpoint only'
docker=['docker','--host',endpoint];containers={};nid=None;observers=[]
image=subprocess.check_output(docker+['image','inspect',options.image,'--format','{{.Id}}'],text=True).strip();assert image.startswith('sha256:') and len(image)==71
tools_image=image
report=pathlib.Path(tempfile.mkdtemp(prefix='tunnex-docker-native-',dir='/private/tmp'));report.chmod(0o700)
binary=options.binary.read_bytes()
psks=[secrets.choice(string.ascii_letters)+''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(47)) for _ in range(2)]
print('COMPOSE_PROJECT_NAME='+project+' binarySHA256='+hashlib.sha256(binary).hexdigest()+' report='+str(report),flush=True)
for kind,name in [('network',project+'-'+n) for n in spec]+[('container',project+'-'+r) for r in list(primary)+['observer']]:
 assert subprocess.run(docker+[kind,'inspect',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0

def check_network():
 for kind,nid in nets.items():
  o=json.loads(subprocess.check_output(docker+['network','inspect',nid]))[0]
  assert o['Id']==nid and o['Name']==project+'-'+kind and o['Labels']['com.docker.compose.project']==project and o['Internal'] and o['Driver']=='bridge'
  assert o['IPAM']['Config'][0]['Subnet']==spec[kind] and o['IPAM']['Config'][0]['Gateway']==spec[kind].split('0/24')[0]+'254'
 print('Verified captured internal networks='+','.join(nets),flush=True)
def check(role):
 check_network();cid=containers[role];o=json.loads(subprocess.check_output(docker+['inspect',cid]))[0];h=o['HostConfig']
 assert o['Id']==cid and o['Image']==role_image(role) and o['Name']=='/'+project+'-'+role and o['Config']['Labels']['com.docker.compose.project']==project
 assert h['NetworkMode']==project+'-'+primary[role] and h['ReadonlyRootfs'] and not h['Privileged'] and not h.get('Binds') and not h.get('Devices') and not h.get('PortBindings') and h['PidMode']!='host'
 assert h['CapDrop']==['ALL'] and set(h['CapAdd'])=={'CAP_NET_ADMIN','CAP_NET_RAW','CAP_NET_BIND_SERVICE'} and all(m['Type']=='tmpfs' and m['Destination'] in ['/run','/test'] for m in o['Mounts'])
 for name,attachment in o['NetworkSettings']['Networks'].items():
  kind=name.removeprefix(project+'-');assert kind in nets
  assert attachment['NetworkID']==nets[kind] or (o['State']['Status']=='created' and attachment['NetworkID']=='')
 return cid

def run(role,args,**kwargs):return subprocess.run(docker+['exec',check(role)]+args,check=True,**kwargs)
def foreign_filter():
 raw=subprocess.check_output(docker+['exec',check('gateway'),'iptables-nft-save','-t','filter'],text=True)
 return [re.sub(r'\[\d+:\d+\]','[counter]',line) for line in raw.splitlines() if line and not line.startswith('#') and 'tunnex-ipsec-fwd:' not in line]

def phase(role,step,lease=30):
 print('Phase '+role+' '+step,flush=True)
 request=json.dumps({'Role':role,'Phase':step,'PSKs':psks,'Forwarded':True,'LeaseSeconds':lease}).encode()
 result=subprocess.run(docker+['exec','-i',check(role),'env','TUNNEX_IPSEC_ENCRYPTED_LAB=1','/test/daemon.test','-test.run=^TestDaemonEncryptedLabPhase$','-test.v'],input=request)
 if result.returncode:
  (report/'failed-state-nokeys.txt').write_bytes(subprocess.check_output(docker+['exec',check(role),'ip','xfrm','state','list','nokeys']))
  (report/'failed-policy-nosock.txt').write_bytes(subprocess.check_output(docker+['exec',check(role),'ip','xfrm','policy','list','nosock']))
  raise RuntimeError('lab phase refused')

def encrypted_counters():
 raw=subprocess.check_output(docker+['exec',check('gateway'),'env','TUNNEX_DOCKER_HOST_PACKET=1','/test/daemon.test','-test.run=^TestDockerHostNativeEncryptedCounters$','-test.v','-test.timeout=8s'],text=True)
 lines=[v for v in raw.splitlines() if v.startswith('ENCRYPTED_COUNTERS ')];assert len(lines)==1
 return json.loads(lines[0].split(' ',1)[1])

def client(protocol, expect=True, wrongport=False):
 nonce=secrets.token_hex(32)
 result=subprocess.run(docker+['exec',check('client'),'env','TUNNEX_DOCKER_HOST_PACKET=1','TUNNEX_PACKET_ROLE=client','TUNNEX_PACKET_PROTOCOL='+protocol,'TUNNEX_PACKET_WRONGPORT='+('1' if wrongport else '0'),'TUNNEX_PACKET_NONCE='+nonce,'TUNNEX_PACKET_EXPECT='+('allow' if expect else 'deny'),'/test/daemon.test','-test.run=^TestDockerHostNativePacketEndpoint$','-test.v','-test.timeout=8s'])
 assert result.returncode==0


try:
 for kind,subnet in spec.items():
  nets[kind]=subprocess.check_output(docker+['network','create','--internal','--subnet',subnet,'--gateway',subnet.split('0/24')[0]+'254','--label','com.docker.compose.project='+project,project+'-'+kind],text=True).strip();check_network()
 addresses={'gateway':'198.19.240.10','peer':'198.19.240.20','client':'10.10.0.2','server':'10.20.0.2'}
 for role in primary:
  cid=subprocess.check_output(docker+['create','--name',project+'-'+role,'--label','com.docker.compose.project='+project,'--label','com.docker.compose.service='+role,'--network',project+'-'+primary[role],'--ip',addresses[role],'--cap-drop','ALL','--cap-add','NET_ADMIN','--cap-add','NET_RAW','--cap-add','NET_BIND_SERVICE','--sysctl','net.ipv4.ip_forward=1','--read-only','--tmpfs','/run:rw,nosuid,nodev,size=8m','--tmpfs','/test:rw,exec,nosuid,nodev,size=32m','--security-opt','no-new-privileges','--pids-limit','128','--memory','256m','--entrypoint','/bin/sh',role_image(role),'-c','sleep 900'],text=True).strip();containers[role]=cid;check(role)
  subprocess.run(docker+['start',cid],check=True,stdout=subprocess.DEVNULL)
 for role,lan in [('gateway','left'),('peer','right')]:
  check(role);subprocess.run(docker+['network','connect','--ip','10.10.0.1' if role=='gateway' else '10.20.0.1',nets[lan],containers[role]],check=True);check(role)
  run(role,['/bin/sh','-c','set -e; mkdir -m 700 /run/tunnex-ipsec'])
  subprocess.run(docker+['exec','-i',check(role),'/bin/sh','-c','set -e; umask 077; cat > /test/daemon.test; chmod 700 /test/daemon.test'],input=binary,check=True)
  if role=='gateway':continue
  config=b'''charon {
 load = random nonce openssl kdf kernel-netlink socket-default vici
 install_routes = no
 install_virtual_ip = no
 plugins {
  kernel-netlink { install_routes_xfrmi = no }
  vici { socket = unix:///run/tunnex-ipsec/charon.vici }
 }
 filelog {
  stderr { default = -1 }
 }
}
'''
  subprocess.run(docker+['exec','-i',check(role),'/bin/sh','-c','set -e; umask 077; cat > /run/tunnex-ipsec/strongswan.conf'],input=config,check=True)
  run(role,['/bin/sh','-c','set -e; umask 077; STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf /opt/tunnex-ipsec/libexec/ipsec/charon > /run/tunnex-ipsec/daemon.log 2>&1 & echo $! > /run/tunnex-ipsec/daemon.pid'])
  run(role,['/bin/sh','-c','set -e; for n in 1 2 3 4 5; do test -S /run/tunnex-ipsec/charon.vici && break; sleep 1; done; test -S /run/tunnex-ipsec/charon.vici; chmod 600 /run/tunnex-ipsec/charon.vici'])
  if role=='peer':run(role,['ip','address','add','198.19.240.21/24','dev','eth0'])
  for iface,xid in [('tnx-lab-a',701 if role=='gateway' else 801),('tnx-lab-b',702 if role=='gateway' else 802)]:
   run(role,['ip','link','add',iface,'type','xfrm','if_id',str(xid)]);run(role,['ip','link','set',iface,'up'])
  destination='10.20.0.0/24' if role=='gateway' else '10.10.0.0/24';peer='198.19.240.20' if role=='gateway' else '198.19.240.10'
  run(role,['ip','-4','route','add',destination,'dev','tnx-lab-a','table','220','proto','99','metric','10'])
  run(role,['ip','-4','rule','add','to',destination,'lookup','220','priority','27000'])
  run(role,['ip','-4','route','add',destination,'via',peer,'dev','eth0','proto','99'])
 run('client',['ip','route','add','10.20.0.0/24','via','10.10.0.1'])
 run('server',['ip','route','add','10.10.0.0/24','via','10.20.0.1'])
 for role in ['client','server']:
  subprocess.run(docker+['exec','-i',check(role),'/bin/sh','-c','umask 077; cat > /test/daemon.test; chmod 700 /test/daemon.test'],input=binary,check=True)
 serverproc=subprocess.Popen(docker+['exec',check('server'),'env','TUNNEX_DOCKER_HOST_PACKET=1','TUNNEX_PACKET_ROLE=server','/test/daemon.test','-test.run=^TestDockerHostNativePacketEndpoint$','-test.v','-test.timeout=190s'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 observers.append(serverproc)
 while True:
  line=serverproc.stdout.readline()
  if not line:raise RuntimeError('endpoint startup failed')
  if 'DOCKER_NATIVE_ENDPOINT_READY' in line:break
 run('gateway',['uname','-r']);run('gateway',['cat','/proc/uptime'])
 # This is a fresh-host model, not Docker's container-local DNS namespace.
 # Remove only the automatic DNS table in this disposable owned namespace
 # before building the exact standalone-host nat/filter fixture.
 run('gateway',['nft','delete','table','ip','nat'])
 # Exact Docker29-style rules live ONLY inside the owned gateway namespace.
 run('gateway',['ip','link','add','docker0','type','bridge'])
 run('gateway',['ip','addr','add','172.17.0.1/16','dev','docker0'])
 run('gateway',['ip','link','set','docker0','up'])
 for chain in ['DOCKER','DOCKER-USER','DOCKER-FORWARD','DOCKER-CT','DOCKER-INTERNAL','DOCKER-BRIDGE']:
  run('gateway',['iptables-nft','-N',chain])
 rules=[['-P','FORWARD','DROP'],['-A','FORWARD','-j','DOCKER-USER'],['-A','FORWARD','-j','DOCKER-FORWARD'],['-A','DOCKER-FORWARD','-j','DOCKER-CT'],['-A','DOCKER-FORWARD','-j','DOCKER-INTERNAL'],['-A','DOCKER-FORWARD','-j','DOCKER-BRIDGE'],['-A','DOCKER-FORWARD','-i','docker0','-j','ACCEPT'],['-A','DOCKER-CT','-o','docker0','-m','conntrack','--ctstate','RELATED,ESTABLISHED','-j','ACCEPT'],['-A','DOCKER-BRIDGE','-o','docker0','-j','DOCKER'],['-A','DOCKER','!','-i','docker0','-o','docker0','-j','DROP']]
 for args in rules:run('gateway',['iptables-nft',*args])
 run('gateway',['iptables-nft','-t','nat','-N','DOCKER'])
 for args in [['-A','PREROUTING','-m','addrtype','--dst-type','LOCAL','-j','DOCKER'],['-A','OUTPUT','!','-d','127.0.0.0/8','-m','addrtype','--dst-type','LOCAL','-j','DOCKER'],['-A','POSTROUTING','-s','172.17.0.0/16','!','-o','docker0','-j','MASQUERADE']]:
  run('gateway',['iptables-nft','-t','nat',*args])
 # Exact IPv6 Docker host inventory (no enabled IPv6 bridge).
 for chain in ['DOCKER','DOCKER-USER','DOCKER-FORWARD','DOCKER-CT','DOCKER-INTERNAL','DOCKER-BRIDGE']:
  run('gateway',['ip6tables-nft','-N',chain])
 for command in [['-A','FORWARD','-j','DOCKER-USER'],['-A','FORWARD','-j','DOCKER-FORWARD'],['-A','DOCKER-FORWARD','-j','DOCKER-CT'],['-A','DOCKER-FORWARD','-j','DOCKER-INTERNAL'],['-A','DOCKER-FORWARD','-j','DOCKER-BRIDGE']]:
  run('gateway',['ip6tables-nft',*command])
 run('gateway',['ip6tables-nft','-t','nat','-N','DOCKER'])
 for command in [['-A','PREROUTING','-m','addrtype','--dst-type','LOCAL','-j','DOCKER'],['-A','OUTPUT','!','-d','::1/128','-m','addrtype','--dst-type','LOCAL','-j','DOCKER']]:
  run('gateway',['ip6tables-nft','-t','nat',*command])
 if options.negative_rule:run('gateway',['iptables-nft','-A','DOCKER-USER','-j','ACCEPT'])
 run('gateway',['iptables-nft-save'])
 baseline='table ip tunnex {\n chain postrouting { type nat hook postrouting priority 99; policy accept; ip saddr 10.99.0.0/24 oifname != "wg0" masquerade; }\n chain forward { type filter hook forward priority 0; policy drop;\n ct state established,related accept\n ct state invalid counter drop comment "tunnex_ct_invalid_drop"\n iifname != "wg0" oifname != "wg0" counter accept comment "tunnex_native_forward_passthrough"\n iifname "wg0" oifname "wg0" tcp flags syn tcp option maxseg size set rt mtu\n iifname "wg0" oifname "wg0" counter accept\n iifname "wg0" oifname != "wg0" counter accept\n }\n}\ntable ip6 tunnex {\n chain postrouting { type nat hook postrouting priority 99; policy accept; }\n chain forward { type filter hook forward priority 0; policy drop;\n ct state established,related accept\n ct state invalid counter drop comment "tunnex_ct_invalid_drop"\n iifname != "wg0" oifname != "wg0" counter accept comment "tunnex_native_forward_passthrough"\n iifname "wg0" oifname "wg0" counter accept\n iifname "wg0" oifname != "wg0" counter accept\n }\n}\n'
 subprocess.run(docker+['exec','-i',check('gateway'),'nft','-f','-'],input=baseline.encode(),check=True)

 docker_before=foreign_filter();assert ':FORWARD DROP [counter]' in docker_before
 phase('peer','stage')
 controller=subprocess.Popen(docker+['exec','-i',check('gateway'),'env','TMPDIR=/test','TUNNEX_IPSEC_CONTROLLER_LAB=1','/test/daemon.test','-test.run=^TestRuntimeControllerNative$','-test.v'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 observers.append(controller)
 controller.stdin.write(json.dumps({'PSKs':psks})+'\n');controller.stdin.flush()
 def expect_marker(marker):
  seen=[]
  while True:
   line=controller.stdout.readline()
   if not line:
    controller.wait(timeout=5)
    if options.negative_rule and marker=='RUNTIME_APPLIED' and controller.returncode==1 and any('native platform probe' in v for v in seen):raise ExpectedProbeRefusal()
    raise RuntimeError('Controller phase failed before '+marker)
   seen.append(line);print(line,end='',flush=True)
   if line.strip()==marker:
    if options.negative_rule:raise RuntimeError('unknown Docker accept unexpectedly qualified')
    return
 def signal(value):controller.stdin.write(value+'\n');controller.stdin.flush()
 expect_marker('RUNTIME_APPLIED')
 phase('peer','allow')
 counter_before=encrypted_counters()
 client('tcp');client('udp');client('tcp',False,True);client('udp',False,True)
 counter_after=encrypted_counters()
 key=lambda r:(r['Name'],r['ReqID'],r['IfIDIn'],r['IfIDOut'],r['SPIIn'],r['SPIOut'])
 before_by={key(r):r for r in counter_before};assert set(before_by)=={key(r) for r in counter_after}
 assert any(r['BytesIn']>before_by[key(r)]['BytesIn'] and r['BytesOut']>before_by[key(r)]['BytesOut'] for r in counter_after),'encrypted same-SPI bidirectional byte growth absent'
 (report/'encrypted-counter-proof.json').write_text(json.dumps({'before':counter_before,'after':counter_after,'scope':'includes background; application payload independently matched'}))
 run('gateway',['iptables-nft-save','-t','filter'])
 assert foreign_filter()==docker_before,'foreign Docker rule order/content changed'
 signal('refresh');expect_marker('RUNTIME_REFRESHED');client('tcp');client('udp')
 signal('restart');expect_marker('RUNTIME_RESTART_REFUSAL')
 client('tcp',False);client('udp',False)
 signal('cleanup');expect_marker('RUNTIME_CLEANED_GUARD_RETAINED');client('tcp',False);client('udp',False)
 signal('done');controller.stdin.close();remaining=controller.stdout.read();print(remaining,flush=True);controller.wait(timeout=10);assert controller.returncode==0
 observers.remove(controller)
 assert foreign_filter()==docker_before,'foreign Docker state changed after exactcleanup'
 phase('peer','cleanup-all')
 print('Real controller composition: encrypted payload, SA-preserving renewal, offline startup denial, retained-guard exact cleanup PASS. CP lease synthetic.',flush=True)

except ExpectedProbeRefusal:
 print('Unknown broad Docker rule actual native qualification refusal PASS',flush=True)
finally:
 for observer in observers:
  if observer.poll() is None:observer.kill()
  try:observer.communicate(timeout=2)
  except subprocess.TimeoutExpired:observer.kill();observer.communicate()
 if observer_id:
  check_observer();subprocess.run(docker+['rm','-f',observer_id],check=True,stdout=subprocess.DEVNULL)
 for role,cid in list(containers.items()):
  check(role);subprocess.run(docker+['rm','-f',cid],check=True,stdout=subprocess.DEVNULL)
 for kind,nid in list(nets.items()):
  check_network();subprocess.run(docker+['network','rm',nid],check=True,stdout=subprocess.DEVNULL);del nets[kind]
 psks.clear();print('Removed only captured owned forwarded-lab resources.',flush=True)
