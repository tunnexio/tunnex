"""Owned internal-network qualification. No host mounts, published ports or cloud."""
import argparse,hashlib,io,json,os,pathlib,secrets,string,subprocess,tarfile,time,queue,threading,re,tempfile
from qualification_helpers import remove_lab_gateway_dns_table
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary",required=True,type=pathlib.Path)
parser.add_argument("--binary-sha256",required=True)
parser.add_argument("--docker-context",default="colima-f10-dev")
parser.add_argument("--candidate-image",default="sha256:f198e0e42f53e507b00ebf3e2450c65dc7dc2a2278b3b8beec3386841bd4fe90")
parser.add_argument("--tools-image",default="sha256:8e7153d3bcfa7f2f0215881806132bc7c02c9ceade13a8bc71a05e725d35e73a")
parser.add_argument("--native-arch",choices=("amd64","arm64"),default="arm64")
parser.add_argument("--project",default="tunnexs2scoexist0924")
parser.add_argument("--evidence-dir",type=pathlib.Path,help="New directory; refuses an existing path")
parser.add_argument("--recovery",action="store_true",help="Qualify automatic alternate-path recovery")
parser.add_argument("--rotation",action="store_true",help="Qualify acknowledged-cleanup PSK maintenance rotation; requires --recovery")
args=parser.parse_args()
if args.rotation and not args.recovery:parser.error("rotation requires recovery fixture")
if not re.fullmatch(r"tunnexs2s[a-z0-9-]{1,40}",args.project):parser.error("expected dedicated tunnexs2s project")
for value in (args.candidate_image,args.tools_image):
 if not re.fullmatch(r"sha256:[0-9a-f]{64}",value):parser.error("image must be immutable sha256 ID")
if not re.fullmatch(r"[0-9a-f]{64}",args.binary_sha256):parser.error("invalid binary digest")
if args.evidence_dir:
 args.evidence_dir.mkdir(mode=0o700,parents=False,exist_ok=False)
 evidence=args.evidence_dir.resolve()
else:evidence=pathlib.Path(tempfile.mkdtemp(prefix="s2s-coexistence-"))
if not __debug__:raise RuntimeError("assertion guards require normal Python mode")
project=args.project;network=project+'-private'
nets={};spec={'private':'198.19.240.0/24','left':'10.10.0.0/24','right':'10.20.0.0/24'}
primary={'gateway':'private','peer':'private','client':'left','server':'right','vpnclient':'private'}
image=args.candidate_image
tools_image=args.tools_image
observer_id=None
def role_image(role):return image if role in ['gateway','peer','vpnclient'] else tools_image
docker=['docker','--context',args.docker_context];containers={};nid=None;observers=[]
binary=args.binary.read_bytes()
assert len(args.binary_sha256)==64 and hashlib.sha256(binary).hexdigest()==args.binary_sha256
# Reject remote Docker transports; this fixture only changes a local daemon.
endpoint=json.loads(subprocess.check_output(docker+['context','inspect',args.docker_context]))[0]['Endpoints']['docker']['Host']
assert endpoint.startswith('unix:///')
if args.docker_context=='colima-f10-dev':assert endpoint.endswith('/.colima/f10-dev/docker.sock')
# Match the actual ELF machine as well as the daemon/image; no QEMU qualification.
assert binary[:6]==b'\x7fELF\x02\x01'
assert int.from_bytes(binary[18:20],'little')=={'amd64':62,'arm64':183}[args.native_arch]
info=json.loads(subprocess.check_output(docker+['info','--format','{{json .}}']))
assert info['OSType']=='linux' and info['Architecture'] in {'arm64':('aarch64','arm64'),'amd64':('x86_64','amd64')}[args.native_arch]
for image_id in (image,tools_image):
 metadata=json.loads(subprocess.check_output(docker+['image','inspect',image_id]))[0]
 assert metadata['Id']==image_id and metadata['Architecture']==args.native_arch and metadata['Os']=='linux'
print('Candidate='+image+' binary_sha256='+args.binary_sha256+' native_arch='+args.native_arch+' evidence='+str(evidence),flush=True)
receipt={'native_arch':args.native_arch,'docker_kernel':info['KernelVersion'],'candidate_image':image,'tools_image':tools_image,'binary_sha256':args.binary_sha256,'harness_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'project':project,'recovery':args.recovery,'rotation':args.rotation,'cp_lease':'synthetic','passed':False,'cleanup_complete':False}
(evidence/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
psks=[secrets.choice(string.ascii_letters)+''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(47)) for _ in range(2)]
print('COMPOSE_PROJECT_NAME='+project,flush=True)
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
 assert h['NetworkMode']==project+'-'+primary[role] and h['ReadonlyRootfs'] and not h['Privileged'] and not h.get('Binds') and h.get('Devices',[])==([{'PathOnHost':'/dev/net/tun','PathInContainer':'/dev/net/tun','CgroupPermissions':'rw'}] if role in ('gateway','vpnclient') else []) and not h.get('PortBindings') and h['PidMode']!='host'
 assert h['CapDrop']==['ALL'] and set(h['CapAdd'])=={'CAP_NET_ADMIN','CAP_NET_RAW','CAP_NET_BIND_SERVICE'} and all(m['Type']=='tmpfs' and m['Destination'] in ['/run','/test'] for m in o['Mounts'])
 for name,attachment in o['NetworkSettings']['Networks'].items():
  kind=name.removeprefix(project+'-');assert kind in nets
  assert attachment['NetworkID']==nets[kind] or (o['State']['Status']=='created' and attachment['NetworkID']=='')
 return cid

def run(role,args,**kwargs):
 kwargs.setdefault('timeout',30)
 return subprocess.run(docker+['exec',check(role)]+args,check=True,**kwargs)
def phase(role,step,lease=30):
 print('Phase '+role+' '+step,flush=True)
 request=json.dumps({'Role':role,'Phase':step,'PSKs':psks,'Forwarded':True,'LeaseSeconds':lease}).encode()
 result=subprocess.run(docker+['exec','-i',check(role),'env','TUNNEX_IPSEC_ENCRYPTED_LAB=1','/test/daemon.test','-test.run=^TestDaemonEncryptedLabPhase$','-test.v'],input=request)
 if result.returncode:
  (evidence/'failed-state-nokeys.txt').write_bytes(subprocess.check_output(docker+['exec',check(role),'ip','xfrm','state','list','nokeys']))
  (evidence/'failed-policy-nosock.txt').write_bytes(subprocess.check_output(docker+['exec',check(role),'ip','xfrm','policy','list','nosock']))
  raise RuntimeError('lab phase refused')

def check_observer():
 assert observer_id is not None
 gateway=check('gateway');o=json.loads(subprocess.check_output(docker+['inspect',observer_id]))[0];h=o['HostConfig']
 assert o['Id']==observer_id and o['Image']==tools_image and o['Name']=='/'+project+'-observer' and o['Config']['Labels']['com.docker.compose.project']==project
 assert h['NetworkMode']=='container:'+gateway and h['ReadonlyRootfs'] and not h['Privileged'] and not h.get('Binds') and not h.get('Devices') and not h.get('PortBindings') and h['PidMode']!='host'
 assert h['CapDrop']==['ALL'] and h['CapAdd']==['CAP_NET_RAW'] and all(m['Type']=='tmpfs' and m['Destination']=='/run' for m in o['Mounts'])
 if o['State']['Status']=='running':
  actual=subprocess.check_output(docker+['exec',observer_id,'readlink','/proc/self/ns/net']).strip()
  expected=subprocess.check_output(docker+['exec',gateway,'readlink','/proc/self/ns/net']).strip()
  assert actual==expected and actual.startswith(b'net:[')
 return observer_id

def watch(filter_expression):
 process=subprocess.Popen(docker+['exec',check_observer(),'timeout','4','tcpdump','-p','-n','-l','-i','eth0','-c','1',filter_expression],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 observers.append(process)
 while True:
  line=process.stderr.readline()
  if 'listening on' in line:return process
  if not line:raise RuntimeError('packet observer failed to become ready')

def client(protocol, expect=True):
 code='''import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if sys.argv[1]=='tcp' else socket.SOCK_DGRAM);s.settimeout(2)
p=b'TunnexSyntheticForwardedProbe'
try:
 if sys.argv[1]=='tcp':s.connect(('10.20.0.2',18080));s.sendall(p);r=s.recv(128)
 else:s.sendto(p,('10.20.0.2',18081));r=s.recv(128)
 sys.exit(0 if r==p else 2)
except (OSError,TimeoutError):sys.exit(3)
finally:s.close()
'''
 result=subprocess.run(docker+['exec',check('client'),'python3','-c',code,protocol])
 print('Forwarded '+protocol+' '+('delivered' if result.returncode==0 else 'refused'),flush=True)
 assert (result.returncode==0)==expect

def established_revocation():
 code="""import socket,sys
s=socket.socket();s.settimeout(2);s.connect(('10.20.0.2',18080));p=b'TunnexEstablishedProbe';s.sendall(p)
assert s.recv(128)==p
print('READY',flush=True)
assert sys.stdin.readline().strip()=='probe'
try:
 s.sendall(p);r=s.recv(128);sys.exit(1 if r==p else 0)
except (OSError,TimeoutError):sys.exit(0)
finally:s.close()
"""
 probe=subprocess.Popen(docker+['exec','-i',check('client'),'python3','-u','-c',code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);observers.append(probe)
 assert probe.stdout.readline().strip()=='READY'
 phase('gateway','deny')
 out,err=probe.communicate(input='probe\n',timeout=5)
 assert probe.returncode==0 and not out.strip()
 print('Previously established TCP flow refused after policy denial.',flush=True)

def legacy_exec(role,argv,data=None):
 result=subprocess.run(docker+['exec']+(['-i'] if data is not None else [])+[check(role)]+argv,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
 if result.returncode:raise RuntimeError('Legacy qualification command refused: '+argv[0])
 return result.stdout

def legacy_put(role,files):
 stream=io.BytesIO()
 with tarfile.open(fileobj=stream,mode='w') as archive:
  for name,body in files.items():
   assert '/' not in name
   item=tarfile.TarInfo(name);item.size=len(body);item.mode=0o600
   archive.addfile(item,io.BytesIO(body))
 legacy_exec(role,['tar','-x','-C','/run/compat'],stream.getvalue())

def make_memory_certificates():
 # Existing host OpenSSL; anonymous pipes only, no secret host filesystem files.
 def ssl(argv,inputs=()):
  opened=[]
  try:
   for flag,value in inputs:
    readfd,writefd=os.pipe();opened.append(readfd)
    try:
     if len(value)>4096:raise RuntimeError('synthetic PEM exceeds pipe bound')
     if os.write(writefd,value)!=len(value):raise RuntimeError('synthetic PEM pipe write failed')
    finally:os.close(writefd)
    argv += [flag,'/dev/fd/'+str(readfd)]
   result=subprocess.run(['openssl']+argv,pass_fds=opened,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
   if result.returncode:raise RuntimeError('synthetic PKI generation failed')
   return result.stdout
  finally:
   for fd in opened:os.close(fd)
 def pem(body,label):
  start=b'-----BEGIN '+label+b'-----';end=b'-----END '+label+b'-----'
  if body.count(start)!=1 or body.count(end)!=1:raise RuntimeError('synthetic PEM shape invalid')
  return body[body.index(start):body.index(end)+len(end)]+b'\n'
 ca_key=ssl(['genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048'])
 ca_cert=pem(ssl(['req','-x509','-days','1','-subj','/CN=tunnex-synthetic-compat-ca','-addext','basicConstraints=critical,CA:TRUE'],[('-key',ca_key)]),b'CERTIFICATE')
 files={'ca.crt':ca_cert}
 for serial,role in enumerate(('server','client'),1):
  key=ssl(['genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048'])
  csr=ssl(['req','-new','-subj','/CN=tunnex-synthetic-'+role],[('-key',key)])
  extension=('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='+('serverAuth' if role=='server' else 'clientAuth')+'\n').encode()
  certificate=ssl(['x509','-req','-set_serial',str(serial),'-days','1'],[('-in',csr),('-CA',ca_cert),('-CAkey',ca_key),('-extfile',extension)])
  files[role+'.key']=key;files[role+'.crt']=pem(certificate,b'CERTIFICATE')
 return files

legacy_expected=b'TunnexSyntheticConcurrentVPNPayload'
def setup_legacy():
 # All generated private keys remain in owned tmpfs or transient pipe memory.
 for role in ('gateway','vpnclient','server'):
  legacy_exec(role,['mkdir','-m','700','/run/compat'])
 certificates=make_memory_certificates()
 public={}
 for role in ('gateway','vpnclient'):
  public[role]=legacy_exec(role,['sh','-c','set -e; umask 077; wg genkey | tee /run/compat/wg.key | wg pubkey']).decode().strip()
  assert len(public[role])==44
 for role,other,own,remote,endpoint in [('gateway','vpnclient','10.77.0.1','10.77.0.2','198.19.240.30'),('vpnclient','gateway','10.77.0.2','10.77.0.1','198.19.240.10')]:
  legacy_exec(role,['ip','link','add','wgcompat','type','wireguard'])
  legacy_exec(role,['wg','set','wgcompat','private-key','/run/compat/wg.key','listen-port','51820','peer',public[other],'allowed-ips',remote+'/32','endpoint',endpoint+':51820','persistent-keepalive','1'])
  legacy_exec(role,['ip','address','add',own+'/24','dev','wgcompat'])
  legacy_exec(role,['ip','link','set','wgcompat','up'])
 for role,certrole,own,remote,endpoint in [('gateway','server','10.78.0.1','10.78.0.2','198.19.240.30'),('vpnclient','client','10.78.0.2','10.78.0.1','198.19.240.10')]:
  files={name:certificates[source] for name,source in [('ca.crt','ca.crt'),('leaf.crt',certrole+'.crt'),('leaf.key',certrole+'.key')]}
  config=f'''dev ovpncompat
dev-type tun
proto udp
port 1194
remote {endpoint} 1194
tls-{certrole}
ifconfig {own} {remote}
ca /run/compat/ca.crt
cert /run/compat/leaf.crt
key /run/compat/leaf.key
remote-cert-tls {'client' if certrole=='server' else 'server'}
verify-x509-name tunnex-synthetic-{'client' if certrole=='server' else 'server'} name
tls-version-min 1.2
data-ciphers AES-256-GCM
data-ciphers-fallback AES-256-GCM
tmp-dir /run/compat
verb 3
log /run/compat/openvpn.log
writepid /run/compat/openvpn.pid
'''
  if certrole=='server':config+='dh none\n'
  files['openvpn.conf']=config.encode();legacy_put(role,files);files.clear()
  legacy_exec(role,['openvpn','--config','/run/compat/openvpn.conf','--daemon'])
 certificates.clear()
 deadline=time.monotonic()+30
 while True:
  logs=[legacy_exec(role,['cat','/run/compat/openvpn.log']) for role in ('gateway','vpnclient')]
  if all(b'Initialization Sequence Completed' in log and b'Peer Connection Initiated' in log for log in logs):break
  if time.monotonic()>=deadline:raise RuntimeError('OpenVPN mutual TLS setup timeout')
  time.sleep(.25)
 legacy_put('gateway',{'payload':legacy_expected})
 listener="while true; do { printf 'HTTP/1.1 200 OK\\r\\nConnection: close\\r\\nContent-Length: "+str(len(legacy_expected))+"\\r\\n\\r\\n'; cat /run/compat/payload; } | busybox nc -l -p 8080 -w 3 >/dev/null; done"
 subprocess.run(docker+['exec','-d',check('gateway'),'sh','-c',listener],check=True,timeout=10)

def legacy_payloads():
 for interface,address in [('wgcompat','10.77.0.1'),('ovpncompat','10.78.0.1')]:
  route=legacy_exec('vpnclient',['ip','route','get',address]).decode()
  assert 'dev '+interface+' ' in route
  actual=legacy_exec('vpnclient',['wget','-T','3','-qO-','http://'+address+':8080/payload'])
  assert actual==legacy_expected
 for role in ('gateway','vpnclient'):
  rows=legacy_exec(role,['wg','show','wgcompat','latest-handshakes']).decode().strip().splitlines()
  assert len(rows)==1 and int(rows[0].split()[1])>0
 print('WireGuard and mutual-TLS OpenVPN payload delivered in controller gateway namespace.',flush=True)

try:
 for kind,subnet in spec.items():
  nets[kind]=subprocess.check_output(docker+['network','create','--internal','--subnet',subnet,'--gateway',subnet.split('0/24')[0]+'254','--label','com.docker.compose.project='+project,project+'-'+kind],text=True).strip();check_network()
 addresses={'gateway':'198.19.240.10','peer':'198.19.240.20','client':'10.10.0.2','server':'10.20.0.2','vpnclient':'198.19.240.30'}
 for role in primary:
  cid=subprocess.check_output(docker+['create']+(['--device','/dev/net/tun:/dev/net/tun:rw'] if role in ('gateway','vpnclient') else [])+['--name',project+'-'+role,'--label','com.docker.compose.project='+project,'--label','com.docker.compose.service='+role,'--network',project+'-'+primary[role],'--ip',addresses[role],'--cap-drop','ALL','--cap-add','NET_ADMIN','--cap-add','NET_RAW','--cap-add','NET_BIND_SERVICE','--sysctl','net.ipv4.ip_forward=1','--read-only','--tmpfs','/run:rw,nosuid,nodev,size=8m','--tmpfs','/test:rw,exec,nosuid,nodev,size=32m','--security-opt','no-new-privileges','--pids-limit','128','--memory','256m','--entrypoint','/bin/sh',role_image(role),'-c','sleep 900'],text=True).strip();containers[role]=cid;check(role)
  subprocess.run(docker+['start',cid],check=True,stdout=subprocess.DEVNULL)
 observer_id=subprocess.check_output(docker+['create','--name',project+'-observer','--label','com.docker.compose.project='+project,'--label','com.docker.compose.service=observer','--network','container:'+check('gateway'),'--cap-drop','ALL','--cap-add','NET_RAW','--read-only','--tmpfs','/run:rw,nosuid,nodev,size=8m','--security-opt','no-new-privileges','--pids-limit','32','--memory','64m','--entrypoint','/bin/sh',tools_image,'-c','sleep 900'],text=True).strip()
 check_observer();subprocess.run(docker+['start',observer_id],check=True,stdout=subprocess.DEVNULL);check_observer()
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
 server='''import socket,threading,time
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(('10.20.0.2',18081))
def udp():
 while True:
  p,a=u.recvfrom(256);u.sendto(p,a)
def echo(c):
 try:
  while True:
   p=c.recv(256)
   if not p:break
   c.sendall(p)
 finally:c.close()
threading.Thread(target=udp,daemon=True).start()
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('10.20.0.2',18080));s.listen(8)
while True:
 c,a=s.accept();threading.Thread(target=echo,args=(c,),daemon=True).start()
'''
 subprocess.run(docker+['exec','-i',check('server'),'/bin/sh','-c','set -e; umask 077; cat > /run/echo.py'],input=server.encode(),check=True)
 subprocess.run(docker+['exec','-d',check('server'),'python3','/run/echo.py'],check=True)
 run('gateway',['uname','-r']);run('gateway',['cat','/proc/uptime'])
 # This dedicated namespace uses literal lab addresses; remove only its Docker DNS table.
 remove_lab_gateway_dns_table(run)
 setup_legacy()
 legacy_payloads()
 phase('peer','stage')
 controller=subprocess.Popen(docker+['exec','-i',check('gateway'),'env','TMPDIR=/test','TUNNEX_IPSEC_CONTROLLER_LAB=1','TUNNEX_IPSEC_RECOVERY_LAB='+('1' if args.recovery else '0'),'TUNNEX_IPSEC_ROTATION_LAB='+('1' if args.rotation else '0'),'/test/daemon.test','-test.run=^TestRuntimeControllerNative$','-test.v'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 observers.append(controller)
 controller.stdin.write(json.dumps({'PSKs':psks})+'\n');controller.stdin.flush()
 controller_lines=queue.Queue()
 def read_controller():
  for line in controller.stdout:controller_lines.put(line)
  controller_lines.put('')
 threading.Thread(target=read_controller,daemon=True).start()
 def expect_marker(marker):
  deadline=time.monotonic()+45
  while True:
   line=controller_lines.get(timeout=max(0.01,deadline-time.monotonic()))
   if not line:raise RuntimeError('Controller phase failed before '+marker)
   print(line,end='',flush=True)
   if line.strip()==marker:return
 def signal(value):controller.stdin.write(value+'\n');controller.stdin.flush()
 expect_marker('RUNTIME_APPLIED')
 phase('peer','allow')
 encrypted=watch('ip proto 50 or udp port 4500');client('tcp');client('udp');out,err=encrypted.communicate(timeout=8);assert encrypted.returncode==0 and out.strip()
 legacy_payloads()
 signal('refresh');expect_marker('RUNTIME_REFRESHED');client('tcp');client('udp');legacy_payloads()
 if args.recovery:
  signal('failover');expect_marker('RUNTIME_RECOVERY_REFUSED')
  plaintext=watch('dst net 10.20.0.0/24');client('tcp',False);client('udp',False);out,err=plaintext.communicate(timeout=8);assert plaintext.returncode in (0,124,143) and not out.strip() and '0 packets captured' in err and '0 packets dropped by kernel' in err
  legacy_payloads()
  run('peer',['ip','-4','route','replace','10.10.0.0/24','dev','tnx-lab-b','table','220','proto','99','metric','10'])
  signal('recover');expect_marker('RUNTIME_RECOVERY_PENDING')
  plaintext=watch('dst net 10.20.0.0/24');client('tcp',False);client('udp',False);out,err=plaintext.communicate(timeout=8);assert plaintext.returncode in (0,124,143) and not out.strip() and '0 packets captured' in err and '0 packets dropped by kernel' in err
  legacy_payloads()
  signal('resume-pending');expect_marker('RUNTIME_RECOVERED')
  encrypted=watch('host 198.19.240.21 and (ip proto 50 or udp port 4500)');client('tcp');client('udp');out,err=encrypted.communicate(timeout=8);assert encrypted.returncode==0 and out.strip()
  legacy_payloads()
  signal('restore-primary');expect_marker('RUNTIME_NO_FAILBACK');client('tcp');client('udp');legacy_payloads()
 signal('restart');expect_marker('RUNTIME_RESTART_REFUSAL')
 plaintext=watch('dst net 10.20.0.0/24');client('tcp',False);client('udp',False);out,err=plaintext.communicate(timeout=8);assert plaintext.returncode in (0,124,143) and not out.strip() and '0 packets captured' in err and '0 packets dropped by kernel' in err
 legacy_payloads()
 if args.recovery:
  signal('resume');expect_marker('RUNTIME_RECOVERY_RESUMED')
  encrypted=watch('host 198.19.240.21 and (ip proto 50 or udp port 4500)');client('tcp');client('udp');out,err=encrypted.communicate(timeout=8);assert encrypted.returncode==0 and out.strip()
  legacy_payloads()
 signal('cleanup');expect_marker('RUNTIME_CLEANED_GUARD_RETAINED');client('tcp',False);client('udp',False);legacy_payloads()
 if args.rotation:
  replacement_psks=[secrets.choice(string.ascii_letters)+''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(47)) for _ in range(2)]
  controller.stdin.write(json.dumps({'PSKs':replacement_psks})+'\n');controller.stdin.flush()
  expect_marker('RUNTIME_ROTATION_OLD_KEY_REFUSED')
  plaintext=watch('dst net 10.20.0.0/24');client('tcp',False);client('udp',False);out,err=plaintext.communicate(timeout=8);assert plaintext.returncode in (0,124,143) and not out.strip() and '0 packets captured' in err and '0 packets dropped by kernel' in err
  legacy_payloads()
  phase('peer','cleanup-all');psks.clear();psks=replacement_psks;replacement_psks=[]
  phase('peer','stage')
  run('peer',['ip','-4','route','replace','10.10.0.0/24','dev','tnx-lab-a','table','220','proto','99','metric','10'])
  signal('rotated-peer-ready');expect_marker('RUNTIME_ROTATION_APPLIED');phase('peer','allow')
  encrypted=watch('host 198.19.240.20 and (ip proto 50 or udp port 4500)');client('tcp');client('udp');out,err=encrypted.communicate(timeout=8);assert encrypted.returncode==0 and out.strip()
  legacy_payloads()
  signal('cleanup-rotation');expect_marker('RUNTIME_ROTATION_CLEANED');client('tcp',False);client('udp',False);legacy_payloads()
 signal('done');controller.stdin.close();controller.wait(timeout=10);assert controller.returncode==0
 observers.remove(controller)
 phase('peer','cleanup-all')
 receipt['passed']=True
 print('Concurrent IPsec TCP/UDP + WireGuard + OpenVPN payload PASS on exact candidate gateway; legacy payload preserved across IPsec renewal, restart refusal and retained cleanup. CP lease synthetic.',flush=True)

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
 psks.clear();receipt['cleanup_complete']=True
 (evidence/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
 print('Removed only captured owned forwarded-lab resources.',flush=True)
