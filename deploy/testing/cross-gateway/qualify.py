#!/usr/bin/env python3
"""Disposable real-kernel qualification of CP projections and node enforcement.
No host network, production endpoint, provider credential, or persistent volume.
"""
import argparse,io,json,os,queue,subprocess,tarfile,threading,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
IMAGE='tunnex-gateway-qualification:local'
PROJECT='tunnexgatewaywire'+uuid.uuid4().hex[:10]
NETWORK=PROJECT+'-internal';LABEL='com.docker.compose.project'
PROOF=ROOT/'.gateway-update-proof';PROOF.mkdir(exist_ok=True)
EVIDENCE=PROOF/PROJECT;EVIDENCE.mkdir()
containers={};adapters={};network_id=None;image_id=None

def docker(args,body=None,check=True):
 return subprocess.run(['docker',*args],input=body,capture_output=True,check=check,timeout=40)
def read(args):return docker(args).stdout.decode().strip()
def verify():
 n=json.loads(read(['network','inspect',network_id]))[0]
 assert n['Id']==network_id and n['Name']==NETWORK and n['Internal'] and n['Labels'][LABEL]==PROJECT
 assert set(n.get('Containers',{})).issubset(set(containers.values()))
 for role,cid in containers.items():
  c=json.loads(read(['inspect',cid]))[0];h=c['HostConfig']
  assert c['Id']==cid and c['Name']=='/'+PROJECT+'-'+role and c['Config']['Labels'][LABEL]==PROJECT and c['Image']==image_id
  assert h['NetworkMode']==NETWORK and not h['Privileged'] and h['ReadonlyRootfs'] and h['CapDrop']==['ALL']
  assert {c.removeprefix('CAP_') for c in h.get('CapAdd',[])}=={'NET_ADMIN','NET_RAW'}
  assert h['Devices']==[{'PathOnHost':'/dev/net/tun','PathInContainer':'/dev/net/tun','CgroupPermissions':'rw'}]
  assert not h['PortBindings'] and h['PidMode']!='host' and not h.get('Binds')
  assert set(c['NetworkSettings']['Networks'])=={NETWORK}
  assert all(m['Type']=='tmpfs' for m in c['Mounts'])
def execute(role,args,body=None,check=True):
 verify()
 p=docker(['exec',*(['-i'] if body is not None else []),containers[role],*args],body,False)
 if check and p.returncode:raise RuntimeError(role+' '+str(args)+': '+p.stderr.decode())
 return p

def put(role,files):
 stream=io.BytesIO()
 with tarfile.open(fileobj=stream,mode='w') as archive:
  for name,body in files.items():
   if isinstance(body,str):body=body.encode()
   entry=tarfile.TarInfo(name);entry.size=len(body);entry.mode=0o700 if name.endswith('.test') else 0o600
   archive.addfile(entry,io.BytesIO(body))
 execute(role,['tar','-x','-C','/run/lab'],stream.getvalue())

def adapter(role):
 put(role,{'reconcile.test':(EVIDENCE/'adapter.test').read_bytes()})
 verify()
 p=subprocess.Popen(['docker','exec','-i','-e','TUNNEX_GATEWAY_LIVE_FIXTURE=owned-container',containers[role],'/run/lab/reconcile.test','-test.run=^TestCrossGatewayLiveAdapter$','-test.v'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
 q=queue.Queue();log=[]
 def drain():
  for line in p.stdout:log.append(line);q.put(line)
  q.put(None)
 threading.Thread(target=drain,daemon=True).start();adapters[role]=(p,q,log)

def apply(states):
 verify()
 for role,ds in states.items():
  p,q,log=adapters[role]
  if p.poll() is not None:raise RuntimeError('adapter exited '+role+': '+''.join(log))
  p.stdin.write(json.dumps(ds)+'\n');p.stdin.flush()
  deadline=time.monotonic()+30
  while True:
   line=q.get(timeout=max(.1,deadline-time.monotonic()))
   if line is None:raise RuntimeError('adapter stopped '+role+': '+''.join(log))
   if line.startswith('{') and json.loads(line).get('applied'):break
   if time.monotonic()>deadline:raise RuntimeError('adapter timeout '+role)
 time.sleep(.5)

def projections(cfg):
 inp=EVIDENCE/'input.json';out=EVIDENCE/'projections.json';inp.write_text(json.dumps(cfg))
 env=dict(os.environ,TUNNEX_GATEWAY_FIXTURE_INPUT=str(inp),TUNNEX_GATEWAY_FIXTURE_OUTPUT=str(out));env.pop('TUNNEX_TEST_DATABASE_URL',None);env.pop('DATABASE_URL',None)
 p=subprocess.run(['go','test','./internal/nodes','-run','^TestCrossGatewayExportLiveFixture$','-count=1','-v'],cwd=ROOT/'apps/api',env=env,capture_output=True,text=True,timeout=90)
 if p.returncode or '--- PASS: TestCrossGatewayExportLiveFixture' not in p.stdout:raise RuntimeError(p.stdout+p.stderr)
 return json.loads(out.read_text())

SERVER='''import socket,threading
def serve(c):
 try:
  while c.recv(4096):c.sendall(b"gateway-qualified\\n")
 except OSError:pass
 finally:c.close()
def listen(port):
 s=socket.socket(socket.AF_INET6);s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("::",port));s.listen()
 while True:
  c,_=s.accept();threading.Thread(target=serve,args=(c,),daemon=True).start()
for port in (8080,8081):threading.Thread(target=listen,args=(port,)).start()
'''
CLIENT='''import socket,sys
s=socket.socket(socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET);s.settimeout(1.5)
try:
 s.connect((sys.argv[1],int(sys.argv[2])));s.sendall(b"probe\\n");data=s.recv(4096);assert data==b"gateway-qualified\\n";print("PAYLOAD_OK")
except (OSError,AssertionError):sys.exit(3)
'''
STREAM='''import socket,time
s=socket.socket();s.settimeout(2);s.connect(("10.99.0.3",8080));n=0
try:
 while True:
  s.sendall(b"stream\\n");assert s.recv(4096)==b"gateway-qualified\\n";n+=1;open("/run/lab/count","w").write(str(n));time.sleep(.2)
except (OSError,AssertionError):open("/run/lab/stream-stopped","w").write(str(n))
'''

def probe(want,address='10.99.0.3',port=8080,role='ca'):
 deadline=time.monotonic()+(35 if want else 0)
 while True:
  p=execute(role,['python3','/run/lab/client.py',address,str(port)],check=False)
  if (p.returncode==0)==want:return
  if time.monotonic()>=deadline:break
  time.sleep(.3)
 for gw in ['a','b','relay']:
  dump=[]
  for args in [['wg','show','wg0','allowed-ips'],['wg','show','wg0','latest-handshakes'],['wg','show','wg0','endpoints'],['ip','route'],['nft','list','table','ip','tunnex']]:
   r=execute(gw,args,check=False);dump.append(str(args)+'\n'+r.stdout.decode()+r.stderr.decode())
  (EVIDENCE/(gw+'-failure.txt')).write_text('\n'.join(dump))
 raise RuntimeError('unexpected payload outcome '+str((role,address,port,want,p.stdout,p.stderr)))

def configure_client(role,gateway,address,v6,pub):
 execute(role,['sh','-c','ip link show wg0 >/dev/null 2>&1 || ip link add wg0 type wireguard'])
 for old in execute(role,['wg','show','wg0','peers']).stdout.decode().split():execute(role,['wg','set','wg0','peer',old,'remove'])
 execute(role,['wg','set','wg0','private-key','/run/lab/private','listen-port','51820','peer',pub,'allowed-ips','10.99.0.0/24,fd99::/64','endpoint',gateway+':51820','persistent-keepalive','1'])
 execute(role,['ip','addr','replace',address+'/24','dev','wg0']);execute(role,['ip','-6','addr','replace',v6+'/64','dev','wg0'])
 execute(role,['ip','link','set','wg0','up']);execute(role,['ip','route','replace','10.99.0.0/24','dev','wg0']);execute(role,['ip','-6','route','replace','fd99::/64','dev','wg0'])

def prepare_openvpn():
 execute('ca',['mkdir','-p','/run/lab/pki'])
 def ssl(*args):execute('ca',['openssl',*args])
 root='/run/lab/pki/'
 ssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',root+'ca.key','-out',root+'ca.crt','-days','1','-subj','/CN=disposable-gateway-test-ca','-addext','basicConstraints=critical,CA:TRUE')
 for name,cn,usage in [('server','server','serverAuth'),('client-ca','ca','clientAuth'),('client-cb','cb','clientAuth')]:
  ssl('req','-new','-newkey','rsa:2048','-nodes','-keyout',root+name+'.key','-out',root+name+'.csr','-subj','/CN='+cn)
  put('ca',{'pki/'+name+'.ext':'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='+usage+'\n'})
  ssl('x509','-req','-in',root+name+'.csr','-CA',root+'ca.crt','-CAkey',root+'ca.key','-CAcreateserial','-out',root+name+'.crt','-days','1','-extfile',root+name+'.ext')
 put('ca',{'pki/index':'','pki/crlnumber':'01\n','pki/ca.cnf':'[ca]\ndefault_ca=local\n[local]\ndatabase='+root+'index\ncertificate='+root+'ca.crt\nprivate_key='+root+'ca.key\ndefault_md=sha256\ndefault_crl_days=1\ncrlnumber='+root+'crlnumber\n'})
 ssl('ca','-gencrl','-config',root+'ca.cnf','-out',root+'crl.pem')
 bundle={name:execute('ca',['cat',root+name]).stdout for name in ['ca.crt','server.crt','server.key','crl.pem']}
 for role in ['a','b']:put(role,bundle)
 for role in ['ca','cb']:
  put(role,{'ca.crt':bundle['ca.crt'],'client.crt':execute('ca',['cat',root+'client-'+role+'.crt']).stdout,'client.key':execute('ca',['cat',root+'client-'+role+'.key']).stdout})

def start_openvpn_client(role,endpoint):
 # Only a pid created inside this owned container may be stopped.
 old=execute(role,['cat','/run/lab/client.pid'],check=False)
 if old.returncode==0:
  pid=int(old.stdout.strip());assert pid>1
  exe=execute(role,['readlink','/proc/'+str(pid)+'/exe'],check=False)
  if exe.returncode==0:
   assert exe.stdout.decode().strip().endswith('/openvpn')
   execute(role,['kill',str(pid)])
   time.sleep(.4)
 conf='client\ndev client0\ndev-type tun\nproto udp\nremote '+endpoint+' 1194\nnobind\nremote-cert-tls server\nca /run/lab/ca.crt\ncert /run/lab/client.crt\nkey /run/lab/client.key\ndata-ciphers AES-256-GCM\nauth SHA256\nconnect-retry 1 1\npull-filter ignore "ping"\nping 1\nping-restart 15\nverb 3\nlog /run/lab/client.log\nwritepid /run/lab/client.pid\n'
 put(role,{'client.conf':conf})
 execute(role,['openvpn','--config','/run/lab/client.conf','--daemon'])
 deadline=time.monotonic()+25
 while time.monotonic()<deadline:
  log=execute(role,['cat','/run/lab/client.log'],check=False).stdout
  if b'Initialization Sequence Completed' in log:return
  time.sleep(.3)
 (EVIDENCE/(role+'-openvpn-failure.log')).write_bytes(log)
 raise RuntimeError('OpenVPN client not ready: '+role)

def main():
 global network_id,image_id
 parser=argparse.ArgumentParser();parser.add_argument('--topology',choices=['both','two_gateway','nat_spokes_relay'],default='both');parser.add_argument('--transport',choices=['wireguard','openvpn','mixed','mixed_reverse'],default='wireguard');args=parser.parse_args()
 os.umask(0o077)
 context=read(['context','show'])
 endpoint=json.loads(read(['context','inspect',context]))[0]['Endpoints']['docker']['Host']
 if not endpoint.startswith('unix://'):raise RuntimeError('qualification requires a local Docker socket')
 image_id=read(['image','inspect','--format','{{.Id}}',IMAGE])
 arch=read(['version','--format','{{.Server.Arch}}'])
 if arch not in ('arm64','amd64'):raise RuntimeError('unsupported fixture architecture')
 subprocess.run(['go','test','-c','-o',str(EVIDENCE/'adapter.test'),'./internal/reconcile'],cwd=ROOT/'apps/node',env=dict(os.environ,GOOS='linux',GOARCH=arch,CGO_ENABLED='0'),check=True)
 for kind,name in [('network',NETWORK),*[('container',PROJECT+'-'+r) for r in ('a','b','relay','ca','cb')]]:
  if docker([kind,'inspect',name],check=False).returncode==0:raise RuntimeError('existing fixture refused')
 print('COMPOSE_PROJECT_NAME='+PROJECT+' network='+NETWORK+' evidence='+str(EVIDENCE),flush=True)
 try:
  network_id=read(['network','create','--internal','--label',LABEL+'='+PROJECT,NETWORK])
  info={}
  for role in ['a','b','relay','ca','cb']:
   cid=read(['run','-d','--name',PROJECT+'-'+role,'--label',LABEL+'='+PROJECT,'--network',NETWORK,'--cap-drop','ALL','--cap-add','NET_ADMIN','--cap-add','NET_RAW','--device','/dev/net/tun:/dev/net/tun:rw','--read-only','--tmpfs','/run/lab:rw,exec,nosuid,nodev,mode=0700,size=128m','--tmpfs','/tmp:rw,nosuid,nodev','--sysctl','net.ipv4.ip_forward=1','--sysctl','net.ipv6.conf.all.forwarding=1','--security-opt','no-new-privileges','--pids-limit','128',image_id,'sleep','1800'])
   containers[role]=cid;verify()
   execute(role,['sh','-c','wg genkey > /run/lab/private; wg pubkey < /run/lab/private > /run/lab/public'])
   c=json.loads(read(['inspect',cid]))[0];info[role]={'key':execute(role,['cat','/run/lab/public']).stdout.decode().strip(),'ip':c['NetworkSettings']['Networks'][NETWORK]['IPAddress']}
  if args.transport!='wireguard':prepare_openvpn()
  for role in ['a','b','relay']:adapter(role)
  for role in ['ca','cb']:
   put(role,{'server.py':SERVER,'client.py':CLIENT,'stream.py':STREAM})
   execute(role,['sh','-c','python3 /run/lab/server.py > /run/lab/server.log 2>&1 &'])
  # A listening forbidden destination makes the port-denial proof non-vacuous.
  probe(True,address='127.0.0.1',port=8081,role='cb')
  cfg={'Gateways':[],'Clients':[]}
  for i,role in enumerate(['a','b','relay']):cfg['Gateways'].append({'Role':role,'ID':str(uuid.UUID(int=i+1)),'Key':info[role]['key'],'Endpoint':info[role]['ip']+':51820','Address':'10.99.0.'+str([1,254,253][i])+'/24,fd99::'+str([1,254,253][i])+'/64'})
  for role,gateway,address,v6 in [('ca','a','10.99.0.2','fd99::2'),('cb','b','10.99.0.3','fd99::3')]:
   transport='openvpn' if args.transport=='openvpn' or (args.transport=='mixed' and role=='ca') or (args.transport=='mixed_reverse' and role=='cb') else 'wireguard'
   cfg['Clients'].append({'Role':role,'Gateway':gateway,'Key':info[role]['key'] if transport=='wireguard' else '', 'Kind':'human','Address':address,'IPv6Address':v6 if transport=='wireguard' else '', 'Transport':transport})
  results=[]
  for topology in (['two_gateway','nat_spokes_relay'] if args.topology=='both' else [args.topology]):
   for g in cfg['Gateways']:g['Endpoint']=info[g['Role']]['ip']+':51820' if topology=='two_gateway' or g['Role']=='relay' else ''
   for source_kind,dest_kind in [('human','human'),('human','agent'),('agent','human'),('agent','agent')]:
    cfg['Clients'][0]['Kind']=source_kind;cfg['Clients'][1]['Kind']=dest_kind
    states=projections(cfg)
    apply(states['off'])
    for c in cfg['Clients']:
     if c['Transport']=='wireguard':configure_client(c['Role'],info[c['Gateway']]['ip'],c['Address'],c['IPv6Address'],info[c['Gateway']]['key'])
     else:start_openvpn_client(c['Role'],info[c['Gateway']]['ip'])
    probe(False)
    apply(states['deny']);probe(False)
    apply(states['allow']);time.sleep(1);probe(True)
    if args.transport=='wireguard':
     probe(True,address='fd99::3');probe(False,address='fd99::3',port=8081)
    probe(False,port=8081);probe(False,address='10.99.0.2',role='cb')
    # Capture actual crypto handshakes without private keys.
    for role in ['a','b','relay']:
     (EVIDENCE/(role+'-handshakes.txt')).write_bytes(execute(role,['wg','show','wg0','latest-handshakes']).stdout)
    execute('ca',['sh','-c','rm -f /run/lab/count /run/lab/stream-stopped; python3 /run/lab/stream.py > /run/lab/stream.log 2>&1 &'])
    deadline=time.monotonic()+12
    while True:
     count=execute('ca',['cat','/run/lab/count'],check=False)
     if count.returncode==0 and int(count.stdout)>=2:break
     if time.monotonic()>deadline:
      log=execute('ca',['cat','/run/lab/stream.log'],check=False).stdout
      raise RuntimeError('stream did not start: '+log.decode())
     time.sleep(.3)
    before=int(count.stdout)
    apply(states['grant_removed']);probe(False);time.sleep(2.5)
    after=int(execute('ca',['cat','/run/lab/count']).stdout);time.sleep(.5)
    stable=int(execute('ca',['cat','/run/lab/count']).stdout)
    if after!=stable or before<2:raise RuntimeError('established flow did not stop')
    apply(states['allow']);probe(True)
    apply(states['off']);probe(False)
    apply(states['allow']);probe(True)
    if args.transport=='wireguard':
     apply(states['moved'])
     configure_client('cb',info['a']['ip'],'10.99.0.3','fd99::3',info['a']['key'])
     probe(True)
     apply(states['allow'])
     configure_client('cb',info['b']['ip'],'10.99.0.3','fd99::3',info['b']['key'])
     probe(True)
    apply(states['revoked']);probe(False)
    apply(states['no_carrier']);probe(False)
    results.append({'transport':args.transport,'topology':topology,'source':source_kind,'destination':dest_kind,'default_off':True,'default_deny':True,'scoped_allow':True,'wrong_port_and_reverse_denied':True,'live_grant_withdrawal':True,'device_revocation':True,'no_carrier':True,'disable_withdrawal':True,'live_move':args.transport=='wireguard'})
    (EVIDENCE/'result.json').write_text(json.dumps(results,indent=2))
    print('PASS '+args.transport+' '+topology+' '+source_kind+' -> '+dest_kind,flush=True)
  (EVIDENCE/'result.json').write_text(json.dumps(results,indent=2))
 finally:
  for role in containers:
   if role in ['a','b','ca','cb']:
    path='/run/lab/ovpn/ovpn.log' if role in ['a','b'] else '/run/lab/client.log'
    log=execute(role,['cat',path],check=False)
    if log.returncode==0:(EVIDENCE/(role+'-openvpn.log')).write_bytes(log.stdout)
  for role,(p,q,log) in adapters.items():
   try:p.stdin.close()
   except BrokenPipeError:pass
   try:p.wait(timeout=5)
   except subprocess.TimeoutExpired:p.terminate();p.wait(timeout=5)
   (EVIDENCE/(role+'-adapter.log')).write_text(''.join(log))
  for role,cid in list(containers.items()):
   verify();docker(['rm','-f',cid]);del containers[role]
  if network_id:
   verify();docker(['network','rm',network_id])
  (EVIDENCE/'adapter.test').unlink(missing_ok=True)
  print('Removed only captured fixture containers/internal network.',flush=True)
if __name__=='__main__':main()
