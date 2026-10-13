"""Native owned dual-peer broad CHILD + encrypted TCP179 component qualification."""
import argparse,hashlib,io,json,pathlib,secrets,subprocess,tarfile,time
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary',type=pathlib.Path,required=True)
p.add_argument('--image',required=True)
p.add_argument('--project',default='tunnexs2srestartothers1008')
p.add_argument('--evidence',type=pathlib.Path,required=True)
p.add_argument('--profile',choices=['static','bgp'],required=True)
p.add_argument('--sessions',action='store_true')
p.add_argument('--crash',action='store_true')
p.add_argument('--startup-crash',choices=['spawn','socket'])
p.add_argument('--wrong-asn',action='store_true')
p.add_argument('--routes',action='store_true')
p.add_argument('--maximum-prefixes',type=int,choices=[1,64],default=1)
p.add_argument('--failover',action='store_true')
a=p.parse_args()
assert a.project=='tunnexs2srestartothers1008'
assert a.routes and not any((a.sessions,a.crash,a.startup_crash,a.wrong_asn,a.failover))
assert a.image.startswith('sha256:') and len(a.image)==71
binary=a.binary.read_bytes();assert binary[:6]==b'\x7fELF\x02\x01'
docker=['docker']
context=subprocess.check_output(docker+['context','show'],text=True).strip()
endpoint=json.loads(subprocess.check_output(docker+['context','inspect',context]))[0]['Endpoints']['docker']['Host']
assert endpoint.startswith('unix:///'), 'local Unix Docker context required'
info=json.loads(subprocess.check_output(docker+['info','--format','{{json .}}']))
arch=info['Architecture'];assert arch in ('aarch64','arm64','amd64','x86_64')
assert int.from_bytes(binary[18:20],'little')== (183 if arch in ('aarch64','arm64') else 62)
meta=json.loads(subprocess.check_output(docker+['image','inspect',a.image]))[0];assert meta['Id']==a.image and meta['Architecture']==('arm64' if arch in ('aarch64','arm64') else 'amd64')
label='tunnex.bgp.transport';netname=a.project+'-private';containers={};netid=None
for kind,name in [('network',netname)]+[('container',a.project+'-'+r)for r in ('gateway','peer')]:assert subprocess.run(docker+[kind,'inspect',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0
a.evidence.mkdir(mode=0o700,parents=False,exist_ok=False)
receipt={'image':a.image,'native_arch':meta['Architecture'],'binary_sha256':hashlib.sha256(binary).hexdigest(),'harness_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'project':a.project,'cp_authority':'synthetic proof callback; no lease','environment':'actual production environment inspector','passed':False,'cleanup_complete':False}
psks=['S'+secrets.token_hex(23)for _ in range(2)]
def own(role):
 cid=containers[role];m=json.loads(subprocess.check_output(docker+['inspect',cid]))[0];assert m['Id']==cid and m['Config']['Labels'][label]==a.project;return cid

def run(role,cmd,input=None):
 try:return subprocess.check_output(docker+['exec']+(['-i']if input is not None else [])+[own(role)]+cmd,input=input,stderr=subprocess.STDOUT)
 except subprocess.CalledProcessError as error:
  (a.evidence/(role+'-failed-command.txt')).write_bytes(error.output)
  raise
def phase(role,step,grant=False):
 request=json.dumps({'Role':role,'Phase':step,'BGP':a.profile=='bgp','BGPMED':a.failover,'BGPRouteWriter':a.routes,'BGPAppGrant':grant,'PSKs':psks}).encode()
 return run(role,['env','TUNNEX_IPSEC_ENCRYPTED_LAB=1','/test/node.test','-test.run=^TestDaemonEncryptedLabPhase$','-test.v'],request)
try:
 netid=subprocess.check_output(docker+['network','create','--internal','--driver','bridge','--subnet','198.19.240.0/24','--label',label+'='+a.project,netname],text=True).strip()
 for role,addr in [('gateway','198.19.240.10'),('peer','198.19.240.20')]:
  cid=subprocess.check_output(docker+['create','--name',a.project+'-'+role,'--label',label+'='+a.project,'--label','com.docker.compose.project='+a.project,'--network',netname,'--ip',addr,'--cap-drop','ALL','--cap-add','NET_ADMIN','--cap-add','NET_RAW','--cap-add','NET_BIND_SERVICE','--cap-add','SETUID','--cap-add','SETGID','--read-only','--tmpfs','/run:rw,nosuid,nodev,size=8m','--tmpfs','/test:rw,exec,nosuid,nodev,size=32m','--tmpfs','/var/tmp/frr:rw,nosuid,nodev,size=8m','--security-opt','no-new-privileges','--pids-limit','128','--entrypoint','/bin/sh',a.image,'-c','sleep 900'],text=True).strip();containers[role]=cid
  # Tar input avoids bind mounts and keeps the synthetic test binary owned locally.
  tar=io.BytesIO()
  with tarfile.open(fileobj=tar,mode='w')as t:
   entry=tarfile.TarInfo('node.test');entry.size=len(binary);entry.mode=0o700;t.addfile(entry,io.BytesIO(binary))
  subprocess.check_call(docker+['start',own(role)],stdout=subprocess.DEVNULL)
  run(role,['tar','-xf','-','-C','/test'],tar.getvalue())
  run(role,['mkdir','-m','700','/run/tunnex-ipsec'])
  if role=='peer':run(role,['ip','addr','add','198.19.240.21/24','dev','eth0'])
  for i in range(2):
   link='tnx-'+str(i+1);xid=701+i+(100 if role=='peer' else 0)
   if a.routes:
    import uuid
    digest=hashlib.sha256(uuid.UUID('dddddddd-0000-0000-0000-00000000000'+str(i+1)).bytes).digest();link='tx'+digest[:6].hex();xid=int.from_bytes(digest[:4],'big')|0x80000000
   local='169.254.20.'+str(1+4*i+(1 if role=='peer' else 0));remote='169.254.20.'+str(2+4*i-(1 if role=='peer' else 0))
   run(role,['ip','link','add',link,'type','xfrm','if_id',str(xid)])
   if a.routes:run(role,['ip','link','set',link,'addrgenmode','none'])
   if a.routes:run(role,['ip','link','set',link,'alias','tunnex-ipsec:eeeeeeee-0000-0000-0000-000000000001:dddddddd-0000-0000-0000-00000000000'+str(i+1)])
   run(role,['ip','addr','add',local+'/30','dev',link,'noprefixroute']);run(role,['ip','link','set',link,'mtu','1422','up'])
   if a.profile=='bgp':run(role,['ip','route','add',remote+'/32','dev',link,'proto','242','metric',str(50001+i)])
  config=b'''charon {
 load = random nonce openssl kdf kernel-netlink socket-default vici
 install_routes = no
 routing_table = 0
 install_virtual_ip = no
 plugins {
  kernel-netlink { install_routes = no
   install_routes_xfrmi = no }
  vici { socket = unix:///run/tunnex-ipsec/charon.vici }
 }
 filelog { stderr { default = -1 } }
}
'''
  run(role,['sh','-c','umask 077; cat > /run/tunnex-ipsec/strongswan.conf'],config)
  run(role,['sh','-c','STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf /opt/tunnex-ipsec/libexec/ipsec/charon >/run/tunnex-ipsec/daemon.log 2>&1 &'])
  for _ in range(20):
   if subprocess.run(docker+['exec',own(role),'test','-S','/run/tunnex-ipsec/charon.vici'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
   time.sleep(.1)
  run(role,['chmod','600','/run/tunnex-ipsec/charon.vici'])
 (a.evidence/'gateway-rules-before-stage.json').write_bytes(run('gateway',['ip','-j','-4','rule','show']))
 for role in ('peer','gateway'):phase(role,'stage')
 phase('gateway','initiate')
 run('gateway',['ip','addr','add','10.10.0.1/24','dev','eth0'])
 for attempt in range(30):
  try:
   output=run('gateway',['env','TMPDIR=/test','TUNNEX_RESTART_OTHERS_NATIVE=1','TUNNEX_RESTART_OTHER_PROFILE='+a.profile,'/test/node.test','-test.run=^TestRestartOtherProviderNative$','-test.v'])
   (a.evidence/'native-test.log').write_bytes(output)
   (a.evidence/'native-proof.json').write_bytes(run('gateway',['cat','/test/native-restart-proof.json']))
   break
  except subprocess.CalledProcessError:
   if attempt==29:raise
   time.sleep(.2)
 receipt['profile']=a.profile
 receipt['scope']='real two-SA transport and locked journal; synthetic CP authority; no FRR/application/grants'
 receipt['passed']=True
finally:
 for role,cid in containers.items():
  own(role)
  subprocess.check_call(docker+['rm','-f',cid],stdout=subprocess.DEVNULL)
 if netid is not None:
  m=json.loads(subprocess.check_output(docker+['network','inspect',netid]))[0]
  assert m['Id']==netid and m['Labels'][label]==a.project and not m['Containers']
  subprocess.check_call(docker+['network','rm',netid],stdout=subprocess.DEVNULL)
 receipt['cleanup_complete']=True
 (a.evidence/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
