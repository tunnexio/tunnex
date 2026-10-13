"""Owned genuine Linux-host stop / new-namespace restoration proof.
Setup adapted from deploy/bgp/qualify_transport.py; no serving services.
"""
import argparse,hashlib,io,json,os,pathlib,secrets,subprocess,tarfile,time
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary',type=pathlib.Path,required=True)
p.add_argument('--image',required=True)
p.add_argument('--project',default='tunnexs2sbgpnamespace1007')
p.add_argument('--evidence',type=pathlib.Path,required=True)
p.add_argument('--sessions',action='store_true')
p.add_argument('--crash',action='store_true')
p.add_argument('--startup-crash',choices=['spawn','socket'])
p.add_argument('--wrong-asn',action='store_true')
p.add_argument('--routes',action='store_true')
p.add_argument('--maximum-prefixes',type=int,choices=[1,64],default=1)
p.add_argument('--failover',action='store_true')
a=p.parse_args()
assert a.project in ('tunnexs2sbgpnamespace1007','tunnexs2sbgpnamespace1007v2')
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
receipt={'image':a.image,'native_arch':meta['Architecture'],'binary_sha256':hashlib.sha256(binary).hexdigest(),'harness_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'project':a.project,'failover':a.failover,'maximum_prefixes':64,'exported_prefixes':2 if a.failover else a.maximum_prefixes,'routes':a.routes,'sessions':a.sessions,'crash':a.crash,'startup_crash':a.startup_crash,'wrong_asn':a.wrong_asn,'observer_requires_sys_admin':False,'cp_authority':'synthetic component lease','passed':False,'cleanup_complete':False}
psks=['S'+secrets.token_hex(23)for _ in range(2)]
def own(role):
 cid=containers[role];m=json.loads(subprocess.check_output(docker+['inspect',cid]))[0];assert m['Id']==cid and m['Config']['Labels'][label]==a.project;return cid

def run(role,cmd,input=None):
 try:return subprocess.check_output(docker+['exec']+(['-i']if input is not None else [])+[own(role)]+cmd,input=input,stderr=subprocess.STDOUT)
 except subprocess.CalledProcessError as error:
  (a.evidence/(role+'-failed-command.txt')).write_bytes(error.output)
  raise
def phase(role,step,grant=False):
 request=json.dumps({'Role':role,'Phase':step,'BGP':True,'BGPMED':a.failover,'BGPRouteWriter':a.routes,'BGPAppGrant':grant,'PSKs':psks}).encode()
 return run(role,['env','TUNNEX_IPSEC_ENCRYPTED_LAB=1','/test/node.test','-test.run=^TestDaemonEncryptedLabPhase$','-test.v'],request)
try:
 volume=a.project+'-namespace-v7-state'
 assert subprocess.run(docker+['volume','inspect',volume],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0
 subprocess.check_call(docker+['volume','create','--label',label+'='+a.project,volume],stdout=subprocess.DEVNULL)
 netid=subprocess.check_output(docker+['network','create','--internal','--driver','bridge','--subnet','198.19.240.0/24','--label',label+'='+a.project,netname],text=True).strip()
 for role,addr in [('gateway','198.19.240.10'),('peer','198.19.240.20')]:
  cid=subprocess.check_output(docker+['create','--name',a.project+'-'+role,'--label',label+'='+a.project,'--label','com.docker.compose.project='+a.project,'--network',netname,'--ip',addr,'--cap-drop','ALL','--cap-add','NET_ADMIN','--cap-add','NET_RAW','--cap-add','NET_BIND_SERVICE','--cap-add','SETUID','--cap-add','SETGID','--read-only','--tmpfs','/run:rw,nosuid,nodev,size=8m','--tmpfs','/test:rw,exec,nosuid,nodev,size=32m','--tmpfs','/var/tmp/frr:rw,nosuid,nodev,size=8m','--security-opt','no-new-privileges','--pids-limit','128',*(['--mount','type=volume,source='+volume+',target=/state'] if role=='gateway' else []),'--entrypoint','/bin/sh',a.image,'-c','sleep 3600'],text=True).strip();containers[role]=cid
  # Tar input avoids bind mounts and keeps the synthetic test binary owned locally.
  tar=io.BytesIO()
  with tarfile.open(fileobj=tar,mode='w')as t:
   entry=tarfile.TarInfo('node.test');entry.size=len(binary);entry.mode=0o700;t.addfile(entry,io.BytesIO(binary))
  subprocess.check_call(docker+['start',own(role)],stdout=subprocess.DEVNULL)
  run(role,['tar','-xf','-','-C','/test'],tar.getvalue())
  if role=='gateway':run(role,['chmod','700','/state'])
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
   run(role,['ip','route','add',remote+'/32','dev',link,'proto','242','metric',str(50001+i)])
  config=b'''charon {
 load = random nonce openssl kdf kernel-netlink socket-default vici
 install_routes = no
 install_virtual_ip = no
 plugins {
  kernel-netlink { install_routes_xfrmi = no }
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
 for role in ('peer','gateway'):phase(role,'stage')
 phase('gateway','initiate')
 for role in ('peer','gateway'):
  for attempt in range(20):
   try:phase(role,'bgp-control');break
   except subprocess.CalledProcessError:
    if attempt==19:raise
    time.sleep(.2)
 if a.sessions:
  baseline={}
  for role in ('gateway','peer'):
   local='10.10.0.1/24' if role=='gateway' else '10.20.0.1/24'
   run(role,['ip','addr','add',local,'dev','eth0'])
   if a.failover:
    run(role,['ip','route','add','10.99.0.0/24','dev','eth0','proto','static'])
    if role=='peer':run(role,['ip','addr','add','10.30.0.1/24','dev','eth0'])
   if a.maximum_prefixes==64:
    for index in range(1,64):run(role,['ip','addr','add','10.'+('10' if role=='gateway' else '20')+'.'+str(index)+'.1/24','dev','eth0'])
   baseline[role]=json.loads(run(role,['ip','-j','-4','route','show','table','all']))
   environment=('TUNNEX_BGP_LAB_JOURNAL_DIR=/state/ipsec ' if role=='gateway' else '')+('TUNNEX_BGP_STARTUP_CRASH_POINT='+a.startup_crash+' ' if a.startup_crash and role=='peer' else '')+('TUNNEX_BGP_CRASH_LAB=1 ' if a.crash else '')+('TUNNEX_BGP_MED_LAB=1 ' if a.failover else '')+('TUNNEX_BGP_LAB_MAX_PREFIXES=64 ' if a.maximum_prefixes==64 else '')+'TUNNEX_IPSEC_BGP_SESSION_LAB=1 TUNNEX_BGP_LAB_ROLE='+role+(' TUNNEX_BGP_LAB_ROUTE_WRITER=1' if a.routes else '')+(' TUNNEX_BGP_LAB_WRONG_ASN=1' if a.wrong_asn and role=='gateway' else '')
   subprocess.check_call(docker+['exec','-d',own(role),'sh','-c',environment+' /test/node.test -test.run=^TestBGPManagedSessionsNative$ -test.v >/run/bgp-process.log 2>&1'])
  stable_digest=None;stable_count=0
  for attempt in range(150):
   try:
    status=json.loads(run('gateway',['cat','/run/bgp-status.json']))
    journal=json.loads(run('gateway',['cat','/state/ipsec/journal.json']))
    ready=b'BGP_MANAGED_READY' in run('gateway',['cat','/run/bgp-process.log'])
    if ready and status['Alive'] and status['ObservationOK'] and all(peer['State']=='established' for peer in status['Status']['Peers']) and len(journal['Payload']['Entries'][0]['BGPRoutes']['Owned'])==1:
     current_digest=hashlib.sha256(json.dumps(journal['Payload']['Entries'],sort_keys=True).encode()).hexdigest()
     stable_count=stable_count+1 if current_digest==stable_digest else 1;stable_digest=current_digest
     if stable_count>=10:break
    else:stable_count=0
   except (subprocess.CalledProcessError,KeyError,TypeError):pass
   time.sleep(.2)
  else:raise RuntimeError('owned persisted-journal BGP ready timeout')
 old=own('gateway'); oldinspect=json.loads(subprocess.check_output(docker+['inspect',old]))[0]
 mount=[m for m in oldinspect['Mounts'] if m['Destination']=='/state'];assert len(mount)==1
 journalpath=pathlib.Path(mount[0]['Source'])/'ipsec/journal.json'
 gate=journalpath.parent/'restoration-startup-gate'
 with gate.open('xb') as f:
  os.chmod(gate,0o600);f.write(b'owned lifecycle supervisor holds Apply until real receipt installed\n');f.flush();os.fsync(f.fileno())
 fd=os.open(str(gate.parent),os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 # Fresh runtime sleeps without daemon, XFRM, nft, or product journal writes.
 newname=a.project+'-restoration'
 assert subprocess.run(docker+['inspect',newname],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0
 new=subprocess.check_output(docker+['create','--name',newname,'--label',label+'='+a.project,'--label','com.docker.compose.project='+a.project,'--network',netname,'--cap-drop','ALL','--cap-add','NET_ADMIN','--cap-add','NET_RAW','--cap-add','NET_BIND_SERVICE','--cap-add','SETUID','--cap-add','SETGID','--read-only','--tmpfs','/run:rw,nosuid,nodev,size=8m','--tmpfs','/test:rw,exec,nosuid,nodev,size=32m','--tmpfs','/var/tmp/frr:rw,nosuid,nodev,size=8m','--security-opt','no-new-privileges','--mount','type=volume,source='+volume+',target=/state','--entrypoint','/bin/sh',a.image,'-c','sleep 3600'],text=True).strip()
 containers['restoration']=new;subprocess.check_call(docker+['start',own('restoration')],stdout=subprocess.DEVNULL)
 # The empty new namespace is allocated while the old runtime is alive,
 # guaranteeing distinct inode identity. No files, daemon or journal writes
 # occur there until the old runtime is stopped and its host proof is saved.
 newnamespace=run('restoration',['readlink','/proc/self/ns/net']).decode().strip()
 oldnamespace=run('gateway',['readlink','/proc/self/ns/net']).decode().strip()
 assert newnamespace!=oldnamespace
 observer=pathlib.Path(__file__).parent/'runtime_stop_proof.py'
 cli=pathlib.Path(__file__).parent/'ipsec-restoration-receipt'
 subprocess.check_call(['python3',str(observer),'snapshot','--container',old,'--journal',str(journalpath),'--state-destination','/state','--output',str(a.evidence/'snapshot.json')])
 (a.evidence/'snapshot-journal.json').write_bytes(journalpath.read_bytes());(a.evidence/'snapshot-journal.json').chmod(0o600)
 subprocess.check_call(docker+['kill','--signal','KILL',old],stdout=subprocess.DEVNULL)
 subprocess.check_call(docker+['wait',old],stdout=subprocess.DEVNULL)
 subprocess.check_call(['python3',str(observer),'prove','--snapshot',str(a.evidence/'snapshot.json'),'--output',str(a.evidence/'stop-proof.json')])
 stopped=journalpath.read_bytes();(a.evidence/'stopped-journal.json').write_bytes(stopped);(a.evidence/'stopped-journal.json').chmod(0o600)
 for src,dest in [(a.binary,'/test/node.test'),(cli,'/test/receipt'),(a.evidence/'stop-proof.json','/test/stop-proof.json'),(a.evidence/'stopped-journal.json','/test/stopped-journal.json')]:
  stream=io.BytesIO(); content=src.read_bytes()
  with tarfile.open(fileobj=stream,mode='w') as t:
   member=tarfile.TarInfo(pathlib.Path(dest).name);member.size=len(content);member.mode=0o600;t.addfile(member,io.BytesIO(content))
  run('restoration',['tar','-xf','-','-C','/test'],stream.getvalue())
 run('restoration',['chmod','700','/test/node.test','/test/receipt']);run('restoration',['chmod','600','/test/stop-proof.json','/test/stopped-journal.json'])
 boot=run('restoration',['cat','/proc/sys/kernel/random/boot_id']).decode().strip()
 ns=run('restoration',['readlink','/proc/self/ns/net']).decode().strip()
 delivery=json.loads(stopped)['Payload']['Entries'][0]['DeliveryID']
 out='/state/ipsec/restore-'+delivery+'.json'
 subprocess.check_call(docker+['exec',new,'env','TMPDIR=/test','/test/receipt','--journal','/test/stopped-journal.json','--evidence','/test/stop-proof.json','--boot',boot,'--namespace',ns,'--out',out])
 assert journalpath.read_bytes()==stopped,'journal changed before receipt installation'
 (a.evidence/'restoration-cli-receipt.json').write_bytes(run('restoration',['cat',out]))
 gate.unlink();fd=os.open(str(gate.parent),os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 output=run('restoration',['env','TUNNEX_BGP_RESTORATION_LAB=1','TUNNEX_BGP_LAB_JOURNAL_DIR=/state/ipsec','/test/node.test','-test.run=^TestBGPRestorationNative$','-test.v'])
 (a.evidence/'restoration-test.log').write_bytes(output)
 (a.evidence/'native-restoration.json').write_bytes(run('restoration',['cat','/run/bgp-native-restoration.json']))
 (a.evidence/'restored-journal.json').write_bytes(journalpath.read_bytes())
 receipt.update(passed=True,old_container=old,new_container=new,state_volume=volume,actual_new_namespace=ns,trusted_stop=True,genuine_cli=True,serving_mutation=False)
 (a.evidence/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
 print('Genuine trusted namespace restoration PASS; owned fixtures retained for review.')
except Exception:
 (a.evidence/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
 print('Owned namespace proof refused; evidence and fixtures retained, serving stack untouched.')
 raise
