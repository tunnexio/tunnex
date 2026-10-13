"""Native owned dual-peer broad CHILD + encrypted TCP179 component qualification."""
import argparse,hashlib,io,json,pathlib,secrets,subprocess,tarfile,time
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary',type=pathlib.Path,required=True)
p.add_argument('--image',required=True)
p.add_argument('--project',default='tunnexs2sbgptransport1007')
p.add_argument('--evidence',type=pathlib.Path,required=True)
p.add_argument('--sessions',action='store_true')
p.add_argument('--crash',action='store_true')
p.add_argument('--startup-crash',choices=['spawn','socket'])
p.add_argument('--wrong-asn',action='store_true')
p.add_argument('--routes',action='store_true')
p.add_argument('--maximum-prefixes',type=int,choices=[1,64],default=1)
p.add_argument('--failover',action='store_true')
a=p.parse_args()
assert a.project=='tunnexs2sbgptransport1007'
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
   environment=('TUNNEX_BGP_STARTUP_CRASH_POINT='+a.startup_crash+' ' if a.startup_crash and role=='peer' else '')+('TUNNEX_BGP_CRASH_LAB=1 ' if a.crash else '')+('TUNNEX_BGP_MED_LAB=1 ' if a.failover else '')+('TUNNEX_BGP_LAB_MAX_PREFIXES=64 ' if a.maximum_prefixes==64 else '')+'TUNNEX_IPSEC_BGP_SESSION_LAB=1 TUNNEX_BGP_LAB_ROLE='+role+(' TUNNEX_BGP_LAB_ROUTE_WRITER=1' if a.routes else '')+(' TUNNEX_BGP_LAB_WRONG_ASN=1' if a.wrong_asn and role=='gateway' else '')
   subprocess.check_call(docker+['exec','-d',own(role),'sh','-c',environment+' /test/node.test -test.run=^TestBGPManagedSessionsNative$ -test.v >/run/bgp-process.log 2>&1'])
  for role in ('gateway','peer'):
   for attempt in range(100):
    log=run(role,['cat','/run/bgp-process.log'])
    if a.startup_crash and role=='peer' and b'BGP_STARTUP_CRASH_REQUESTED' in log:
     assert a.crash and a.routes
     prior=json.loads(run(role,['cat','/run/bgp-journal/journal.json']))
     identity=prior['Payload']['Entries'][0]['BGPProcess']
     assert identity['Stage']==('reserved' if a.startup_crash=='spawn' else 'partial')
     assert len(identity['Children'])==(0 if a.startup_crash=='spawn' else 1)
     (a.evidence/'startup-crash-journal.json').write_text(json.dumps(prior,indent=2)+'\n')
     witnesses=json.loads(run(role,['cat','/run/bgp-startup-crash-children.json']))
     for attempt_absence in range(100):
      surviving=[]
      for child in witnesses:
       check=subprocess.run(docker+['exec',own(role),'cat','/proc/'+str(child['PID'])+'/stat'],capture_output=True)
       if check.returncode==0:
        fields=check.stdout.decode().rsplit(') ',1)[1].split()
        if int(fields[19])==child['StartTicks'] and fields[0]!='Z':surviving.append(child['Name'])
      if not surviving:break
      time.sleep(.05)
     else:raise RuntimeError('Uncheckpointed old child survived parent death')
     statcmd=['sh','-c','for f in "$1"/*; do stat -c "%n %i %f %u %a" "$f"; done','fixture',identity['Directory']]
     preserved=run(role,statcmd)
     (a.evidence/'startup-uncertain-files-before.txt').write_bytes(preserved)
     (a.evidence/'startup-child-absence.json').write_text(json.dumps({'point':a.startup_crash,'externally_observed_children':witnesses,'all_original_children_absent':True,'not_deletion_authority':True})+'\n')
     subprocess.check_call(docker+['exec','-d',own(role),'sh','-c','TUNNEX_BGP_CRASH_LAB=1 TUNNEX_IPSEC_BGP_SESSION_LAB=1 TUNNEX_BGP_LAB_ROLE=peer TUNNEX_BGP_LAB_ROUTE_WRITER=1 /test/node.test -test.run=^TestBGPManagedSessionsNative$ -test.v >/run/bgp-process.log 2>&1'])
     for resumed_attempt in range(100):
      resumed=json.loads(run(role,['cat','/run/bgp-journal/journal.json']))
      entry=resumed['Payload']['Entries'][0]
      if entry['BGPProcess']['Generation']==2 and entry['BGPProcess']['Stage']=='ready':break
      if b'FAIL' in run(role,['cat','/run/bgp-process.log']):raise RuntimeError('Uncertain startup generation recovery refused')
      time.sleep(.1)
     else:raise RuntimeError('New generation did not become ready after genuine startup crash')
     assert entry['BGPProcessRetired'][0]['Stage']=='retired-uncertain' and entry['BGPProcessRetired'][0]['Files']==identity['Files'] and entry['BGPProcessRetired'][0]['Children']==identity['Children']
     assert run(role,statcmd)==preserved,'Uncertain old artifact adopted/deleted'
     (a.evidence/'startup-uncertain-files-preserved.txt').write_bytes(preserved)
     (a.evidence/'startup-new-generation-journal.json').write_text(json.dumps(resumed,indent=2)+'\n')
     break
    if b'BGP_MANAGED_READY' in log:break
    if b'FAIL' in log:
     for name,cmd in [('links',['ip','-j','-d','link','show']),('addresses',['ip','-j','-4','addr','show']),('routes',['ip','-j','-d','-N','-4','route','show','table','all']),('v6',['ip','-j','-d','-N','-6','route','show','table','all'])]:
      (a.evidence/(role+'-prerequisite-'+name+'.json')).write_bytes(run(role,cmd))
     raise RuntimeError('Managed process start refused: '+log.decode())
    time.sleep(.1)
  if a.failover:
   run('peer',['env','TUNNEX_BGP_MED_LAB=1','TUNNEX_BGP_MED_ACTION=initial','/test/node.test','-test.run=^TestBGPMEDFixture$','-test.v'])
  for attempt in range(40):
   observations={role:json.loads(run(role,['cat','/run/bgp-status.json']))for role in ('gateway','peer')}
   established=all(o['Alive'] and o['ObservationOK'] and all(p['State']=='established' for p in o['Status']['Peers'])for o in observations.values())
   if established and not a.wrong_asn and all(p['AcceptedPrefixes']==(2 if a.failover and role=='gateway' else a.maximum_prefixes) for role,o in observations.items() for p in o['Status']['Peers']):break
   if a.wrong_asn and attempt>=30:
    assert all(o['ObservationOK'] and all(p['State']!='established' and p['AcceptedPrefixes']==0 for p in o['Status']['Peers']) for o in observations.values());break
   time.sleep(.2)
  else:
   for role in ('gateway','peer'):
    (a.evidence/(role+'-raw-summary.txt')).write_bytes(run(role,['/opt/tunnex-bgp/vtysh','--vty_socket','/run/tunnex-bgp','-d','bgpd','-c','show bgp ipv4 unicast summary json']))
    (a.evidence/(role+'-process.txt')).write_bytes(run(role,['cat','/run/bgp-process.log']))
    (a.evidence/(role+'-running-config.txt')).write_bytes(run(role,['/opt/tunnex-bgp/vtysh','--vty_socket','/run/tunnex-bgp','-d','bgpd','-c','show running-config']))
    for title,daemon,command in [('neighbor','bgpd','show bgp neighbors json'),('interface','zebra','show interface json')]:
     (a.evidence/(role+'-'+title+'.txt')).write_bytes(run(role,['/opt/tunnex-bgp/vtysh','--vty_socket','/run/tunnex-bgp','-d',daemon,'-c',command]))
    (a.evidence/(role+'-listeners.txt')).write_bytes(run(role,['ss','-lnpt']))
    (a.evidence/(role+'-routes.txt')).write_bytes(run(role,['ip','-j','-4','route','show','table','all']))

   raise RuntimeError('Both BGP sessions did not establish: '+json.dumps(observations))
  for role,observation in observations.items():
   vtydir=json.loads(run(role,['cat','/run/bgp-owned-identity.json']))['Directory'] if a.crash and a.routes else '/run/tunnex-bgp'
   caps=run(role,['sh','-c','cat /proc/self/status; cat /proc/"$(cat '+vtydir+'/zebra.pid)"/status; cat /proc/"$(cat '+vtydir+'/bgpd.pid)"/status'])
   for line in caps.decode().splitlines():
    if line.startswith(('CapBnd:','CapEff:')):assert not (int(line.split()[1],16)&(1<<21)), 'SYS_ADMIN present'
   (a.evidence/(role+'-capabilities.txt')).write_bytes(caps)

   vtydir=json.loads(run(role,['cat','/run/bgp-owned-identity.json']))['Directory'] if a.crash and a.routes else '/run/tunnex-bgp'
   (a.evidence/(role+'-rib.json')).write_bytes(run(role,['/opt/tunnex-bgp/vtysh','--vty_socket',vtydir,'-d','bgpd','-c','show bgp ipv4 unicast json']))
   (a.evidence/(role+'-sessions.json')).write_text(json.dumps(observation,indent=2)+'\n')
   # bgpd -n and no-rib must leave learned remote routes absent from kernel.
   routes=json.loads(run(role,['ip','-j','-4','route','show','table','main']))
   remote='10.20.0.0/24' if role=='gateway' else '10.10.0.0/24'
   if not a.routes:assert all(r.get('dst')!=remote for r in routes),'FRR wrote learned route into kernel'
   if not a.routes:assert json.loads(run(role,['ip','-j','-4','route','show','table','all']))==baseline[role],'FRR changed baseline kernel routes'
   (a.evidence/(role+'-kernel-baseline.json')).write_text(json.dumps(baseline[role],indent=2)+'\n')
  if a.routes:
   for role in ('gateway','peer'):
    log=run(role,['cat','/run/bgp-process.log']);assert b'BGP_NO_KERNEL_BEFORE_GO_WRITER' in log
    routes=json.loads(run(role,['ip','-j','-4','route','show','table','main']))
    remote='10.20.0.0/24' if role=='gateway' else '10.10.0.0/24'
    owned=[r for r in routes if r.get('dst')==remote];assert len(owned)==1 and str(owned[0].get('protocol'))=='242'
    (a.evidence/(role+'-owned-journal.json')).write_bytes(run(role,['cat','/run/bgp-journal/journal.json']))
   for role,underlay,local,gateway,destination in [('client','198.19.240.30','10.10.0.2/24','10.10.0.1','10.20.0.0/24'),('target','198.19.240.40','10.20.0.2/24','10.20.0.1','10.10.0.0/24')]:
    cid=subprocess.check_output(docker+['create','--name',a.project+'-'+role,'--label',label+'='+a.project,'--label','com.docker.compose.project='+a.project,'--network',netname,'--ip',underlay,'--read-only','--cap-drop','ALL','--cap-add','NET_ADMIN','--tmpfs','/test:rw,exec,mode=0700','--tmpfs','/run:rw,mode=0755','--entrypoint','/bin/sh',a.image,'-c','sleep 300'],text=True).strip();containers[role]=cid
    subprocess.check_call(docker+['start',own(role)],stdout=subprocess.DEVNULL)
    run(role,['tar','-xf','-','-C','/test'],tar.getvalue());run(role,['ip','addr','add',local,'dev','eth0']);run(role,['ip','route','add',destination,'via',gateway])
   subprocess.check_call(docker+['exec','-d',own('target'),'sh','-c','TUNNEX_BGP_APP_LAB=1 /test/node.test -test.run=^TestBGPForwardApplicationServer$ -test.v >/run/app.log 2>&1'])
   for attempt in range(20):
    if b'BGP_APP_READY' in run('target',['cat','/run/app.log']):break
    time.sleep(.1)
   for role in ('gateway','peer'):phase(role,'bgp-control')
   (a.evidence/'forward-denied.txt').write_bytes(run('client',['env','TUNNEX_BGP_APP_LAB=1','TUNNEX_BGP_APP_EXPECT=deny','/test/node.test','-test.run=^TestBGPForwardApplicationClient$','-test.v']))
   for role in ('gateway','peer'):
    phase(role,'bgp-control',True)
    (a.evidence/(role+'-app-forwarding.txt')).write_bytes(run(role,['cat','/proc/sys/net/ipv4/ip_forward']))
    (a.evidence/(role+'-app-nft.json')).write_bytes(run(role,['nft','-j','list','table','inet','tunnex_ipsec']))
    (a.evidence/(role+'-app-routes.json')).write_bytes(run(role,['ip','-j','-4','route','show','table','all']))
    (a.evidence/(role+'-app-xfrm.txt')).write_bytes(run(role,['ip','xfrm','state','list','nokeys']))
   (a.evidence/'forward-allowed.txt').write_bytes(run('client',['env','TUNNEX_BGP_APP_LAB=1','TUNNEX_BGP_APP_EXPECT=allow','/test/node.test','-test.run=^TestBGPForwardApplicationClient$','-test.v']))
   for role in ('gateway','peer'):(a.evidence/(role+'-encrypted-proof.txt')).write_bytes(phase(role,'bgp-observe'))
  if a.failover:
   def selected():
    journal=json.loads(run('gateway',['cat','/run/bgp-journal/journal.json']));entry=journal['Payload']['Entries'][0];state=entry.get('BGPRoutes');return ({r['Prefix']:r['Slot']for r in state['Owned']}if state and state['Stage']=='completed' else None)
   def wait_selected(expected,title):
    for attempt in range(100):
     if selected()==expected:break
     if attempt%40==0:
      for role in ('gateway','peer'):phase(role,'bgp-control',True)
     time.sleep(.2)
    else:raise RuntimeError('Exact selected paths not observed '+title+': '+str(selected()))
    (a.evidence/(title+'-journal.json')).write_bytes(run('gateway',['cat','/run/bgp-journal/journal.json']))
   wait_selected({'10.20.0.0/24':2,'10.30.0.0/24':1},'opposite-med-initial')
   for role in ('gateway','peer'):phase(role,'bgp-control')
   run('peer',['env','TUNNEX_BGP_MED_LAB=1','TUNNEX_BGP_MED_ACTION=flip','/test/node.test','-test.run=^TestBGPMEDFixture$','-test.v'])
   wait_selected({'10.20.0.0/24':1,'10.30.0.0/24':2},'opposite-med-flipped')
   for role in ('gateway','peer'):phase(role,'bgp-control',True)
   run('peer',['env','TUNNEX_BGP_MED_LAB=1','TUNNEX_BGP_MED_ACTION=lose-slot1','/test/node.test','-test.run=^TestBGPMEDFixture$','-test.v'])
   wait_selected({'10.20.0.0/24':2,'10.30.0.0/24':2},'lost-peer-survivor')
   run('peer',['env','TUNNEX_BGP_MED_LAB=1','TUNNEX_BGP_MED_ACTION=withdraw-first','/test/node.test','-test.run=^TestBGPMEDFixture$','-test.v'])
   wait_selected({'10.30.0.0/24':2},'withdrawn-prefix-survivor')
   (a.evidence/'withdrawn-prefix-denied.txt').write_bytes(run('client',['env','TUNNEX_BGP_APP_LAB=1','TUNNEX_BGP_APP_EXPECT=deny','/test/node.test','-test.run=^TestBGPForwardApplicationClient$','-test.v']))
   for role in ('gateway','peer'):
    routes=json.loads(run(role,['ip','-j','-4','route','show','table','main']));foreign=[r for r in routes if r.get('dst')=='10.99.0.0/24'];assert len(foreign)==1 and foreign[0]['dev']=='eth0' and foreign[0]['protocol']=='static'
    (a.evidence/(role+'-foreign-preserved.json')).write_text(json.dumps(foreign)+'\n')
  if a.crash:
   assert not a.wrong_asn
   crash_role="gateway" if a.routes else "peer"
   identity=json.loads(run(crash_role,['cat','/run/bgp-owned-identity.json']))
   assert identity['Stage']=='ready' and len(identity['Children'])==2
   (a.evidence/(crash_role+'-before-crash-identity.json')).write_text(json.dumps(identity,indent=2)+'\n')
   if a.routes:(a.evidence/(crash_role+'-before-crash-journal.json')).write_bytes(run(crash_role,['cat','/run/bgp-journal/journal.json']))
   run(crash_role,['touch','/run/bgp-supervisor-crash'])
   for attempt in range(100):
    alive=[]
    for child in identity['Children']:
     check=subprocess.run(docker+['exec',own(crash_role),'cat','/proc/'+str(child['PID'])+'/stat'],capture_output=True)
     if check.returncode==0:
      fields=check.stdout.decode().rsplit(') ',1)[1].split()
      if int(fields[19])==child['StartTicks'] and fields[0]!='Z':alive.append(child['Name'])
    if not alive:break
    time.sleep(.05)
   else:raise RuntimeError('Parent-death owned child remained alive: '+str(alive))
   (a.evidence/'parent-death.json').write_text(json.dumps({'crash_role':crash_role,'original_children_absent':True,'churn_before_crash':True,'unknown_artifacts_adopted':False})+'\n')
   run(crash_role,['rm','/run/bgp-supervisor-crash'])
   for role in ('gateway','peer'):phase(role,'bgp-control')
   subprocess.check_call(docker+['exec','-d',own(crash_role),'sh','-c','TUNNEX_BGP_CRASH_LAB=1 TUNNEX_IPSEC_BGP_SESSION_LAB=1 TUNNEX_BGP_LAB_ROLE='+crash_role+' '+('TUNNEX_BGP_LAB_ROUTE_WRITER=1 ' if a.routes else '')+'/test/node.test -test.run=^TestBGPManagedSessionsNative$ -test.v >/run/bgp-process.log 2>&1'])
   for attempt in range(200):
    restored={role:json.loads(run(role,['cat','/run/bgp-status.json'])) for role in ('gateway','peer')}
    if all(o['Alive'] and o['ObservationOK'] and all(p['State']=='established' for p in o['Status']['Peers']) for o in restored.values()):
     newidentity=json.loads(run(crash_role,['cat','/run/bgp-owned-identity.json']))
     if newidentity['Supervisor']['PID']!=identity['Supervisor']['PID'] and newidentity['Stage']=='ready':
      if not a.routes:break
      finaljournal=json.loads(run(crash_role,['cat','/run/bgp-journal/journal.json']))
      if finaljournal['Payload']['Entries'][0]['BGPRoutes']['Stage']=='completed' and len(finaljournal['Payload']['Entries'][0]['BGPRoutes']['Owned'])==1:break
    if attempt%50==0:
     for role in ('gateway','peer'):phase(role,'bgp-control')
    time.sleep(.2)
   else:raise RuntimeError('Abrupt supervisor recovery failed')
   if a.routes:(a.evidence/(crash_role+'-restart-cleanup.json')).write_bytes(run(crash_role,['cat','/run/bgp-crash-cleanup-proof.json']))
   (a.evidence/(crash_role+'-after-crash-identity.json')).write_text(json.dumps(newidentity,indent=2)+'\n')
   for role in ('gateway','peer'):
    if not a.routes:assert json.loads(run(role,['ip','-j','-4','route','show','table','all']))==baseline[role]
    if a.routes:(a.evidence/(role+'-crash-journal.json')).write_bytes(run(role,['cat','/run/bgp-journal/journal.json']))
    (a.evidence/(role+'-crash-restarted.json')).write_text(json.dumps(restored[role],indent=2)+'\n')
  if not a.crash and not a.wrong_asn and not a.routes:
   run('peer',['sh','-c','kill -TERM "$(cat /run/tunnex-bgp/bgpd.pid)"'])
   time.sleep(1)
   failed=json.loads(run('peer',['cat','/run/bgp-status.json']));assert not failed['Alive'] and not failed['ObservationOK']
   (a.evidence/'peer-daemon-loss.json').write_text(json.dumps(failed,indent=2)+'\n')
   for attempt in range(200):
    survivor=json.loads(run('gateway',['cat','/run/bgp-status.json']))
    if survivor['ObservationOK'] and all(p['State']!='established' for p in survivor['Status']['Peers']):break
    time.sleep(.2)
   else:raise RuntimeError('Peer loss falsely stayed established')
   (a.evidence/'gateway-peer-loss.json').write_text(json.dumps(survivor,indent=2)+'\n')
   for role in ('gateway','peer'):phase(role,'bgp-control')
   run('peer',['touch','/run/bgp-restart'])
   for attempt in range(200):
    restored={role:json.loads(run(role,['cat','/run/bgp-status.json'])) for role in ('gateway','peer')}
    if all(o['Alive'] and o['ObservationOK'] and all(p['State']=='established' and p['AcceptedPrefixes']==a.maximum_prefixes for p in o['Status']['Peers']) for o in restored.values()):break
    if attempt%50==0:
     for role in ('gateway','peer'):phase(role,'bgp-control')
    time.sleep(.2)
   else:raise RuntimeError('Owned daemon restart did not reestablish both sessions')
   for role in ('gateway','peer'):
    assert json.loads(run(role,['ip','-j','-4','route','show','table','all']))==baseline[role],'Restart changed baseline kernel routes'
    (a.evidence/(role+'-restarted.json')).write_text(json.dumps(restored[role],indent=2)+'\n')
 else:
  subprocess.check_call(docker+['exec','-d',own('peer'),'sh','-c','TUNNEX_IPSEC_BGP_TRANSPORT_LAB=1 /test/node.test -test.run=^TestBGPTransportTCPServer$ -test.v >/run/tcp179.log 2>&1'])
  for _ in range(30):
   if b'TCP179_SYNTHETIC_READY' in run('peer',['cat','/run/tcp179.log']):break
   time.sleep(.1)
  output=run('gateway',['env','TUNNEX_IPSEC_BGP_TRANSPORT_LAB=1','/test/node.test','-test.run=^TestBGPTransportTCPClient$','-test.v'])
  (a.evidence/'traffic.txt').write_bytes(output)
  for role in ('gateway','peer'):(a.evidence/(role+'-selectors.txt')).write_bytes(phase(role,'bgp-observe'))
 receipt['passed']=True
finally:
 if a.routes and not receipt['passed']:
  for role in containers:
   for name,cmd in [('routes',['ip','-j','-4','route','show','table','all']),('neighbors',['ip','-j','neighbor','show']),('sockets',['ss','-ntlp'])]+([('nft',['nft','-j','list','table','inet','tunnex_ipsec']),('xfrm',['ip','-s','xfrm','state','list','nokeys'])] if role in ('gateway','peer') else []):
    try:(a.evidence/(role+'-failure-'+name+'.txt')).write_bytes(run(role,cmd))
    except subprocess.CalledProcessError:pass
 for role in list(containers):subprocess.check_call(docker+['rm','-f',own(role)],stdout=subprocess.DEVNULL)
 if netid:
  m=json.loads(subprocess.check_output(docker+['network','inspect',netid]))[0];assert m['Id']==netid and m['Labels'][label]==a.project;subprocess.check_call(docker+['network','rm',netid],stdout=subprocess.DEVNULL)
 receipt['cleanup_complete']=True
 (a.evidence/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt,indent=2))
