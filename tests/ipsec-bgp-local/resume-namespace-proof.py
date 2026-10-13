"""Resume only an owned proof stopped before artifact transfer; no stop action."""
import hashlib,importlib.util,io,json,os,pathlib,subprocess,tarfile,time
root=pathlib.Path(__file__).resolve().parent
evidence=root/'evidence';project='tunnexs2sbgptransport1007';label='tunnex.bgp.transport'
docker=['docker'];image='sha256:868b425d65ef30b6f0c221c834e8925079d658281e89380ead59a929021c50a2'
def command(args):return subprocess.check_output(docker+args,stderr=subprocess.STDOUT)
def inspect(name):return json.loads(command(['inspect',name]))[0]
old=inspect(project+'-gateway');new=inspect(project+'-restoration')
for obj in (old,new):
 assert obj['Config']['Labels'][label]==project and obj['Config']['Labels']['com.docker.compose.project']==project and obj['Image']==image
assert not old['State']['Running'] and old['State']['Pid']==0
assert new['State']['Running'] and new['State']['Pid']>0
snapshot=json.loads((evidence/'snapshot.json').read_text());assert old['Id']==snapshot['container']
mounts=[m for m in new['Mounts'] if m['Destination']=='/state'];assert len(mounts)==1
assert mounts[0]['Source']==snapshot['state_mount']['source'] and mounts[0]['Type']==snapshot['state_mount']['type'] and mounts[0]['RW']
journalpath=pathlib.Path(mounts[0]['Source'])/'ipsec/journal.json'
stopped=(evidence/'stopped-journal.json').read_bytes();assert journalpath.read_bytes()==stopped
# Original durable observer proof remains authoritative after event-ring eviction.
# Independently corroborate current absence without changing observer checks or
# manufacturing a replacement termination event/proof.
proofpath=evidence/'stop-proof.json';proofraw=proofpath.read_bytes();proof=json.loads(proofraw)
assert proof['snapshot']==snapshot and proof['stopped_journal_raw_sha256']==hashlib.sha256(stopped).hexdigest()
spec=importlib.util.spec_from_file_location('owned_stop_observer',root/'runtime_stop_proof.py');observer=importlib.util.module_from_spec(spec);spec.loader.exec_module(observer)
checks=[]
for _ in range(2):
 current=observer.inspect(old['Id']);observer.validate_stopped(snapshot,current,observer.boot())
 cgroup=pathlib.Path(snapshot['cgroup'])/'cgroup.events'
 state=cgroup.read_text().splitlines() if cgroup.exists() else []
 assert not state or 'populated 0' in state
 holders=observer.namespace_holders(snapshot['namespace']);assert not holders
 observer.validate_stopped(snapshot,observer.inspect(old['Id']),observer.boot())
 assert journalpath.read_bytes()==stopped and proofpath.read_bytes()==proofraw
 checks.append({'time_ns':time.time_ns(),'container':current['id'],'pid':current['state']['Pid'],'started_at':current['state']['StartedAt'],'finished_at':current['state']['FinishedAt'],'cgroup_exists':cgroup.exists(),'cgroup_empty':True,'namespace_holders':holders,'journal_unchanged':True,'state_mount':observer.state_mount(current,str(journalpath),'/state')})
newcheck=observer.inspect(new['Id']);assert newcheck['state']['Running'] and newcheck['state']['Pid']==new['State']['Pid']
newns=os.readlink('/proc/'+str(newcheck['state']['Pid'])+'/ns/net');assert newns!='net:['+str(snapshot['namespace']['inode'])+']'
observer.private_write(evidence/('resume-current-checks-'+str(time.time_ns())+'.json'),{'version':1,'kind':'current-corroboration-of-original-durable-stop-proof','original_proof_sha256':hashlib.sha256(proofraw).hexdigest(),'original_proof_rewritten':False,'event_ring_eviction':'original event already captured in immutable genuine proof; no synthetic replacement','checks':checks,'new_container':new['Id'],'new_namespace':newns,'resume_source_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()})
def run(args,input=None):return subprocess.check_output(docker+['exec']+(['-i'] if input is not None else [])+[new['Id']]+args,input=input,stderr=subprocess.STDOUT)
assert b'charon.vici' not in run(['find','/run','-name','charon.vici'])
links=json.loads(run(['ip','-j','link','show']));assert all(link.get('linkinfo',{}).get('info_kind')!='xfrm' for link in links)
assert not any(table['table']['name'].startswith('tunnex') for table in json.loads(run(['nft','-j','list','tables']))['nftables'] if 'table' in table)
for src,dest in [(root/'node.test','node.test'),(root/'ipsec-restoration-receipt','receipt'),(evidence/'stop-proof.json','stop-proof.json'),(evidence/'stopped-journal.json','stopped-journal.json')]:
 stream=io.BytesIO();content=src.read_bytes()
 with tarfile.open(fileobj=stream,mode='w') as archive:
  member=tarfile.TarInfo(dest);member.size=len(content);member.mode=0o600;archive.addfile(member,io.BytesIO(content))
 run(['tar','-xf','-','-C','/test'],stream.getvalue())
run(['chmod','700','/test/node.test','/test/receipt'])
boot=run(['cat','/proc/sys/kernel/random/boot_id']).decode().strip();ns=run(['readlink','/proc/self/ns/net']).decode().strip()
assert ns!='net:['+str(snapshot['namespace']['inode'])+']'
delivery=json.loads(stopped)['Payload']['Entries'][0]['DeliveryID'];out='/state/ipsec/restore-'+delivery+'.json'
subprocess.check_call(docker+['exec',new['Id'],'env','TMPDIR=/test','/test/receipt','--journal','/test/stopped-journal.json','--evidence','/test/stop-proof.json','--boot',boot,'--namespace',ns,'--out',out])
assert journalpath.read_bytes()==stopped
(evidence/'restoration-cli-receipt.json').write_bytes(run(['cat',out]))
gate=journalpath.parent/'restoration-startup-gate';assert gate.is_file() and gate.stat().st_uid==0 and (gate.stat().st_mode&0o777)==0o600
gate.unlink();fd=os.open(str(gate.parent),os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
try:
 output=run(['env','TUNNEX_BGP_RESTORATION_LAB=1','TUNNEX_BGP_LAB_JOURNAL_DIR=/state/ipsec','/test/node.test','-test.run=^TestBGPRestorationNative$','-test.v'])
except subprocess.CalledProcessError as err:
 (evidence/'restoration-test.log').write_bytes(err.output);raise
(evidence/'restoration-test.log').write_bytes(output)
(evidence/'native-restoration.json').write_bytes(run(['cat','/run/bgp-native-restoration.json']))
(evidence/'restored-journal.json').write_bytes(journalpath.read_bytes())
receipt=json.loads((evidence/'result.json').read_text());receipt.update(passed=True,old_container=old['Id'],new_container=new['Id'],state_volume=project+'-namespace-v7-state',actual_new_namespace=ns,trusted_stop=True,genuine_cli=True,serving_mutation=False,transfer='root-owned exec tar into tmpfs',resume_harness_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest())
(evidence/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
print('Genuine trusted namespace restoration PASS; exact fixtures retained for review.')
