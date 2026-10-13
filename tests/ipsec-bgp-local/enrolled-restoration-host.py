#!/usr/bin/env python3
"""REVIEW-ONLY default; genuine Linux-HOST stop proof for exact enrolled gateway."""
import argparse,datetime,hashlib,json,os,pathlib,stat,subprocess,sys,time
p=argparse.ArgumentParser();p.add_argument('--expected-container',default='4b8464af422fcff9cf2009e435ce003641a2b8d5c4227191f102de6ad3d122b8');p.add_argument('--layout',type=pathlib.Path,required=True);p.add_argument('--observer',type=pathlib.Path,required=True);p.add_argument('--evidence',type=pathlib.Path,required=True);p.add_argument('--execute-stop',action='store_true');p.add_argument('--pause-old',action='store_true');a=p.parse_args();os.umask(0o077)
assert os.geteuid()==0 and pathlib.Path('/proc/1/ns/net').exists(),'Actual root Linux HOST required'
for path in [a.layout,a.observer]:
 st=path.lstat();assert stat.S_ISREG(st.st_mode)and st.st_uid==0 and st.st_mode&0o077==0,'Private root source required'
assert hashlib.sha256(a.observer.read_bytes()).hexdigest()=='eb0cf334663c713f7075cd8e41e46c1f44c2345faa15841710d937b3789d01f3','Unapproved observer source'
x=json.loads(a.layout.read_text());cid=x['container_id'];assert cid==a.expected_container and len(cid)==64 and all(c in '0123456789abcdef'for c in cid)
d=['docker','--host','unix:///var/run/docker.sock']
def inspect():
 g=json.loads(subprocess.check_output(d+['inspect',cid]))[0];assert g['Id']==cid and g['State']['Running'];assert g['Config']['Labels']['com.docker.compose.project']=='tunnexs2sbgplocal1007';assert g['Image']==x['image'];assert g['HostConfig']==x['host_config'];assert {k:g['Config'][k]for k in x['config']}==x['config'];assert g['NetworkSettings']['Networks']==x['networks'];assert sorted(g['Mounts'],key=lambda m:m['Destination'])==sorted(x['all_mounts'],key=lambda m:m['Destination']);assert hashlib.sha256(json.dumps(sorted(g['Config']['Env'])).encode()).hexdigest()==x['environment_equality_sha256'];assert [m for m in g['Mounts']if m['Destination']=='/state']==x['state_mount'];return g
g=inspect();mount=x['state_mount'];assert len(mount)==1 and mount[0]['Type']=='volume'and mount[0]['RW']and mount[0]['Name']=='tunnexs2sbgplocal1007_gateway_state';journal=pathlib.Path(mount[0]['Source'])/'ipsec/journal.json';assert journal.resolve()==journal and journal.lstat().st_uid==0 and journal.lstat().st_mode&0o077==0;assert hashlib.sha256(journal.read_bytes()).hexdigest()==x['journal_sha256'],'Journal changed; refresh audit/review, never overwrite'
if not a.execute_stop:print('Exact enrolled host/volume/journal identity preflight verified; no gate or stop');raise SystemExit(0)
assert not a.evidence.exists(),'Evidence must be fresh';a.evidence.mkdir(mode=0o700)
receipt={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'container_id':cid,'old_namespace':x['namespace'],'observer_sha256':hashlib.sha256(a.observer.read_bytes()).hexdigest(),'helper_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'journal_sha256':x['journal_sha256'],'stop_complete':False,'gateway_restarted':False};(a.evidence/'operation.json').write_text(json.dumps(receipt,indent=2)+'\n')
gate=journal.parent/'restoration-startup-gate';paused=False;killed=False;gate_identity=None
try:
 if a.pause_old:
  # Docker targets only the exact container PID1, not the host or a cgroup.
  assert hashlib.sha256(pathlib.Path('/proc/'+str(g['State']['Pid'])+'/exe').read_bytes()).hexdigest()==x['actual_executable_sha256'],'PID1 executable differs'
  subprocess.run(d+['kill','--signal','STOP',cid],check=True);paused=True
  for _ in range(25):
   status=pathlib.Path('/proc/'+str(g['State']['Pid'])+'/status').read_text()
   if any(line.startswith('State:')and 'T ('in line for line in status.splitlines()):break
   time.sleep(.04)
  else:raise RuntimeError('Exact node PID1 did not stop')
  inspect();assert hashlib.sha256(journal.read_bytes()).hexdigest()==x['journal_sha256'],'Paused journal differs from reviewed audit'
 fd=os.open(gate,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  os.write(fd,b'owned enrolled restoration supervisor blocks Apply until genuine new namespace receipt durable\n');os.fsync(fd);st=os.fstat(fd);gate_identity=(st.st_dev,st.st_ino)
 finally:os.close(fd)
 fd=os.open(journal.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 subprocess.run([sys.executable,str(a.observer),'snapshot','--container',cid,'--journal',str(journal),'--state-destination','/state','--output',str(a.evidence/'snapshot.json')],check=True,env={**os.environ,'DOCKER_HOST':'unix:///var/run/docker.sock'})
 raw=journal.read_bytes();assert hashlib.sha256(raw).hexdigest()==x['journal_sha256'],'Journal changed after gate/snapshot; refuse stop';(a.evidence/'snapshot-journal.json').write_bytes(raw)
 inspect();subprocess.run(d+['kill','--signal','KILL',cid],check=True);killed=True;subprocess.run(d+['wait',cid],check=True)
except BaseException:
 receipt.update(snapshot_refused=True,pid1_paused=paused,old_killed=killed)
 if paused and not killed:
  # Abort only while the same old runtime is independently still running.
  current=inspect();assert current['State']['Pid']==g['State']['Pid'] and current['State']['StartedAt']==g['State']['StartedAt']
  if gate_identity is not None:
   st=gate.lstat();assert (st.st_dev,st.st_ino)==gate_identity and st.st_uid==0 and st.st_mode&0o077==0
   gate.unlink();fd=os.open(journal.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
  subprocess.run(d+['kill','--signal','CONT',cid],check=True);receipt['old_resumed_after_snapshot_refusal']=True
 (a.evidence/'operation.json').write_text(json.dumps(receipt,indent=2)+'\n');raise
subprocess.run([sys.executable,str(a.observer),'prove','--snapshot',str(a.evidence/'snapshot.json'),'--output',str(a.evidence/'stop-proof.json')],check=True,env={**os.environ,'DOCKER_HOST':'unix:///var/run/docker.sock'})
assert journal.read_bytes()==raw,'Stopped journal differs';(a.evidence/'stopped-journal.json').write_bytes(raw);receipt.update(stop_complete=True,stop_proof_sha256=hashlib.sha256((a.evidence/'stop-proof.json').read_bytes()).hexdigest(),startup_gate_retained=True);(a.evidence/'operation.json').write_text(json.dumps(receipt,indent=2)+'\n');print('Genuine enrolled stop proof complete; gate retained; no restart/receipt/new namespace action')
