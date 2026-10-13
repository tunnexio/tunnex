#!/usr/bin/env python3
"""Start owned target endpoint and assert independent forwarded TCP outcome."""
import argparse,hashlib,io,json,pathlib,subprocess,tarfile,time,os,stat
p=argparse.ArgumentParser(description=__doc__);p.add_argument('expectation',choices=['allow','deny']);p.add_argument('--probe-binary',type=pathlib.Path);p.add_argument('--probe-name',default='packet-probe');a=p.parse_args()
root=pathlib.Path(__file__).resolve().parent;s=json.loads((root/'.runtime/integrated-topology.json').read_text());docker=[str(root/'docker-local.sh')]
subprocess.run([str(root/'ownership.py')],check=True)
def out(*args):return subprocess.check_output(docker+list(args),text=True)
for role,cid in s['containers'].items():
 m=json.loads(out('inspect',cid))[0];assert m['Id']==cid and m['Config']['Labels']['tunnex.bgp.integrated']==s['project']
assert pathlib.Path(a.probe_name).name==a.probe_name and a.probe_name.startswith('packet-probe')and all(c.isalnum()or c in '-_'for c in a.probe_name);assert bool(a.probe_binary)==(a.probe_name!='packet-probe')
selected=root/'.runtime/bin/packet-probe'if a.probe_binary is None else a.probe_binary.absolute();assert selected.parent==root/'.runtime/bin';assert stat.S_ISREG(selected.lstat().st_mode)and selected.lstat().st_uid==os.getuid(),'Probe must be owned regular local binary';binary=selected.read_bytes();probe_path='/test/'+a.probe_name
proof_path=root/'.runtime'/('integrated-probe-'+a.expectation+(('-'+a.probe_name)if a.probe_binary else '')+'.json');
if a.probe_binary is not None:assert not proof_path.exists(),'Retain previous proof; choose a fresh probe name'
for role in (['client','target']if a.probe_binary is None else ['client']):
 exists=subprocess.run(docker+['exec',s['containers'][role],'test','-e',probe_path],stdout=subprocess.DEVNULL).returncode==0
 if exists:
  assert out('exec',s['containers'][role],'sha256sum',probe_path).split()[0]==hashlib.sha256(binary).hexdigest(),'Existing endpoint binary differs; no live executable overwrite'
  continue
 stream=io.BytesIO()
 with tarfile.open(fileobj=stream,mode='w')as tar:
  entry=tarfile.TarInfo(a.probe_name);entry.size=len(binary);entry.mode=0o700;tar.addfile(entry,io.BytesIO(binary))
 subprocess.run(docker+['exec','-i',s['containers'][role],'tar','-xf','-','-C','/test'],input=stream.getvalue(),check=True)
ready=subprocess.run(docker+['exec',s['containers']['target'],'test','-f','/run/target.pid'],stdout=subprocess.DEVNULL).returncode==0
if a.probe_binary is not None:assert ready,'New client-only probe must preserve existing running target'
if ready:out('exec',s['containers']['target'],'sh','-ec','kill -0 "$(cat /run/target.pid)"')
else:out('exec','-d',s['containers']['target'],'sh','-ec','/test/packet-probe server 10.20.0.2:18080 >/run/target.log 2>&1 & echo $! >/run/target.pid; wait')
for _ in range(30):
 if 'OWNED_TARGET_READY'in out('exec',s['containers']['target'],'cat','/run/target.log'):break
 time.sleep(.1)
else:raise SystemExit('Owned target failed readiness')
result=out('exec',s['containers']['client'],probe_path,'client','10.20.0.2:18080','10.10.0.2',a.expectation)
proof={'expectation':a.expectation,'result':result.strip(),'probe_name':a.probe_name,'probe_binary_sha256':hashlib.sha256(binary).hexdigest(),'gateway_id':s['gateway_id'],'containers':s['containers'],'provider_intent':json.loads((root/'.runtime/integrated-local-api-state.json').read_text()).get('last_intent','disabled'),'activation_performed_by_probe':False,'probe_is_read_only':True}
path=proof_path;
if a.probe_binary is not None:
 import os
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w')as f:f.write(json.dumps(proof,indent=2)+'\n')
else:path.write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof,indent=2))
