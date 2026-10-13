#!/usr/bin/env python3
"""Read-only final barrier review; exact topology rebind and release require flags."""
import argparse,hashlib,json,os,pathlib,subprocess,io,tarfile
os.umask(0o077);p=argparse.ArgumentParser();p.add_argument('--run-directory',type=pathlib.Path);p.add_argument('--execute',action='store_true');p.add_argument('--release',action='store_true');p.add_argument('--resume-after-pending',action='store_true');a=p.parse_args();assert not a.release or a.execute
r=pathlib.Path(__file__).resolve().parent;shared=r/'.runtime';from enrolled_approval import reviewed_run, validate_resume;rt,approval,run_index=reviewed_run(shared,a.run_directory)
d=[str(r/'docker-local.sh')]
def call(*args):return subprocess.check_output(d+list(args))
def inspect(cid):return json.loads(call('inspect',cid))[0]
def private_write(path,data):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:os.write(fd,data);os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
pre=json.loads((rt/'enrolled-preallocation.json').read_text());installed=json.loads((rt/'enrolled-restoration-installed.json').read_text());layout=json.loads((rt/'enrolled-restoration-before-layout-v3.json').read_text());before=json.loads((rt/'enrolled-restoration-before-gateway.json').read_text());old=pre['old_container_id'];new=pre['new_container_id'];o=inspect(old);n=inspect(new)
assert installed['installation_complete']and installed['old_container_id']==old and installed['new_container_id']==new
assert not o['State']['Running']and o['State']['Pid']==0 and n['State']['Running'];assert n['Image']==pre['image']and n['HostConfig']==pre['expected_host_config'];assert {k:v for k,v in n['Config'].items()if k!='Env'}==pre['actual_config_without_env'];assert hashlib.sha256(json.dumps(sorted(n['Config']['Env'])).encode()).hexdigest()==pre['environment_equality_sha256'];assert sorted(n['Mounts'],key=lambda m:m['Destination'])==sorted(pre['all_mounts'],key=lambda m:m['Destination'])
def run(*args):return call('exec',new,*args)
assert run('readlink','/proc/1/ns/net').decode().strip()==pre['new_namespace']!=layout['namespace'];assert run('sha256sum',pre['mounted_node_path']).decode().split()[0]==pre['mounted_node_sha256'];assert all(v not in run('ps','-eo','comm').decode().splitlines()for v in ['tunnex-node','charon','bgpd','zebra']);assert subprocess.run(d+['exec',new,'test','-e','/run/enrolled-restoration-release'],stdout=subprocess.DEVNULL).returncode==1
journal=run('cat','/state/ipsec/journal.json');assert hashlib.sha256(journal).hexdigest()==layout['journal_sha256'];receipt_path='/state/ipsec/restore-'+installed['delivery_id']+'.json';receipt=run('cat',receipt_path);assert hashlib.sha256(receipt).hexdigest()==installed['genuine_receipt_sha256'];assert run('cat','/state/ipsec/restoration-startup-gate')==b'owned enrolled restoration supervisor blocks Apply until genuine new namespace receipt durable\n'
query="select json_build_object('id',id,'org_id',org_id,'cert_serial',cert_serial,'cert_key_fingerprint',cert_key_fingerprint,'cert_not_after',cert_not_after,'status',status) from nodes where name='bgp-local-gateway';"
node=json.loads(call('exec','tunnexs2sbgplocal1007-postgres-1','psql','-U','bgplocal','-d','bgplocal','-At','-c',query));assert node==before['node']
cert=run('cat','/state/cert.pem');assert hashlib.sha256(cert).hexdigest()==json.loads((rt/'enrolled-restoration-before-cert.json').read_text())['certificate_pem_sha256']
license_after=rt/('enrolled-restoration-finish-license-resume-'+('execute'if a.execute else'review')+'.json'if a.resume_after_pending else'enrolled-restoration-finish-license.json');subprocess.run(['python3',str(r/'license-proof.py'),'--output',str(license_after)],check=True,stdout=subprocess.DEVNULL)
b=json.loads((rt/'enrolled-restoration-final-before-license.json').read_text());c=json.loads(license_after.read_text());assert b['persistence']==c['persistence'];assert all(b['entitlement'][k]==c['entitlement'][k]for k in ['tier','state']);assert set(b['entitlement']['features'])==set(c['entitlement']['features'])
marker=shared/'integrated-topology.json';current_topology=json.loads(marker.read_bytes());raw=(rt/'integrated-topology-before-enrolled-restoration.json').read_bytes()if a.resume_after_pending else marker.read_bytes();topology=json.loads(raw);assert topology['gateway_id']==old
for cid in topology['containers'].values():assert inspect(cid)['State']['Running']
if approval:
 for name,cid in json.loads((rt/'nongateway-before.json').read_text()).items():assert inspect(name)['Id']==cid and inspect(cid)['State']['Running']
for name,expected in layout['networks'].items():
 got=n['NetworkSettings']['Networks'][name];assert all(got.get(k)==expected.get(k)for k in ['NetworkID','IPAddress','MacAddress','GlobalIPv6Address','Aliases'])
result={'old_container_id':old,'new_container_id':new,'retained_old_stopped':True,'same_node_certificate_scale':True,'journal_sha256':hashlib.sha256(journal).hexdigest(),'genuine_receipt_sha256':hashlib.sha256(receipt).hexdigest(),'worker_released':False}
if a.resume_after_pending:
 assert run_index==3
 validate_resume(json.loads((rt/'enrolled-restoration-finish-pending.json').read_text()),result,topology,current_topology)
else:assert current_topology==topology
if a.resume_after_pending:
 for peer in ['13.50.7.159','51.20.220.141']:
  route=json.loads(run('ip','-j','-4','route','get',peer))[0];assert route['dev']=='eth1'and route['prefsrc']=='13.63.169.255'and route['gateway']=='198.19.241.20'
if not a.execute:print(json.dumps(result,indent=2));raise SystemExit(0)
if not a.resume_after_pending:
 private_write(rt/'enrolled-restoration-finish-pending.json',(json.dumps({**result,'finish_complete':False},indent=2)+'\n').encode());private_write(rt/'integrated-topology-before-enrolled-restoration.json',raw);updated={**topology,'gateway_id':new};marker.write_text(json.dumps(updated,indent=2)+'\n')
 subprocess.run(['python3',str(r/'prepare-public-aliases.py')],check=True,stdout=subprocess.DEVNULL)
 if run_index==4:subprocess.run(['python3',str(r/'restore-disposable-underlay.py'),'--run-directory',str(rt),'--execute'],check=True)
for peer in ['13.50.7.159','51.20.220.141']:
 route=json.loads(run('ip','-j','-4','route','get',peer))[0];assert route['dev']=='eth1'and route['prefsrc']=='13.63.169.255'and route['gateway']=='198.19.241.20'
assert run('cat','/state/ipsec/journal.json')==journal;assert run('cat',receipt_path)==receipt
if a.release:
 tool='enrolled-release-v2'if run_index in (3,4) else'enrolled-release'
 assert subprocess.run(d+['exec',new,'test','-e','/tmp/'+tool],stdout=subprocess.DEVNULL).returncode==1
 binary=(shared/tool).read_bytes();expected='d5a8ea55beb13518b32c8871aec5cc7974e498e7f8a7af75bef2dea913cb90b4'if run_index in (3,4) else'1473879ef50d8fc50b2f4b763b056400e570c41e8373e2622ebdc6d62dcb12c3';assert hashlib.sha256(binary).hexdigest()==expected
 if run_index in (3,4):
  build=json.loads((shared/'enrolled-release-v2-build-receipt.json').read_text());assert build['tool_sha256']==expected and build['toolchain']=='go1.26.8'and build['source_before_after_equal']and not build['runtime_executed']
  for name,digest in build['source_files'].items():assert hashlib.sha256((r.parents[1]/name).read_bytes()).hexdigest()==digest
 stream=io.BytesIO()
 with tarfile.open(fileobj=stream,mode='w')as t:
  item=tarfile.TarInfo(tool);item.mode=0o700;item.uid=item.gid=0;item.size=len(binary);t.addfile(item,io.BytesIO(binary))
 subprocess.run(d+['exec','-i',new,'tar','-xf','-','-C','/tmp'],input=stream.getvalue(),check=True)
 args=['/tmp/'+tool,'--namespace',pre['new_namespace'],'--journal-sha',result['journal_sha256'],'--receipt-sha',result['genuine_receipt_sha256']]
 if run_index in (3,4):args+=['--delivery',installed['delivery_id']]
 run(*args);result['worker_released']=True
private_write(rt/'enrolled-restoration-finish.json',(json.dumps(result,indent=2)+'\n').encode());print(json.dumps(result,indent=2))
