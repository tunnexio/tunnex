#!/usr/bin/env python3
"""Review-only default: connect proved replacement, genuine CLI, then startup release."""
import argparse,hashlib,io,json,os,pathlib,subprocess,tarfile,copy,http.client,socket
os.umask(0o077);p=argparse.ArgumentParser();p.add_argument('--run-directory',type=pathlib.Path);p.add_argument('--evidence',type=pathlib.Path,required=True);p.add_argument('--execute',action='store_true');p.add_argument('--resume-after-staging',action='store_true');a=p.parse_args();r=pathlib.Path(__file__).resolve().parent;shared=r/'.runtime';from enrolled_approval import reviewed_run,selected_applied;rt,approval,run_index=reviewed_run(shared,a.run_directory)
layout=json.loads((rt/'enrolled-restoration-before-layout-v3.json').read_text());pre=json.loads((rt/'enrolled-preallocation.json').read_text());old=layout['container_id'];new=pre['new_container_id'];d=[str(r/'docker-local.sh')]
def inspect(cid):return json.loads(subprocess.check_output(d+['inspect',cid]))[0]
def out(*args):return subprocess.check_output(d+['exec',new]+list(args))
o=inspect(old);n=inspect(new);assert not o['State']['Running']and o['State']['Pid']==0 and n['State']['Running'];assert n['Id']==new and n['Config']['Labels']['tunnex.bgp.enrolled.restoration']=='story9-actual'
assert n['Image']==pre['image'] and n['Config']['Cmd']==pre['actual_new_config'] and {k:v for k,v in n['Config'].items()if k!='Env'}==pre['actual_config_without_env']
assert n['HostConfig']==pre['expected_host_config'] and sorted(n['Mounts'],key=lambda m:m['Destination'])==sorted(pre['all_mounts'],key=lambda m:m['Destination'])
assert hashlib.sha256(json.dumps(sorted(n['Config']['Env'])).encode()).hexdigest()==pre['environment_equality_sha256']
assert out('sha256sum',pre['mounted_node_path']).decode().split()[0]==pre['mounted_node_sha256']==approval.get('binary_sha256','f5813d090fdb37474fa7de47cd9e030ae0230c7b2794927e12232c78aa493f69')
assert subprocess.run(d+['exec',new,'test','-e','/run/enrolled-restoration-release'],stdout=subprocess.DEVNULL).returncode==1
assert all(name not in out('ps','-eo','comm').decode().splitlines()for name in ['tunnex-node','charon','bgpd','zebra'])
assert out('readlink','/proc/1/ns/net').decode().strip()==pre['new_namespace']!=layout['namespace'];assert out('ip','xfrm','state').strip()==b''
proof=json.loads((a.evidence/'stop-proof.json').read_text());assert proof['snapshot']['container']==old and proof['checks']==['exact-stopped-runtime','empty-cgroup','no-namespace-holders-two-passes']
journal=(a.evidence/'stopped-journal.json').read_bytes();assert hashlib.sha256(journal).hexdigest()==proof['stopped_journal_raw_sha256'];assert out('cat','/state/ipsec/journal.json')==journal
assert subprocess.run(d+['exec',new,'test','-f','/state/ipsec/restoration-startup-gate'],stdout=subprocess.DEVNULL).returncode==0
entries=json.loads(journal)['Payload']['Entries'];applied=selected_applied(entries);delivery=applied['DeliveryID'];receipt='/state/ipsec/restore-'+delivery+'.json'
if approval.get('prior_receipt_sha256'):
 prior=out('cat',receipt);assert hashlib.sha256(prior).hexdigest()==approval['prior_receipt_sha256'];assert prior==(rt/'prior-genuine-restoration-receipt.json').read_bytes();prior_json=json.loads(prior);assert prior_json['Namespace']==layout['namespace'] and prior_json['DeliveryID']==delivery
else:assert subprocess.run(d+['exec',new,'test','-e',receipt],stdout=subprocess.DEVNULL).returncode==1
cli=shared/approval.get('cli_file','enrolled-restoration-receipt');clibytes=cli.read_bytes();assert hashlib.sha256(clibytes).hexdigest()==approval.get('cli_sha256','03e4098ee328e324ac35c0809bc7610dcee125e9e186d23285dc63e57b0454a1')
build=json.loads((shared/approval.get('cli_build_receipt','enrolled-cli-build-receipt.json')).read_text());manifest=shared/build['source_manifest_file'];assert build['tool_sha256']==hashlib.sha256(clibytes).hexdigest() and build['source_before_after_equal']and build['toolchain']=='go1.26.8';assert hashlib.sha256(manifest.read_bytes()).hexdigest()==build['source_manifest_sha256']==approval.get('cli_source_manifest_sha256','d570562552795b61d952c3b06cce2ff9c64289de81d8e58efcc70fbf35867515')
for path,digest in json.loads(manifest.read_text())['source_files'].items():assert hashlib.sha256((r.parent.parent/path).read_bytes()).hexdigest()==digest,'Tool source changed: '+path
summary={'old_container_id':old,'new_container_id':new,'actual_new_namespace':pre['new_namespace'],'delivery_id':delivery,'genuine_cli_sha256':hashlib.sha256(clibytes).hexdigest(),'stop_proof_sha256':hashlib.sha256((a.evidence/'stop-proof.json').read_bytes()).hexdigest(),'worker_started':False}
if not a.execute:print(json.dumps(summary,indent=2));raise SystemExit(0)
# Disconnect only recorded old endpoints after genuine host proof, retaining
# the old stopped container and all journal evidence. Connect exact IPs in
# original physical order: CP eth0, isolated outer eth1, customer LAN eth2.
endpoint=json.loads(subprocess.check_output(d+['context','inspect']))[0]['Endpoints']['docker']['Host'];assert endpoint.startswith('unix:///')
class UnixHTTP(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(20);self.sock.connect(endpoint[len('unix://'):])
summary['installation_complete']=False;pending_path=rt/'enrolled-restoration-installed.json'
if a.resume_after_staging:
 pending=json.loads(pending_path.read_text());assert pending==summary,'Pending installation identity/proof differs'
else:
 assert not pending_path.exists();pending_path.write_text(json.dumps(summary,indent=2)+'\n')
staging=pre['staging_network_name'];staging_id=pre['staging_network_id']
st=json.loads(subprocess.check_output(d+['network','inspect',staging_id]))[0];assert st['Name']==staging and st['Internal'] and st['Labels'].get('tunnex.bgp.enrolled.restoration')=='story9-staging'
if a.resume_after_staging:
 assert st['Containers']=={} and inspect(new)['NetworkSettings']['Networks']=={},'Resume requires exact already-detached empty namespace'
else:
 assert set(st['Containers'])=={new} and set(inspect(new)['NetworkSettings']['Networks'])=={staging}
 subprocess.run(d+['network','disconnect',staging_id,new],check=True)
assert inspect(new)['NetworkSettings']['Networks']=={} and out('readlink','/proc/1/ns/net').decode().strip()==pre['new_namespace'],'Namespace changed on staging detach'
assert json.loads(subprocess.check_output(d+['network','inspect',staging_id]))[0]['Containers']=={}
summary['staging_network_retained']=True
for name in ['tunnexs2sbgplocal1007_default','tunnexs2sbgpintegrated1007-outer','tunnexs2sbgpintegrated1007-local']:
 expected=layout['networks'][name];actual=inspect(old)['NetworkSettings']['Networks'];assert name in actual and actual[name]['NetworkID']==expected['NetworkID']
 stopped=actual[name];assert stopped.get('IPAMConfig')==expected.get('IPAMConfig')and stopped.get('Aliases')==expected.get('Aliases')
 if stopped.get('IPAddress')!=expected['IPAddress']:
  assert not inspect(old)['State']['Running']and inspect(old)['State']['Pid']==0
  assert all(stopped.get(key,'')=='' for key in ['IPAddress','MacAddress','Gateway','EndpointID','GlobalIPv6Address','IPv6Gateway']),'Unexpected stopped endpoint canonicalization'
 else:assert stopped['MacAddress']==expected['MacAddress']
 subprocess.run(d+['network','disconnect',name,old],check=True)
 ipam=copy.deepcopy(expected.get('IPAMConfig')or{});ipam['IPv4Address']=expected['IPAddress']
 if expected.get('GlobalIPv6Address'):ipam['IPv6Address']=expected['GlobalIPv6Address']
 ep={'IPAMConfig':ipam,'Aliases':expected.get('Aliases'),'MacAddress':expected['MacAddress']}
 conn=UnixHTTP('localhost');conn.request('POST','/networks/'+expected['NetworkID']+'/connect',body=json.dumps({'Container':new,'EndpointConfig':ep}),headers={'Content-Type':'application/json'});response=conn.getresponse();response.read();conn.close();assert response.status==200,'Exact endpoint connect refused'
 got=inspect(new)['NetworkSettings']['Networks'][name];assert got['NetworkID']==expected['NetworkID']and got['IPAddress']==expected['IPAddress']and got['MacAddress']==expected['MacAddress'] and got.get('GlobalIPv6Address','')==expected.get('GlobalIPv6Address','');assert got.get('Aliases')==expected.get('Aliases'),'Original aliases differ'
addresses=json.loads(out('ip','-j','-4','address','show'));expected_by_iface={'eth0':layout['networks']['tunnexs2sbgplocal1007_default']['IPAddress'],'eth1':layout['networks']['tunnexs2sbgpintegrated1007-outer']['IPAddress'],'eth2':layout['networks']['tunnexs2sbgpintegrated1007-local']['IPAddress']}
for iface,address in expected_by_iface.items():assert any(link['ifname']==iface and any(v.get('local')==address for v in link.get('addr_info',[]))for link in addresses),'Physical interface address ordering differs'
summary['physical_address_readback']=addresses
assert out('readlink','/proc/1/ns/net').decode().strip()==pre['new_namespace'];assert out('cat','/state/ipsec/journal.json')==journal
out('mkdir','-m','700','/tmp/enrolled-restoration-proof')
stream=io.BytesIO()
with tarfile.open(fileobj=stream,mode='w')as t:
 for name,b,mode in [('receipt',clibytes,0o700),('stopped-journal.json',journal,0o600),('stop-proof.json',(a.evidence/'stop-proof.json').read_bytes(),0o600)]:
  e=tarfile.TarInfo(name);e.uid=e.gid=0;e.mode=mode;e.size=len(b);t.addfile(e,io.BytesIO(b))
subprocess.run(d+['exec','-i',new,'tar','-xf','-','-C','/tmp/enrolled-restoration-proof'],input=stream.getvalue(),check=True)
if approval.get('prior_receipt_sha256'):
 archive='restore-history-'+old+'-'+delivery+'.json';archive_source=next(m['Source']for m in n['Mounts']if m['Destination']=='/state')+'/ipsec/'
 request={'old':old,'new':new,'parent':archive_source,'canonical':'restore-'+delivery+'.json','archive':archive,'sha256':approval['prior_receipt_sha256'],'namespace':layout['namespace'],'journal_sha256':hashlib.sha256(journal).hexdigest()}
 script='''import os,sys,json,stat,hashlib,subprocess,pathlib,ctypes
q=json.loads(sys.argv[1]);d=['docker','--host','unix:///var/run/docker.sock']
o=json.loads(subprocess.check_output(d+['inspect',q['old']]))[0];n=json.loads(subprocess.check_output(d+['inspect',q['new']]))[0]
assert o['Id']==q['old']and not o['State']['Running']and o['State']['Pid']==0 and n['State']['Running']
parent=pathlib.Path(q['parent']);assert parent.resolve()==parent and [m['Source']for m in o['Mounts']if m['Destination']=='/state']==[str(parent.parent)] and [m['Source']for m in n['Mounts']if m['Destination']=='/state']==[str(parent.parent)]
assert hashlib.sha256((parent/'journal.json').read_bytes()).hexdigest()==q['journal_sha256'];assert (parent/'restoration-startup-gate').is_file()
source=parent/q['canonical'];dest=parent/q['archive'];fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW);st=os.fstat(fd);assert stat.S_ISREG(st.st_mode)and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600
raw=os.read(fd,1<<20);assert hashlib.sha256(raw).hexdigest()==q['sha256'] and json.loads(raw)['Namespace']==q['namespace'];assert not dest.exists();assert source.lstat().st_ino==st.st_ino
libc=ctypes.CDLL(None,use_errno=True);assert libc.renameat2(-100,os.fsencode(source),-100,os.fsencode(dest),1)==0,ctypes.get_errno()
pfd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(pfd);os.close(pfd);os.close(fd);assert hashlib.sha256(dest.read_bytes()).hexdigest()==q['sha256']and not source.exists()
'''
 subprocess.run(['colima','ssh','--','sudo','-n','python3','-c',script,json.dumps(request)],check=True)
 summary['prior_receipt_preserved_at']=archive;assert subprocess.run(d+['exec',new,'test','-e',receipt],stdout=subprocess.DEVNULL).returncode==1
boot=out('cat','/proc/sys/kernel/random/boot_id').decode().strip();out('env','TMPDIR=/tmp/enrolled-restoration-proof','/tmp/enrolled-restoration-proof/receipt','--journal','/tmp/enrolled-restoration-proof/stopped-journal.json','--evidence','/tmp/enrolled-restoration-proof/stop-proof.json','--boot',boot,'--namespace',pre['new_namespace'],'--out',receipt)
assert out('cat','/state/ipsec/journal.json')==journal;actual=out('cat',receipt);(rt/'enrolled-genuine-restoration-receipt.json').write_bytes(actual);summary['installation_complete']=True;summary['genuine_receipt_sha256']=hashlib.sha256(actual).hexdigest();(rt/'enrolled-restoration-installed.json').write_text(json.dumps(summary,indent=2)+'\n')
# Release is a separate reviewed action. This phase intentionally retains the
# durable gate and sleeping wrapper; caller must restore aliases/readiness
# topology before fsynced gate removal and root0600 /run release marker.
print('Genuine receipt installed; startup gate and sleeping worker barrier retained')
