#!/usr/bin/env python3
"""Cycle3 reviewed already-connected endpoint resume; no network operations.
Default source-only; --execute required. Original V6 and frozen capture unchanged.
"""
import argparse,copy,hashlib,json,os,pathlib,stat
V6_SHA='59864a6daf8c563ee2d5fbf015cf1f91d5530a3332cdd12b2accffe50570a3c7'
REVIEWED_NEW='0faef89deabf2fe2cbe8595967e1b611e7699279ea09c7f4d98f85045ffa4514'
REVIEWED_NS='net:[4026532946]'
REVIEWED_NETWORK='026856f1cdf8332d2e4dfea4994ffe478a2f521067c676a9dd374115ea857a5f'
OLD_MAC='e2:2c:b1:94:6d:0d'
NEW_MAC='fe:09:82:6b:6c:47'
def endpoint_proof(old,new):
 assert len(old)==len(new)==1 and set(old)==set(new)
 name=next(iter(old));before=old[name];after=new[name]
 assert before['NetworkID']==after['NetworkID']==REVIEWED_NETWORK
 assert before['MacAddress']==OLD_MAC and after['MacAddress']==NEW_MAC
 for key in ['IPAddress','IPAMConfig','Aliases','Links','DriverOpts','GwPriority','Gateway','IPPrefixLen','GlobalIPv6Address','GlobalIPv6PrefixLen','IPv6Gateway']:
  assert before.get(key)==after.get(key),'Endpoint mismatch: '+key
 assert before['DNSNames']==['tunnex-bgp-20261007-gateway','gateway','382b1763ae4b']
 assert after['DNSNames']==['tunnex-bgp-20261007-gateway-trusted-restart-3','gateway','0faef89deabf']
 assert after['IPAddress']=='172.30.88.2' and after['EndpointID']
 return True
def reviewed_link_proof(links,addresses,old_links,old_addresses):
 before=copy.deepcopy(old_links);matches=[r for r in before if r.get('ifname')=='eth0'];assert len(matches)==1
 assert matches[0]['address']==OLD_MAC and matches[0]['mtu']==1500
 matches[0]['address']=NEW_MAC
 proof=link_proof(links,addresses,before,old_addresses)
 assert proof['current_ifindex']==3 and proof['mac']==NEW_MAC and proof['mtu']==1500
 proof['old_mac']=OLD_MAC
 return proof
def physical_underlay(cid):
 def read():return reviewed_link_proof(json.loads(execout(cid,'ip','-d','-j','link','show')),json.loads(execout(cid,'ip','-j','address','show')),load('namespace-link-census.json'),load('namespace-address-census.json'))
 bound=read();routes={outside:routeget_proof(json.loads(execout(cid,'ip','-j','-4','route','get',outside,'from','172.30.88.2')),outside)for outside in ['13.50.7.159','51.20.220.141']}
 assert read()==bound
 return {'link':bound,'outside_routes':routes}
def main():
 global run,b,base,pre,n,s,a
 p=argparse.ArgumentParser();p.add_argument('stage',choices=['install','release']);p.add_argument('--run',type=pathlib.Path,required=True);p.add_argument('--v6',type=pathlib.Path,required=True);p.add_argument('--cli',type=pathlib.Path);p.add_argument('--release',type=pathlib.Path);p.add_argument('--release-sha');p.add_argument('--execute',action='store_true');a=p.parse_args();os.umask(0o077);assert os.geteuid()==0
 # Load only the reviewed reusable definitions; never invoke V6's stage driver.
 st=a.v6.lstat();raw=a.v6.read_bytes();assert stat.S_ISREG(st.st_mode)and st.st_uid==0 and not st.st_mode&0o022 and hashlib.sha256(raw).hexdigest()==V6_SHA
 override=physical_underlay
 exec(compile(raw.decode().split('p=argparse.ArgumentParser();',1)[0],str(a.v6),'exec'),globals())
 globals()['physical_underlay']=override
 run=a.run;assert str(run)=='/home/ubuntu/tunnex-bgp-lab/cloud-enrolled-restart-21169a9f-cycle3'
 if not a.execute:print(json.dumps({'source_only':True,'stage':a.stage,'new':REVIEWED_NEW,'namespace':REVIEWED_NS,'v6_sha256':V6_SHA}));return
 b=load('inspect-private.json');base=load('baseline.json');pre=load('preallocated.json')
 assert base['helper_sha256']==V6_SHA and base['old']==OLD and base['delivery']==DELIVERY
 assert pre['new']==REVIEWED_NEW and pre['namespace']==REVIEWED_NS
 assert load('install-pending.json')=={'old':OLD,'new':REVIEWED_NEW,'cli_sha256':CLI}
 stopped=load('stopped.json');proof=load('stop-proof.json')
 assert stopped['proof_sha256']==sha(private(run/'stop-proof.json')) and stopped['new']==REVIEWED_NEW
 assert proof['snapshot']['container']==OLD and proof['checks']==['exact-stopped-runtime','empty-cgroup','no-namespace-holders-two-passes'] and proof['stopped_journal_raw_sha256']==base['journal_sha256']
 old=inspect(OLD);unchanged_layout(old,b,False);assert not old['State']['Running']and old['State']['Pid']==0 and old['NetworkSettings']['Networks']=={}
 n=fresh_worker(b,pre);endpoint_proof(b['NetworkSettings']['Networks'],n['NetworkSettings']['Networks'])
 assert n['NetworkSettings']['Ports']==b['NetworkSettings']['Ports']
 assert inventory(OLD_BIN_DIR)==load('new-worker-artifact.json')['old_binary_inventory']
 assert new_artifact(b)==load('new-worker-artifact.json')
 assert other_runtime()==load('other-runtime-private.json')and cp_binding()==load('cp-binding.json')and host_preservation()==load('host-preservation.json')
 s=state_path(n);gate=s/'ipsec/restoration-startup-gate';st=gate.lstat();gate_proof({'device':st.st_dev,'inode':st.st_ino,'uid':st.st_uid,'mode':stat.S_IMODE(st.st_mode)},load('gate-published.json'),private(gate),base['journal_sha256'])
 assert private(s/'ipsec/journal.json')==private(run/'journal-frozen.json')
 current=physical_underlay(REVIEWED_NEW)
 if a.stage=='install':
  assert a.cli;tool(a.cli,CLI)
  assert not(run/'installed.json').exists()and not(run/'receipt.json').exists()and not(s/('ipsec/restore-'+DELIVERY+'.json')).exists()
  rows=json.loads(execout(REVIEWED_NEW,'ip','-j','-4','route','show','table','all'));assert not any(r.get('dst')in ['10.84.2.0/24','10.84.3.0/24']for r in rows)
  assert subprocess.run(D+['exec',REVIEWED_NEW,'test','-e','/tmp/cloud-enrolled-restoration'],stdout=subprocess.DEVNULL).returncode==1
  save('endpoint-resume-source.json',{'helper_sha256':sha(pathlib.Path(__file__).read_bytes()),'v6_sha256':V6_SHA,'new':REVIEWED_NEW,'namespace':REVIEWED_NS,'reviewed_mac':NEW_MAC,'network_mutations':False})
  save('physical-underlay-proof.json',current)
  for route in base['lan_routes']:
   existing=json.loads(execout(pre['new'],'ip','-j','-4','route','show','table','all'));assert not any(r.get('dst')==route['dst']for r in existing)
   save('route-pending-'+route['dst'].split('/')[0]+'.json',route)
   args=['ip','-4','route','add',route['dst'],'via',route['gateway'],'dev',route['dev'],'proto',str(route.get('protocol','boot'))]
   if 'metric'in route:args+=['metric',str(route['metric'])]
   if 'prefsrc'in route:args+=['src',route['prefsrc']]
   execout(pre['new'],*args)
  got,_=lan_routes(pre['new']);assert sorted(got,key=lambda r:r['dst'])==sorted(base['lan_routes'],key=lambda r:r['dst']);assert physical_underlay(pre['new'])==load('physical-underlay-proof.json')
  assert namespace(pre['new'])==pre['namespace'];assert private(s/'ipsec/journal.json')==private(run/'journal-frozen.json')
  temp='/tmp/cloud-enrolled-restoration';execout(pre['new'],'mkdir','-m','700',temp);stream=io.BytesIO()
  with tarfile.open(fileobj=stream,mode='w')as t:
   for name,raw,mode in [('receipt',a.cli.read_bytes(),0o700),('journal.json',private(run/'journal-frozen.json'),0o600),('proof.json',private(run/'stop-proof.json'),0o600)]:
    e=tarfile.TarInfo(name);e.uid=e.gid=0;e.mode=mode;e.size=len(raw);t.addfile(e,io.BytesIO(raw))
  subprocess.run(D+['exec','-i',pre['new'],'tar','-xf','-','-C',temp],input=stream.getvalue(),check=True)
  canonical=s/('ipsec/restore-'+DELIVERY+'.json');assert not canonical.exists()
  boot=execout(pre['new'],'cat','/proc/sys/kernel/random/boot_id').decode().strip()
  execout(pre['new'],'env','TMPDIR='+temp,temp+'/receipt','--journal',temp+'/journal.json','--evidence',temp+'/proof.json','--boot',boot,'--namespace',pre['namespace'],'--out','/state/ipsec/restore-'+DELIVERY+'.json')
  raw=private(canonical);r=json.loads(raw);assert r['DeliveryID']==DELIVERY and r['Namespace']==pre['namespace'];assert sha(private(s/'ipsec/journal.json'))==base['journal_sha256'];publish(run/'receipt.json',raw);save('installed.json',{'resume_helper_sha256':sha(pathlib.Path(__file__).read_bytes()),'new':pre['new'],'namespace':pre['namespace'],'receipt_sha256':sha(raw),'journal_sha256':base['journal_sha256']});print('Genuine receipt and exact LAN routes installed; worker remains sleeping');return
 if a.stage=='release':
  assert load('endpoint-resume-source.json')['helper_sha256']==sha(pathlib.Path(__file__).read_bytes())
  installed=load('installed.json');assert installed['resume_helper_sha256']==sha(pathlib.Path(__file__).read_bytes());assert installed['new']==pre['new'];assert a.release and a.release_sha=='b3c2ec306d80c49f5735772a1dbf3ec92fb06b248dca6c82ee70c63d702ced17';tool(a.release,a.release_sha)
  assert sha(private(s/('ipsec/restore-'+DELIVERY+'.json')))==installed['receipt_sha256'];got,_=lan_routes(pre['new']);assert sorted(got,key=lambda r:r['dst'])==sorted(base['lan_routes'],key=lambda r:r['dst']);assert physical_underlay(pre['new'])==load('physical-underlay-proof.json')
  save('release-pending.json',{'new':pre['new'],'release_sha256':a.release_sha,'receipt_sha256':installed['receipt_sha256']})
  stream=io.BytesIO()
  with tarfile.open(fileobj=stream,mode='w')as t:
   raw=a.release.read_bytes();e=tarfile.TarInfo('release');e.uid=e.gid=0;e.mode=0o700;e.size=len(raw);t.addfile(e,io.BytesIO(raw))
  subprocess.run(D+['exec','-i',pre['new'],'tar','-xf','-','-C','/tmp/cloud-enrolled-restoration'],input=stream.getvalue(),check=True)
  execout(pre['new'],'/tmp/cloud-enrolled-restoration/release','--delivery',DELIVERY,'--namespace',pre['namespace'],'--journal-sha',base['journal_sha256'],'--receipt-sha',installed['receipt_sha256'])
  save('released.json',{'old_proof_node_sha256':NODE,'new_worker_node_sha256':NEW_NODE,'new_worker_source_sha256':NEW_SOURCE,'new_binary_mount_source':NEW_BIN_DIR,'new':pre['new'],'namespace':pre['namespace'],'worker_released':True,'product_recovery_acceptance':'pending','state_json_unmodified':True,'old_retained':True});print('Worker released; actual CP lease/native recovery/packet proof required separately')
 

if __name__=='__main__':main()
