#!/usr/bin/env python3
"""Exact run4-only restoration of simulator underlay routes; no journal/authority writes."""
import argparse,hashlib,ipaddress,json,os,pathlib,subprocess
from enrolled_approval import reviewed_run
os.umask(0o077)
p=argparse.ArgumentParser();p.add_argument('--run-directory',type=pathlib.Path,required=True);p.add_argument('--execute',action='store_true');a=p.parse_args()
r=pathlib.Path(__file__).resolve().parent;shared=r/'.runtime';rt,approval,index=reviewed_run(shared,a.run_directory);assert index==4
def read(path):
 assert not path.is_symlink()and path.stat().st_mode&0o777==0o600
 return path.read_bytes()
def doc(name):return json.loads(read(rt/name))
d=[str(r/'docker-local.sh')]
def out(*args):return subprocess.check_output(d+list(args))
plan=doc('disposable-underlay-before.json');pre=doc('enrolled-preallocation.json');installed=doc('enrolled-restoration-installed.json');layout=doc('enrolled-restoration-before-layout-v3.json');new=pre['new_container_id']
assert plan['old_image']=='sha256:e789c8c86054e7b2507e7f00da1c13d4498725b47fc7f8158f7f7102e5ec435e'and plan['old_binary_sha256']=='a14d312802d64be51ab6c06193fd6dc4c7583b79977653ca2eac44197867100e'
assert plan['old_container_id']==pre['old_container_id']==approval['old_container_id']and plan['old_namespace']==layout['namespace']=='net:[4026532931]'
assert installed['installation_complete']and installed['new_container_id']==new and installed['actual_new_namespace']==pre['new_namespace']
n=json.loads(out('inspect',new))[0];old=json.loads(out('inspect',pre['old_container_id']))[0];assert n['State']['Running']and not old['State']['Running']and n['Image']==approval['image']
def run(*args):return out('exec',new,*args)
assert run('readlink','/proc/1/ns/net').decode().strip()==pre['new_namespace'];assert not any(x in run('ps','-eo','comm').decode().splitlines()for x in ['tunnex-node','charon','bgpd','zebra'])
journal=run('cat','/state/ipsec/journal.json');assert hashlib.sha256(journal).hexdigest()==layout['journal_sha256']
receipt=run('cat','/state/ipsec/restore-'+installed['delivery_id']+'.json');assert hashlib.sha256(receipt).hexdigest()==installed['genuine_receipt_sha256'];assert run('cat','/state/ipsec/restoration-startup-gate')==b'owned enrolled restoration supervisor blocks Apply until genuine new namespace receipt durable\n'
links=json.loads(run('ip','-j','-d','link','show','dev','eth1'));addr=json.loads(run('ip','-j','addr','show','dev','eth1'));assert len(links)==len(addr)==1 and 'UP'in links[0]['flags']and links[0]['link_type']=='ether'and links[0].get('linkinfo',{}).get('info_kind')=='veth'
expected_mac=layout['networks']['tunnexs2sbgpintegrated1007-outer']['MacAddress'];assert links[0]['address']==expected_mac
assert all(any(x.get('local')==ip and x.get('prefixlen')==bits for x in addr[0]['addr_info'])for ip,bits in [('198.19.241.10',24),('13.63.169.255',32)])
expected={x:(via,metric)for xs,via,metric in [(['13.50.7.160','51.20.220.142'],'198.19.241.30',51030),(['13.50.7.161','51.20.220.143'],'198.19.241.31',51032)]for x in xs}
def exact(row):
 dst=str(ipaddress.ip_network(row['dst']));host=str(ipaddress.ip_network(dst).network_address);assert host in expected and dst==host+'/32';via,metric=expected[host]
 assert row.get('gateway')==via and row.get('dev')=='eth1'and row.get('protocol')=='static'and row.get('metric')==metric and row.get('prefsrc')=='13.63.169.255'and row.get('table',254)in [254,'main']and row.get('type','unicast')=='unicast'and not row.get('flags')and not any(k in row for k in ['nexthops','nhid','encap','encap_type'])
 return dst
assert len(plan['routes'])==4 and len({exact(x['actual'])for x in plan['routes']})==4
for item in plan['routes']:
 row=item['actual'];own=item['ownership'];dst=exact(row);assert item['fixture']in ['limits','static']and own['container_id']==plan['old_container_id']and own['destination']==dst and own['gateway']==row['gateway']and own['dev']=='eth1'and own['protocol']=='static'and own['table']==254 and own['metric']==row['metric']and own.get('preferred_source')=='13.63.169.255'and own['state']=='installed'
 assert row['metric']==(51030 if item['fixture']=='limits'else 51032)
assert set(plan['fixture_source_hashes'])=={'story9-limits/topology-v2.json','story9-static/topology.json'}
for name,digest in plan['fixture_source_hashes'].items():
 raw=read(shared/name);assert hashlib.sha256(raw).hexdigest()==digest;top=json.loads(raw);assert top['gateway_id']==plan['old_container_id']
 expected_hosts=top['outside'];assert all(any(o['container_id']==plan['old_container_id']and o['destination']==host+'/32'and o['state']=='installed'and o.get('preferred_source')=='13.63.169.255'for o in top['route_obligations'])for host in expected_hosts)
 peer=json.loads(out('inspect',top['containers']['peer']))[0];assert peer['State']['Running']and peer['Config']['Labels']['tunnex.bgp.integrated']==top['project']
 for host in expected_hosts:assert peer['NetworkSettings']['Networks']['tunnexs2sbgpintegrated1007-outer']['IPAddress']==expected[host][0]
def routes():return json.loads(run('ip','-j','-4','route','show','table','all'))
before=routes();assert not any(str(ipaddress.ip_network(x['dst'])).split('/')[0]in expected for x in before if x.get('dst')not in [None,'default'])
if not a.execute:print(json.dumps({'run':4,'routes':4,'worker_released':False,'mutation_performed':False}));raise SystemExit(0)
def write(path,value):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:os.write(fd,(json.dumps(value,indent=2)+'\n').encode());os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
for i,item in enumerate(plan['routes']):
 row=item['actual'];dst=exact(row);write(rt/f'disposable-underlay-pending-{i}.json',{'new_container_id':new,'namespace':pre['new_namespace'],'plan_sha256':hashlib.sha256(read(rt/'disposable-underlay-before.json')).hexdigest(),'route':row})
 run('ip','route','add',dst,'via',row['gateway'],'dev','eth1','table','254','proto','static','metric',str(row['metric']),'src','13.63.169.255')
 got=json.loads(run('ip','-j','-4','route','show','table','main','exact',dst));assert len(got)==1 and exact(got[0])==dst
 resolved=json.loads(run('ip','-j','-4','route','get',dst.split('/')[0]));assert len(resolved)==1 and resolved[0].get('gateway')==row['gateway']and resolved[0].get('dev')=='eth1'and resolved[0].get('prefsrc')=='13.63.169.255'and not resolved[0].get('flags')
 write(rt/f'disposable-underlay-installed-{i}.json',{'route':got[0],'source_route':resolved[0]})
after=routes();foreign=[x for x in after if not(x.get('dst')not in [None,'default']and str(ipaddress.ip_network(x['dst'])).split('/')[0]in expected)];assert sorted(map(lambda x:json.dumps(x,sort_keys=True),foreign))==sorted(map(lambda x:json.dumps(x,sort_keys=True),before))
assert run('cat','/state/ipsec/journal.json')==journal and run('cat','/state/ipsec/restore-'+installed['delivery_id']+'.json')==receipt
write(rt/'disposable-underlay-restored.json',{'new_container_id':new,'namespace':pre['new_namespace'],'route_count':4,'foreign_routes_unchanged':True,'journal_unchanged':True,'worker_released':False})
