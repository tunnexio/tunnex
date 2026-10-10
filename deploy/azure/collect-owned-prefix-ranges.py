#!/usr/bin/env python3
"""Read-only owned lab range inventory. No network mutation or acceptance assertion."""
import argparse
from datetime import datetime, timezone
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import uuid


def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
prefix=load('prefix_helpers',Path(__file__).with_name('qualify-owned-unapproved-prefix.py'))
enroll=load('range_enroll',Path(__file__).parents[2]/'tests/azure-s2s-local/enroll-local.py')
life=load('range_lifecycle',Path(__file__).parents[2]/'tests/azure-s2s-local/lifecycle-live.py')
lab=prefix.lab


def now():return datetime.now(timezone.utc).isoformat()
def ident(value):
 if not isinstance(value,str) or str(uuid.UUID(value))!=value:raise ValueError('UUID shape')
 return value

def parent(path):
 path=Path(path).absolute();info=path.parent.lstat()
 if path.parent!=path.parent.resolve() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('private parent')
 return path

def rows(value):
 if not isinstance(value,list) or len(value)>128:raise ValueError('inventory bounds')
 return value

def network(value,host=False):
 net=ipaddress.ip_network(value+('/32' if host else ''),strict=True)
 if net.version!=4:raise ValueError('IPv4 range required')
 return str(net)

def add(output,source,value,host=False):
 item={'source':source,'cidr':network(value,host)}
 if item not in output:output.append(item)
 if len(output)>512:raise ValueError('range bounds')

def envelope(kind,started,ranges,**fields):
 return dict(version=1,kind=kind,observed_at=started,completed_at=now(),subscription=lab.SUBSCRIPTION,resource_group=lab.RG,owner=lab.OWNER,vnet_id=prefix.VNET,ranges=ranges,**fields)


def expected_contract(value):
 if not isinstance(value,dict):raise ValueError('expected connection contract')
 ident(value['id'])
 for key in ('desired_revision','configuration_revision'):
  if type(value.get(key))!=int or value[key]<1:raise ValueError('expected revision')
 if type(value.get('maximum_prefixes'))!=int:raise ValueError('expected maximum prefix integer')
 if value.get('profile_id')!='azure-active-active-bgp-ipv4-v1' or value.get('remote_prefixes')!=['10.231.0.0/16','10.235.77.0/24'] or value.get('maximum_prefixes')!=1 or value['id']==prefix.CP:raise ValueError('bounded maximum-prefix contract')
 return value


def api_collect(root,expected=None):
 root=Path(root);parent(root/'placeholder')
 if expected is not None:expected_contract(expected)
 current_id=expected['id'] if expected else prefix.CP
 accounts=json.loads(prefix.helpers.private_read(root/'ui-accounts.json'));setup=json.loads(prefix.helpers.private_read(root/'api-setup.json'))
 for key in ('org_id','site_id','gateway_id'):ident(setup[key])
 if isinstance(accounts,dict):accounts=accounts.get('accounts',list(accounts.values()))
 owners=[a for a in accounts if a.get('email')=='browser-owner@azure-s2s.local']
 if len(owners)!=1:raise ValueError('owned login')
 client=enroll.Client({'email':owners[0]['email'],'password':owners[0]['password']})
 started=now();ranges=[];base='/api/v1/organizations/'+setup['org_id']
 organizations=client.call('GET','/api/v1/organizations')
 if isinstance(organizations,dict):organizations=organizations['organizations']
 owned=[o for o in rows(organizations) if o['id']==setup['org_id'] and o['slug']=='azure-s2s-local']
 if len(owned)!=1:raise ValueError('owned organization')
 add(ranges,'org_pool',owned[0]['pool_cidr'])
 def get(suffix):return client.call('GET',base+suffix)
 before=life.connection_projection(get('/ipsec/connections/'+current_id),setup,current_id)
 sites=rows(get('/sites'));nodes=rows(get('/nodes'))
 if not any(s['id']==setup['site_id'] for s in sites) or not any(n['id']==setup['gateway_id'] for n in nodes):raise ValueError('owned Site/Gateway absent')
 contexts=0
 if len(sites)*len(nodes)>128:raise ValueError('resolver context bounds')
 for site in sites:
  sid=ident(site['id'])
  for subnet in rows(get('/sites/'+sid+'/subnets')):add(ranges,'site_subnet',subnet['cidr'])
  for forward in rows(get('/sites/'+sid+'/dns-forwards')):add(ranges,'site_resolver',forward['resolver_ip'],True)
  for node in nodes:
   nid=ident(node['id'])
   try:config=get('/fqdn-resolver-contexts/'+sid+'/'+nid)
   except enroll.LabError as error:
    if error.status==404 and error.code=='fqdn_resolver_config_not_found':continue
    raise
   if config['site_id']!=sid or config['gateway_id']!=nid or config['org_id']!=setup['org_id'] or config['state']!='active':raise ValueError('resolver binding')
   contexts+=1
   for profile in rows(config['profiles']):
    for endpoint in rows(profile['endpoints']):add(ranges,'resolver_endpoint',endpoint['address'],True)
    if profile.get('ipsec_path'):add(ranges,'resolver_source',profile['ipsec_path']['source_address'],True)
 routed=get('/routed-ranges')
 for value in rows(routed['ranges']):add(ranges,'routed_range',value)
 for item in rows(routed['forwards']):add(ranges,'routed_resolver',item['resolver_ip'],True)
 for resource in rows(get('/resources')):add(ranges,'resource',resource['cidr'])
 policies=rows(get('/policies'))
 for rule in policies:
  if rule.get('src_cidr') is not None:add(ranges,'policy_source',rule['src_cidr'])
 cursor=None;seen=set();connections=0;normal=None
 for unused in range(8):
  page=get('/ipsec/connections?limit=100'+('&after='+cursor if cursor else ''))
  for connection in rows(page['items']):
   cid=ident(connection['id']);connections+=1
   if cid in seen:raise ValueError('duplicate connection page')
   seen.add(cid)
   raw=get('/ipsec/connections/'+cid+'/configuration');config=raw.get('configuration')
   if connection.get('finalized_at') is not None:
    life.timestamp(connection['finalized_at'])
    if connection['desired_intent']!='deleted' or config is not None or cid==current_id:raise ValueError('finalized connection shape')
    continue
   if not isinstance(config,dict):raise ValueError('active connection configuration absent')
   for key in ('local_prefixes','remote_prefixes'):
    for value in rows(config[key]):
     if expected is not None and cid==current_id and key=='remote_prefixes' and value=='10.235.77.0/24':
      if raw.get('profile_id')!=expected['profile_id'] or raw.get('configuration_revision')!=expected['configuration_revision'] or config[key]!=expected['remote_prefixes'] or config.get('bgp',{}).get('maximum_prefixes')!=1:raise ValueError('candidate reservation contract changed')
      continue
     add(ranges,'connection_'+key,value)
   for tunnel in rows(config['tunnels']):
    if tunnel.get('inside_cidr'):add(ranges,'connection_inside',tunnel['inside_cidr'])
   if cid==current_id:
    normal=dict(before,profile_id=raw['profile_id'],remote_prefixes=config['remote_prefixes'],maximum_prefixes=config['bgp']['maximum_prefixes'])
    if expected is not None:normal['configuration_revision']=raw['configuration_revision']
  cursor=page['next_cursor']
  if cursor is None:break
  ident(cursor)
 else:raise ValueError('connection pagination incomplete')
 after=life.connection_projection(get('/ipsec/connections/'+current_id),setup,current_id)
 if before!=after or normal is None:raise ValueError('connection changed during review')
 if expected is None:
  if normal['desired_revision']!=34:raise ValueError('revision34 required')
 else:
  if any(normal.get(key)!=value for key,value in expected.items()) or normal['desired_intent']!='enabled' or normal['application_state']!='applied':raise ValueError('current normal contract changed')
 return envelope('owned_api_ranges',started,ranges,normal_connection=normal,org_id=setup['org_id'],site_id=setup['site_id'],gateway_id=setup['gateway_id'],candidate_reservation=({'connection_id':current_id,'configuration_revision':expected['configuration_revision'],'prefix':'10.235.77.0/24'} if expected else None),counts={'sites':len(sites),'nodes':len(nodes),'resolver_contexts':contexts,'policies':len(policies),'connections':connections})


def kernel_collect(expected_device,expected_inode):
 if os.geteuid()!=0:raise ValueError('root kernel observation required')
 ns=os.stat('/proc/self/ns/net')
 if (ns.st_dev,ns.st_ino)!=(expected_device,expected_inode):raise ValueError('actual owned namespace mismatch')
 ip=Path('/sbin/ip').resolve();info=ip.stat()
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('trusted ip binary required')
 def read(*args):
  run=subprocess.run([str(ip),'-j','-4',*args],capture_output=True,text=True,timeout=10)
  if run.returncode or len(run.stdout)>262144:raise ValueError('kernel read refused')
  return rows(json.loads(run.stdout))
 started=now();ranges=[];addresses=read('addr','show');routes=read('route','show','table','all');defaults=0
 for interface in addresses:
  for address in rows(interface['addr_info']):
   if address['family']!='inet':raise ValueError('kernel IPv4 shape')
   # Kernel interfaces may contain host bits; record their actual connected subnet.
   add(ranges,'kernel_interface',str(ipaddress.ip_network(address['local']+'/'+str(address['prefixlen']),strict=False)))
 for route in routes:
  destination=route.get('dst','default')
  if destination in ('default','0.0.0.0/0'):defaults+=1;continue
  add(ranges,'kernel_route',destination if '/' in destination else destination+'/32')
  if route.get('gateway'):add(ranges,'kernel_next_hop',route['gateway'],True)
 return envelope('owned_kernel_ranges',started,ranges,namespace={'device':ns.st_dev,'inode':ns.st_ino},default_route_count=defaults)


def azure_collect():
 if socket.gethostname()!='bastion-host':raise ValueError('bastion hostname required')
 started=now();prefix.cloud_binding();ranges=[];counts={}
 for command,kind in [('vnet','virtualNetworks'),('local-gateway','localNetworkGateways')]:
  values=rows(lab.az('network',command,'list','-g',lab.RG,'--subscription',lab.SUBSCRIPTION))
  counts[kind]=len(values)
  for value in values:
   lab.resource_id(value['id'],lab.SUBSCRIPTION,kind)
   if value.get('tags',{}).get('owner')!=lab.OWNER:raise ValueError('foreign cloud owner')
   if value.get('name')!=value['id'].rsplit('/',1)[1] or value.get('provisioningState')!='Succeeded':raise ValueError('cloud inventory unsettled')
   for cidr in rows(value['addressSpace' if command=='vnet' else 'localNetworkAddressSpace']['addressPrefixes']):add(ranges,'azure_'+command,cidr)
   if command!='vnet':continue
   if value.get('summarizedGatewayPrefixes') or value['addressSpace'].get('summarizedGatewayPrefixes'):raise ValueError('summarized advertisement unsupported')
   name=value['name']
   subnets=rows(lab.az('network','vnet','subnet','list','-g',lab.RG,'--vnet-name',name,'--subscription',lab.SUBSCRIPTION))
   for subnet in subnets:
    if not subnet['id'].lower().startswith(value['id'].lower()+'/subnets/'):raise ValueError('subnet binding')
    for cidr in subnet.get('addressPrefixes') or [subnet['addressPrefix']]:add(ranges,'azure_subnet',cidr)
   peerings=rows(lab.az('network','vnet','peering','list','-g',lab.RG,'--vnet-name',name,'--subscription',lab.SUBSCRIPTION))
   for peer in peerings:
    if not peer['id'].lower().startswith(value['id'].lower()+'/virtualnetworkpeerings/'):raise ValueError('peering binding')
    remote=peer['remoteVirtualNetwork']['id'];lab.resource_id(remote,lab.SUBSCRIPTION,'virtualNetworks')
    if not any(v['id'].lower()==remote.lower() for v in values):raise ValueError('unreviewed remote peering')
    for field in ('remoteAddressSpace','remoteVirtualNetworkAddressSpace'):
     for cidr in peer.get(field,{}).get('addressPrefixes',[]):add(ranges,'azure_peering',cidr)
   for ip in value.get('dhcpOptions',{}).get('dnsServers',[]):add(ranges,'azure_dns',ip,True)
 tables=rows(lab.az('network','route-table','list','-g',lab.RG,'--subscription',lab.SUBSCRIPTION));counts['route_tables']=len(tables)
 for table in tables:
  lab.resource_id(table['id'],lab.SUBSCRIPTION,'routeTables')
  if table.get('tags',{}).get('owner')!=lab.OWNER:raise ValueError('foreign route table')
  if table.get('name')!=table['id'].rsplit('/',1)[1] or table.get('provisioningState')!='Succeeded':raise ValueError('route table unsettled')
  for route in rows(lab.az('network','route-table','route','list','-g',lab.RG,'--route-table-name',table['name'],'--subscription',lab.SUBSCRIPTION)):
   if not route['id'].lower().startswith(table['id'].lower()+'/routes/'):raise ValueError('UDR binding')
   if route['addressPrefix']=='0.0.0.0/0':raise ValueError('default UDR needs separate review')
   add(ranges,'azure_udr',route['addressPrefix'])
   if route.get('nextHopIpAddress'):add(ranges,'azure_udr_next_hop',route['nextHopIpAddress'],True)
 return envelope('owned_azure_ranges',started,ranges,counts=counts)


def assemble(values,candidate,expected_device,expected_inode,clock,expected=None):
 if expected is not None:expected_contract(expected)
 if len(values)!=3:raise ValueError('three inventories required')
 kinds=('owned_api_ranges','owned_kernel_ranges','owned_azure_ranges');ranges=[];times=[]
 candidate=network(candidate);net=ipaddress.ip_network(candidate)
 if net.prefixlen!=24 or not net.subnet_of(ipaddress.ip_network('10.0.0.0/8')):raise ValueError('bounded candidate prefix')
 labels={'owned_api_ranges':{'org_pool','site_subnet','site_resolver','resolver_endpoint','resolver_source','routed_range','routed_resolver','resource','policy_source','connection_local_prefixes','connection_remote_prefixes','connection_inside'},'owned_kernel_ranges':{'kernel_interface','kernel_route','kernel_next_hop'},'owned_azure_ranges':{'azure_vnet','azure_local-gateway','azure_subnet','azure_peering','azure_dns','azure_udr','azure_udr_next_hop'}}
 for value,kind in zip(values,kinds):
  if value.get('version')!=1 or value.get('kind')!=kind:raise ValueError('inventory kind')
  for key,wanted in [('subscription',lab.SUBSCRIPTION),('resource_group',lab.RG),('owner',lab.OWNER),('vnet_id',prefix.VNET)]:
   if value.get(key)!=wanted:raise ValueError('inventory ownership')
  for key in ('observed_at','completed_at'):prefix.helpers.fresh(value[key],clock)
  start=datetime.fromisoformat(value['observed_at']);end=datetime.fromisoformat(value['completed_at'])
  if start>end:raise ValueError('inventory chronology')
  times.append(start)
  if not isinstance(value['ranges'],list) or not 1<=len(value['ranges'])<=512:raise ValueError('range bounds')
  for item in value['ranges']:
   if set(item)!=set(('source','cidr')) or item['source'] not in labels[kind]:raise ValueError('range projection fields')
   ranges.append(network(item['cidr']))
 if values[1]['namespace']!={'device':expected_device,'inode':expected_inode}:raise ValueError('namespace review binding')
 raw=values[0]['normal_connection']
 normal={key:raw[key] for key in ('id','desired_revision','desired_intent','application_state','profile_id','remote_prefixes','maximum_prefixes')}
 if type(normal['desired_revision'])!=int or type(normal['maximum_prefixes'])!=int:raise ValueError('normal integer shape')
 if expected is None:
  if normal['desired_revision']!=34:raise ValueError('revision34 required')
 else:
  normal['configuration_revision']=raw['configuration_revision']
  if any(normal.get(key)!=value for key,value in expected.items()) or normal['desired_intent']!='enabled' or normal['application_state']!='applied':raise ValueError('current normal contract changed')
  if values[0].get('candidate_reservation')!={'connection_id':expected['id'],'configuration_revision':expected['configuration_revision'],'prefix':candidate}:raise ValueError('candidate reservation binding')
 output=envelope('owned_prefix_range_review',min(times).isoformat(),sorted(set(ranges)),candidate=candidate,normal_connection=normal,source_sha256=[prefix.digest(value) for value in values],namespace=values[1]['namespace'])
 if expected is None:prefix.evidence(output,candidate,clock)
 else:
  output['candidate_reservation']=values[0]['candidate_reservation']
  for item in ranges:
   if net.overlaps(ipaddress.ip_network(item)):raise ValueError('candidate range overlap')
 return output


def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=['api','kernel','azure','assemble']);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--private-root',type=Path);parser.add_argument('--inputs',type=Path,nargs=3);parser.add_argument('--namespace-device',type=int);parser.add_argument('--namespace-inode',type=int);parser.add_argument('--candidate',default='10.235.77.0/24');parser.add_argument('--expected-connection-file',type=Path);args=parser.parse_args();output=parent(args.output)
 if args.phase in ('kernel','assemble') and (args.namespace_device is None or args.namespace_inode is None or args.namespace_device<1 or args.namespace_inode<1):raise ValueError('actual namespace binding required')
 expected=json.loads(prefix.helpers.private_read(args.expected_connection_file)) if args.expected_connection_file else None
 if expected is not None:
  expected=expected.get('normal_connection',expected)
  expected={key:expected[key] for key in ('id','desired_revision','configuration_revision','profile_id','remote_prefixes','maximum_prefixes')}
 if args.phase=='api':result=api_collect(args.private_root,expected)
 elif args.phase=='kernel':result=kernel_collect(args.namespace_device,args.namespace_inode)
 elif args.phase=='azure':result=azure_collect()
 else:
  if args.inputs is None:raise ValueError('three private inputs required')
  result=assemble([json.loads(prefix.helpers.private_read(path)) for path in args.inputs],network(args.candidate),args.namespace_device,args.namespace_inode,datetime.now(timezone.utc),expected)
 prefix.private_write(output,result);print(json.dumps({'version':1,'phase':args.phase,'projection_written':True}))

if __name__=='__main__':
 try:main()
 except (ValueError,KeyError,TypeError,OSError,subprocess.TimeoutExpired,enroll.LabError):
  print('{"version":1,"range_collection":"refused"}');raise SystemExit(1)
