#!/usr/bin/env python3
"""Owned VNet prefix experiment only. No CP changes, grants, keys or acceptance claim."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess

spec=importlib.util.spec_from_file_location('owned_mode_helpers',Path(__file__).with_name('set-owned-responder-only.py'))
helpers=importlib.util.module_from_spec(spec);spec.loader.exec_module(helpers)
lab=helpers.lab
BASE='/subscriptions/'+lab.SUBSCRIPTION+'/resourceGroups/'+lab.RG+'/providers/Microsoft.Network/'
VNET=BASE+'virtualNetworks/azure-vnet'
CONNECTION=BASE+'connections/tunnex-connection'
CP='9bfa4090-d3ca-4a8e-9ef9-3b41bd91fe99'


def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def private_write(path,value):
 if path.exists() or path.is_symlink():helpers.private_read(path)
 temporary=path.with_name(path.name+'.pending')
 if temporary.exists() or temporary.is_symlink():raise ValueError('private write reservation exists')
 fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,'w') as stream:json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
  os.replace(temporary,path)
  fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(fd)
  finally:os.close(fd)
 finally:
  if temporary.exists():temporary.unlink()


def protected(raw):
 if not isinstance(raw,dict):raise ValueError('resource object')
 # ARM etags are concurrency metadata, not an assertion that resource properties changed.
 def strip(value):
  if isinstance(value,dict):return {key:strip(item) for key,item in value.items() if key!='etag'}
  if isinstance(value,list):return [strip(item) for item in value]
  return value
 value=strip(copy.deepcopy(raw))
 value['addressSpace'].pop('addressPrefixes')
 return value


def vnet(raw):
 if raw.get('id','').lower()!=VNET.lower() or raw.get('tags',{}).get('owner')!=lab.OWNER or raw.get('provisioningState')!='Succeeded':raise ValueError('owned VNet binding')
 if raw.get('summarizedGatewayPrefixes') or raw.get('addressSpace',{}).get('summarizedGatewayPrefixes'):raise ValueError('summarized advertisement unsupported')
 prefixes=raw['addressSpace']['addressPrefixes']
 if not isinstance(prefixes,list) or not 1<=len(prefixes)<=16 or len(set(prefixes))!=len(prefixes):raise ValueError('VNet prefix shape')
 for prefix in prefixes:
  network=ipaddress.ip_network(prefix,strict=True)
  if network.version!=4:raise ValueError('IPv4 VNet required')
 return prefixes


def evidence(review,candidate,now):
 if not isinstance(review,dict):raise ValueError('fresh reviewed ranges required')
 if review.get('version')!=1 or review.get('kind')!='owned_prefix_range_review' or review.get('subscription')!=lab.SUBSCRIPTION or review.get('resource_group')!=lab.RG or review.get('owner')!=lab.OWNER or review.get('vnet_id')!=VNET or review.get('candidate')!=candidate:raise ValueError('prefix review binding')
 helpers.fresh(review['observed_at'],now)
 cp=review['normal_connection']
 if cp.get('id')!=CP or type(cp.get('desired_revision'))!=int or cp['desired_revision']<30 or cp.get('desired_intent')!='enabled' or cp.get('application_state')!='applied' or cp.get('profile_id')!='azure-active-active-bgp-ipv4-v1' or cp.get('remote_prefixes')!=['10.231.0.0/16'] or cp.get('maximum_prefixes')!=8:raise ValueError('normal CP allowlist boundary')
 ranges=review['ranges']
 if not isinstance(ranges,list) or not 1<=len(ranges)<=512:raise ValueError('reviewed ranges required')
 for prefix in ranges:
  if ipaddress.ip_network(candidate).overlaps(ipaddress.ip_network(prefix,strict=True)):raise ValueError('candidate range overlap')


def cloud_binding():
 discovery=lab.discover(lab.SUBSCRIPTION,CONNECTION)
 if discovery['gateway_id'].lower()!=(BASE+'virtualNetworkGateways/azure-vpn').lower() or discovery['local_gateway_id'].lower()!=(BASE+'localNetworkGateways/tunnex-local').lower() or discovery['active_active'] is not True or discovery['enable_bgp'] is not True:raise ValueError('owned AA BGP binding')
 view=lab.az('network','vpn-connection','show','--ids',CONNECTION,'--subscription',lab.SUBSCRIPTION,'--query',helpers.QUERY)
 if helpers.projection(view,discovery)['mode']!='Default':raise ValueError('preserve actual Default mode')
 return discovery


def cloud_ranges(candidate):
 for kind,command,query in [('virtualNetworks','vnet','[].{id:id,owner:tags.owner,prefixes:addressSpace.addressPrefixes}'),('localNetworkGateways','local-gateway','[].{id:id,owner:tags.owner,prefixes:localNetworkAddressSpace.addressPrefixes}')]:
  values=lab.az('network',command,'list','--resource-group',lab.RG,'--subscription',lab.SUBSCRIPTION,'--query',query)
  if not isinstance(values,list) or len(values)>64:raise ValueError('owned range inventory')
  for value in values:
   lab.resource_id(value['id'],lab.SUBSCRIPTION,kind)
   if value.get('owner')!=lab.OWNER:raise ValueError('foreign range owner')
   for prefix in value.get('prefixes') or []:
    if ipaddress.ip_network(candidate).overlaps(ipaddress.ip_network(prefix,strict=True)):raise ValueError('cloud range overlap')


def external_properties():
 values={}
 for name,kind,api in [('azure-private-app-lb','loadBalancers','2024-05-01'),('azure-resolver','dnsResolvers','2022-07-01'),('azure-s2s.test','privateDnsZones','2020-06-01')]:
  expected=BASE+kind+'/'+name
  value=lab.az('resource','show','--ids',expected,'--api-version',api,'--subscription',lab.SUBSCRIPTION)
  if value.get('id','').lower()!=expected.lower() or value.get('tags',{}).get('owner')!=lab.OWNER:raise ValueError('protected resource ownership')
  values[kind]=value
 for slot in (1,2):
  expected=BASE+'dnsResolvers/azure-resolver/inboundEndpoints/inbound'+str(slot)
  value=lab.az('resource','show','--ids',expected,'--api-version','2022-07-01','--subscription',lab.SUBSCRIPTION)
  if value.get('id','').lower()!=expected.lower() or value.get('tags',{}).get('owner')!=lab.OWNER:raise ValueError('resolver endpoint ownership')
  values['inbound'+str(slot)]=value
 values['dns_records']=lab.az('network','private-dns','record-set','list','--resource-group',lab.RG,'--zone-name','azure-s2s.test','--subscription',lab.SUBSCRIPTION)
 values['dns_links']=lab.az('network','private-dns','link','vnet','list','--resource-group',lab.RG,'--zone-name','azure-s2s.test','--subscription',lab.SUBSCRIPTION)
 def strip(value):
  if isinstance(value,dict):return {key:strip(item) for key,item in value.items() if key!='etag'}
  if isinstance(value,list):return [strip(item) for item in value]
  return value
 return strip(values)


def read_vnet():
 raw=lab.az('network','vnet','show','--ids',VNET,'--subscription',lab.SUBSCRIPTION)
 vnet(raw);return raw


def run(phase,state_path,review=None,candidate='10.235.77.0/24'):
 if socket.gethostname()!='bastion-host':raise ValueError('bastion hostname required')
 network=ipaddress.ip_network(candidate,strict=True)
 if network.version!=4 or network.prefixlen!=24 or not network.subnet_of(ipaddress.ip_network('10.0.0.0/8')):raise ValueError('bounded candidate prefix')
 now=datetime.now(timezone.utc)
 if phase=='prepare':
  if state_path.exists() or state_path.is_symlink():raise ValueError('existing experiment; inspect instead')
  evidence(review,candidate,now);discovery=cloud_binding();cloud_ranges(candidate);baseline=read_vnet();external=external_properties()
  state={'version':1,'stage':'prepared','candidate':candidate,'vnet_id':VNET,'baseline':baseline,'protected_sha256':digest(protected(baseline)),'discovery':discovery,'external':external,'external_sha256':digest(external)}
  private_write(state_path,state)
 else:
  state=json.loads(helpers.private_read(state_path))
  if state.get('version')!=1 or state.get('vnet_id')!=VNET or state.get('candidate')!=candidate or state.get('stage') not in ('prepared','add_sent','added','restore_sent','restored') or digest(protected(state['baseline']))!=state['protected_sha256']:raise ValueError('private experiment binding')
  discovery=cloud_binding()
  for key in ('gateway_id','local_gateway_id','active_active','sku','vpn_type','enable_bgp','public_endpoints','local_prefixes'):
   if discovery.get(key)!=state['discovery'].get(key):raise ValueError('gateway discovery changed')
  if digest(state['external'])!=state['external_sha256'] or digest(external_properties())!=state['external_sha256']:raise ValueError('protected DNS or LB properties changed')
  current=read_vnet();original=vnet(state['baseline']);added=original+[candidate]
  if digest(protected(current))!=state['protected_sha256']:raise ValueError('protected VNet property changed')
  if phase in ('read','reconcile'):
   classification='original' if vnet(current)==original else 'added' if vnet(current)==added else 'unexpected'
   if classification=='unexpected':raise ValueError('prefix list changed')
   return {'version':1,'phase':phase,'saved_stage':state['stage'],'current_prefix_state':classification,'observed_at':now.isoformat(),'scope':'Resource observation only; advertisement and native rejection unproven'}
  if phase=='add':
   if state['stage']!='prepared' or vnet(current)!=original:raise ValueError('addition already reserved; reconcile')
   evidence(review,candidate,now);cloud_ranges(candidate);target=added
  elif phase=='restore':
   if state['stage'] not in ('add_sent','added','restore_sent') or vnet(current) not in (original,added):raise ValueError('restoration boundary')
   target=original
   if state['stage']=='restore_sent' and vnet(current)!=original:raise ValueError('ambiguous restore; read-only reconciliation required')
  else:raise ValueError('phase')
  fresh=read_vnet()
  if digest(external_properties())!=state['external_sha256']:raise ValueError('protected DNS or LB properties changed')
  if protected(fresh)!=protected(current) or vnet(fresh)!=vnet(current):raise ValueError('concurrent VNet change')
  if phase=='add':evidence(review,candidate,datetime.now(timezone.utc))
  if vnet(current)!=target:
   state['stage']=phase+'_sent';private_write(state_path,state)
   # One mutation only. Ambiguous failures retain the sent reservation for read-only reconciliation.
   returned=lab.az('network','vnet','update','--ids',VNET,'--subscription',lab.SUBSCRIPTION,'--address-prefixes',*target,'--query','id')
   if not isinstance(returned,str) or returned.lower()!=VNET.lower():raise ValueError('ambiguous VNet update')
  after=read_vnet()
  if vnet(after)!=target or digest(protected(after))!=state['protected_sha256']:raise ValueError('VNet readback mismatch')
  cloud_binding()
  if digest(external_properties())!=state['external_sha256']:raise ValueError('protected DNS or LB readback changed')
  state['stage']='added' if phase=='add' else 'restored';private_write(state_path,state)
 return {'version':1,'phase':phase,'saved_stage':state['stage'],'candidate':candidate,'observed_at':datetime.now(timezone.utc).isoformat(),'protected_sha256':state['protected_sha256'],'scope':'Owned resource list mutation/readback only; actual Azure advertisement and BGP rejection remain separately observed'}


def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=['prepare','read','add','reconcile','restore']);parser.add_argument('--state',type=Path,required=True);parser.add_argument('--range-review',type=Path);parser.add_argument('--candidate',default='10.235.77.0/24');args=parser.parse_args()
 if socket.gethostname()!='bastion-host':raise ValueError('bastion hostname required')
 # Protect destination metadata before any Azure call; existing state is read privately.
 if args.state.exists() or args.state.is_symlink():helpers.private_read(args.state)
 else:lab.output_preflight(args.state)
 review=json.loads(helpers.private_read(args.range_review)) if args.range_review else None
 print(json.dumps(run(args.phase,args.state,review,args.candidate),sort_keys=True))


if __name__=='__main__':
 try:main()
 except (ValueError,KeyError,TypeError,OSError,subprocess.TimeoutExpired):raise SystemExit('Owned prefix operation refused; inspect/reconcile private state before retry. No acceptance claim.')
