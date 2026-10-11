#!/usr/bin/env python3
"""Bastion-only owned static settings: durable per-write reservations, exact restore.
No key retrieval, provisioning, CP/grant change, retry or automatic rollback.
"""
import argparse
import copy
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import socket
import subprocess

spec=importlib.util.spec_from_file_location('static_standby',Path(__file__).with_name('convert-owned-standby.py'))
shared=importlib.util.module_from_spec(spec);spec.loader.exec_module(shared)
common=shared.common;lab=shared.lab;helpers=shared.helpers
LNG=shared.BASE+'localNetworkGateways/tunnex-local'
STATIC_PREFIXES=['10.233.10.0/24']
# Complete public GET projection for known connection/LNG settings; no key fields.
CONNECTION_QUERY='{id:id,name:name,type:type,location:location,tags:tags,etag:etag,provisioningState:provisioningState,authorizationKeyPresent:authorizationKey!=null,connectionMode:connectionMode,enableBgp:enableBgp,connectionProtocol:connectionProtocol,connectionType:connectionType,virtualNetworkGateway1:virtualNetworkGateway1,virtualNetworkGateway2:virtualNetworkGateway2,localNetworkGateway2:localNetworkGateway2,ipsecPolicies:ipsecPolicies,usePolicyBasedTrafficSelectors:usePolicyBasedTrafficSelectors,trafficSelectorPolicies:trafficSelectorPolicies,ingressNatRules:ingressNatRules,egressNatRules:egressNatRules,routingWeight:routingWeight,dpdTimeoutSeconds:dpdTimeoutSeconds,enablePrivateLinkFastPath:enablePrivateLinkFastPath,expressRouteGatewayBypass:expressRouteGatewayBypass,expressRouteCircuitPeering:expressRouteCircuitPeering,egressBytesTransferred:egressBytesTransferred,ingressBytesTransferred:ingressBytesTransferred,connectionStatus:connectionStatus,tunnelConnectionStatus:tunnelConnectionStatus}'
LNG_QUERY='{id:id,name:name,type:type,location:location,tags:tags,etag:etag,provisioningState:provisioningState,gatewayIpAddress:gatewayIpAddress,fqdn:fqdn,bgpSettings:bgpSettings,localNetworkAddressSpace:localNetworkAddressSpace}'

def read_projection(command,resource,query):
 r=subprocess.run(['az','network',command,'show','--ids',resource,'--subscription',lab.SUBSCRIPTION,'--query',query,'--only-show-errors','-o','json'],capture_output=True,timeout=180)
 if r.returncode or not 1<=len(r.stdout)<=262144:raise ValueError('public resource read refused')
 value=json.loads(r.stdout)
 if value.get('id','').lower()!=resource.lower() or value.get('tags',{}).get('owner')!=lab.OWNER:raise ValueError('owned resource binding')
 return r.stdout,value

def prefixes(value):
 values=value['localNetworkAddressSpace']['addressPrefixes']
 if not isinstance(values,list) or len(values)>64 or len(set(values))!=len(values):raise ValueError('LNG prefix list')
 for raw in values:
  p=ipaddress.ip_network(raw,strict=True)
  if p.version!=4 or p.prefixlen==0 or str(p)!=raw:raise ValueError('canonical IPv4 LNG')
 return values

def protected_connection(value):
 out=copy.deepcopy(value)
 for key in ('enableBgp','etag','provisioningState','egressBytesTransferred','ingressBytesTransferred','connectionStatus','tunnelConnectionStatus'):out.pop(key,None)
 return out

def protected_lng(value):
 out=copy.deepcopy(value);out.pop('etag',None);out.pop('provisioningState',None)
 out['localNetworkAddressSpace'].pop('addressPrefixes')
 return out

def observed():
 if lab.az('account','show','--query','id')!=lab.SUBSCRIPTION:raise ValueError('authorized subscription')
 lab.owned(lab.az('group','show','-n',lab.RG,'--subscription',lab.SUBSCRIPTION,'--query','{id:id,owner:tags.owner}'),'/subscriptions/'+lab.SUBSCRIPTION+'/resourceGroups/'+lab.RG)
 cr,c=read_projection('vpn-connection',shared.CONNECTION,CONNECTION_QUERY);lr,l=read_projection('local-gateway',LNG,LNG_QUERY)
 required={'ikeEncryption':'AES256','ikeIntegrity':'SHA256','dhGroup':'DHGroup14','ipsecEncryption':'AES256','ipsecIntegrity':'SHA256','pfsGroup':'PFS2048'}
 if c['connectionMode']!='Default' or c['connectionProtocol']!='IKEv2' or c['connectionType']!='IPsec' or c['usePolicyBasedTrafficSelectors'] is not False or c.get('trafficSelectorPolicies') or c.get('ingressNatRules') or c.get('egressNatRules') or type(c['enableBgp'])!=bool or c.get('authorizationKeyPresent') is not False or c['virtualNetworkGateway1']['id'].lower()!=shared.GATEWAY.lower() or c['localNetworkGateway2']['id'].lower()!=LNG.lower() or c.get('virtualNetworkGateway2'):raise ValueError('owned Default connection contract')
 if not isinstance(c['ipsecPolicies'],list) or len(c['ipsecPolicies'])!=1 or any(c['ipsecPolicies'][0].get(k)!=v for k,v in required.items()):raise ValueError('custom policy contract')
 if l['bgpSettings']['asn']!=65000 or l['bgpSettings']['bgpPeeringAddress']!='169.254.10.1' or l.get('fqdn'):raise ValueError('owned LNG contract')
 prefixes(l);gr,g=shared.raw_read_gateway()
 if type(g['activeActive'])!=bool:raise ValueError('observed topology')
 shared.gateway(g,g['activeActive'])
 pips=[]
 for pip in shared.PIPS:
  value=lab.az('network','public-ip','show','--ids',pip,'--subscription',lab.SUBSCRIPTION,'--query','{id:id,owner:tags.owner,address:ipAddress}')
  lab.owned(value,pip);pips.append(value)
 vnet=common.read_vnet();external=common.external_properties()
 return {'connection':c,'lng':l,'gateway':g,'pips':pips,'vnet':vnet,'external':external},{'connection':cr,'lng':lr,'gateway':gr}

def protection(value):
 return {'connection':protected_connection(value['connection']),'lng':protected_lng(value['lng']),'gateway':shared.protected(value['gateway']),'pips':value['pips'],'vnet':common.protected(value['vnet']),'vnet_prefixes':common.vnet(value['vnet']),'external':value['external']}

def classify(value,baseline):
 if protection(value)!=protection(baseline):raise ValueError('protected property changed')
 if any(value[k].get('provisioningState')!='Succeeded' for k in ('connection','lng','gateway')):return 'provisioning_pending'
 bgp=value['connection']['enableBgp'];ranges=prefixes(value['lng']);original=prefixes(baseline['lng'])
 if bgp==baseline['connection']['enableBgp'] and ranges==original:return 'original'
 if bgp is False and ranges==STATIC_PREFIXES:return 'static'
 if bgp in (False,baseline['connection']['enableBgp']) and ranges in (original,STATIC_PREFIXES):return 'owned_partial'
 raise ValueError('unexpected static settings')

def snapshot(state_path,name,raw):
 path=state_path.with_name(state_path.name+'.'+name+'-original.json');shared.reserve_bytes(path,raw)
 return {'file':path.name,'sha256':hashlib.sha256(raw).hexdigest()}

def run(phase,state_path,binding=None,cleanup=None,native=None,native_bytes=None,native_hash=None):
 if socket.gethostname()!='bastion-host':raise ValueError('bastion hostname required')
 if phase=='prepare':shared.output_parent(state_path)
 else:helpers.private_read(state_path)
 if phase=='prepare':
  if lab.az('version').get('azure-cli')!='2.91.0':raise ValueError('reviewed CLI version required')
  value,raw=observed()
  if value['connection']['enableBgp'] is not True or prefixes(value['lng'])==STATIC_PREFIXES or any(value[k].get('provisioningState')!='Succeeded' for k in ('connection','lng','gateway')):raise ValueError('original settled BGP baseline required')
  # Validate actual externally attested normal coordinates, never build them here.
  for key in ('org_id','site_id','gateway_id','connection_id'):
   if str(shared.uuid.UUID(binding[key]))!=binding[key]:raise ValueError('normal allocated UUID')
  for key in ('namespace_device','namespace_inode'):
   if type(binding[key])!=int or binding[key]<1:raise ValueError('actual namespace binding')
  baseline={name:snapshot(state_path,name,data) for name,data in raw.items()}
  state={'version':1,'kind':'owned_static_settings','stage':'prepared','subscription':lab.SUBSCRIPTION,'owner':lab.OWNER,'expected':binding,'baseline':value,'snapshots':baseline,'protected_sha256':common.digest(protection(value))}
  common.private_write(state_path,state)
 else:
  state=json.loads(helpers.private_read(state_path))
  if state.get('version')!=1 or state.get('kind')!='owned_static_settings' or state.get('owner')!=lab.OWNER or state.get('subscription')!=lab.SUBSCRIPTION or state.get('stage') not in ('prepared','apply_sent','static','restore_sent','restored'):raise ValueError('static state binding')
  for name,item in state['snapshots'].items():
   if item['file']!=state_path.name+'.'+name+'-original.json':raise ValueError('snapshot path')
   raw=helpers.private_read(state_path.with_name(item['file']))
   if hashlib.sha256(raw).hexdigest()!=item['sha256'] or json.loads(raw)!=state['baseline'][name]:raise ValueError('original snapshot digest')
  if common.digest(protection(state['baseline']))!=state['protected_sha256']:raise ValueError('saved protected digest')
  value,unused=observed();kind=classify(value,state['baseline'])
  if phase in ('apply','restore'):
   restore=phase=='restore'
   if kind=='provisioning_pending':raise ValueError('pending; reconcile only')
   if not restore and (state['stage']!='prepared' or kind!='original'):raise ValueError('single prepared apply only')
   if restore and state['stage'] not in ('apply_sent','static','restore_sent'):raise ValueError('restoration boundary')
   current=shared.restoration_binding(binding,state['expected']) if restore else state['expected']
   shared.evidence(cleanup,native,native_bytes,native_hash,current,shared.now())
   if lab.az('version').get('azure-cli')!='2.91.0':raise ValueError('reviewed CLI version required')
   action='restore' if restore else 'apply';target_prefix=prefixes(state['baseline']['lng']) if restore else STATIC_PREFIXES;target_bgp=state['baseline']['connection']['enableBgp'] if restore else False
   steps=('connection','lng') if restore else ('lng','connection')
   for step in steps:
    needed=value['connection']['enableBgp']!=target_bgp if step=='connection' else prefixes(value['lng'])!=target_prefix
    if not needed:continue
    # Exact observed result may allow a *different*, never previously reserved
    # step. A reserved step is never repeated, even after crash-before-dispatch.
    refreshed,unused=observed();classify(refreshed,state['baseline'])
    if refreshed['connection']['enableBgp']!=value['connection']['enableBgp'] or prefixes(refreshed['lng'])!=prefixes(value['lng']):raise ValueError('settings changed before reservation')
    value=refreshed;shared.evidence(cleanup,native,native_bytes,native_hash,current,shared.now())
    reservation=state_path.with_name(state_path.name+'.'+action+'-'+step+'-reserved')
    shared.reserve_bytes(reservation,json.dumps({'version':1,'action':action,'step':step,'current_connection_id':current['connection_id'],'disabled_revision':cleanup['connection']['desired_revision'],'native_receipt_sha256':native_hash,'protected_sha256':state['protected_sha256']}).encode())
    state.update(stage=action+'_sent',last_reserved_step=step);common.private_write(state_path,state)
    shared.evidence(cleanup,native,native_bytes,native_hash,current,shared.now())
    if step=='connection':returned=lab.az('network','vpn-connection','update','--ids',shared.CONNECTION,'--subscription',lab.SUBSCRIPTION,'--enable-bgp','true' if target_bgp else 'false','--query','id');expected=shared.CONNECTION
    else:returned=lab.az('network','local-gateway','update','--ids',LNG,'--subscription',lab.SUBSCRIPTION,'--set','localNetworkAddressSpace.addressPrefixes='+json.dumps(target_prefix,separators=(',',':')),'--query','id');expected=LNG
    if not isinstance(returned,str) or returned.lower()!=expected.lower():raise ValueError('ambiguous update response; reconcile only')
    value,unused=observed();kind=classify(value,state['baseline'])
    if kind=='provisioning_pending':raise ValueError('pending; reconcile only')
    if step=='connection' and value['connection']['enableBgp']!=target_bgp or step=='lng' and prefixes(value['lng'])!=target_prefix:raise ValueError('write readback unknown; reconcile only')
   kind=classify(value,state['baseline'])
   wanted='original' if restore else 'static'
   if kind!=wanted:raise ValueError('target settings incomplete; reconcile only')
   state['stage']='restored' if restore else 'static';common.private_write(state_path,state)
  elif phase in ('read','reconcile'):
   if state['stage']=='apply_sent' and kind=='static':state['stage']='static';common.private_write(state_path,state)
   if state['stage']=='restore_sent' and kind=='original':state['stage']='restored';common.private_write(state_path,state)
  else:raise ValueError('phase')
  return {'version':1,'phase':phase,'stage':state['stage'],'classification':kind,'observed_at':shared.now().isoformat(),'protected_sha256':state['protected_sha256'],'scope':'Owned static setting/property observation only; no tunnel, route, application or profile acceptance'}
 return {'version':1,'phase':phase,'stage':'prepared','observed_at':shared.now().isoformat(),'protected_sha256':state['protected_sha256'],'scope':'Saved actual public baseline bytes; no mutation or readiness'}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=('prepare','apply','read','reconcile','restore'));p.add_argument('--state',type=Path,required=True);p.add_argument('--binding',type=Path);p.add_argument('--cleanup',type=Path);p.add_argument('--native',type=Path);p.add_argument('--native-sha256');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if socket.gethostname()!='bastion-host':raise ValueError('bastion hostname required')
 shared.output_parent(a.output)
 binding=json.loads(helpers.private_read(a.binding)) if a.binding else None
 raw=helpers.private_read(a.native) if a.native else None
 cleanup=json.loads(helpers.private_read(a.cleanup)) if a.cleanup else None
 result=run(a.phase,a.state,binding,cleanup,json.loads(raw) if raw else None,raw,a.native_sha256)
 shared.reserve_bytes(a.output,json.dumps(result).encode());print('{"version":1,"static_projection_written":true}')
if __name__=='__main__':
 try:main()
 except (ValueError,KeyError,TypeError,OSError,subprocess.TimeoutExpired):raise SystemExit('Owned static settings refused; preserve all reservations and reconcile read-only.')
