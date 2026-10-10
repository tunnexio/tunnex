#!/usr/bin/env python3
"""Owned AA→AS qualification only. One reserved update; ambiguous results reconcile read-only."""
import argparse
import copy
from datetime import datetime,timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import uuid

spec=importlib.util.spec_from_file_location('standby_prefix',Path(__file__).with_name('qualify-owned-unapproved-prefix.py'))
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
lab=common.lab
helpers=common.helpers
BASE=common.BASE
GATEWAY=BASE+'virtualNetworkGateways/azure-vpn'
SUBNET=BASE+'virtualNetworks/azure-vnet/subnets/GatewaySubnet'
CONNECTION=common.CONNECTION
NAMES=('vnetGatewayConfig0','vnetGatewayConfig1')
PIPS=(BASE+'publicIPAddresses/gateway-ip1',BASE+'publicIPAddresses/gateway-ip2')
CUSTOM=('169.254.21.2','169.254.22.2')


def now():return datetime.now(timezone.utc)
def digest(value):return common.digest(value)

def output_parent(path):
 path=Path(path).absolute();lab.output_preflight(path);return path

def raw_read_gateway():
 run=subprocess.run(['az','network','vnet-gateway','show','--ids',GATEWAY,'--subscription',lab.SUBSCRIPTION,'--only-show-errors','-o','json'],capture_output=True,timeout=180)
 if run.returncode or not 1<=len(run.stdout)<=262144:raise ValueError('gateway read refused')
 return run.stdout,json.loads(run.stdout)

def gateway(value,active):
 if value.get('id','').lower()!=GATEWAY.lower() or value.get('tags',{}).get('owner')!=lab.OWNER or value.get('activeActive') is not active or value.get('gatewayType')!='Vpn' or value.get('vpnType')!='RouteBased' or value.get('vpnGatewayGeneration')!='Generation1' or value.get('sku',{}).get('name')!='VpnGw1AZ' or value.get('sku',{}).get('capacity')!=2:raise ValueError('exact gateway binding')
 if value.get('vpnClientConfiguration') or value.get('natRules'):raise ValueError('additional gateway feature')
 configs=value['ipConfigurations'];peers=value['bgpSettings']['bgpPeeringAddresses']
 expected=2 if active else 1
 if not isinstance(configs,list) or len(configs)!=expected or not isinstance(peers,list) or len(peers)!=expected or value['bgpSettings']['asn']!=65515:raise ValueError('gateway cardinality/ASN')
 indexes={};peer_indexes={}
 for index,config in enumerate(configs):
  name=config['name']
  if name not in NAMES[:expected] or name in indexes or config['id'].lower()!=(GATEWAY+'/ipConfigurations/'+name).lower() or config['subnet']['id'].lower()!=SUBNET.lower() or config['publicIPAddress']['id'].lower()!=PIPS[NAMES.index(name)].lower() or config['privateIPAllocationMethod']!='Dynamic':raise ValueError('IP configuration binding')
  indexes[name]=index
 for index,peer in enumerate(peers):
  if set(peer)-{'ipconfigurationId','customBgpIpAddresses','defaultBgpIpAddresses','tunnelIpAddresses'}:raise ValueError('unknown BGP mapping property')
  names=[name for name in indexes if peer['ipconfigurationId'].lower()==(GATEWAY+'/ipConfigurations/'+name).lower()]
  if len(names)!=1 or names[0] in peer_indexes or peer['customBgpIpAddresses']!=[CUSTOM[NAMES.index(names[0])]]:raise ValueError('custom APIPA binding')
  peer_indexes[names[0]]=index
 return indexes,peer_indexes


def protected(value):
 result=copy.deepcopy(value)
 # Exclude only explicit ARM resource metadata paths, never arbitrary recursive fields.
 result.pop('etag',None);result.pop('provisioningState',None)
 for config in result['ipConfigurations']:
  config.pop('etag',None);config.pop('provisioningState',None)
 # These documented platform-assigned arrays are never policy/custom settings.
 for peer in result['bgpSettings']['bgpPeeringAddresses']:
  peer.pop('defaultBgpIpAddresses',None);peer.pop('tunnelIpAddresses',None)
 return result


def target(baseline):
 indexes,peer_indexes=gateway(baseline,True);value=copy.deepcopy(baseline)
 value['activeActive']=False
 value['ipConfigurations']=[copy.deepcopy(baseline['ipConfigurations'][indexes[NAMES[0]]])]
 value['bgpSettings']['bgpPeeringAddresses']=[copy.deepcopy(baseline['bgpSettings']['bgpPeeringAddresses'][peer_indexes[NAMES[0]]])]
 return value


def bindings():
 if lab.az('account','show','--query','id')!=lab.SUBSCRIPTION:raise ValueError('authorized subscription')
 lab.owned(lab.az('group','show','-n',lab.RG,'--subscription',lab.SUBSCRIPTION,'--query','{id:id,owner:tags.owner}'),'/subscriptions/'+lab.SUBSCRIPTION+'/resourceGroups/'+lab.RG)
 query=helpers.QUERY[:-1]+',policies:ipsecPolicies,bgp:enableBgp,ingress:ingressNatRules,egress:egressNatRules,protocol:connectionProtocol,type:connectionType}'
 view=lab.az('network','vpn-connection','show','--ids',CONNECTION,'--subscription',lab.SUBSCRIPTION,'--query',query)
 discovery={'connection_id':CONNECTION,'gateway_id':GATEWAY,'local_gateway_id':BASE+'localNetworkGateways/tunnex-local'}
 if helpers.projection(view,discovery)['mode']!='Default':raise ValueError('Default connection required')
 required={'ikeEncryption':'AES256','ikeIntegrity':'SHA256','dhGroup':'DHGroup14','ipsecEncryption':'AES256','ipsecIntegrity':'SHA256','pfsGroup':'PFS2048'}
 if view['protocol']!='IKEv2' or view['type']!='IPsec' or view.get('ingress') or view.get('egress') or type(view['bgp'])!=bool or not isinstance(view['policies'],list) or len(view['policies'])!=1 or any(view['policies'][0].get(key)!=value for key,value in required.items()):raise ValueError('owned connection contract')
 lng=lab.az('network','local-gateway','show','--ids',discovery['local_gateway_id'],'--subscription',lab.SUBSCRIPTION,'--query','{id:id,owner:tags.owner,outside:gatewayIpAddress,asn:bgpSettings.asn,bgp:bgpSettings.bgpPeeringAddress,prefixes:localNetworkAddressSpace.addressPrefixes,state:provisioningState}')
 lab.owned(lng,discovery['local_gateway_id'])
 if lng['state']!='Succeeded':raise ValueError('LNG pending')
 # The fixed query contains public configuration only, never a shared key.
 connection={'protected_connection_sha256':digest(view),'protected_lng_sha256':digest(lng)}
 for pip in PIPS:
  lab.owned(lab.az('network','public-ip','show','--ids',pip,'--subscription',lab.SUBSCRIPTION,'--query','{id:id,owner:tags.owner}'),pip)
 return connection


def evidence(cleanup,native,native_bytes,native_hash,expected,clock):
 if not isinstance(native_hash,str) or not re.fullmatch('[0-9a-f]{64}',native_hash) or hashlib.sha256(native_bytes).hexdigest()!=native_hash:raise ValueError('native bytes digest')
 helpers.fresh(cleanup['observed_at'],clock);helpers.fresh(native['observed_at'],clock)
 cp=cleanup['connection']
 if cleanup.get('phase') not in ('read','disable') or cleanup.get('cleanup_readback_settled') is not True or cp.get('desired_intent')!='disabled' or cp.get('application_state')!='not_applied' or cp.get('cleanup_state') not in ('not_required','retained_guard') or type(cp.get('desired_revision'))!=int or cp['desired_revision']<1:raise ValueError('normal cleanup not settled')
 if cp.get('id')!=expected['connection_id']:raise ValueError('CP connection mismatch')
 if native.get('version')!=1 or native.get('kind')!='owned_native_cleanup_absence' or native.get('connection_id')!=cp['id'] or native.get('desired_revision')!=cp['desired_revision'] or native.get('azure_connection_id')!=CONNECTION or native.get('guard_retained') is not True:raise ValueError('native cleanup binding')
 # Explicit root-attested normal binding/namespace metadata, not a source-derived identity.
 for key in ('org_id','site_id','gateway_id'):
  if native.get(key)!=expected[key]:raise ValueError('native normal binding')
 for key in ('namespace_device','namespace_inode'):
  if type(native.get(key))!=int or native[key]<1 or native[key]!=expected[key]:raise ValueError('native namespace binding')
 for key in ('owned_ike','owned_children','owned_sad','owned_spd','owned_interfaces','owned_routes'):
  if type(native.get(key))!=int or native[key]!=0:raise ValueError('native objects remain')
 return cp['desired_revision']


def reserve_bytes(path,data):
 lab.output_preflight(path)
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)


def classify(actual,baseline):
 # A completed topology is a preservation assertion, not connectivity readiness.
 if actual.get('id','').lower()!=GATEWAY.lower() or actual.get('tags',{}).get('owner')!=lab.OWNER:return 'unexpected_properties_or_topology'
 if actual.get('provisioningState')!='Succeeded':return 'provisioning_pending'
 try:
  gateway(actual,True)
  if protected(actual)==protected(baseline):return 'original_aa'
 except (ValueError,KeyError,TypeError):pass
 try:
  gateway(actual,False)
  if protected(actual)==protected(target(baseline)):return 'preserved_as'
 except (ValueError,KeyError,TypeError):pass
 return 'unexpected_properties_or_topology'


def run(phase,state_path,expected,cleanup=None,native=None,native_bytes=None,native_hash=None):
 if socket.gethostname()!='bastion-host':raise ValueError('bastion hostname required')
 # Path metadata must be checked before any Azure command.
 if phase=='prepare':output_parent(state_path)
 else:helpers.private_read(state_path)
 if phase=='prepare':
  if lab.az('version').get('azure-cli')!='2.91.0':raise ValueError('reviewed CLI version required')
  connection=bindings();raw,baseline=raw_read_gateway();gateway(baseline,True)
  if baseline['provisioningState']!='Succeeded':raise ValueError('gateway not settled')
  for key in ('org_id','site_id','gateway_id','connection_id'):
   if str(uuid.UUID(expected[key]))!=expected[key]:raise ValueError('normal allocated UUID')
  for key in ('namespace_device','namespace_inode'):
   if type(expected[key])!=int or expected[key]<1:raise ValueError('actual namespace input')
  snapshot=state_path.with_name(state_path.name+'.gateway-original.json');reserve_bytes(snapshot,raw)
  state={'version':1,'kind':'owned_standby_conversion','stage':'prepared','observed_at':now().isoformat(),'subscription':lab.SUBSCRIPTION,'owner':lab.OWNER,'gateway_id':GATEWAY,'expected':expected,'connection':connection,'baseline_file':snapshot.name,'baseline_sha256':hashlib.sha256(raw).hexdigest()}
  common.private_write(state_path,state)
 else:
  state=json.loads(helpers.private_read(state_path))
  if state.get('version')!=1 or state.get('kind')!='owned_standby_conversion' or state.get('gateway_id')!=GATEWAY or state.get('owner')!=lab.OWNER or state.get('subscription')!=lab.SUBSCRIPTION or state.get('stage') not in ('prepared','apply_sent','converted'):raise ValueError('state binding')
  if state['baseline_file']!=state_path.name+'.gateway-original.json':raise ValueError('snapshot path')
  raw=helpers.private_read(state_path.with_name(state['baseline_file']))
  if hashlib.sha256(raw).hexdigest()!=state['baseline_sha256']:raise ValueError('snapshot digest')
  baseline=json.loads(raw);gateway(baseline,True)
  connection=bindings()
  if connection!=state['connection']:raise ValueError('connection/LNG changed')
  unused,actual=raw_read_gateway();result=classify(actual,baseline)
  if phase=='apply':
   if state['stage']!='prepared' or result!='original_aa':raise ValueError('single prepared update required')
   if lab.az('version').get('azure-cli')!='2.91.0':raise ValueError('reviewed CLI version required')
   indexes,peer_indexes=gateway(actual,True)
   revision=evidence(cleanup,native,native_bytes,native_hash,state['expected'],now())
   retained=actual['bgpSettings']['bgpPeeringAddresses'][peer_indexes[NAMES[0]]]
   # Explicitly retain ONLY the writable reviewed primary mapping. Unknown mapping keys refuse above.
   mapping=[{'ipconfigurationId':retained['ipconfigurationId'],'customBgpIpAddresses':retained['customBgpIpAddresses']}]
   # Exclusive durable reservation also prevents two concurrent apply processes.
   reservation=state_path.with_name(state_path.name+'.mutation-reserved')
   reserve_bytes(reservation,json.dumps({'version':1,'kind':'owned_standby_single_mutation','reserved_at':now().isoformat(),'disabled_revision':revision,'native_receipt_sha256':native_hash,'baseline_sha256':state['baseline_sha256']}).encode())
   state.update(stage='apply_sent',sent_at=now().isoformat(),disabled_revision=revision,native_receipt_sha256=native_hash,remove_index=indexes[NAMES[1]])
   common.private_write(state_path,state)
   # No keys, no whole ARM PUT, no auto retry. --no-wait avoids a45minute blocking wait.
   evidence(cleanup,native,native_bytes,native_hash,state['expected'],now())
   lab.az('network','vnet-gateway','update','--ids',GATEWAY,'--subscription',lab.SUBSCRIPTION,'--set','activeActive=false','bgpSettings.bgpPeeringAddresses='+json.dumps(mapping,separators=(',',':')),'--remove','ipConfigurations',str(indexes[NAMES[1]]),'--no-wait','--query','id')
   # Any failure remains apply_sent. No automatic repeated mutation or rollback.
   connection=bindings()
   if connection!=state['connection']:raise ValueError('postupdate connection changed')
   unused,actual=raw_read_gateway();result=classify(actual,baseline)
  if result=='preserved_as' and state['stage']=='apply_sent':
   state['stage']='converted';state['completed_observed_at']=now().isoformat();common.private_write(state_path,state)
  return {'version':1,'phase':phase,'stage':state['stage'],'observed_at':now().isoformat(),'gateway_classification':result,'baseline_sha256':state['baseline_sha256'],'retained_configuration':NAMES[0],'retained_custom_apipa':CUSTOM[0],'unused_public_ip_retained':True,'scope':'Topology/property readback only; no tunnel, BGP, DNS or packet readiness'}
 return {'version':1,'phase':phase,'stage':state['stage'],'observed_at':state['observed_at'],'baseline_sha256':state['baseline_sha256'],'scope':'Private original baseline captured; no mutation or readiness'}


def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=('prepare','apply','read','reconcile'));parser.add_argument('--state',type=Path,required=True);parser.add_argument('--binding',type=Path);parser.add_argument('--cleanup',type=Path);parser.add_argument('--native',type=Path);parser.add_argument('--native-sha256');parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
 if socket.gethostname()!='bastion-host':raise ValueError('bastion hostname required')
 output_parent(args.output)
 expected=json.loads(helpers.private_read(args.binding)) if args.phase=='prepare' and args.binding else None
 if args.phase=='prepare' and expected is None:raise ValueError('private normal binding required')
 native_bytes=helpers.private_read(args.native) if args.phase=='apply' and args.native else None
 cleanup=json.loads(helpers.private_read(args.cleanup)) if args.phase=='apply' and args.cleanup else None
 if args.phase=='apply' and (native_bytes is None or cleanup is None or args.native_sha256 is None):raise ValueError('fresh cleanup/native input required')
 result=run(args.phase,args.state,expected,cleanup,json.loads(native_bytes) if native_bytes else None,native_bytes,args.native_sha256)
 reserve_bytes(args.output,json.dumps(result).encode());print('{"version":1,"standby_projection_written":true}')

if __name__=='__main__':
 try:main()
 except (ValueError,KeyError,TypeError,OSError,subprocess.TimeoutExpired):
  print('{"version":1,"standby_operation":"refused","next_step":"read_only_reconcile"}');raise SystemExit(1)
