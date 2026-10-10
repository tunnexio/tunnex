#!/usr/bin/env python3
"""Reviewed owned qualification only; run on bastion after fresh normal cleanup proof."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess

spec=importlib.util.spec_from_file_location('owned_discovery',Path(__file__).with_name('discover-owned-profile.py'))
lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)
QUERY='{id:id,owner:tags.owner,mode:connectionMode,state:provisioningState,gateway:virtualNetworkGateway1.id,lng:localNetworkGateway2.id,selectors:usePolicyBasedTrafficSelectors,trafficSelectors:trafficSelectorPolicies}'


def private_read(path):
 path=Path(path)
 parent=path.parent; info=parent.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700 or parent.absolute()!=parent.resolve():raise ValueError('private input parent')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as stream:
  info=os.fstat(stream.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>262144:raise ValueError('private input metadata')
  data=stream.read(262145)
 if len(data)>262144:raise ValueError('private input bounds')
 return data


def fresh(value,now):
 if not isinstance(value,str) or len(value)>64:raise ValueError('receipt timestamp')
 parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
 if parsed.tzinfo is None or not 0<=(now-parsed).total_seconds()<=60:raise ValueError('stale receipt')


def evidence(discovery,cleanup,native,native_digest,raw_native,now):
 if not isinstance(native_digest,str) or not re.fullmatch('[0-9a-f]{64}',native_digest) or hashlib.sha256(raw_native).hexdigest()!=native_digest:raise ValueError('native receipt digest')
 if discovery.get('version')!=1 or discovery.get('subscription')!=lab.SUBSCRIPTION or discovery.get('resource_group')!=lab.RG or discovery.get('owner')!=lab.OWNER:raise ValueError('discovery ownership')
 for field,kind,name in [('connection_id','connections','tunnex-connection'),('gateway_id','virtualNetworkGateways','azure-vpn'),('local_gateway_id','localNetworkGateways','tunnex-local')]:
  lab.resource_id(discovery[field],lab.SUBSCRIPTION,kind)
  expected='/subscriptions/'+lab.SUBSCRIPTION+'/resourceGroups/'+lab.RG+'/providers/Microsoft.Network/'+kind+'/'+name
  if discovery[field].lower()!=expected.lower():raise ValueError('exact lab resource binding')
 fresh(cleanup.get('observed_at'),now);fresh(native.get('observed_at'),now)
 cp=cleanup.get('connection',{})
 if cleanup.get('phase') not in ('read','disable') or cleanup.get('cleanup_readback_settled') is not True or cp.get('id')!='9bfa4090-d3ca-4a8e-9ef9-3b41bd91fe99' or type(cp.get('desired_revision'))!=int or cp['desired_revision']!=15 or cp.get('desired_intent')!='disabled' or cp.get('application_state')!='not_applied' or cp.get('cleanup_state')!='retained_guard':raise ValueError('normal cleanup not acknowledged')
 # Separate receipt from root's independently observed native absence, never API status.
 if native.get('version')!=1 or native.get('kind')!='owned_native_cleanup_absence' or native.get('connection_id')!=cp['id'] or native.get('desired_revision')!=15 or native.get('guard_retained') is not True or native.get('azure_connection_id')!=discovery['connection_id']:raise ValueError('native receipt binding')
 for field in ('owned_ike','owned_children','owned_sad','owned_spd','owned_interfaces','owned_routes'):
  if type(native.get(field))!=int or native[field]!=0:raise ValueError('native objects remain')
 return cp['id']


def projection(value,discovery):
 if not isinstance(value,dict):raise ValueError('connection projection')
 lab.owned(value,discovery['connection_id'])
 for field,expected in [('gateway',discovery['gateway_id']),('lng',discovery['local_gateway_id'])]:
  if not isinstance(value.get(field),str) or value[field].lower()!=expected.lower():raise ValueError('connection binding changed')
 if value.get('mode') not in ('Default','ResponderOnly') or value.get('state')!='Succeeded' or value.get('selectors') is not False or value.get('trafficSelectors') not in (None,[]):raise ValueError('connection mode contract')
 return {'mode':value['mode'],'state':value['state']}


def configure(discovery,cleanup,native,digest,raw_native,now):
 if socket.gethostname()!='bastion-host':raise ValueError('bastion hostname required')
 evidence(discovery,cleanup,native,digest,raw_native,now)
 def checked():
  current=lab.discover(lab.SUBSCRIPTION,discovery['connection_id'])
  for field in ('gateway_id','local_gateway_id','active_active','sku','vpn_type','enable_bgp','public_endpoints','local_prefixes'):
   if current.get(field)!=discovery.get(field):raise ValueError('owned discovery changed')
  return projection(lab.az('network','vpn-connection','show','--ids',discovery['connection_id'],'--subscription',lab.SUBSCRIPTION,'--query',QUERY),discovery)
 before=checked();sent=False
 if before['mode']=='Default':
  checked()
  # Evidence is checked immediately before mutation, after potentially slow reads.
  evidence(discovery,cleanup,native,digest,raw_native,datetime.now(timezone.utc))
  sent=True
  identifier=lab.az('network','vpn-connection','update','--ids',discovery['connection_id'],'--subscription',lab.SUBSCRIPTION,'--set','connectionMode=ResponderOnly','--query','id')
  if not isinstance(identifier,str) or identifier.lower()!=discovery['connection_id'].lower():raise ValueError('ambiguous update result')
 after=checked()
 if after['mode']!='ResponderOnly':raise ValueError('mode readback refused')
 return {'version':1,'observed_at':datetime.now(timezone.utc).isoformat(),'subscription':lab.SUBSCRIPTION,'resource_group':lab.RG,'owner':lab.OWNER,'azure_connection_id':discovery['connection_id'],'gateway_id':discovery['gateway_id'],'local_gateway_id':discovery['local_gateway_id'],'before':before,'after':after,'mutation_sent':sent,'native_receipt_sha256':digest,'scope':'Owned initial-initiation qualification setting only; no connectivity or Default-mode readiness claim'}


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('discovery','cleanup','native','output'):parser.add_argument('--'+name,required=True,type=Path)
 parser.add_argument('--native-sha256',required=True)
 args=parser.parse_args()
 if socket.gethostname()!='bastion-host':raise ValueError('bastion hostname required')
 lab.output_preflight(args.output)
 raw_native=private_read(args.native)
 result=configure(json.loads(private_read(args.discovery)),json.loads(private_read(args.cleanup)),json.loads(raw_native),args.native_sha256,raw_native,datetime.now(timezone.utc))
 fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as stream:json.dump(result,stream,indent=2);stream.write('\n')
 print('Owned mode readback saved privately; no connectivity claim.')


if __name__=='__main__':
 try:main()
 except (ValueError,KeyError,TypeError,OSError,subprocess.TimeoutExpired):raise SystemExit('Owned mode operation refused; inspect fresh state before any retry.')
