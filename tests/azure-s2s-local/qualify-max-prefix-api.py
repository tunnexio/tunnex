#!/usr/bin/env python3
"""Normal owned maximum-prefix lifecycle only; no cloud calls/grants/readiness claim."""
import argparse
import copy
import hashlib
import re
from datetime import datetime,timezone
import importlib.util
import json
import os
from pathlib import Path
import uuid


def load(name,file):
 spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
transition=load('max_transition','transition-aa-static.py')
secure=load('max_secure','rotate-bad-psk.py')
life=transition.life
api=life.activation
PROFILE='azure-active-active-bgp-ipv4-v1'
CANDIDATE='10.235.77.0/24'
ORIGINAL=secure.CONNECTION


def instant(value):
 if not isinstance(value,str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})',value):raise ValueError('strict RFC3339 timestamp')
 return datetime.fromisoformat(life.timestamp(value))


def fresh(value,clock):
 if not 0<=(clock-instant(value)).total_seconds()<=60:raise ValueError('fresh actual evidence required')


def reserve(path):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as stream:stream.write('owned maximum-prefix operation reserved\n');stream.flush();os.fsync(stream.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)


def configuration(raw,purpose,psk=None):
 secure.config_identity(raw)
 config=copy.deepcopy(raw['configuration'])
 if config.get('bgp',{}).get('maximum_prefixes')!=8:raise ValueError('original limit8 required')
 if purpose=='limit':config['remote_prefixes']=['10.231.0.0/16',CANDIDATE];config['bgp']['maximum_prefixes']=1
 elif purpose!='baseline':raise ValueError('configuration purpose')
 config['profile_id']=PROFILE
 if psk is not None:
  for tunnel in config['tunnels']:tunnel['psk']=psk
 return config


def contract(raw,identity):
 value=raw['configuration']
 if raw.get('profile_id')!=PROFILE or value.get('mode')!='ipv4-bgp' or value['local_prefixes']!=['10.233.10.0/24'] or len(value['tunnels'])!=2:raise ValueError('AA BGP contract')
 if value['remote_prefixes'] not in (['10.231.0.0/16'],['10.231.0.0/16',CANDIDATE]):raise ValueError('bounded allowlist')
 expected=8 if len(value['remote_prefixes'])==1 else 1
 if value['bgp']['maximum_prefixes']!=expected:raise ValueError('limit binding')
 return {'id':life.identifier(identity),'configuration_revision':life.bounded_int(raw['configuration_revision'],1,9223372036854775807),'profile_id':PROFILE,'remote_prefixes':value['remote_prefixes'],'maximum_prefixes':expected}


def native_absence(proof,proof_bytes,proof_hash,binding,setup,identity,revision):
 if not isinstance(proof_hash,str) or not re.fullmatch('[0-9a-f]{64}',proof_hash) or hashlib.sha256(proof_bytes).hexdigest()!=proof_hash:raise ValueError('independent native receipt digest')
 if json.loads(proof_bytes)!=proof:raise ValueError('native proof bytes binding')
 if binding is None or any(binding.get(key)!=setup[key] for key in ('org_id','site_id','gateway_id')) or binding.get('connection_id')!=identity:raise ValueError('independent native normal binding')
 observed=instant(proof['observed_at'])
 if not 0<=(datetime.now(timezone.utc)-observed).total_seconds()<=60:raise ValueError('fresh actual native absence required')
 arm='/subscriptions/34e2f259-b462-40bf-8f4a-06a3930d99e6/resourceGroups/tunnex-azure-s2s-20261010/providers/Microsoft.Network/connections/tunnex-connection'
 if proof.get('version')!=1 or proof.get('kind')!='owned_native_cleanup_absence' or proof.get('azure_connection_id')!=arm or proof.get('connection_id')!=identity or proof.get('desired_revision')!=revision or proof.get('guard_retained') is not True:raise ValueError('native cleanup identity')
 for key in ('org_id','site_id','gateway_id','namespace_device','namespace_inode'):
  if proof.get(key)!=binding.get(key):raise ValueError('native namespace binding')
 for key in ('namespace_device','namespace_inode'):
  if type(binding.get(key))!=int or binding[key]<1:raise ValueError('independently observed namespace')
 for key in ('owned_ike','owned_children','owned_sad','owned_spd','owned_interfaces','owned_routes'):
  if type(proof.get(key))!=int or proof[key]!=0:raise ValueError('native owned objects remain')


def no_grants(client,base):
 policies=client.call('GET',base+'/policies')
 if isinstance(policies,dict):policies=policies['policies']
 if policies!=[]:raise ValueError('all owned grants must be explicitly withdrawn')


def operate(phase,client,setup,state_path,allocation=None,purpose='limit',baseline=None,psk=None,discovery=None,absence=None,absence_bytes=None,absence_hash=None,native_binding=None):
 base='/api/v1/organizations/'+setup['org_id'];prefix=base+'/ipsec/connections/'
 if phase=='prepare':
  if state_path.exists() or state_path.is_symlink():raise ValueError('existing state; read only')
  if purpose=='baseline' and allocation is not None and 'target' in allocation:allocation=allocation['target']
  ids=[life.identifier(value) for value in allocation['tunnel_ids']];prior=life.identifier(allocation['id'])
  if len(ids)!=2 or len(set(ids+[prior]))!=3:raise ValueError('two distinct prior tunnels')
  if purpose=='limit' and prior!=ORIGINAL:raise ValueError('exact original connection')
  raw=client.call('GET',prefix+prior);life.connection_projection(raw,setup,prior)
  current=client.call('GET',prefix+prior+'/configuration')
  if purpose=='limit':original=current;configuration(original,'limit')
  else:
   if baseline is None or baseline.get('purpose')!='limit' or baseline.get('target',{}).get('id')!=prior or baseline.get('setup')!=setup:raise ValueError('exact original rollback lineage')
   original=baseline['original_configuration'];expected=configuration(original,'limit');observed=copy.deepcopy(current['configuration']);expected.pop('profile_id')
   if expected!=observed or current['profile_id']!=PROFILE:raise ValueError('test configuration changed')
  reserve(state_path.with_name(state_path.name+'.prepare-reserved'))
  state={'version':1,'purpose':purpose,'setup':setup,'prior':{'id':prior,'tunnel_ids':ids},'original_configuration':original,'prior_configuration':current,'stage':'prepared'}
  if purpose=='baseline':state['original_prior']=baseline['prior']
  secure.write(state_path,state)
 else:
  state=json.loads(secure.read(state_path))
  if state.get('version')!=1 or state.get('setup')!=setup or state.get('purpose')!=purpose:raise ValueError('saved owned state')
  configuration(state['original_configuration'],purpose)
  prior=state['prior']['id']
 raw=client.call('GET',prefix+prior);previous=transition.prior_projection(raw,setup,prior)
 target=state.get('target',state['prior']);path=prefix+target['id']
 reserved_absence=None
 if phase=='reserved-prior-read':
  if state.get('stage')!='create_reserved' or 'target' not in state:raise ValueError('existing reserved target required')
  ids=[life.identifier(v) for v in target['tunnel_ids']]
  if len(ids)!=2 or len(set(ids+[life.identifier(target['id']),prior]))!=4:raise ValueError('reserved distinct identities')
  secure.read(state_path.with_name(state_path.name+'.create-reserved'))
  try:client.call('GET',path)
  except api.APIError as error:
   if error.status!=404 or error.code!='ipsec_connection_not_found':raise
  else:raise ValueError('reserved target observed; normal same-ID read required')
  reserved_absence={'id':target['id'],'tunnel_ids':ids,'saved_stage':state['stage'],'classification':'normal_GET404_only'}
  # This phase explicitly observes the original finalized prior. It neither
  # erases the saved target nor interprets its 404 as replay authority.
  target=state['prior'];path=prefix+prior
 try:live_raw=raw if target['id']==prior else client.call('GET',path)
 except api.APIError as error:
  if phase not in ('read','restore-read') or 'target' not in state or error.status!=404 or error.code!='ipsec_connection_not_found':raise
  return {'version':1,'phase':phase,'purpose':purpose,'observed_at':datetime.now(timezone.utc).isoformat(),'saved_stage':state['stage'],'target_id':target['id'],'classification':'reserved_target_not_observed','requires_review':True,'scope':'Exact normal GET404 only; does not prove POST never committed and permits no replay or allocation'}
 current=transition.prior_projection(live_raw,setup,prior) if target['id']==prior else life.connection_projection(live_raw,setup,target['id'])
 if phase in ('disable','enable'):
  if current['desired_intent']=='deleted':raise ValueError('tombstone has no live authority')
  desired='disabled' if phase=='disable' else 'enabled'
  if desired=='enabled':
   if 'target' not in state or not transition.finalized_prior(raw,previous) or current['cleanup_state']=='pending':raise ValueError('target/finalization required')
   actual=client.call('GET',path+'/configuration');expected=configuration(state['original_configuration'],purpose);expected.pop('profile_id')
   if actual.get('profile_id')!=PROFILE or actual.get('configuration')!=expected:raise ValueError('target immutable configuration')
  if current['desired_intent']!=desired:
   reserve(state_path.with_name(state_path.name+'.'+target['id']+'-'+desired+'-'+str(current['desired_revision'])+'-reserved'))
   after=life.connection_projection(client.call('PUT',path+'/intent',{'intent':desired},current['desired_revision']),setup,target['id'])
   if after['desired_revision']!=current['desired_revision']+1 or after['desired_intent']!=desired:raise ValueError('CAS successor')
 elif phase=='delete':
  if 'target' in state:raise ValueError('delete prior only')
  if previous['desired_intent']!='deleted':
   if not transition.settled(previous) or previous['application_state']!='not_applied':raise ValueError('disabled cleanup required')
   if absence is None:raise ValueError('independent native absence required')
   native_absence(absence,absence_bytes,absence_hash,native_binding,setup,prior,previous['desired_revision'])
   state['cleanup_revision']=previous['desired_revision'];state['native_binding']=native_binding;secure.write(state_path,state)
   reserve(state_path.with_name(state_path.name+'.'+prior+'-delete-'+str(previous['desired_revision'])+'-reserved'))
   transition.prior_projection(client.call('DELETE',prefix+prior,revision=previous['desired_revision']),setup,prior)
 elif phase=='create':
  if 'target' in state:raise ValueError('create already reserved; read/reconcile only')
  if not transition.finalized_prior(raw,previous):raise ValueError('prior finalization required')
  if psk is None or discovery is None:raise ValueError('private key/fresh discovery required')
  if absence is None or native_binding!=state.get('native_binding'):raise ValueError('fresh independent prior absence required')
  native_absence(absence,absence_bytes,absence_hash,native_binding,setup,prior,state['cleanup_revision'])
  # Validate recorded AA endpoints directly; never reinterpret a slot as standby.
  proof_previous=copy.deepcopy(state['original_configuration'])
  secure.config_identity(proof_previous)
  if discovery.get('active_active') is not True or discovery.get('enable_bgp') is not True or discovery.get('owner')!='azure-s2s-01a12505' or discovery.get('subscription')!='34e2f259-b462-40bf-8f4a-06a3930d99e6':raise ValueError('actual owned AA BGP discovery')
  observed=instant(discovery['observed_at'])
  if not 0<=(datetime.now(timezone.utc)-observed).total_seconds()<=60:raise ValueError('fresh topology required')
  arm='/subscriptions/34e2f259-b462-40bf-8f4a-06a3930d99e6/resourceGroups/tunnex-azure-s2s-20261010/providers/Microsoft.Network/'
  for name,resource in [('connection_id','connections/tunnex-connection'),('gateway_id','virtualNetworkGateways/azure-vpn'),('local_gateway_id','localNetworkGateways/tunnex-local')]:
   if discovery.get(name,'').lower()!=(arm+resource).lower():raise ValueError('exact ARM ownership binding')
  source=proof_previous['configuration']
  if discovery.get('resource_group')!='tunnex-azure-s2s-20261010' or discovery.get('sku')!=source['azure']['gateway_sku'] or discovery.get('vpn_type')!='RouteBased' or discovery.get('local_asn')!=source['bgp']['local_asn'] or discovery.get('remote_asn')!=source['bgp']['remote_asn'] or discovery.get('customer_bgp_address')!='169.254.10.1':raise ValueError('exact gateway policy/BGP binding')
  if discovery.get('customer_outside_address')!=source['customer_outside_address'] or len(discovery.get('public_endpoints',[]))!=2 or [{'outside_address':v['outside_address'],'cloud_inside_address':v['cloud_inside_address']} for v in source['tunnels']]!=discovery['public_endpoints']:raise ValueError('exact endpoints/APIPA')
  no_grants(client,base);config=configuration(proof_previous,purpose,psk);client.call('POST',base+'/ipsec/configuration-check',config)
  reserve(state_path.with_name(state_path.name+'.create-reserved'))
  state['target']={'id':str(uuid.uuid4()),'tunnel_ids':[str(uuid.uuid4()),str(uuid.uuid4())]};state['stage']='create_reserved';secure.write(state_path,state)
  target=state['target'];path=prefix+target['id']
  client.call('POST',base+'/ipsec/connections',{**target,'name':'Azure owned maximum-prefix '+purpose,'site_id':setup['site_id'],'gateway_node_id':setup['gateway_id'],'configuration':config})
 elif phase not in ('prepare','read','restore-read','finalized-read','reserved-prior-read'):raise ValueError('phase')
 fresh=client.call('GET',path)
 if phase in ('finalized-read','reserved-prior-read'):
  if (phase=='finalized-read' and 'target' in state) or target['id']!=prior or not transition.finalized_prior(fresh,transition.prior_projection(fresh,setup,prior)):raise ValueError('finalized prior only')
  if fresh.get('site_id') is not None or fresh.get('gateway_node_id') is not None:raise ValueError('finalized live binding forbidden')
  no_grants(client,base)
  metadata=client.call('GET',path+'/configuration')
  saved=state.get('prior_configuration')
  if saved is None:
   if purpose!='limit':raise ValueError('saved test prior configuration required')
   saved=state['original_configuration']
  expected=contract(saved,prior)
  if set(metadata)!={'profile_id','configuration_revision'} or metadata['profile_id']!=PROFILE or metadata['configuration_revision']!=expected['configuration_revision']:raise ValueError('actual tombstone configuration metadata')
  cleanup=life.bounded_int(state['cleanup_revision'],1,9223372036854775807)
  projected=transition.prior_projection(fresh,setup,prior)
  if projected['desired_revision']<cleanup:raise ValueError('cleanup revision superseded')
  result={'version':1,'kind':'owned_finalized_prior_authority','phase':phase,'purpose':purpose,'observed_at':datetime.now(timezone.utc).isoformat(),'policy_count':0,'runtime_observation':'not_requested','finalized_authority':{**projected,**{key:setup[key] for key in ('org_id','site_id','gateway_id')},'historical_site_id':fresh['historical_site_id'],'historical_gateway_node_id':fresh['historical_gateway_node_id'],'deleted_at':fresh['deleted_at'],'finalized_at':fresh['finalized_at'],'profile_id':metadata['profile_id'],'configuration_revision':metadata['configuration_revision']},'saved_cleanup_revision':cleanup,'saved_prior_contract':expected,'saved_prior_configuration_sha256':hashlib.sha256(json.dumps(saved,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'scope':'Actual finalized tombstone and surviving public metadata only; saved predelete config explicitly historical; no live authority or native absence proof'}
  if reserved_absence is not None:
   result['reserved_target_absence']=reserved_absence
   result['scope']+='; reserved target GET404 does not prove POST never committed or permit replay'
  return result
 projected=transition.prior_projection(fresh,setup,prior) if target['id']==prior else life.connection_projection(fresh,setup,target['id'])
 output={'version':1,'phase':phase,'purpose':purpose,'observed_at':datetime.now(timezone.utc).isoformat(),'connection':projected,'saved_stage':state['stage'],'scope':'Normal API readback only; no BGP/native/packet proof'}
 if fresh['desired_intent']!='deleted':
  if phase=='restore-read' or 'target' in state or state['purpose']=='baseline':no_grants(client,base);output['policy_count']=0
  output['normal_connection']={**contract(client.call('GET',path+'/configuration'),target['id']),**projected}
  if phase=='restore-read':output['runtime_observation']='not_requested';output['scope']='Immutable normal connection/config/policy identity only; no runtime or readiness inference'
  else:output['runtime']=life.runtime_projection(client.call('GET',path+'/status'),target['tunnel_ids'])
 return output


def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=('prepare','read','restore-read','finalized-read','reserved-prior-read','disable','delete','create','enable'));parser.add_argument('--private-root',required=True);parser.add_argument('--state',type=Path,required=True);parser.add_argument('--purpose',choices=('limit','baseline'),default='limit');parser.add_argument('--allocation',type=Path);parser.add_argument('--baseline-state',type=Path);parser.add_argument('--psk-file',type=Path);parser.add_argument('--discovery',type=Path);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--native-absence',type=Path);parser.add_argument('--native-sha256');parser.add_argument('--native-binding',type=Path);args=parser.parse_args()
 root=secure.private_root(args.private_root)
 if args.output==args.state or args.output.exists() or args.output.is_symlink():raise ValueError('new separate receipt required')
 for path in (args.state,args.output):
  if path.parent!=root or path.is_symlink():raise ValueError('owned private destination')
  if path.exists():secure.read(path)
 reserve(args.output.with_name(args.output.name+'.output-reserved'))
 setup=json.loads(secure.read(root/'api-setup.json'));accounts=json.loads(secure.read(root/'ui-accounts.json'))
 if isinstance(accounts,dict):accounts=accounts.get('accounts',list(accounts.values()))
 owners=[v for v in accounts if v.get('email')=='browser-owner@azure-s2s.local']
 if len(owners)!=1:raise ValueError('exact owner login')
 client=api.Client();client.call('POST','/api/v1/auth/login',{'email':owners[0]['email'],'password':owners[0]['password']})
 orgs=client.call('GET','/api/v1/organizations');orgs=orgs.get('organizations',[]) if isinstance(orgs,dict) else orgs
 if not any(v['id']==setup['org_id'] and v['slug']=='azure-s2s-local' for v in orgs):raise ValueError('owned org')
 absence_bytes=secure.read(args.native_absence) if args.native_absence else None
 result=operate(args.phase,client,setup,args.state,json.loads(secure.read(args.allocation)) if args.allocation else None,args.purpose,json.loads(secure.read(args.baseline_state)) if args.baseline_state else None,secure.key(args.psk_file) if args.psk_file else None,json.loads(secure.read(args.discovery)) if args.discovery else None,json.loads(absence_bytes) if absence_bytes else None,absence_bytes,args.native_sha256,json.loads(secure.read(args.native_binding)) if args.native_binding else None)
 secure.write(args.output,result);print(json.dumps({'version':1,'phase':args.phase,'private_projection_written':True}))

if __name__=='__main__':
 try:main()
 except (ValueError,KeyError,TypeError,OSError,api.APIError):raise SystemExit('Owned maximum-prefix lifecycle refused; use fresh read, never blind mutation replay.')
