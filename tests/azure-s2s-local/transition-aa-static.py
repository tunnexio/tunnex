#!/usr/bin/env python3
"""Owned normal API active-active BGP→static transition; no Azure/cloud calls."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import stat
import uuid

spec=importlib.util.spec_from_file_location('transition_lifecycle',Path(__file__).with_name('lifecycle-live.py'))
life=importlib.util.module_from_spec(spec);spec.loader.exec_module(life)
api=life.activation
STAGE='arguments'


def settled(connection):
 return connection['desired_intent']=='disabled' and connection['cleanup_state'] in ('not_required','retained_guard')


def static_configuration(previous,psk):
 if previous.get('profile_id')!='azure-active-active-bgp-ipv4-v1':raise ValueError('prior profile')
 source=previous['configuration']
 if len(source['tunnels'])!=2:raise ValueError('prior topology')
 config={key:source[key] for key in ('customer_outside_address','local_prefixes','remote_prefixes')}
 # Provider profile is top-level; Azure metadata is nested network configuration.
 config.update(profile_id='azure-active-active-static-ipv4-v1',mode='ipv4-static',azure=source['azure'],tunnels=[])
 if config['local_prefixes']!=['10.233.10.0/24'] or config['remote_prefixes']!=['10.231.0.0/16']:raise ValueError('owned prefixes')
 for index,tunnel in enumerate(source['tunnels']):
  part=70+index
  config['tunnels'].append({'outside_address':tunnel['outside_address'],'inside_cidr':f'169.254.{part}.0/30','customer_inside_address':f'169.254.{part}.1','cloud_inside_address':f'169.254.{part}.2','psk':psk})
 return config


def main():
 global STAGE
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('phase',choices=['read','disable','delete','create-static','enable'])
 parser.add_argument('--private-root',required=True,type=Path)
 parser.add_argument('--psk-file',type=Path)
 args=parser.parse_args();root=args.private_root.resolve();info=root.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('private root')
 STAGE='private_inputs'
 setup=json.loads(api.private_read(str(root/'api-setup.json')));accounts=json.loads(api.private_read(str(root/'ui-accounts.json')))
 for key in ('org_id','site_id','gateway_id'):life.identifier(setup[key])
 if isinstance(accounts,dict):accounts=accounts.get('accounts',list(accounts.values()))
 owner=next(value for value in accounts if value.get('email')=='browser-owner@azure-s2s.local')
 client=api.Client();STAGE='normal_owner_login';client.call('POST','/api/v1/auth/login',{'email':owner['email'],'password':owner['password']});client.call('GET','/api/v1/auth/me')
 orgs=client.call('GET','/api/v1/organizations')
 if isinstance(orgs,dict):orgs=orgs.get('organizations',[])
 if not any(value['id']==setup['org_id'] and value['slug']=='azure-s2s-local' for value in orgs):raise ValueError('owned org')
 prefix='/api/v1/organizations/'+setup['org_id']+'/ipsec';state_path=root/'azure-static-transition.json'
 if state_path.exists():state=json.loads(api.private_read(str(state_path)))
 else:
  prior=json.loads(api.private_read(str(root/'azure-live-activation.json')))
  state={'prior':{'id':life.identifier(prior['id']),'tunnel_ids':[life.identifier(value) for value in prior['tunnel_ids']]}}
 old_path=prefix+'/connections/'+life.identifier(state['prior']['id'])
 def owned(raw,identity):
  if raw.get('finalized_at'):
   if raw.get('historical_site_id')!=setup['site_id'] or raw.get('historical_gateway_node_id')!=setup['gateway_id']:raise ValueError('historical binding')
   raw={**raw,'site_id':setup['site_id'],'gateway_node_id':setup['gateway_id']}
  return life.connection_projection(raw,setup,identity)
 def intent(path,current,target_id,desired):
  successor=owned(client.call('PUT',path+'/intent',{'intent':desired},current['desired_revision']),target_id)
  if successor['desired_revision']!=current['desired_revision']+1 or successor['desired_intent']!=desired:raise ValueError('CAS successor')
  return successor
 STAGE='fresh_prior_read';prior_raw=client.call('GET',old_path);prior=owned(prior_raw,state['prior']['id'])
 if 'target' in state:
  target=state['target'];path=prefix+'/connections/'+life.identifier(target['id']);current_raw=client.call('GET',path);current=owned(current_raw,target['id'])
 else:target=state['prior'];path=old_path;current=prior
 sent=False
 if args.phase=='disable':
  STAGE='disable_cas'
  if current['desired_intent']!='disabled':current=intent(path,current,target['id'],'disabled');sent=True
 elif args.phase=='delete':
  if 'target' in state:raise ValueError('only prior deletion permitted')
  if not settled(prior):raise ValueError('prior cleanup pending')
  if not prior_raw.get('deleted_at'):
   STAGE='save_prior_nonsecret_binding';state['prior_configuration']=client.call('GET',old_path+'/configuration')
   if state['prior_configuration'].get('profile_id')!='azure-active-active-bgp-ipv4-v1':raise ValueError('prior Azure AA BGP required')
   api.private_write(str(state_path),state)
   STAGE='delete_cas';current=owned(client.call('DELETE',old_path,revision=prior['desired_revision']),target['id']);sent=True
 elif args.phase=='create-static':
  if 'target' in state:raise ValueError('target already allocated; inspect read')
  if not settled(prior) or not prior_raw.get('deleted_at') or not prior_raw.get('finalized_at'):raise ValueError('prior finalization required')
  if not args.psk_file:raise ValueError('private PSK required')
  psk=api.private_read(str(args.psk_file)).decode().rstrip('\r\n')
  if not 8<=len(psk)<=64 or any(ord(char)<32 or ord(char)==127 for char in psk):raise ValueError('PSK shape')
  config=static_configuration(state['prior_configuration'],psk);STAGE='configuration_check';client.call('POST',prefix+'/configuration-check',config)
  target={'id':str(uuid.uuid4()),'tunnel_ids':[str(uuid.uuid4()),str(uuid.uuid4())]}
  # Save allocation BEFORE request; ambiguous errors must never allocate duplicates.
  state['target']=target;api.private_write(str(state_path),state);STAGE='create_disabled'
  current=owned(client.call('POST',prefix+'/connections',{**target,'name':'Azure owned live active-active static','site_id':setup['site_id'],'gateway_node_id':setup['gateway_id'],'configuration':config}),target['id']);sent=True
 elif args.phase=='enable':
  if 'target' not in state or not prior_raw.get('finalized_at'):raise ValueError('target/prior finalization required')
  contract=client.call('GET',path+'/configuration')
  if contract.get('profile_id')!='azure-active-active-static-ipv4-v1':raise ValueError('target profile')
  if current['cleanup_state']=='pending':raise ValueError('target cleanup pending')
  STAGE='enable_cas'
  if current['desired_intent']!='enabled':current=intent(path,current,target['id'],'enabled');sent=True
 STAGE='fresh_status';path=prefix+'/connections/'+target['id'];fresh_raw=client.call('GET',path);current=owned(fresh_raw,target['id'])
 output={'phase':args.phase,'observed_at':datetime.now(timezone.utc).isoformat(),'cas_request_sent':sent,'connection':current,'scope':'Normal API transition only; Azure alignment and actual packet readiness independently required'}
 if not fresh_raw.get('deleted_at'):
  output['runtime']=life.runtime_projection(client.call('GET',path+'/status'),target['tunnel_ids'])
 api.private_write(str(root/('azure-static-transition-'+args.phase+'.json')),output);print(json.dumps(output,sort_keys=True))


if __name__=='__main__':
 try:main()
 except (api.APIError,ValueError,KeyError,StopIteration,OSError,UnicodeError,TypeError):
  print(json.dumps({'error':'static_transition_failed','stage':STAGE}));raise SystemExit(1)
