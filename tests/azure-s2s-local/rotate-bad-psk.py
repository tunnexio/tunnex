#!/usr/bin/env python3
"""Normal owned AA-BGP rotation only; no Azure calls, automatic enable or secret output."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import unicodedata

spec=importlib.util.spec_from_file_location('owned_lifecycle',Path(__file__).with_name('lifecycle-live.py'))
lifecycle=importlib.util.module_from_spec(spec);spec.loader.exec_module(lifecycle)
activation=lifecycle.activation
CONNECTION='9bfa4090-d3ca-4a8e-9ef9-3b41bd91fe99'
PROFILE='azure-active-active-bgp-ipv4-v1'


def private_root(value):
 path=Path(value).absolute();info=path.lstat()
 if path!=path.resolve() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('private root')
 return path


def read(path):
 info=Path(path).lstat()
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError('private file')
 return activation.private_read(str(path))


def key(path):
 value=read(path).decode('utf-8')
 # One conventional terminal LF is file framing, not part of the key.
 if value.endswith('\n'):value=value[:-1]
 if not 8<=len(value.encode('utf-8'))<=64 or any(unicodedata.category(c).startswith('C') for c in value):raise ValueError('bounded private key')
 return value


def write(path,value):
 if path.exists() or path.is_symlink():read(path)
 activation.private_write(str(path),value)


def config_identity(raw):
 if not isinstance(raw,dict) or raw.get('profile_id')!=PROFILE or type(raw.get('configuration_revision'))!=int or raw['configuration_revision']<=0:raise ValueError('AA BGP configuration')
 config=raw.get('configuration')
 if not isinstance(config,dict) or config.get('mode')!='ipv4-bgp' or len(config.get('tunnels',[]))!=2 or config.get('local_prefixes')!=['10.233.10.0/24'] or config.get('remote_prefixes')!=['10.231.0.0/16'] or not isinstance(config.get('azure'),dict):raise ValueError('owned network configuration')
 # Public GET is nonsecret; store only digest and revision, never the envelope.
 return {'configuration_revision':raw['configuration_revision'],'network_sha256':hashlib.sha256(json.dumps(config,sort_keys=True,separators=(',',':')).encode()).hexdigest()}


def binding(setup,allocation):
 for field in ('org_id','site_id','gateway_id'):lifecycle.identifier(setup[field])
 if allocation.get('id')!=CONNECTION:raise ValueError('exact owned connection')
 ids=[lifecycle.identifier(value) for value in allocation['tunnel_ids']]
 if len(ids)!=2 or len(set(ids+[CONNECTION]))!=3:raise ValueError('two owned tunnel IDs')
 return ids


def snapshot(client,path,setup):
 connection=lifecycle.connection_projection(client.call('GET',path),setup,CONNECTION)
 config=config_identity(client.call('GET',path+'/configuration'))
 return connection,config


def disabled_cleaned(connection):
 if connection['desired_intent']!='disabled' or connection['application_state']!='not_applied' or connection['cleanup_state']!='retained_guard':raise ValueError('normal completed disabled cleanup required')


def operate(phase,client,path,setup,allocation,state_path,good=None,bad=None):
 ids=binding(setup,allocation)
 current,config=snapshot(client,path,setup)
 state=json.loads(read(state_path)) if state_path.exists() else None
 if state is not None:
  if state.get('stage') not in ('bad_prepared','bad_sent','bad_ambiguous','bad_acknowledged','restore_sent','restore_ambiguous','restore_acknowledged'):raise ValueError('saved rotation stage')
  if state.get('version')!=1 or state.get('connection_id')!=CONNECTION or state.get('tunnel_ids')!=ids or state.get('setup')!=setup or state.get('config')!=config:raise ValueError('saved rotation binding changed')
 if phase=='read':return {'phase':phase,'connection':current,'config':config,'saved_stage':state.get('stage') if state else 'none'}
 if phase=='reconcile':
  if state is None or state['stage'] not in ('bad_sent','bad_ambiguous','restore_sent','restore_ambiguous'):raise ValueError('ambiguous operation required')
  revision=state['expected_revision']
  classification='unchanged_revision' if current['desired_revision']==revision else 'successor_observed_unattributed' if current['desired_revision']==revision+1 else 'revision_changed_requires_review'
  # A GET cannot prove which secret committed; never promote to acknowledged.
  return {'phase':phase,'classification':classification,'connection':current,'saved_stage':state['stage'],'requires_review':True}
 disabled_cleaned(current)
 if phase=='bad':
  if state is not None:raise ValueError('bad operation already reserved; reconcile instead')
  if good is None or bad is None or good==bad:raise ValueError('distinct private rollback and bad keys required')
  state={'version':1,'connection_id':CONNECTION,'tunnel_ids':ids,'setup':setup,'config':config,'restore_psk':good,'stage':'bad_prepared'}
 elif phase=='restore':
  if state is None or state['stage']!='bad_acknowledged':raise ValueError('acknowledged bad rotation required; reconcile ambiguity')
  bad=state['restore_psk']
 else:raise ValueError('phase')
 # Persist rollback input and reservation BEFORE any credential mutation.
 state['expected_revision']=current['desired_revision'];state['stage']=phase+'_sent';write(state_path,state)
 # Final fresh normal GET before POST; no reused cached revision and no retry.
 fresh,fresh_config=snapshot(client,path,setup)
 if fresh!=current or fresh_config!=config:raise ValueError('fresh CAS binding changed; reservation retained')
 disabled_cleaned(fresh)
 body={'expected_desired_revision':fresh['desired_revision'],'tunnels':[{'tunnel_id':tid,'psk':bad} for tid in ids]}
 try:
  reply=lifecycle.connection_projection(client.call('POST',path+'/rotate-psks',body),setup,CONNECTION)
  if reply['desired_revision']!=fresh['desired_revision']+1:raise ValueError('rotation successor')
  disabled_cleaned(reply)
  after,after_config=snapshot(client,path,setup)
  if after!=reply or after_config!=config:raise ValueError('rotation readback binding changed')
 except (activation.APIError,ValueError,OSError,KeyError,TypeError):
  state['stage']=phase+'_ambiguous';write(state_path,state)
  raise ValueError('rotation outcome requires read-only reconciliation') from None
 state['stage']=phase+'_acknowledged';state['ack_revision']=reply['desired_revision'];write(state_path,state)
 return {'phase':phase,'connection':reply,'config':after_config,'saved_stage':state['stage'],'scope':'Normal disabled PSK rotation acknowledgement only; no bad-key negotiation or restoration packet proof'}


def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=['read','bad','reconcile','restore']);parser.add_argument('--private-root',required=True);parser.add_argument('--good-psk-file');parser.add_argument('--bad-psk-file');args=parser.parse_args()
 root=private_root(args.private_root)
 setup=json.loads(read(root/'api-setup.json'));allocation=json.loads(read(root/'azure-live-activation.json'));binding(setup,allocation)
 accounts=json.loads(read(root/'ui-accounts.json'))
 if isinstance(accounts,dict):accounts=accounts.get('accounts',list(accounts.values()))
 owner=next(account for account in accounts if account.get('email')=='browser-owner@azure-s2s.local')
 client=activation.Client();client.call('POST','/api/v1/auth/login',{'email':owner['email'],'password':owner['password']});client.call('GET','/api/v1/auth/me')
 orgs=client.call('GET','/api/v1/organizations')
 if isinstance(orgs,dict):orgs=orgs.get('organizations',[])
 if not any(org.get('id')==setup['org_id'] and org.get('slug')=='azure-s2s-local' for org in orgs):raise ValueError('owned organization')
 if args.phase=='bad' and (not args.good_psk_file or not args.bad_psk_file):raise ValueError('private key files required')
 path='/api/v1/organizations/'+setup['org_id']+'/ipsec/connections/'+CONNECTION
 result=operate(args.phase,client,path,setup,allocation,root/'azure-bad-psk-rotation.json',key(args.good_psk_file) if args.phase=='bad' else None,key(args.bad_psk_file) if args.phase=='bad' else None)
 write(root/('azure-bad-psk-'+args.phase+'-receipt.json'),result)
 print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
 try:main()
 except (ValueError,KeyError,TypeError,OSError,StopIteration):raise SystemExit('Owned rotation refused; inspect private state and reconcile before retry. No readiness claim.')
