#!/usr/bin/env python3
"""Owned Azure normal API disable/read/enable only. No cloud calls, keys or raw responses."""
import argparse
from datetime import datetime, timezone
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import stat
import time
import uuid

spec=importlib.util.spec_from_file_location('owned_activation',Path(__file__).with_name('activate-live.py'))
activation=importlib.util.module_from_spec(spec);spec.loader.exec_module(activation)
STAGE='arguments'


def stage(value):
 global STAGE
 STAGE=value


def identifier(value):
 if not isinstance(value,str) or str(uuid.UUID(value))!=value:raise ValueError('identity shape')
 return value


def bounded_int(value,low,high):
 if type(value)!=int or not low<=value<=high:raise ValueError('integer shape')
 return value


def enum(value,values):
 if value not in values:raise ValueError('enum shape')
 return value


def timestamp(value):
 if value is None:return None
 if not isinstance(value,str) or len(value)>64:raise ValueError('timestamp shape')
 parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
 if parsed.tzinfo is None:raise ValueError('timestamp timezone')
 return parsed.isoformat()


def connection_projection(raw,setup,connection_id):
 if not isinstance(raw,dict) or raw.get('id')!=connection_id or raw.get('org_id')!=setup['org_id'] or raw.get('site_id')!=setup['site_id'] or raw.get('gateway_node_id')!=setup['gateway_id']:raise ValueError('owned binding shape')
 return {'id':identifier(raw['id']),'desired_revision':bounded_int(raw['desired_revision'],1,9223372036854775807),'desired_intent':enum(raw['desired_intent'],('enabled','disabled')),'application_state':enum(raw['application_state'],('applied','pending','not_applied')),'cleanup_state':enum(raw['cleanup_state'],('pending','retained_guard','not_required'))}


def runtime_projection(raw,tunnel_ids):
 if not isinstance(raw,dict) or not isinstance(raw.get('tunnels'),list) or len(raw['tunnels'])!=len(tunnel_ids):raise ValueError('runtime shape')
 output={'observed_at':timestamp(raw.get('observed_at')),'tunnels':[]}
 for index,tunnel in enumerate(raw['tunnels']):
  if not isinstance(tunnel,dict) or tunnel.get('id')!=tunnel_ids[index] or tunnel.get('slot')!=index+1 or type(tunnel.get('selected'))!=bool:raise ValueError('runtime tunnel identity')
  output['tunnels'].append({'id':identifier(tunnel['id']),'slot':index+1,'status':enum(tunnel['status'],('unknown','up','down')),'selected':tunnel['selected']})
 bgp=raw.get('bgp')
 if bgp is not None:
  if not isinstance(bgp,dict) or not isinstance(bgp.get('peers'),list) or len(bgp['peers'])!=len(tunnel_ids) or not isinstance(bgp.get('routes'),list) or len(bgp['routes'])>64:raise ValueError('runtime BGP shape')
  output['bgp']={'version':bounded_int(bgp['version'],1,1),'sequence':bounded_int(bgp['sequence'],0,9007199254740991),'peers':[],'routes':[]}
  for index,peer in enumerate(bgp['peers']):
   if not isinstance(peer,dict) or peer.get('slot')!=index+1:raise ValueError('BGP peer slot')
   item={'slot':index+1,'state':enum(peer['state'],('unknown','idle','connect','active','opensent','openconfirm','established'))}
   for key in ('accepted_prefixes','installed_prefixes'):item[key]=bounded_int(peer[key],0,64)
   if peer.get('rejected_prefixes') is not None:item['rejected_prefixes']=bounded_int(peer['rejected_prefixes'],0,1000000000)
   output['bgp']['peers'].append(item)
  for route in bgp['routes']:
   network=ipaddress.ip_network(route['prefix'],strict=True)
   if network.version!=4 or not network.subnet_of(ipaddress.ip_network('10.231.0.0/16')):raise ValueError('unowned route shape')
   output['bgp']['routes'].append({'prefix':str(network),'slot':bounded_int(route['slot'],1,len(tunnel_ids))})
 return output


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('phase',choices=['disable','read','enable'])
 parser.add_argument('--private-root',required=True)
 parser.add_argument('--wait-cleanup-seconds',type=int,default=0,help='Disable/read only, bounded0..60; pending remains pending at timeout')
 args=parser.parse_args()
 if not 0<=args.wait_cleanup_seconds<=60 or args.phase=='enable' and args.wait_cleanup_seconds:raise ValueError('bounded wait shape')
 root=os.path.abspath(args.private_root);stage('private_root')
 info=os.lstat(root)
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise ValueError('owned private root')
 stage('private_inputs')
 accounts=json.loads(activation.private_read(root+'/ui-accounts.json'));setup=json.loads(activation.private_read(root+'/api-setup.json'));state=json.loads(activation.private_read(root+'/azure-live-activation.json'))
 for key in ('org_id','site_id','gateway_id'):identifier(setup[key])
 connection_id=identifier(state['id']);tunnel_ids=[identifier(value) for value in state['tunnel_ids']]
 if not 1<=len(tunnel_ids)<=2 or len(set([connection_id]+tunnel_ids))!=len(tunnel_ids)+1:raise ValueError('private allocated identity')
 if isinstance(accounts,dict):accounts=accounts.get('accounts',list(accounts.values()))
 owner=next(account for account in accounts if account.get('email')=='browser-owner@azure-s2s.local')
 client=activation.Client();stage('normal_owner_login')
 client.call('POST','/api/v1/auth/login',{'email':owner['email'],'password':owner['password']});client.call('GET','/api/v1/auth/me')
 stage('owned_organization')
 organizations=client.call('GET','/api/v1/organizations')
 if isinstance(organizations,dict):organizations=organizations.get('organizations',[])
 if not any(org['id']==setup['org_id'] and org['slug']=='azure-s2s-local' for org in organizations):raise ValueError('owned organization')
 path='/api/v1/organizations/'+setup['org_id']+'/ipsec/connections/'+connection_id
 def read_connection():return connection_projection(client.call('GET',path),setup,connection_id)
 stage('fresh_connection_revision');before=read_connection();sent=False
 if args.phase in ('disable','enable'):
  stage('nonsecret_azure_contract')
  config=client.call('GET',path+'/configuration')['configuration']
  if config['profile_id'] not in ('azure-active-active-bgp-ipv4-v1','azure-active-active-static-ipv4-v1','azure-active-standby-bgp-ipv4-v1','azure-active-standby-static-ipv4-v1'):raise ValueError('Azure contract required')
  desired='disabled' if args.phase=='disable' else 'enabled'
  if before['desired_intent']!=desired:
   if desired=='enabled' and before['cleanup_state']=='pending':raise ValueError('cleanup remains pending')
   stage('intent_cas_'+desired)
   changed=connection_projection(client.call('PUT',path+'/intent',{'intent':desired},before['desired_revision']),setup,connection_id)
   if changed['desired_intent']!=desired or changed['desired_revision']!=before['desired_revision']+1:raise ValueError('unexpected CAS successor')
   sent=True
 stage('fresh_cleanup_readback');current=read_connection();deadline=time.monotonic()+args.wait_cleanup_seconds
 while current['desired_intent']=='disabled' and current['cleanup_state']=='pending' and time.monotonic()<deadline:
  time.sleep(min(2,max(0,deadline-time.monotonic())));current=read_connection()
 stage('typed_runtime_status');runtime=runtime_projection(client.call('GET',path+'/status'),tunnel_ids)
 stage('receipt')
 output={'phase':args.phase,'observed_at':datetime.now(timezone.utc).isoformat(),'cas_request_sent':sent,'before_revision':before['desired_revision'],'connection':current,'runtime':runtime,'cleanup_readback_settled':current['desired_intent']=='disabled' and current['cleanup_state'] in ('not_required','retained_guard'),'scope':'Normal API intent/status readback only; no packet or connectivity proof and no synthetic runtime acknowledgement'}
 activation.private_write(root+'/azure-lifecycle-'+args.phase+'.json',output)
 print(json.dumps(output,sort_keys=True))


if __name__=='__main__':
 try:main()
 except (activation.APIError,ValueError,KeyError,StopIteration,OSError,UnicodeError,TypeError) as error:
  diagnostic={'error':'lifecycle_failed','stage':STAGE,'category':'api' if isinstance(error,activation.APIError) else 'input_or_response_shape'}
  if isinstance(error,activation.APIError):
   if error.status is not None:diagnostic['http_status']=error.status
   if error.code is not None:diagnostic['api_code']=error.code
  print(json.dumps(diagnostic,sort_keys=True));raise SystemExit(1)
