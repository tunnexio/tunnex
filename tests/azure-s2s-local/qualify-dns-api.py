#!/usr/bin/env python3
"""Phased normal API setup for owned Azure DNS/application traffic qualification.
This helper changes authority; it does not claim packet, expiry or DNS-answer proof.
"""
import argparse
from datetime import datetime, timedelta, timezone
import importlib.util
import ipaddress
import json
from pathlib import Path
import sys
spec=importlib.util.spec_from_file_location('azure_enrollment',Path(__file__).with_name('enroll-local.py'))
lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('phase',choices=['prepare','dns-grant','app-grant','app-revoke','app-expiry','dns-revoke','fqdn-enable','fqdn-grant','fqdn-revoke','read'])
 p.add_argument('--private-root',type=Path,required=True)
 p.add_argument('--connection-id',required=True)
 p.add_argument('--source-prefix',default='10.233.10.0/24',help='Actually approved Site prefix and current connection local prefix')
 p.add_argument('--source-address',required=True,help='Actual owned LAN client IPv4, not a fabricated principal')
 p.add_argument('--resolver-source',required=True,help='Actual gateway local-prefix source used for upstream DNS over IPsec')
 p.add_argument('--expiry-seconds',type=int,default=90)
 a=p.parse_args();private=a.private_root.resolve()
 for name in ('ui-accounts.json','api-setup.json'):
  file=private/name
  if file.is_symlink() or file.stat().st_mode&0o077:raise lab.LabError('Private owned inputs required')
 accounts=json.loads((private/'ui-accounts.json').read_text());setup=json.loads((private/'api-setup.json').read_text())
 if accounts['owner']['email']!='browser-owner@azure-s2s.local':raise lab.LabError('Unrelated owner refused')
 client=lab.Client(accounts['owner']);base='/api/v1/organizations/'+setup['org_id']
 orgs=client.call('GET','/api/v1/organizations')
 if not any(o['id']==setup['org_id'] and o['slug']=='azure-s2s-local' for o in orgs):raise lab.LabError('Owned Azure organization required')
 local=ipaddress.ip_network(a.source_prefix,strict=True)
 if str(local)!='10.233.10.0/24' or a.source_address!='10.233.10.2' or a.resolver_source!='10.233.10.1':raise lab.LabError('Owned real namespace/veth principal required')
 for value in (a.source_address,a.resolver_source):
  address=ipaddress.ip_address(value)
  if address.version!=4 or address not in local or address in (local.network_address,local.broadcast_address):raise lab.LabError('Real source must be a usable owned local-prefix address')
 if a.source_address==a.resolver_source:raise lab.LabError('LAN principal and gateway resolver source must be distinct')
 connection=client.call('GET',base+'/ipsec/connections/'+a.connection_id)
 if connection['site_id']!=setup['site_id'] or connection['gateway_node_id']!=setup['gateway_id'] or connection['desired_intent']!='enabled':raise lab.LabError('Enabled owned Site/Gateway connection required')
 stored=client.call('GET',base+'/ipsec/connections/'+a.connection_id+'/configuration')['configuration']
 if str(local) not in stored['local_prefixes']:raise lab.LabError('Actual namespace prefix absent from connection local prefixes')
 statepath=private/'dns-api-setup.json'
 state=json.loads(statepath.read_text()) if statepath.exists() else {'connection_id':a.connection_id,'source_address':a.source_address,'resolver_source':a.resolver_source,'dns_rules':[],'app_rules':[],'fqdn_rules':[]}
 if any(state[k]!=v for k,v in [('connection_id',a.connection_id),('source_address',a.source_address),('resolver_source',a.resolver_source)]):raise lab.LabError('Refuse changing existing qualification identity')
 def save():lab.private_write(statepath,json.dumps(state,indent=2))
 def grant(resource,kind='resource',expiry=None):
  body={'src_kind':'cidr','src_cidr':a.source_address+'/32','dst_kind':kind,'dst_'+kind+'_id':resource}
  if expiry:body['expires_at']=expiry
  return client.call('POST',base+'/policies',body)['id']
 def revoke(key):
  for ident in list(state[key]):
   client.call('DELETE',base+'/policies/'+ident);state[key].remove(ident);save()
 if a.phase=='prepare':
  if 'resources' in state:raise lab.LabError('Already prepared; use explicit grant/revoke phases')
  # Broad pre-existing grants would invalidate default-deny evidence.
  if client.call('GET',base+'/policies'):raise lab.LabError('Review/remove existing owned-lab rules before default-deny qualification')
  client.call('PUT',base+'/zero-trust-mode',{'mode':'enforcing'})
  endpoints=[{'address':ip,'port':53,'transport':transport} for ip in ('10.231.2.4','10.231.2.20') for transport in ('udp','tcp')]
  config=client.call('PUT',base+'/fqdn-resolver-contexts/'+setup['site_id']+'/'+setup['gateway_id'],{'profiles':[{'name':'Azure owned private DNS','provider_hint':'azure','zone_suffixes':['azure-s2s.test'],'endpoints':endpoints,'ipsec_path':{'connection_id':a.connection_id,'configuration_revision':1,'source_address':a.resolver_source}}]})
  state['resolver_config_id']=config['id'];state['resources']={};save()
  for ip in ('10.231.2.4','10.231.2.20'):
   for protocol in ('udp','tcp'):
    name='dns-'+ip+'-'+protocol
    r=client.call('POST',base+'/resources',{'name':'Azure owned '+name,'cidr':ip+'/32','protocol':protocol,'port_low':53,'port_high':53})
    state['resources'][name]=r['id'];save()
  for protocol,port in (('tcp',8080),('udp',8081)):
   name='app-'+protocol
   r=client.call('POST',base+'/resources',{'name':'Azure owned '+name,'cidr':'10.231.1.4/32','protocol':protocol,'port_low':port,'port_high':port})
   state['resources'][name]=r['id'];save()
  fqdn=client.call('POST',base+'/fqdn-resources',{'name':'Azure owned service FQDN','fqdn':'service.azure-s2s.test','protocol':'tcp','port_low':8080,'port_high':8080,'resolver_context':{'site_id':setup['site_id'],'gateway_id':setup['gateway_id']}})
  state['fqdn_resource_id']=fqdn['id'];save()
 elif a.phase=='dns-grant':
  if state['dns_rules']:raise lab.LabError('DNS grants already present')
  for name,ident in state['resources'].items():
   if name.startswith('dns-'):state['dns_rules'].append(grant(ident));save()
 elif a.phase in ('app-grant','app-expiry'):
  if state['app_rules']:raise lab.LabError('Revoke previous app grants first')
  expiry=None
  if a.phase=='app-expiry':
   if not 30<=a.expiry_seconds<=300:raise lab.LabError('Bounded expiry must be30..300seconds')
   expiry=(datetime.now(timezone.utc)+timedelta(seconds=a.expiry_seconds)).isoformat();state['expires_at']=expiry
  for name,ident in state['resources'].items():
   if name.startswith('app-'):state['app_rules'].append(grant(ident,expiry=expiry));save()
 elif a.phase=='fqdn-enable':
  impact=client.call('GET',base+'/fqdn-resources/setting/impact')
  if not impact['entitlement_available']:raise lab.LabError('Actual FQDN entitlement unavailable; no bypass')
  client.call('PUT',base+'/fqdn-resources/setting',{'enabled':True,'expected_impact_token':impact['expected_impact_token']})
 elif a.phase=='fqdn-grant':
  if state['app_rules'] or state.get('fqdn_rules'):raise lab.LabError('Revoke IP app grants before distinct FQDN grant proof')
  state['fqdn_rules']=[grant(state['fqdn_resource_id'],'fqdn_resource')];save()
 elif a.phase=='fqdn-revoke':revoke('fqdn_rules')
 elif a.phase=='app-revoke':revoke('app_rules')
 elif a.phase=='dns-revoke':revoke('dns_rules')
 elif a.phase=='read':
  state['observed_rules']=client.call('GET',base+'/policies');state['observed_at']=datetime.now(timezone.utc).isoformat();save()
 print('API phase completed: '+a.phase+'; traffic and expiry enforcement require actual LAN probes.')

if __name__=='__main__':
 try:main()
 except (lab.LabError,KeyError,OSError,ValueError):
  error=sys.exc_info()[1];print(str(error) if isinstance(error,lab.LabError) else 'Private input or actual API shape invalid',file=sys.stderr);raise SystemExit(1)
