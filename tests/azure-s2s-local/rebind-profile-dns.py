#!/usr/bin/env python3
"""Owned normal API DNS context transition; revoke/rebind only, never grant or activate."""
import argparse
import copy
from datetime import datetime,timezone
import importlib.util
import json
import os
from pathlib import Path
import stat
import uuid


def load(name,file):
 spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
lb=load('rebind_lb','qualify-lb-api.py');lab=lb.lab
life=load('rebind_lifecycle','lifecycle-live.py')
api=life.activation
PROFILES={'azure-active-active-static-ipv4-v1','azure-active-standby-bgp-ipv4-v1','azure-active-standby-static-ipv4-v1'}


def ident(value):
 if not isinstance(value,str) or str(uuid.UUID(value))!=value:raise ValueError('UUID shape')
 return value

def private_root(value):
 root=Path(value).absolute();info=root.lstat()
 if root!=root.resolve() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('private root')
 return root

def read(path):return json.loads(api.private_read(str(path)))
def write(path,value):api.private_write(str(path),value)
def save_new(path,value):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as stream:json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)


def context_binding(value,setup,connection,revision):
 if value.get('org_id')!=setup['org_id'] or value.get('site_id')!=setup['site_id'] or value.get('gateway_id')!=setup['gateway_id'] or type(value.get('version'))!=int or value['version']<1 or len(value['profiles'])!=1:raise ValueError('single owned resolver context')
 profile=lb.selected_profile(value,connection,revision)
 ident(value['id']);ident(profile['id'])
 return {'context_id':value['id'],'context_version':value['version'],'profile_id':profile['id'],'configuration_revision':revision,'source_address':'10.233.10.1'}

def request_profile(context,connection,revision):
 profile=context['profiles'][0]
 return {'profiles':[{'name':profile['name'],'provider_hint':profile['provider_hint'],'zone_suffixes':profile['zone_suffixes'],'endpoints':profile['endpoints'],'ipsec_path':{'connection_id':connection,'configuration_revision':revision,'source_address':'10.233.10.1'}}]}

def rule_map(dns,lbstate):
 result={}
 def add(ident_value,source,kind,destination):
  if ident_value is None:return
  ident(ident_value);ident(destination)
  if ident_value in result:raise ValueError('duplicate grant identity')
  result[ident_value]={'src_kind':'cidr','src_cidr':source+'/32','dst_kind':kind,'dst_'+kind+'_id':destination}
 resources=dns['resources']
 for key,predicate,source in [('dns_rules',lambda n:n.startswith('dns-'),'10.233.10.2'),('app_rules',lambda n:n.startswith('app-'),'10.233.10.2')]:
  destinations=sorted(value for name,value in resources.items() if predicate(name))
  values=dns.get(key,[])
  if len(values)!=len(destinations):raise ValueError('complete original DNS/app grants required')
  # Rule order need not match resource name order; validate against allowed destination set below.
  for value in values:
   ident(value)
   if value in result:raise ValueError('duplicate grant identity')
   result[value]={'src_kind':'cidr','src_cidr':source+'/32','dst_kind':'resource','allowed_destinations':destinations}
 reverse=dns.get('reverse_rules',[])
 if len(reverse)!=2 or len(dns.get('reverse_resources',{}))!=2:raise ValueError('complete reverse grants required')
 for value in reverse:
  ident(value)
  if value in result:raise ValueError('duplicate grant identity')
  result[value]={'src_kind':'cidr','src_cidr':'10.231.1.4/32','dst_kind':'resource','allowed_destinations':sorted(dns['reverse_resources'].values())}
 for value in dns.get('fqdn_rules',[]):add(value,'10.233.10.2','fqdn_resource',dns['fqdn_resource_id'])
 add(lbstate.get('rule_id'),'10.233.10.2','resource',lbstate['resource_id'])
 if lbstate.get('fqdn_rule_id'):add(lbstate['fqdn_rule_id'],'10.233.10.2','fqdn_resource',lbstate['fqdn_resource_id'])
 if len(result)>12:raise ValueError('grant bounds')
 return result

def verify_rule(rule,expected,org):
 if rule.get('org_id')!=org or any(rule.get(key)!=value for key,value in expected.items() if key!='allowed_destinations'):raise ValueError('owned grant changed')
 if 'allowed_destinations' in expected and rule.get('dst_resource_id') not in expected['allowed_destinations']:raise ValueError('grant destination changed')
 if any(rule.get(key) is True for key in ('managed_by_operator','managed_by_agent_template','managed_by_agent_access')):raise ValueError('managed grant refused')


def verify_complete(current,expected):
 groups={}
 for identity,body in expected.items():
  if 'allowed_destinations' not in body:continue
  key=(body['src_cidr'],tuple(body['allowed_destinations']))
  groups.setdefault(key,[]).append(current[identity]['dst_resource_id'])
 for (source,destinations),actual in groups.items():
  if len(actual)!=len(destinations) or set(actual)!=set(destinations):raise ValueError('incomplete exact grant destinations')


def validate_resources(client,base,dns,lbstate,setup):
 resources=client.call('GET',base+'/resources')
 if not isinstance(resources,list) or len(resources)>128:raise ValueError('resource bounds')
 by_id={r['id']:r for r in resources}
 expected={}
 for ip in ('10.231.2.4','10.231.2.20'):
  for protocol in ('udp','tcp'):expected[dns['resources']['dns-'+ip+'-'+protocol]]=(ip+'/32',protocol,53)
 for protocol,port in [('tcp',8080),('udp',8081)]:expected[dns['resources']['app-'+protocol]]=('10.231.1.4/32',protocol,port)
 for protocol,port in [('tcp',8082),('udp',8083)]:expected[dns['reverse_resources'][protocol]]=('10.233.10.2/32',protocol,port)
 expected[lbstate['resource_id']]=('10.231.1.10/32','tcp',8080)
 if len(expected)!=9:raise ValueError('distinct owned resources required')
 for identity,(cidr,protocol,port) in expected.items():
  resource=by_id[identity]
  if resource.get('org_id')!=setup['org_id'] or any(resource.get(key)!=value for key,value in {'cidr':cidr,'protocol':protocol,'port_low':port,'port_high':port}.items()):raise ValueError('owned resource binding')
 for state,host in [(dns,'service.azure-s2s.test'),(lbstate,'lbapp.azure-s2s.test')]:
  if state.get('fqdn_resource_id'):
   resource=client.call('GET',base+'/fqdn-resources/'+ident(state['fqdn_resource_id']))['resource']
   context=resource['resolver_context']
   if resource.get('org_id')!=setup['org_id'] or resource.get('fqdn')!=host or resource.get('protocol')!='tcp' or resource.get('port_low')!=8080 or resource.get('port_high')!=8080 or context.get('site_id')!=setup['site_id'] or context.get('gateway_id')!=setup['gateway_id']:raise ValueError('owned FQDN resource')


def execute(phase,client,root,setup,transition=None,state_path=None):
 path=state_path or root/'dns-profile-transition.json'
 if path.parent!=root or path.is_symlink():raise ValueError('owned private transition state path')
 base='/api/v1/organizations/'+setup['org_id'];context_path=base+'/fqdn-resolver-contexts/'+setup['site_id']+'/'+setup['gateway_id']
 dns=read(root/'dns-api-setup.json');lbstate=read(root/'lb-api-setup.json')
 if dns['source_address']!='10.233.10.2' or dns['resolver_source']!='10.233.10.1' or lbstate['source_address']!='10.233.10.2':raise ValueError('actual owned sources')
 def policies():
  values=client.call('GET',base+'/policies')
  if not isinstance(values,list) or len(values)>128:raise ValueError('policy bounds')
  result={ident(p['id']):p for p in values}
  if len(result)!=len(values):raise ValueError('duplicate policy identities')
  return result
 def connection(identity,finalized=False):
  raw=client.call('GET',base+'/ipsec/connections/'+ident(identity))
  site='historical_site_id' if finalized else 'site_id';gateway='historical_gateway_node_id' if finalized else 'gateway_node_id'
  if raw.get('org_id')!=setup['org_id'] or raw.get(site)!=setup['site_id'] or raw.get(gateway)!=setup['gateway_id']:raise ValueError('normal connection binding')
  return raw
 impact=client.call('GET',base+'/fqdn-resources/setting/impact')
 if type(impact.get('enabled'))!=bool or type(impact.get('entitlement_available'))!=bool:raise ValueError('actual FQDN settings shape')
 settings={key:impact[key] for key in ('enabled','entitlement_available')}
 if phase=='prepare':
  if path.name not in ('dns-profile-transition.json','dns-profile-transition-'+ident(dns['connection_id'])+'.json'):raise ValueError('state name bound to old connection')
  if path.exists() or path.is_symlink() or dns['connection_id']!=lbstate['connection_id']:raise ValueError('new original transition required')
  old=connection(dns['connection_id'])
  contract=client.call('GET',base+'/ipsec/connections/'+old['id']+'/configuration')
  if contract['profile_id'] not in PROFILES|{'azure-active-active-bgp-ipv4-v1'}:raise ValueError('original Azure profile')
  context=client.call('GET',context_path);binding=context_binding(context,setup,old['id'],contract['configuration_revision'])
  lb.protected_ids(dns)
  if set(lbstate['protected_policy_ids'])!=lb.protected_ids(dns) or lbstate.get('fqdn_binding',binding)!=binding:raise ValueError('old protected/context binding')
  validate_resources(client,base,dns,lbstate,setup);expected=rule_map(dns,lbstate);current=policies()
  if set(current)-set(expected):raise ValueError('unrelated policies must remain untouched')
  if not lb.protected_ids(dns)<=set(current):raise ValueError('original eight protected grants missing')
  verify_complete(current,{key:value for key,value in expected.items() if 'allowed_destinations' in value})
  concrete={}
  for identity,body in expected.items():
   if identity not in current:continue # Saved expired rule may already be server-terminal.
   verify_rule(current[identity],body,setup['org_id']);body=copy.deepcopy(body)
   body.pop('allowed_destinations',None);body['dst_'+body['dst_kind']+'_id']=current[identity]['dst_'+body['dst_kind']+'_id'];concrete[identity]=body
  state={'version':1,'stage':'prepared','old_connection':old['id'],'old_context':context,'old_binding':binding,'expected_rules':concrete,'saved_rule_ids':sorted(expected),'dns_original':dns,'lb_original':lbstate,'revoked':[],'settings':settings}
  save_new(path,state)
 else:
  state=read(path)
  if path.name not in ('dns-profile-transition.json','dns-profile-transition-'+ident(state['old_connection'])+'.json'):raise ValueError('state name bound to saved connection')
  if settings!=state['settings']:raise ValueError('entitlement or opt-in changed; explicit review required')
  if state.get('version')!=1 or state.get('stage') not in ('prepared','revoking','revoked','rebind_sent','rebound'):raise ValueError('transition state')
  if phase=='revoke':
   if state['stage'] not in ('prepared','revoking','revoked'):raise ValueError('rebind already begun')
   current=policies()
   if set(current)-set(state['saved_rule_ids']):raise ValueError('unrelated policies must remain untouched')
   state['stage']='revoking';write(path,state)
   for identity in state['saved_rule_ids']:
    if identity in current:
     if identity not in state['expected_rules']:raise ValueError('previous terminal rule unexpectedly present')
     verify_rule(current[identity],state['expected_rules'][identity],setup['org_id'])
     try:client.call('DELETE',base+'/policies/'+identity)
     except lab.LabError as error:
      if error.status!=404 or error.code!='rule_not_found':raise
    state['revoked']=sorted(set(state['revoked']+[identity]));write(path,state)
   if policies():raise ValueError('authority removal not observed')
   state['stage']='revoked';write(path,state)
  elif phase in ('rebind','reconcile'):
   if state['stage'] not in ('revoked','rebind_sent','rebound') or policies():raise ValueError('grants must remain absent during rebind')
   if transition is None:raise ValueError('actual profile transition allocation')
   prior_id=transition.get('original_prior',{}).get('id') if transition.get('purpose')=='baseline' else transition['prior']['id']
   if prior_id!=state['old_connection'] or transition['target']['id']==state['old_connection']:raise ValueError('actual profile transition allocation')
   old=connection(state['old_connection'],True)
   if old.get('desired_intent')!='deleted' or old.get('application_state')!='not_applied' or not old.get('finalized_at'):raise ValueError('old normal finalization required')
   new=connection(transition['target']['id'])
   if new.get('desired_intent')!='enabled' or new.get('application_state')!='applied' or new.get('deleted_at') or new.get('finalized_at'):raise ValueError('new enabled Applied normal connection required')
   contract=client.call('GET',base+'/ipsec/connections/'+new['id']+'/configuration')
   if contract['profile_id']=='azure-active-active-bgp-ipv4-v1':restored_bgp_binding(transition,state['old_connection'],contract,connection(transition['prior']['id'],True))
   elif contract['profile_id'] not in PROFILES:raise ValueError('new owned profile')
   if contract['configuration']['local_prefixes']!=['10.233.10.0/24'] or contract['configuration']['remote_prefixes']!=['10.231.0.0/16']:raise ValueError('new owned profile/prefixes')
   revision=contract['configuration_revision']
   if type(revision)!=int or revision<1:raise ValueError('actual configuration revision')
   context=client.call('GET',context_path)
   if phase=='rebind':
    if state['stage']!='revoked' or context!=state['old_context']:raise ValueError('one unchanged old context PUT required')
    save_new(path.with_name(path.name+'.put-reserved'),{'version':1,'target':new['id'],'configuration_revision':revision})
    state.update(stage='rebind_sent',new_connection=new['id'],new_configuration_revision=revision);write(path,state)
    client.call('PUT',context_path,request_profile(context,new['id'],revision))
    context=client.call('GET',context_path)
   else:
    if state.get('new_connection')!=new['id'] or state.get('new_configuration_revision')!=revision:raise ValueError('reconcile exact reserved target')
   binding=context_binding(context,setup,new['id'],revision)
   if request_profile(context,new['id'],revision)!=request_profile(state['old_context'],new['id'],revision):raise ValueError('resolver profile metadata changed')
   if binding['context_version']<=state['old_binding']['context_version'] or binding['context_id']==state['old_binding']['context_id'] or binding['profile_id']==state['old_binding']['profile_id']:raise ValueError('actual immutable context replacement required')
   state.update(stage='rebound',new_binding=binding);write(path,state)
   # Private local state can be reconciled after a partial local write; no API replay.
   for current_state in (dns,lbstate):
    if current_state['connection_id'] not in (state['old_connection'],new['id']):raise ValueError('unrelated local binding')
   dns['connection_id']=new['id'];dns['resolver_config_id']=binding['context_id']
   for key in ('dns_rules','app_rules','reverse_rules','fqdn_rules'):dns[key]=[]
   for key in ('observed_rules','observed_at','expires_at'):dns.pop(key,None)
   lbstate.update(connection_id=new['id'],protected_policy_ids=[],rule_id=None,fqdn_rule_id=None)
   if lbstate.get('fqdn_resource_id'):lbstate['fqdn_binding']=binding
   for key in ('fqdn_observation','fqdn_expires_at','expires_at','observed_at'):lbstate.pop(key,None)
   write(root/'dns-api-setup.json',dns);write(root/'lb-api-setup.json',lbstate)
  elif phase=='sync-grants':
   if state['stage']!='rebound' or dns['connection_id']!=state['new_connection'] or lbstate['connection_id']!=state['new_connection']:raise ValueError('rebound current state')
   new=connection(state['new_connection'])
   if new.get('desired_intent')!='enabled' or new.get('application_state')!='applied' or new.get('deleted_at') or new.get('finalized_at'):raise ValueError('new normal connection changed')
   context=client.call('GET',context_path)
   if context_binding(context,setup,state['new_connection'],state['new_configuration_revision'])!=state['new_binding']:raise ValueError('resolver changed after rebind')
   validate_resources(client,base,dns,lbstate,setup);expected=rule_map(dns,lbstate);current=policies();protected=lb.protected_ids(dns)
   if set(current)!=protected or set(expected)!=protected:raise ValueError('exact eight explicit new normal grants required')
   for identity,body in expected.items():verify_rule(current[identity],body,setup['org_id'])
   verify_complete(current,expected)
   lbstate['protected_policy_ids']=sorted(protected);write(root/'lb-api-setup.json',lbstate)
  elif phase=='read':
   context=client.call('GET',context_path)
   if state['stage']=='rebound':
    if context_binding(context,setup,state['new_connection'],state['new_configuration_revision'])!=state['new_binding']:raise ValueError('current context changed')
   elif state['stage']!='rebind_sent' and context!=state['old_context']:raise ValueError('old context changed')
   policies()
  else:raise ValueError('phase')
 return {'version':1,'phase':phase,'stage':state['stage'],'observed_at':datetime.now(timezone.utc).isoformat(),'resolver_context_rebound':state['stage']=='rebound','scope':'Normal API authority/context operations only; no withdrawal, DNS generation or packet readiness proof'}


def restored_bgp_binding(transition,old_id,contract,test):
 if transition.get('version')!=1 or transition.get('purpose')!='baseline' or transition.get('original_prior',{}).get('id')!=old_id or transition['prior']['id']==old_id or transition['target']['id'] in (old_id,transition['prior']['id']):raise ValueError('exact maximum-prefix restoration lineage')
 if test.get('id')!=transition['prior']['id'] or test.get('desired_intent')!='deleted' or test.get('application_state')!='not_applied' or test.get('cleanup_state') not in ('not_required','retained_guard') or not test.get('deleted_at') or not test.get('finalized_at'):raise ValueError('test connection finalization required')
 original=transition['original_configuration']
 source=original['configuration']
 if original.get('profile_id')!='azure-active-active-bgp-ipv4-v1' or source.get('local_prefixes')!=['10.233.10.0/24'] or source.get('remote_prefixes')!=['10.231.0.0/16'] or source.get('bgp',{}).get('maximum_prefixes')!=8 or len(source.get('tunnels',[]))!=2 or contract.get('profile_id')!=original['profile_id'] or contract.get('configuration')!=source:raise ValueError('exact restored original AA BGP configuration')


def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=('prepare','revoke','rebind','reconcile','sync-grants','read'));parser.add_argument('--private-root',required=True);parser.add_argument('--transition-file',type=Path);parser.add_argument('--state-file',type=Path);args=parser.parse_args();root=private_root(args.private_root)
 setup=read(root/'api-setup.json');accounts=read(root/'ui-accounts.json')
 for key in ('org_id','site_id','gateway_id'):ident(setup[key])
 if accounts['owner']['email']!='browser-owner@azure-s2s.local':raise ValueError('owned owner')
 client=lab.Client(accounts['owner']);orgs=client.call('GET','/api/v1/organizations')
 if not any(o['id']==setup['org_id'] and o['slug']=='azure-s2s-local' for o in orgs):raise ValueError('owned organization')
 if args.transition_file and args.transition_file.absolute().parent!=root:raise ValueError('owned transition allocation path')
 result=execute(args.phase,client,root,setup,read(args.transition_file) if args.transition_file else None,args.state_file.absolute() if args.state_file else None)
 write(root/('dns-profile-transition-'+args.phase+'.json'),result);print(json.dumps(result))

if __name__=='__main__':
 try:main()
 except (lab.LabError,ValueError,KeyError,TypeError,OSError):
  print('{"version":1,"dns_profile_transition":"refused"}');raise SystemExit(1)
