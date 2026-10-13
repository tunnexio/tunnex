import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

spec=importlib.util.spec_from_file_location('dns_rebind',Path(__file__).with_name('rebind-profile-dns.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def uid():return str(uuid.uuid4())

class Fixture:
 def __init__(self,folder):
  self.root=Path(folder).resolve();self.setup={k:uid() for k in ('org_id','site_id','gateway_id')};self.old=uid();self.new=uid();self.resources=[];self.policies={};self.calls=[];self.timeout=False
  self.dns={'connection_id':self.old,'source_address':'10.233.10.2','resolver_source':'10.233.10.1','resources':{},'reverse_resources':{},'dns_rules':[],'app_rules':[],'reverse_rules':[],'fqdn_rules':[]}
  self.lb={'connection_id':self.old,'source_address':'10.233.10.2','resource_body':m.lb.resource_body(),'rule_id':None,'fqdn_rule_id':None}
  def resource(name,cidr,protocol,port,group):
   identity=uid();self.resources.append(dict(id=identity,org_id=self.setup['org_id'],cidr=cidr,protocol=protocol,port_low=port,port_high=port))
   if group=='reverse':self.dns['reverse_resources'][protocol]=identity
   elif group=='lb':self.lb['resource_id']=identity;return
   else:self.dns['resources'][name]=identity
   rid=uid();self.dns[group+'_rules'].append(rid);self.policies[rid]=dict(id=rid,org_id=self.setup['org_id'],src_kind='cidr',src_cidr='10.231.1.4/32' if group=='reverse' else '10.233.10.2/32',dst_kind='resource',dst_resource_id=identity,enabled=True)
  for ip in ('10.231.2.4','10.231.2.20'):
   for protocol in ('udp','tcp'):resource('dns-'+ip+'-'+protocol,ip+'/32',protocol,53,'dns')
  for protocol,port in [('tcp',8080),('udp',8081)]:resource('app-'+protocol,'10.231.1.4/32',protocol,port,'app')
  for protocol,port in [('tcp',8082),('udp',8083)]:resource('reverse-'+protocol,'10.233.10.2/32',protocol,port,'reverse')
  resource('lb','10.231.1.10/32','tcp',8080,'lb');self.lb['protected_policy_ids']=sorted(self.policies)
  self.context=dict(id=uid(),org_id=self.setup['org_id'],site_id=self.setup['site_id'],gateway_id=self.setup['gateway_id'],version=7,state='active',profiles=[dict(id=uid(),name='Azure owned private DNS',provider_hint='azure',legacy_default=False,zone_suffixes=['azure-s2s.test'],endpoints=[dict(address=ip,port=53,transport=transport) for ip in ('10.231.2.4','10.231.2.20') for transport in ('udp','tcp')],ipsec_path=dict(connection_id=self.old,configuration_revision=3,source_address='10.233.10.1'))])
  self.old_finalized=False;self.new_enabled=True;self.settings={'enabled':True,'entitlement_available':True}
  self.transition={'prior':{'id':self.old},'target':{'id':self.new}}
  for name,value in [('dns-api-setup.json',self.dns),('lb-api-setup.json',self.lb)]:m.write(self.root/name,value)
 def call(self,method,path,body=None):
  self.calls.append((method,path,body))
  suffix=path.split(self.setup['org_id'])[-1]
  if suffix=='/fqdn-resources/setting/impact':return self.settings
  if suffix=='/resources':return self.resources
  if suffix=='/policies':return list(self.policies.values())
  if suffix.startswith('/policies/') and method=='DELETE':self.policies.pop(suffix.rsplit('/',1)[1],None);return None
  if suffix.startswith('/ipsec/connections/'):
   identity=suffix.split('/')[3]
   if suffix.endswith('/configuration'):return {'profile_id':'azure-active-active-bgp-ipv4-v1' if identity==self.old else 'azure-active-active-static-ipv4-v1','configuration_revision':3 if identity==self.old else 5,'configuration':{'local_prefixes':['10.233.10.0/24'],'remote_prefixes':['10.231.0.0/16']}}
   return dict(id=identity,org_id=self.setup['org_id'],site_id=self.setup['site_id'],gateway_node_id=self.setup['gateway_id'],historical_site_id=self.setup['site_id'],historical_gateway_node_id=self.setup['gateway_id'],desired_intent='deleted' if identity==self.old and self.old_finalized else ('enabled' if self.new_enabled else 'disabled'),application_state='not_applied' if identity==self.old and self.old_finalized else 'applied',finalized_at='2026-10-10T00:00:00Z' if identity==self.old and self.old_finalized else None)
  if suffix.startswith('/fqdn-resolver-contexts/'):
   if method=='PUT':
    self.context=dict(self.context,id=uid(),version=self.context['version']+1,profiles=[dict(body['profiles'][0],id=uid(),legacy_default=False)])
    if self.timeout:raise m.lab.LabError('ambiguous timeout')
   return copy.deepcopy(self.context)
  raise AssertionError((method,path))
 def execute(self,phase):return m.execute(phase,self,self.root,self.setup,self.transition if phase in ('rebind','reconcile') else None)

class Rebind(unittest.TestCase):
 def test_normal_revoke_rebind_actual_versions_and_exact_new_grant_sync(self):
  with tempfile.TemporaryDirectory() as folder:
   f=Fixture(folder);f.execute('prepare');old_ids=set(f.policies);f.execute('revoke');self.assertFalse(f.policies)
   self.assertEqual({path.rsplit('/',1)[1] for method,path,body in f.calls if method=='DELETE'},old_ids)
   f.old_finalized=True;result=f.execute('rebind');self.assertEqual(result['stage'],'rebound');self.assertEqual(f.context['version'],8)
   dns=m.read(f.root/'dns-api-setup.json');self.assertEqual(dns['connection_id'],f.new);self.assertFalse(dns['dns_rules']);self.assertEqual(f.context['profiles'][0]['ipsec_path']['configuration_revision'],5)
   # Explicit separate normal grant workflow, represented offline; helper never POSTs grants.
   for category in ('dns','app','reverse'):
    for rid in f.dns[category+'_rules']:
     old_rule=m.read(f.root/'dns-profile-transition.json')['expected_rules'][rid]
     new_id=uid();f.policies[new_id]=dict(old_rule,id=new_id,org_id=f.setup['org_id']);dns[category+'_rules'].append(new_id)
   m.write(f.root/'dns-api-setup.json',dns);f.execute('sync-grants');self.assertEqual(set(m.read(f.root/'lb-api-setup.json')['protected_policy_ids']),set(f.policies))
   self.assertFalse(any(method=='POST' for method,path,body in f.calls))
 def test_ambiguous_put_reconciles_without_replay(self):
  with tempfile.TemporaryDirectory() as folder:
   f=Fixture(folder);f.execute('prepare');f.execute('revoke');f.old_finalized=True;f.timeout=True
   with self.assertRaises(m.lab.LabError):f.execute('rebind')
   self.assertEqual(m.read(f.root/'dns-profile-transition.json')['stage'],'rebind_sent')
   with self.assertRaises(ValueError):f.execute('rebind')
   f.execute('reconcile');self.assertEqual(sum(method=='PUT' for method,path,body in f.calls),1)
 def test_unrelated_policy_refuses_before_mutations(self):
  with tempfile.TemporaryDirectory() as folder:
   f=Fixture(folder);foreign=uid();f.policies[foreign]={'id':foreign,'foreign':True}
   with self.assertRaises(ValueError):f.execute('prepare')
   self.assertFalse(any(method in ('PUT','DELETE') for method,path,body in f.calls))
 def test_new_disabled_old_notfinalized_settings_changed_and_context_changed_refuse(self):
  for cause in ('old','new','setting','context'):
   with tempfile.TemporaryDirectory() as folder:
    f=Fixture(folder);f.execute('prepare');f.execute('revoke');f.old_finalized=cause!='old'
    if cause=='new':f.new_enabled=False
    if cause=='setting':f.settings['enabled']=False
    if cause=='context':f.context['version']+=1
    with self.subTest(cause=cause),self.assertRaises(ValueError):f.execute('rebind')
    self.assertFalse(any(method=='PUT' for method,path,body in f.calls))
 def test_duplicate_destinations_refuse_even_with_eight_rule_ids(self):
  with tempfile.TemporaryDirectory() as folder:
   f=Fixture(folder);first,second=f.dns['dns_rules'][:2];f.policies[second]['dst_resource_id']=f.policies[first]['dst_resource_id']
   with self.assertRaises(ValueError):f.execute('prepare')
 def test_saved_rule_changed_after_prepare_refuses_delete(self):
  with tempfile.TemporaryDirectory() as folder:
   f=Fixture(folder);f.execute('prepare');first=sorted(f.policies)[0];f.policies[first]['src_cidr']='10.233.10.3/32'
   with self.assertRaises(ValueError):f.execute('revoke')
   self.assertFalse(any(method=='DELETE' for method,path,body in f.calls))
 def test_single_put_marker_prevents_replay_after_reservation_before_state_save(self):
  with tempfile.TemporaryDirectory() as folder:
   f=Fixture(folder);f.execute('prepare');f.execute('revoke');f.old_finalized=True
   marker=f.root/'dns-profile-transition.json.put-reserved';marker.write_text('{}');marker.chmod(0o600)
   with self.assertRaises(FileExistsError):f.execute('rebind')
   self.assertFalse(any(method=='PUT' for method,path,body in f.calls))
 def test_state_name_is_old_connection_bound_and_private(self):
  with tempfile.TemporaryDirectory() as folder:
   f=Fixture(folder)
   with self.assertRaises(ValueError):m.execute('prepare',f,f.root,f.setup,state_path=f.root/'arbitrary.json')
   result=m.execute('prepare',f,f.root,f.setup,state_path=f.root/('dns-profile-transition-'+f.old+'.json'))
   self.assertEqual(result['stage'],'prepared')
 def test_current_read_checks_actual_context_after_rebind(self):
  with tempfile.TemporaryDirectory() as folder:
   f=Fixture(folder);f.execute('prepare');f.execute('revoke');f.old_finalized=True;f.execute('rebind');f.execute('read')
   f.context['version']+=1
   with self.assertRaises(ValueError):f.execute('read')

if __name__=='__main__':unittest.main()
