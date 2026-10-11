import copy
from datetime import datetime,timezone,timedelta
import importlib.util
import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
ROOT=Path(__file__).resolve().parents[2]
a=load('max_test_api',Path(__file__).with_name('qualify-max-prefix-api.py'))
c=load('max_test_cloud',ROOT/'deploy/azure/qualify-owned-max-prefix.py')
r=c.collector
d=load('max_test_dns',Path(__file__).with_name('rebind-profile-dns.py'))
I=lambda n:'00000000-0000-4000-8000-'+str(n).zfill(12)
NOW=lambda:datetime.now(timezone.utc).isoformat()


def original():
 return {'profile_id':a.PROFILE,'configuration_revision':5,'configuration':{'mode':'ipv4-bgp','azure':{'gateway_sku':'VpnGw1AZ','vpn_type':'RouteBased','ike_version':2,'custom_policy':'aes256-sha256-dh14-pfs2048','use_policy_based_traffic_selectors':False,'nat_enabled':False},'customer_outside_address':'20.219.28.146','local_prefixes':['10.233.10.0/24'],'remote_prefixes':['10.231.0.0/16'],'tunnels':[{'outside_address':outside,'inside_cidr':'169.254.10.1/32','customer_inside_address':'169.254.10.1','cloud_inside_address':inside} for outside,inside in [('52.140.60.21','169.254.21.2'),('20.219.125.34','169.254.22.2')]],'bgp':{'local_asn':65000,'remote_asn':65515,'router_id':'10.233.10.1','maximum_prefixes':8}}}

class Lifecycle(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.root.chmod(0o700);self.state=self.root/'max.json'
  self.setup={'org_id':I(1),'site_id':I(2),'gateway_id':I(3)};self.allocation={'id':a.ORIGINAL,'tunnel_ids':[I(4),I(5)]};self.calls=[];self.configs={a.ORIGINAL:original()};self.allocations={a.ORIGINAL:self.allocation};self.rows={a.ORIGINAL:self.row(a.ORIGINAL)};self.grants=[];self.ambiguous=False
  base=c.prefix.BASE;source=original()['configuration']
  self.discovery={'observed_at':NOW(),'subscription':c.prefix.lab.SUBSCRIPTION,'owner':c.prefix.lab.OWNER,'resource_group':c.prefix.lab.RG,'connection_id':c.prefix.CONNECTION,'gateway_id':base+'virtualNetworkGateways/azure-vpn','local_gateway_id':base+'localNetworkGateways/tunnex-local','active_active':True,'enable_bgp':True,'sku':'VpnGw1AZ','vpn_type':'RouteBased','local_asn':65000,'remote_asn':65515,'customer_bgp_address':'169.254.10.1','customer_outside_address':source['customer_outside_address'],'public_endpoints':[{'outside_address':v['outside_address'],'cloud_inside_address':v['cloud_inside_address']} for v in source['tunnels']]}
 def tearDown(self):self.temp.cleanup()
 def row(self,identity):return {'id':identity,'org_id':self.setup['org_id'],'site_id':self.setup['site_id'],'gateway_node_id':self.setup['gateway_id'],'desired_revision':40,'desired_intent':'enabled','application_state':'applied','cleanup_state':'not_required'}
 def call(self,method,path,body=None,revision=None):
  self.calls.append((method,path,copy.deepcopy(body),revision))
  if path.endswith('/policies'):return self.grants
  if path.endswith('/configuration-check'):return {}
  if method=='POST' and path.endswith('/connections'):
   if self.ambiguous:raise ValueError('ambiguous offline response')
   identity=body['id'];self.rows[identity]={**self.row(identity),'desired_revision':1,'desired_intent':'disabled','application_state':'not_applied'};config=copy.deepcopy(body['configuration']);profile=config.pop('profile_id');[v.pop('psk') for v in config['tunnels']];self.configs[identity]={'profile_id':profile,'configuration_revision':7,'configuration':config};self.allocations[identity]=body;return self.rows[identity]
  identity=path.split('/connections/')[1].split('/')[0]
  if path.endswith('/configuration'):return copy.deepcopy(self.configs[identity])
  if path.endswith('/status'):return {'observed_at':NOW(),'tunnels':[{'id':v,'slot':index+1,'status':'unknown','selected':False} for index,v in enumerate(self.allocations[identity]['tunnel_ids'])]}
  row=self.rows[identity]
  if method=='PUT':
   assert revision==row['desired_revision'];row.update(desired_intent=body['intent'],desired_revision=revision+1,application_state='not_applied',cleanup_state='retained_guard');return copy.deepcopy(row)
  if method=='DELETE':
   assert revision==row['desired_revision'];row.update(desired_intent='deleted',desired_revision=revision+1,site_id=None,gateway_node_id=None,historical_site_id=self.setup['site_id'],historical_gateway_node_id=self.setup['gateway_id'],deleted_at=NOW(),finalized_at=NOW());return copy.deepcopy(row)
  return copy.deepcopy(row)
 def absence(self,identity,revision):
  binding={**self.setup,'connection_id':identity,'namespace_device':4,'namespace_inode':9}
  proof={**binding,'version':1,'kind':'owned_native_cleanup_absence','observed_at':NOW(),'azure_connection_id':c.prefix.CONNECTION,'desired_revision':revision,'guard_retained':True,**{key:0 for key in ('owned_ike','owned_children','owned_sad','owned_spd','owned_interfaces','owned_routes')}}
  payload=json.dumps(proof).encode();return {'absence':proof,'absence_bytes':payload,'absence_hash':hashlib.sha256(payload).hexdigest(),'native_binding':binding}
 def run_phase(self,phase,**kw):
  if phase in ('delete','create'):
   revision=self.rows[a.ORIGINAL]['desired_revision'] if phase=='delete' else json.loads(a.secure.read(self.state))['cleanup_revision']
   kw.update(self.absence(a.ORIGINAL,revision))
  return a.operate(phase,type('Client',(),{'call':staticmethod(self.call)})(),self.setup,self.state,**kw)
 def prep(self):self.run_phase('prepare',allocation=self.allocation)
 def remove(self):self.run_phase('disable');self.run_phase('delete')
 def test_finalized_read_real_metadata_distinct_cleanup_and_no_live_config(self):
  self.prep();self.remove();saved=json.loads(a.secure.read(self.state));original_config=self.configs[a.ORIGINAL]
  self.configs[a.ORIGINAL]={k:original_config[k] for k in ('profile_id','configuration_revision')}
  self.calls=[];receipt=self.run_phase('finalized-read')
  self.assertEqual(receipt['kind'],'owned_finalized_prior_authority');self.assertNotIn('normal_connection',receipt)
  self.assertEqual(receipt['saved_cleanup_revision'],41);self.assertEqual(receipt['finalized_authority']['desired_revision'],42)
  self.assertEqual(receipt['finalized_authority']['historical_site_id'],self.setup['site_id'])
  self.assertFalse(any(path.endswith('/status') for _,path,_,_ in self.calls))
  prepare=load('finalized_prepare_test',Path(__file__).with_name('prepare-max-prefix-observer.py'))
  b={**self.setup,'connection_id':a.ORIGINAL,'desired_revision':41,'configuration_revision':5,'maximum_prefixes':8,'namespace_device':4,'namespace_inode':9}
  attestation={'observed_at':NOW(),'container_id':prepare.CONTAINER,'image_sha256':prepare.IMAGE,'node_executable_sha256':prepare.NODE,'binding':b,'journal_cleanup_desired_revision':41}
  result=prepare.build(receipt,attestation,saved,'absence',datetime.now(timezone.utc));self.assertEqual(result['desired_revision'],41)
  for mutation in ('pending','historical','cleanup','metadata','hash','live_mode'):
   value=copy.deepcopy(receipt);att=copy.deepcopy(attestation)
   if mutation=='pending':value['finalized_authority']['cleanup_state']='pending'
   if mutation=='historical':value['finalized_authority']['historical_site_id']=I(99)
   if mutation=='cleanup':att['journal_cleanup_desired_revision']=42
   if mutation=='metadata':value['finalized_authority']['configuration_revision']=6
   if mutation=='hash':value['saved_prior_configuration_sha256']='a'*64
   with self.assertRaises(ValueError):prepare.build(value,att,saved,'baseline' if mutation=='live_mode' else 'absence',datetime.now(timezone.utc))
 def test_finalized_read_refuses_unfinalized_live_config_extra_policy(self):
  self.prep();self.remove();old=self.configs[a.ORIGINAL];self.configs[a.ORIGINAL]={k:old[k] for k in ('profile_id','configuration_revision')}
  for change in ('unfinalized','config','policy'):
   value=copy.deepcopy(self.rows[a.ORIGINAL])
   if change=='unfinalized':self.rows[a.ORIGINAL]['finalized_at']=None
   if change=='config':self.configs[a.ORIGINAL]=old
   if change=='policy':self.grants=[{'id':I(99)}]
   with self.assertRaises(ValueError):self.run_phase('finalized-read')
   self.rows[a.ORIGINAL]=value;self.grants=[];self.configs[a.ORIGINAL]={k:old[k] for k in ('profile_id','configuration_revision')}
 def reserve_failed_target(self):
  self.prep();self.remove();self.ambiguous=True
  with self.assertRaises(ValueError):self.run_phase('create',psk='private.offline.key',discovery=self.discovery)
  self.ambiguous=False;old=self.configs[a.ORIGINAL]
  self.configs[a.ORIGINAL]={k:old[k] for k in ('profile_id','configuration_revision')}
  saved=json.loads(a.secure.read(self.state));target=saved['target']['id'];original_call=self.call
  def call(method,path,body=None,revision=None):
   if method=='GET' and path.endswith('/connections/'+target) and target not in self.rows:raise a.api.APIError(404,'ipsec_connection_not_found')
   return original_call(method,path,body,revision)
  self.call=call;return saved
 def test_reserved_prior_read_preserves_reservation_and_has_no_mutation_or_replay_authority(self):
  saved=self.reserve_failed_target();before=a.secure.read(self.state);self.calls=[]
  receipt=self.run_phase('reserved-prior-read')
  self.assertEqual(receipt['finalized_authority']['id'],a.ORIGINAL)
  self.assertEqual(receipt['reserved_target_absence']['id'],saved['target']['id'])
  self.assertEqual(receipt['reserved_target_absence']['classification'],'normal_GET404_only')
  self.assertNotIn('normal_connection',receipt);self.assertEqual(before,a.secure.read(self.state))
  self.assertTrue(all(method=='GET' for method,path,body,revision in self.calls))
  self.assertFalse(any(path.endswith('/status') for _,path,_,_ in self.calls))
  prepare=load('reserved_prepare_test',Path(__file__).with_name('prepare-max-prefix-observer.py'))
  b={**self.setup,'connection_id':a.ORIGINAL,'desired_revision':41,'configuration_revision':5,'maximum_prefixes':8,'namespace_device':4,'namespace_inode':9}
  att={'observed_at':NOW(),'container_id':prepare.CONTAINER,'image_sha256':prepare.IMAGE,'node_executable_sha256':prepare.NODE,'binding':b,'journal_cleanup_desired_revision':41}
  self.assertEqual(prepare.build(receipt,att,saved,'absence',datetime.now(timezone.utc))['connection_id'],a.ORIGINAL)
  for change in ('target','phase','stage','classification','mode'):
   n=copy.deepcopy(receipt);s=copy.deepcopy(saved)
   if change=='target':n['reserved_target_absence']['id']=I(99)
   if change=='phase':n['phase']='finalized-read'
   if change=='stage':s['stage']='prepared'
   if change=='classification':n['reserved_target_absence']['classification']='POST_unsent'
   with self.subTest(change=change),self.assertRaises(ValueError):prepare.build(n,att,s,'baseline' if change=='mode' else 'absence',datetime.now(timezone.utc))
 def test_reserved_prior_read_refuses_observed_target_bad_404_pending_prior_and_extra_grant(self):
  saved=self.reserve_failed_target();target=saved['target']['id'];good_call=self.call;self.calls=[]
  for change in ('observed','wrong404','pending','grant','marker'):
   if change=='observed':self.rows[target]=self.row(target)
   if change=='wrong404':
    def bad404(method,path,body=None,revision=None):
     if path.endswith('/connections/'+target):raise a.api.APIError(404,None)
     return good_call(method,path,body,revision)
    self.call=bad404
   if change=='pending':self.rows[a.ORIGINAL]['cleanup_state']='pending'
   if change=='grant':self.grants=[{'id':I(99)}]
   if change=='marker':self.state.with_name('max.json.create-reserved').unlink()
   with self.subTest(change=change),self.assertRaises((ValueError,OSError)):self.run_phase('reserved-prior-read')
   self.rows.pop(target,None);self.call=good_call;self.rows[a.ORIGINAL]['cleanup_state']='retained_guard';self.grants=[]
  self.assertTrue(all(method=='GET' for method,path,body,revision in self.calls))
 def test_original_restore_read_real_empty_policy_proof(self):
  self.grants=[{'id':I(99)}];self.prep()
  # Original prepare/read may retain eight real grants; restore-read for observation must prove empty.
  with self.assertRaises(ValueError):self.run_phase('restore-read')
  self.grants=[];result=self.run_phase('restore-read')
  self.assertEqual(result['policy_count'],0);self.assertEqual(result['runtime_observation'],'not_requested')
  self.assertFalse(any(method!='GET' and path.endswith('/policies') for method,path,body,revision in self.calls))
 def test_full_normal_new_ids_limit_and_restoration_lineage_no_grants(self):
  self.prep();self.remove();self.run_phase('create',psk='private.offline.key',discovery=self.discovery)
  saved=json.loads(a.secure.read(self.state));self.assertNotEqual(saved['target']['id'],a.ORIGINAL);self.assertTrue(set(saved['target']['tunnel_ids']).isdisjoint(self.allocation['tunnel_ids']))
  target=saved['target']['id'];self.assertEqual(self.configs[target]['configuration']['remote_prefixes'],['10.231.0.0/16',a.CANDIDATE]);self.assertEqual(self.configs[target]['configuration']['bgp']['maximum_prefixes'],1)
  self.run_phase('enable');self.assertFalse(any(path.endswith('/policies') and method!='GET' for method,path,body,revision in self.calls))
  restore=self.root/'restore.json';client=type('Client',(),{'call':staticmethod(self.call)})();a.operate('prepare',client,self.setup,restore,saved['target'],'baseline',saved)
  for phase in ('disable','delete'):a.operate(phase,client,self.setup,restore,purpose='baseline',**(self.absence(target,self.rows[target]['desired_revision']) if phase=='delete' else {}))
  a.operate('create',client,self.setup,restore,purpose='baseline',psk='private.offline.key',discovery=self.discovery,**self.absence(target,json.loads(a.secure.read(restore))['cleanup_revision']))
  restored=json.loads(a.secure.read(restore));self.assertEqual(restored['original_prior']['id'],a.ORIGINAL)
  self.assertEqual(self.configs[restored['target']['id']]['configuration'],original()['configuration'])
  d.restored_bgp_binding(restored,a.ORIGINAL,self.configs[restored['target']['id']],self.rows[target])
  with self.assertRaises(ValueError):d.restored_bgp_binding(restored,a.ORIGINAL,self.configs[target],self.rows[target])
 def test_unfinalized_pending_grants_and_stale_discovery_refuse_creation(self):
  self.prep();self.remove()
  for key,value in [('finalized_at',None),('cleanup_state','pending'),('application_state','applied')]:
   old=self.rows[a.ORIGINAL][key];self.rows[a.ORIGINAL][key]=value
   with self.assertRaises(ValueError):self.run_phase('create',psk='private.offline.key',discovery=self.discovery)
   self.rows[a.ORIGINAL][key]=old
  self.grants=[{'id':I(99)}]
  with self.assertRaises(ValueError):self.run_phase('create',psk='private.offline.key',discovery=self.discovery)
  self.grants=[];self.discovery['observed_at']=(datetime.now(timezone.utc)-timedelta(seconds=61)).isoformat()
  with self.assertRaises(ValueError):self.run_phase('create',psk='private.offline.key',discovery=self.discovery)
  self.assertFalse(any(method=='POST' and path.endswith('/connections') for method,path,body,revision in self.calls))
 def test_ambiguous_create_durable_reservation_never_reposts(self):
  self.prep();self.remove();self.ambiguous=True
  with self.assertRaises(ValueError):self.run_phase('create',psk='private.offline.key',discovery=self.discovery)
  self.assertTrue(self.state.with_name('max.json.create-reserved').exists())
  self.assertIn('target',json.loads(a.secure.read(self.state)))
  with self.assertRaises(KeyError):self.run_phase('create',psk='private.offline.key',discovery=self.discovery)
  self.assertEqual(sum(method=='POST' and path.endswith('/connections') for method,path,body,revision in self.calls),1)
 def test_native_absence_digest_namespace_and_nonzero_refuse_delete(self):
  self.prep();self.run_phase('disable');revision=self.rows[a.ORIGINAL]['desired_revision']
  for kind in ('digest','namespace','objects','stale'):
   params=self.absence(a.ORIGINAL,revision)
   if kind=='digest':params['absence_hash']='b'*64
   if kind=='namespace':params['native_binding']['namespace_inode']=10
   if kind=='objects':params['absence']['owned_ike']=1
   if kind=='stale':params['absence']['observed_at']=(datetime.now(timezone.utc)-timedelta(seconds=61)).isoformat()
   if kind in ('objects','stale'):
    params['absence_bytes']=json.dumps(params['absence']).encode();params['absence_hash']=hashlib.sha256(params['absence_bytes']).hexdigest()
   with self.subTest(kind=kind),self.assertRaises(ValueError):a.operate('delete',type('Client',(),{'call':staticmethod(self.call)})(),self.setup,self.state,**params)
  self.assertFalse(any(method=='DELETE' for method,path,body,revision in self.calls))

 def test_restore_read_skips_refused_runtime_but_preserves_real_config_identity(self):
  self.prep();self.remove();self.run_phase('create',psk='private.offline.key',discovery=self.discovery)
  target=json.loads(a.secure.read(self.state))['target']['id'];self.rows[target]['application_state']='pending'
  original_call=self.call
  def call(method,path,body=None,revision=None):
   if path.endswith('/status'):raise ValueError('actual runtime route parser refused')
   return original_call(method,path,body,revision)
  self.call=call
  with self.assertRaises(ValueError):self.run_phase('read')
  result=self.run_phase('restore-read');self.assertEqual(result['normal_connection']['id'],target);self.assertEqual(result['normal_connection']['application_state'],'pending');self.assertEqual(result['runtime_observation'],'not_requested');self.assertNotIn('runtime',result)

 def test_existing_create_marker_prevents_any_post(self):
  self.prep();self.remove();a.reserve(self.state.with_name('max.json.create-reserved'))
  with self.assertRaises(OSError):self.run_phase('create',psk='private.offline.key',discovery=self.discovery)
  self.assertFalse(any(method=='POST' and path.endswith('/connections') for method,path,body,revision in self.calls))

class CloudGuards(unittest.TestCase):
 def setUp(self):
  self.current={'id':I(8),'desired_revision':2,'configuration_revision':7,'profile_id':a.PROFILE,'remote_prefixes':['10.231.0.0/16',a.CANDIDATE],'maximum_prefixes':1,'desired_intent':'enabled','application_state':'applied'}
  self.receipt={'version':1,'phase':'read','purpose':'limit','observed_at':NOW(),'policy_count':0,'normal_connection':self.current}
  self.namespace={'device':4,'inode':9}
  self.review={'version':1,'kind':'owned_prefix_range_review','subscription':c.prefix.lab.SUBSCRIPTION,'resource_group':c.prefix.lab.RG,'owner':c.prefix.lab.OWNER,'vnet_id':c.prefix.VNET,'candidate':a.CANDIDATE,'observed_at':NOW(),'normal_connection':self.current,'ranges':['10.231.0.0/16'],'source_sha256':['a'*64]*3,'namespace':self.namespace,'candidate_reservation':{'connection_id':I(8),'configuration_revision':7,'prefix':a.CANDIDATE}}
  self.proof={'version':1,'kind':'owned_max_prefix_baseline','observed_at':NOW(),'connection_id':I(8),'desired_revision':2,'configuration_revision':7,'namespace':self.namespace,'native':{'sad':4,'spd_in':2,'spd_out':2,'spd_fwd':2},'tunnels':[{'slot':n,'state':'up','owned_ike':1,'owned_installed_children':1} for n in (1,2)],'bgp':{'peers':[{'slot':n,'state':'established','accepted_prefixes':1} for n in (1,2)],'routes':['10.231.0.0/16']}}
 def test_explicit_original_current_revision_collects_without_candidate_exception(self):
  expected={'id':c.prefix.CP,'desired_revision':40,'configuration_revision':9,'profile_id':a.PROFILE,'remote_prefixes':['10.231.0.0/16'],'maximum_prefixes':8}
  values=[]
  for kind,source in [('owned_api_ranges','site_subnet'),('owned_kernel_ranges','kernel_route'),('owned_azure_ranges','azure_subnet')]:values.append(r.envelope(kind,NOW(),[{'source':source,'cidr':'10.231.0.0/16'}]))
  values[0]['normal_connection']={**expected,'desired_intent':'enabled','application_state':'applied'};values[1]['namespace']=self.namespace
  result=r.assemble(values,a.CANDIDATE,4,9,datetime.now(timezone.utc),expected)
  self.assertEqual(result['normal_connection']['desired_revision'],40);self.assertNotIn('candidate_reservation',result)
  values[0]['ranges'].append({'source':'connection_remote_prefixes','cidr':a.CANDIDATE})
  with self.assertRaisesRegex(ValueError,'overlap'):r.assemble(values,a.CANDIDATE,4,9,datetime.now(timezone.utc),expected)
  forged=copy.deepcopy(self.receipt);forged['normal_connection']['id']=c.prefix.CP
  with self.assertRaises(ValueError):c.normal(forged,datetime.now(timezone.utc))

 def test_add_requires_fresh_exact_revision_native_oneprefix_and_no_grants(self):
  c.evidence(self.review,a.CANDIDATE,datetime.now(timezone.utc),self.receipt,self.proof)
  for changed in ('stale','overlap','revision','native','secondprefix','grant'):
   receipt=copy.deepcopy(self.receipt);review=copy.deepcopy(self.review);proof=copy.deepcopy(self.proof)
   if changed=='stale':review['observed_at']=(datetime.now(timezone.utc)-timedelta(seconds=61)).isoformat()
   if changed=='overlap':review['ranges'].append(a.CANDIDATE)
   if changed=='revision':proof['desired_revision']=3
   if changed=='native':proof['native']['sad']=6
   if changed=='secondprefix':proof['bgp']['peers'][0]['accepted_prefixes']=2
   if changed=='grant':receipt['policy_count']=1
   with self.subTest(changed=changed),self.assertRaises(ValueError):c.evidence(review,a.CANDIDATE,datetime.now(timezone.utc),receipt,proof)
 def test_restore_binding_accepts_blocked_status_without_false_applied(self):
  binding=c.normal(self.receipt,datetime.now(timezone.utc));self.receipt['normal_connection'].update(application_state='pending',desired_revision=3)
  c.normal(self.receipt,datetime.now(timezone.utc),binding)
  with self.assertRaises(ValueError):c.evidence(self.review,a.CANDIDATE,datetime.now(timezone.utc),self.receipt,self.proof)
  self.receipt['normal_connection']['configuration_revision']=8
  with self.assertRaises(ValueError):c.normal(self.receipt,datetime.now(timezone.utc),binding)
 def test_wrong_host_and_reused_original_state_refuse_before_cloud(self):
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'state.json'
   with patch.object(c.socket,'gethostname',return_value='other'),patch.object(c.prefix,'run') as run:
    with self.assertRaises(ValueError):c.run('prepare',path,self.receipt,self.review,self.proof)
    run.assert_not_called()
 def test_collector_exception_annotation_does_not_remove_other_candidate_uses(self):
  expected={key:self.current[key] for key in ('id','desired_revision','configuration_revision','profile_id','remote_prefixes','maximum_prefixes')}
  def inputs():
   result=[]
   for kind,source in [('owned_api_ranges','site_subnet'),('owned_kernel_ranges','kernel_route'),('owned_azure_ranges','azure_subnet')]:
    result.append(r.envelope(kind,NOW(),[{'source':source,'cidr':'10.231.0.0/16'}]))
   result[0].update(normal_connection=copy.deepcopy(self.current),candidate_reservation=self.review['candidate_reservation']);result[1]['namespace']=self.namespace
   return result
  r.assemble(inputs(),a.CANDIDATE,4,9,datetime.now(timezone.utc),expected)
  for index in range(3):
   values=inputs();values[index]['ranges'].append({'source':['connection_remote_prefixes','kernel_route','azure_subnet'][index],'cidr':a.CANDIDATE})
   with self.assertRaisesRegex(ValueError,'overlap'):r.assemble(values,a.CANDIDATE,4,9,datetime.now(timezone.utc),expected)
  values=inputs();values[0]['candidate_reservation']['connection_id']=I(99)
  with self.assertRaises(ValueError):r.assemble(values,a.CANDIDATE,4,9,datetime.now(timezone.utc),expected)

class ActualCollectorEnvelope(unittest.TestCase):
 def test_only_exact_current_remote_reservation_is_annotated(self):
  setup={'org_id':I(1),'site_id':I(2),'gateway_id':I(3)}
  expected={'id':I(8),'desired_revision':2,'configuration_revision':7,'profile_id':a.PROFILE,'remote_prefixes':['10.231.0.0/16',a.CANDIDATE],'maximum_prefixes':1}
  current={**expected,'org_id':I(1),'site_id':I(2),'gateway_node_id':I(3),'desired_intent':'enabled','application_state':'applied','cleanup_state':'not_required'}
  foreign={'id':I(9),'finalized_at':None};include_foreign=False;changed=False
  def call(method,path):
   self.assertEqual(method,'GET');suffix=path.split(I(1))[-1]
   if path=='/api/v1/organizations':return [{'id':I(1),'slug':'azure-s2s-local','pool_cidr':'10.244.0.0/16'}]
   if suffix=='/sites':return [{'id':I(2)}]
   if suffix=='/nodes':return [{'id':I(3)}]
   if suffix.endswith('/subnets'):return [{'cidr':'10.233.10.0/24'}]
   if suffix.endswith('/dns-forwards'):return []
   if suffix.startswith('/fqdn-resolver-contexts/'):raise r.enroll.LabError('fixture',404,'fqdn_resolver_config_not_found')
   if suffix=='/routed-ranges':return {'ranges':[],'forwards':[]}
   if suffix in ('/resources','/policies'):return []
   if suffix=='/ipsec/connections?limit=100':return {'items':[current]+([foreign] if include_foreign else []),'next_cursor':None}
   if suffix=='/ipsec/connections/'+I(8):return current
   if suffix.endswith('/configuration'):
    value=original();value['configuration_revision']=8 if changed else 7;value['configuration']['remote_prefixes']=['10.231.0.0/16',a.CANDIDATE];value['configuration']['bgp']['maximum_prefixes']=1;return value
   raise AssertionError(path)
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve();root.chmod(0o700)
   for name,value in [('api-setup.json',setup),('ui-accounts.json',[{'email':'browser-owner@azure-s2s.local','password':'private.offline'}])]:
    (root/name).write_text(json.dumps(value));(root/name).chmod(0o600)
   with patch.object(r.enroll,'Client',return_value=type('Client',(),{'call':staticmethod(call)})()):
    value=r.api_collect(root,expected)
    self.assertEqual(value['candidate_reservation'],{'connection_id':I(8),'configuration_revision':7,'prefix':a.CANDIDATE})
    self.assertFalse(any(v['cidr']==a.CANDIDATE for v in value['ranges']))
    include_foreign=True;value=r.api_collect(root,expected)
    self.assertIn({'source':'connection_remote_prefixes','cidr':a.CANDIDATE},value['ranges'])
    include_foreign=False;changed=True
    with self.assertRaisesRegex(ValueError,'reservation contract'):r.api_collect(root,expected)

class TimestampCompatibility(unittest.TestCase):
 def test_variable_go_fractions_normalized_before_python310_parse(self):
  original=a.datetime
  seen=[]
  class Python310:
   @staticmethod
   def fromisoformat(value):
    seen.append(value)
    if '.' in value:
     fractional=value.split('.')[1].split('+')[0]
     if len(fractional)!=6:raise ValueError('Python310 fractional length')
    return original.fromisoformat(value)
  with patch.object(a,'datetime',Python310):
   for fraction in ('1','12','123','1234','12345','123456','1234567','12345678','123456789'):
    self.assertEqual(a.instant('2026-10-10T19:40:21.'+fraction+'Z').microsecond,int(fraction[:6].ljust(6,'0')))
  self.assertEqual(len(seen),9)
  for value in ('2026-10-10 19:40:21Z','2026-10-10T19:40:21.1234567890Z','2026-10-10T19:40:21','2026-13-10T19:40:21Z'):
   with self.assertRaises(ValueError):a.instant(value)

class MainPrivateGuard(unittest.TestCase):
 def test_existing_receipt_refuses_before_normal_login(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve();root.chmod(0o700);output=root/'prepared-dns-state.json';output.write_text('{"preserve":true}');output.chmod(0o600)
   args=['qualify-max-prefix-api.py','read','--private-root',str(root),'--state',str(root/'max.json'),'--output',str(output)]
   with patch('sys.argv',args),patch.object(a.api,'Client') as client:
    with self.assertRaisesRegex(ValueError,'new separate receipt'):a.main()
    client.assert_not_called()
   self.assertEqual(output.read_text(),'{"preserve":true}')

class RealCloudReservation(unittest.TestCase):
 def test_exclusive_add_and_restore_drain_under_blocked_normal_status(self):
  guard=CloudGuards();guard.setUp()
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve();root.chmod(0o700);state=root/'cloud.json'
   vnet={'id':c.prefix.VNET,'tags':{'owner':c.prefix.lab.OWNER},'provisioningState':'Succeeded','addressSpace':{'addressPrefixes':['10.231.0.0/16']},'unknownProtectedProperty':{'preserve':True}}
   discovery={'gateway_id':c.prefix.BASE+'virtualNetworkGateways/azure-vpn','local_gateway_id':c.prefix.BASE+'localNetworkGateways/tunnex-local','active_active':True,'sku':'VpnGw1AZ','vpn_type':'RouteBased','enable_bgp':True,'public_endpoints':[{},{}],'local_prefixes':['10.233.10.0/24']}
   updates=[];fail=False
   def az(*args):
    updates.append(args);self.assertTrue(state.with_name(state.name+('.add-reserved' if len(updates)==1 else '.restore-reserved')).exists())
    if fail:raise ValueError('ambiguous actual update fixture')
    start=args.index('--address-prefixes')+1;end=args.index('--query');vnet['addressSpace']['addressPrefixes']=list(args[start:end]);return c.prefix.VNET
   with patch.object(c.socket,'gethostname',return_value='bastion-host'),patch.object(c.prefix,'cloud_binding',return_value=discovery),patch.object(c.prefix,'cloud_ranges'),patch.object(c.prefix,'read_vnet',side_effect=lambda:copy.deepcopy(vnet)),patch.object(c.prefix,'external_properties',return_value={'dns':'preserve','lb':'preserve'}),patch.object(c.prefix.lab,'az',side_effect=az):
    c.run('prepare',state,guard.receipt,guard.review,guard.proof)
    c.run('add',state,guard.receipt,guard.review,guard.proof)
    with self.assertRaises(ValueError):c.run('add',state,guard.receipt,guard.review,guard.proof)
    self.assertEqual(len(updates),1)
    guard.receipt['normal_connection']['application_state']='pending'
    c.run('restore',state,guard.receipt)
    self.assertEqual(vnet['addressSpace']['addressPrefixes'],['10.231.0.0/16']);self.assertTrue(vnet['unknownProtectedProperty']['preserve'])
    self.assertEqual(len(updates),2)

class RestoredDNSBoundary(unittest.TestCase):
 def test_real_rebind_path_restoration_only_after_test_finalization(self):
  fixtures=load('max_dns_existing_fixture',Path(__file__).with_name('test_profile_dns_rebind.py'))
  for bad in (None,'pending','limit'):
   with self.subTest(bad=bad),tempfile.TemporaryDirectory() as folder:
    f=fixtures.Fixture(folder);f.execute('prepare');f.execute('revoke');f.old_finalized=True
    test_id=I(77);f.transition={'version':1,'purpose':'baseline','setup':f.setup,'original_prior':{'id':f.old},'prior':{'id':test_id},'target':{'id':f.new},'original_configuration':original()}
    original_call=f.call
    def call(method,path,body=None):
     if path.endswith('/ipsec/connections/'+test_id):
      return {'id':test_id,'org_id':f.setup['org_id'],'historical_site_id':f.setup['site_id'],'historical_gateway_node_id':f.setup['gateway_id'],'desired_intent':'deleted','application_state':'not_applied','cleanup_state':'pending' if bad=='pending' else 'retained_guard','deleted_at':NOW(),'finalized_at':NOW()}
     if path.endswith('/ipsec/connections/'+f.new+'/configuration'):
      value=original();value['configuration_revision']=9
      if bad=='limit':value['configuration']['remote_prefixes']=['10.231.0.0/16',a.CANDIDATE];value['configuration']['bgp']['maximum_prefixes']=1
      return value
     return original_call(method,path,body)
    f.call=call
    if bad is None:
     f.execute('rebind');self.assertEqual(f.context['profiles'][0]['ipsec_path']['connection_id'],f.new);self.assertEqual(f.context['profiles'][0]['ipsec_path']['configuration_revision'],9)
    else:
     with self.assertRaises(ValueError):f.execute('rebind')
     self.assertFalse(any(method=='PUT' for method,path,body in f.calls))

if __name__=='__main__':unittest.main()
