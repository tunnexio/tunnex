import importlib.util,pathlib,unittest,copy,uuid
spec=importlib.util.spec_from_file_location('f',pathlib.Path(__file__).with_name('fqdn-api.py'));f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
def rows(n):return [{'id':str(uuid.uuid4())}for _ in range(n)]
def baseline():
 return {'configurations':{cid:{}for cid in ('80c20667-8d84-4dd8-8e51-ae4a10445cbb','b79d7eda-fafe-41cf-af2c-4115d4ef32c6','431fa305-4d3d-4c38-b0e4-88068c0e2297')},'connections':rows(9),'resources':rows(13),'policies':rows(12),'fqdn':[],'setting':{'enabled':True,'expected_impact_token':None},'context':{'id':f.plan.CONFIG,'site_id':f.plan.SITE,'gateway_id':f.plan.NODE,'state':'active','version':1,'profiles':[{'id':f.plan.PROFILE,'zone_suffixes':[f.plan.ZONE],'provider_hint':'google_cloud','legacy_default':False,'ipsec_path':{'connection_id':f.plan.CONNECTION,'configuration_revision':1,'source_address':'10.70.0.2'},'endpoints':[{'address':'10.81.0.2','port':53,'transport':'tcp'},{'address':'10.81.0.2','port':53,'transport':'udp'}]}]}}
class Tests(unittest.TestCase):
 def test_unknown_baseline_duplicate_context(self):
  for mutate in [lambda b:b['policies'].append({'id':str(uuid.uuid4())}),lambda b:b['resources'].__setitem__(1,b['resources'][0]),lambda b:b['context'].__setitem__('version',2)]:
   b=baseline();mutate(b)
   with self.assertRaises(ValueError):f.baseline_valid(b)
 def test_actual_nullable_setting_shape(self):
  b=baseline();f.baseline_valid(b)
  b['setting']['enabled']=False
  with self.assertRaises(ValueError):f.baseline_valid(b)
 def test_existing_name_refuses(self):
  b=baseline();b['fqdn']=[{'id':str(uuid.uuid4()),'name':'GCP Classic FQDN qualification app 20261010'}]
  with self.assertRaises(ValueError):f.baseline_valid(b)
 def test_legitimate_changed_impact_and_three_posts(self):
  b=baseline();current=copy.deepcopy(b);events=[];calls=[];impact=[0]
  def request(path,method='GET',body=None):
   calls.append((path,method))
   if path.endswith('/setting/impact'):
    impact[0]+=1;return {'enabled':True,'entitlement_available':True,'expected_impact_token':'a'if impact[0]<3 else'b'}
   if method=='POST':
    r={**body,'id':str(uuid.uuid4())};current['fqdn'].append(r);return r
   if path.endswith('/configuration'):return {}
   if path.startswith('/ipsec/'):return {'items':current['connections'],'next_cursor':None}
   for k,route in [('resources','/resources'),('policies','/policies'),('fqdn','/fqdn-resources'),('context',f.CONTEXT),('setting','/fqdn-resources/setting')]:
    if path==route:return copy.deepcopy(current[k])
   return {'resource':next(r for r in current['fqdn']if path.endswith(r['id']))}
  f.create(request,b,events.append)
  self.assertEqual(sum(m=='POST'for _,m in calls),3);self.assertTrue(events[-1]['original_baseline_preserved']);self.assertIn('created_id',events[0])
 def test_cleanup_refusal_preserves_original(self):
  b=baseline();rid=str(uuid.uuid4());body=f.plan.create(b['context'],'app',[]);r={**body,'id':rid};current=copy.deepcopy(b);current['fqdn']=[r];events=[]
  def request(path,method='GET',body=None):
   if method=='DELETE':raise ValueError('active generation')
   if path.endswith('/impact'):return {'active_generation':True}
   if path.endswith('/configuration'):return {}
   if path.startswith('/ipsec/'):return {'items':current['connections']}
   for k,route in [('resources','/resources'),('policies','/policies'),('fqdn','/fqdn-resources'),('context',f.CONTEXT),('setting','/fqdn-resources/setting')]:
    if path==route:return copy.deepcopy(current[k])
   return {'resource':r}
  remaining=f.cleanup(request,b,{rid:{'label':'app','body':body}},events.append)
  self.assertEqual(list(remaining),[rid]);self.assertTrue(events[-1]['original_baseline_preserved'])
 def test_runtime_projection_only_and_authority_drift(self):
  b=baseline();c=copy.deepcopy(b)
  c['connections'][0].update(application_state='applied',cleanup_state='retained_guard',updated_at='new')
  f.preserve(b,c,[])
  c['connections'][0]['unknown_authority']='changed'
  with self.assertRaises(ValueError):f.preserve(b,c,[])
  c=copy.deepcopy(b);c['configurations'][next(iter(c['configurations']))]={'configuration_revision':2}
  with self.assertRaises(ValueError):f.preserve(b,c,[])
 def test_pending_null_generation_not_success(self):
  body=f.plan.create(baseline()['context'],'app',[]);r={**body,'generation':None,'resolver_profile_selection':{'id':f.plan.PROFILE,'config_version':1,'matched_suffix':f.plan.ZONE}}
  r['resolver_context']['resolver_config']={'id':f.plan.CONFIG}
  import datetime
  self.assertFalse(f.plan.generation({'resource':r,'fresh_until_at':None},'app',datetime.datetime.now(datetime.timezone.utc)))
if __name__=='__main__':unittest.main()
