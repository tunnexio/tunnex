import datetime
import importlib.util,json,pathlib,unittest
s=importlib.util.spec_from_file_location('p',pathlib.Path(__file__).with_name('gcp-classic-fqdn-qualification-plan.py'));p=importlib.util.module_from_spec(s);s.loader.exec_module(p)
def context():return {'id':p.CONFIG,'site_id':p.SITE,'gateway_id':p.NODE,'state':'active','version':1,'profiles':[{'id':p.PROFILE,'zone_suffixes':[p.ZONE],'ipsec_path':{'connection_id':p.CONNECTION,'configuration_revision':1,'source_address':'10.70.0.2'},'provider_hint':'google_cloud','legacy_default':False,'endpoints':[{'address':'10.81.0.2','port':53,'transport':'tcp'},{'address':'10.81.0.2','port':53,'transport':'udp'}]}]}
class Tests(unittest.TestCase):
 def test_exact_three_plans_refuse_large_collision_or_context_drift(self):
  c=context()
  for label in ['app','alias','nx-qualification']:self.assertEqual(p.create(c,label,[])['fqdn'],label+'.'+p.ZONE)
  for label in ['large','tc-large']:
   with self.assertRaises(ValueError):p.create(c,label,[])
  with self.assertRaises(ValueError):p.create(dict(c,version=2),'app',[])
  with self.assertRaises(ValueError):p.create(c,'app',[p.create(c,'app',[])['name']])
 def test_server_token_preserved_and_only_app_grant(self):
  self.assertEqual(p.enforcement_body({'enabled':True,'entitlement_available':True,'expected_impact_token':'server-issued'}),{'enabled':True,'expected_impact_token':'server-issued'})
  with self.assertRaises(ValueError):p.enforcement_body({'enabled':False,'entitlement_available':True,'expected_impact_token':'x'})
  r=dict(p.create(context(),'alias',[]),id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
  with self.assertRaises(ValueError):p.app_grant(r)
  r=p.create(context(),'app',[]);r['id']='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';self.assertEqual(p.app_grant(r)['dst_kind'],'fqdn_resource')
 def test_actual_generation_binding_nxdomain_and_stale_refuse(self):
  now=datetime.datetime.now(datetime.timezone.utc);resource={'fqdn':'app.'+p.ZONE,'state':'healthy','generation':1,'resolver_context':{'site_id':p.SITE,'gateway_id':p.NODE,'resolver_config':{'id':p.CONFIG}},'resolver_profile_selection':{'id':p.PROFILE,'config_version':1,'matched_suffix':p.ZONE}};d={'resource':resource,'status_source':'active_generation','active_answer_addresses':['10.81.0.10'],'fresh_until_at':(now+datetime.timedelta(seconds=30)).isoformat()}
  self.assertTrue(p.generation(d,'app',now));self.assertFalse(p.generation(dict(d,fresh_until_at=(now-datetime.timedelta(seconds=1)).isoformat()),'app',now))
  bad=json.loads(json.dumps(d));bad['resource']['resolver_profile_selection']['id']='foreign'
  with self.assertRaises(ValueError):p.generation(bad,'app',now)
  nx=json.loads(json.dumps(d));nx['resource'].update(fqdn='nx-qualification.'+p.ZONE,state='nxdomain',generation=None);nx.update(server_reason='NXDOMAIN',active_answer_addresses=[]);self.assertTrue(p.generation(nx,'nx-qualification',now));nx['active_answer_addresses']=['10.81.0.10'];self.assertFalse(p.generation(nx,'nx-qualification',now))
if __name__=='__main__':unittest.main()
