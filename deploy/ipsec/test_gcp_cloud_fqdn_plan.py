import importlib.util,pathlib,unittest
s=importlib.util.spec_from_file_location('plan',pathlib.Path(__file__).with_name('gcp-cloud-fqdn-plan.py'));p=importlib.util.module_from_spec(s);s.loader.exec_module(p)
class PlanTests(unittest.TestCase):
 def test_bound_scope_and_diagnostic_names(self):
  c={'site_id':p.SITE,'gateway_id':p.NODE,'state':'active','profiles':[{'zone_suffixes':['ha.gcp.s2s-qa.tunnex.app'],'provider_hint':'google_cloud','ipsec_path':{'source_address':'10.70.0.2','configuration_revision':1,'connection_id':'actual-id'},'endpoints':[{'address':'10.80.0.2','port':53,'transport':t} for t in ('tcp','udp')]}]}
  r=p.prepare('ha',c);self.assertEqual(len(r),4);self.assertTrue(all(i['resolver_context']['gateway_id']==p.NODE and i['expected_impact_token'] is None for i in r));self.assertEqual(r[0]['fqdn'],'app.ha.gcp.s2s-qa.tunnex.app')
  c['profiles'][0]['ipsec_path']['source_address']='10.70.0.10'
  with self.assertRaises(ValueError):p.prepare('ha',c)
if __name__=='__main__':unittest.main()
