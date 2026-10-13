import copy,importlib.util,pathlib,unittest
s=importlib.util.spec_from_file_location('m',pathlib.Path(__file__).with_name('customer-api-disabled-fixture-generator.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Generator(unittest.TestCase):
 def seed(self):return {'provider_id':m.SOURCE_PROVIDER,'org_id':m.ORG,'site_id':m.SITE,'gateway_node_id':m.GW,'public_configuration':copy.deepcopy(m.EXPECTED)}
 def test_four_disjoint_disabled_profiles(self):
  seed=self.seed();f=[m.generate(seed,p,'a'*64)for p in m.PROFILES];self.assertEqual(len({v['body']['configuration']['remote_prefixes'][0]for v in f}),4);self.assertEqual(len({t['inside_cidr']for v in f for t in v['body']['configuration']['tunnels']}),8);self.assertEqual(seed,self.seed())
  for p,v in zip(m.PROFILES,f):
   c=v['body']['configuration'];self.assertEqual('bgp'in c,p.endswith('-bgp'));self.assertTrue(all(t['psk'].startswith('S')and len(t['psk'])==49 for t in c['tunnels']));self.assertNotIn('intent',v['body'])
 def test_foreign_or_changed_seed_refused(self):
  for field,value in [('provider_id','foreign'),('gateway_node_id','foreign')]:
   seed=self.seed();seed[field]=value
   with self.assertRaises(AssertionError):m.generate(seed,'vgw-bgp','a'*64)
  seed=self.seed();seed['public_configuration']['configuration']['local_prefixes']=['10.84.3.0/24']
  with self.assertRaises(AssertionError):m.generate(seed,'vgw-bgp','a'*64)
 def test_no_existing_secret_input_accepted(self):
  seed=self.seed();seed['public_configuration']['configuration']['tunnels'][0]['psk']='unknown'
  with self.assertRaises(AssertionError):m.generate(seed,'vgw-bgp','a'*64)
if __name__=='__main__':unittest.main()
