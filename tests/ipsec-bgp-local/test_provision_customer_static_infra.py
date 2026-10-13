import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name('provision-customer-static-infra.py');s=importlib.util.spec_from_file_location('infra',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Executor(unittest.TestCase):
 def test_no_host_or_eni_attach_mutations(self):
  actions=[x['argv'][6]for x in m.STEPS];self.assertNotIn('attach-network-interface',actions);self.assertNotIn('run-instances',actions);self.assertNotIn('modify-transit-gateway',actions)
 def test_placeholder_refusal_before_aws(self):
  with self.assertRaises(AssertionError):m.expand(['${UNKNOWN}'],{})
  self.assertEqual(m.expand(['${VPC}'],{'VPC':'vpc-owned'}),['vpc-owned'])
 def test_app_rt_not_tgw_association_rt(self):
  app=next(x for x in m.STEPS if x['id']=='tgw-return-route');self.assertIn('${TGW_RT}',app['argv'])
  for x in m.STEPS:
   if x['id']in ['tgw-vpc-associate','tgw-vpn-associate','tgw-to-target','tgw-to-customer']:self.assertIn('${TGW_RT_TABLE}',x['argv']);self.assertNotIn('${TGW_RT}',x['argv'])
 def test_unknown_outcome_no_mutation_replay(self):
  source=p.read_text();branch=source[source.index(' if intent.exists():'):source.index(' argv=expand')];self.assertIn('describe-',branch);self.assertIn('raise AssertionError',branch);self.assertNotIn('response=aws(argv',branch)
if __name__=='__main__':unittest.main()
