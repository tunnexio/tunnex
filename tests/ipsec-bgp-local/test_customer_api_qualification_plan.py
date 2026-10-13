import copy,importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name('customer-api-qualification-plan.py');s=importlib.util.spec_from_file_location('q',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Cases(unittest.TestCase):
 def test_cases_and_fourprofiles(self):self.assertEqual({x['id']for x in m.CASES},{'C01','C02','C03','C04','C05','C06','C09'});self.assertEqual(len(m.plan()['profiles']),4);self.assertTrue(m.plan()['source_only'])
 def test_invalid_inputs_do_not_mutate_frozen_fixture(self):
  c={'mode':'ipv4-bgp','bgp':{'local_asn':65000,'remote_asn':64512,'router_id':'10.84.2.1','maximum_prefixes':1},'tunnels':[{'inside_cidr':'169.254.124.0/30','psk':'fixture-safe-123456'},{'inside_cidr':'169.254.124.4/30','psk':'fixture-safe-abcdef'}]};before=copy.deepcopy(c);cases=m.invalid_cases(c);self.assertEqual(c,before);self.assertEqual(len(cases),11);self.assertTrue(all(x['expected_status']==400 for x in cases))
 def test_roles_no_simulated_authority(self):self.assertIn('no Principal/context/DB spoof',next(x['mutations']for x in m.CASES if x['id']=='C02'));self.assertIn('Only actualadmin',m.plan()['role_account_gap'])
if __name__=='__main__':unittest.main()
