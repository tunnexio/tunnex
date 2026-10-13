import importlib.util,pathlib,json,unittest
p=pathlib.Path(__file__).with_name('customer-static-infra-plan.py');s=importlib.util.spec_from_file_location('plan',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Plan(unittest.TestCase):
 def test_source_only_no_instances_or_attachments(self):
  v=m.plan();self.assertTrue(v['source_only']);self.assertEqual(len(v['steps']),len(set(x['id']for x in v['steps'])));self.assertFalse(any(x['argv'][6]in ['run-instances','attach-network-interface','stop-instances','modify-transit-gateway']for x in v['steps']))
 def test_disjoint_static_modes_and_selectors(self):
  rows=[x for x in m.plan()['steps']if x['id']in ['vgw-vpn','tgw-vpn']];self.assertEqual(len(rows),2)
  for x,remote in zip(rows,['10.87.1.0/24','10.87.2.0/24']):
   args=x['argv'];options=json.loads(args[args.index('--options')+1]);self.assertIs(options['StaticRoutesOnly'],True);self.assertEqual(options['LocalIpv4NetworkCidr'],'10.84.2.0/24');self.assertEqual(options['RemoteIpv4NetworkCidr'],remote)
 def test_tgw_own_associations_only_defaults_unchanged(self):
  rows=m.plan()['steps'];ids=[x['id']for x in rows];self.assertLess(ids.index('tgw-vpc-attachment'),ids.index('tgw-return-route'));self.assertEqual(sum(x['argv'][6]=='associate-transit-gateway-route-table'for x in rows),2);self.assertTrue(all('${TGW_RT}'in x['argv']for x in rows if x['argv'][6]=='associate-transit-gateway-route-table'))
if __name__=='__main__':unittest.main()
