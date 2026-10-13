import importlib.util,json,pathlib,tempfile,unittest
spec=importlib.util.spec_from_file_location('m',pathlib.Path(__file__).with_name('provision-customer-static-central-v2.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Central(unittest.TestCase):
 def step(self,name):return next(s['argv']for s in m.STEPS if s['id']==name)
 def test_region_and_no_north_foreign_ids(self):
  raw=json.dumps(m.STEPS);self.assertNotIn('eu-north-1',raw);self.assertNotIn('tgw-09a6',raw);self.assertNotIn('cgw-052',raw);self.assertNotIn('attach-network-interface',raw);self.assertNotIn('index2',raw);self.assertIn('device index1',raw)
 def test_private_http_and_management_only(self):
  a=self.step('sg-http');p=json.loads(a[a.index('--ip-permissions')+1])[0];self.assertEqual((p['FromPort'],p['ToPort'],p['IpRanges'][0]['CidrIp']),(8080,8080,'10.84.2.10/32'))
  a=self.step('sg-ssh');p=json.loads(a[a.index('--ip-permissions')+1])[0];self.assertEqual((p['FromPort'],p['IpRanges'][0]['CidrIp']),(22,'16.170.207.192/32'))
 def test_one_target_no_secondary_attachment(self):
  a=self.step('target');self.assertEqual(a[a.index('--instance-type')+1],'t3.micro');self.assertEqual(a[a.index('--max-count')+1],'1');self.assertIn('--client-token',a);n=json.loads(a[a.index('--network-interfaces')+1]);self.assertEqual(len(n),1);self.assertEqual(n[0]['PrivateIpAddress'],'10.87.1.10');self.assertTrue(n[0]['AssociatePublicIpAddress']);self.assertNotIn('psk',a[a.index('--user-data')+1].lower())
 def test_static_narrow_and_independent_tables(self):
  for role,remote in [('vgw','10.87.1.0/24'),('tgw','10.87.2.0/24')]:
   a=self.step(role+'-vpn');o=json.loads(a[a.index('--options')+1]);self.assertTrue(o['StaticRoutesOnly']);self.assertEqual(o['LocalIpv4NetworkCidr'],'10.84.2.0/24');self.assertEqual(o['RemoteIpv4NetworkCidr'],remote)
  a=self.step('tgw-vpc-associate');self.assertEqual(a[a.index('--transit-gateway-route-table-id')+1],'${TGW_RT_TABLE}')
 def test_unknown_owner_refused_and_placeholder_not_guessed(self):
  with self.assertRaises(AssertionError):m.known_owner({'VpcId':'vpc-unknown','Tags':[{'Key':'TunnexLab','Value':m.OWNER}]},'VpcId',{})
  with self.assertRaises(AssertionError):m.expand(['--vpc-id','${VPC}'],{})
 def test_global_vpn_projection_no_secrets(self):
  self.assertNotIn('CustomerGatewayConfiguration',m.VPN_INVENTORY_QUERY);self.assertNotIn('PreSharedKey',m.VPN_INVENTORY_QUERY);self.assertIn('InsideCidrs',m.VPN_INVENTORY_QUERY)
if __name__=='__main__':unittest.main()
