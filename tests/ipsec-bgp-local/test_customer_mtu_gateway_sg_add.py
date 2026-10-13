import importlib.util,pathlib,unittest,copy
p=pathlib.Path(__file__).with_name('customer-mtu-gateway-sg-add.py');s=importlib.util.spec_from_file_location('sg',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Rules(unittest.TestCase):
 def row(self):return {'GroupId':m.SG,'IsEgress':False,'IpProtocol':'tcp','FromPort':8081,'ToPort':8081,'CidrIpv4':m.CLIENT,'Description':m.DESCRIPTION,'SecurityGroupRuleId':'sgr-owned'}
 def test_exact_client32_only(self):self.assertTrue(m.exact(self.row()))
 def test_foreign_wider_udp_egress_refuse(self):
  for key,value in [('CidrIpv4','10.84.2.0/24'),('IpProtocol','udp'),('IsEgress',True),('GroupId','foreign'),('ToPort',8082)]:
   row=self.row();row[key]=value;self.assertFalse(m.exact(row))
 def test_rule_order_only_is_canonical(self):
  rows=[self.row(),{**self.row(),'SecurityGroupRuleId':'sgr-second'}];self.assertEqual(m.canonical(rows),m.canonical(rows[::-1]));changed=copy.deepcopy(rows);changed[0]['Description']='foreign';self.assertNotEqual(m.canonical(rows),m.canonical(changed))
if __name__=='__main__':unittest.main()
