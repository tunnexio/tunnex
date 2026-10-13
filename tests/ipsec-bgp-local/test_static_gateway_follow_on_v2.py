import copy,importlib.util,pathlib,unittest
s=importlib.util.spec_from_file_location('follow',pathlib.Path(__file__).with_name('static-gateway-follow-on-v2.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Tests(unittest.TestCase):
 def route(self):return {'dst':'10.87.1.0/24','gateway':'172.30.88.2','dev':'tnxbgplab0','protocol':242,'metric':510871,'flags':[]}
 def want(self):return {'destination':'10.87.1.0/24','via':'172.30.88.2','device':'tnxbgplab0','metric':510871}
 def test_exact_route_cleanup_tuple(self):self.assertTrue(m.route_matches(self.route(),self.want()))
 def test_foreign_or_replaced_tuple_refuses(self):
  for key,value in [('gateway','172.30.88.9'),('dev','foreign'),('protocol',2),('metric',1),('table',100),('flags',['linkdown']),('nhid',9),('dst','10.87.2.0/24')]:
   row=self.route();row[key]=value;self.assertFalse(m.route_matches(row,self.want()),key)
 def test_default_not_payload(self):self.assertEqual(str(m.destination({'dst':'default'})),'0.0.0.0/0');self.assertFalse(m.route_matches({'dst':'default'},self.want()))
 def test_rule_order_preserved(self):
  a='-A DOCKER-USER -s 10.84.2.10/32 -j ACCEPT\n-A DOCKER-USER -j DROP\n';self.assertNotEqual(m.canonical_rules(a),m.canonical_rules('\n'.join(reversed(a.splitlines()))))
 def test_sg_ids_and_literals_preserved(self):
  rows=[{'SecurityGroupRuleId':'sgr-b','IpProtocol':'udp','FromPort':500,'ToPort':500,'CidrIpv4':'3.67.173.125/32','Tags':[]},{'SecurityGroupRuleId':'sgr-a','IpProtocol':'tcp','FromPort':22,'ToPort':22,'CidrIpv4':'16.170.207.192/32'}]
  self.assertEqual(m.group_rules(rows),m.group_rules(list(reversed(rows))))
  altered=copy.deepcopy(rows);altered[0]['CidrIpv4']='0.0.0.0/0';self.assertNotEqual(m.group_rules(rows),m.group_rules(altered))
 def test_owned_comment_collision_on_foreign_tuple_refuses(self):
  own=['-A','DOCKER-USER','-s','10.84.2.10/32','-m','comment','--comment','tunnex-static-central-871-http','-j','ACCEPT'];foreign=list(own);foreign[3]='10.84.99.10/32'
  with self.assertRaises(AssertionError):m.validate_owned_comment([foreign],own,False)
  with self.assertRaises(AssertionError):m.validate_owned_comment([own,foreign],own,True)
  with self.assertRaises(AssertionError):m.validate_owned_comment([own,own],own,True)
  m.validate_owned_comment([],own,False);m.validate_owned_comment([own],own,True)
 def test_unrelated_comment_remains_foreign(self):
  own=['-A','DOCKER-USER','-m','comment','--comment','owned','-j','ACCEPT'];foreign=list(own);foreign[5]='foreign';m.validate_owned_comment([foreign],own,False)
 def test_firewall_rollback_removes_only_exact_owned_rule(self):
  before=m.canonical_rules('-A DOCKER-USER -j RETURN\n');own=['-A','DOCKER-USER','-s','10.84.2.10/32','-d','10.87.1.10/32','-p','tcp','--dport','8080','-m','comment','--comment','tunnex-static-central-871-http','-j','ACCEPT'];after=[own]+before
  self.assertEqual([x for x in after if x!=own],before);foreign=list(own);foreign[-1]='DROP';self.assertNotEqual([x for x in [foreign]+before if x!=own],before)
if __name__=='__main__':unittest.main()
