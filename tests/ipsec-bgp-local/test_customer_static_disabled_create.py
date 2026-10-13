import copy,importlib.util,pathlib,unittest
s=importlib.util.spec_from_file_location('sut',pathlib.Path(__file__).with_name('customer-static-disabled-create.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def body():
 p=m.PINS['vgw'];return {'id':p[0],'name':'Customer static vgw central owned','site_id':m.SITE,'gateway_node_id':m.GW,'tunnel_ids':['11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222'],'configuration':{'mode':'ipv4-static','customer_outside_address':'13.63.169.255','local_prefixes':['10.84.2.0/24'],'remote_prefixes':[p[4]],'tunnels':[{'outside_address':p[2][i],'inside_cidr':p[3][i],'cloud_inside_address':str(m.ipaddress.ip_network(p[3][i]).network_address+1),'customer_inside_address':str(m.ipaddress.ip_network(p[3][i]).network_address+2),'psk':'SyntheticOnly123'}for i in range(2)]}}
class Tests(unittest.TestCase):
 def test_exact_binding_and_no_public_psk(self):
  b=body();self.assertEqual(m.validate(b,'vgw',m.PINS['vgw'][1]),b);self.assertNotIn('psk',str(m.expected(b)))
 def test_wrong_pin_profile_prefix_and_bgp_refuse(self):
  for mutate in [lambda b:b.update(id=m.PINS['tgw'][0]),lambda b:b['configuration'].update(remote_prefixes=['10.85.0.0/16']),lambda b:b['configuration'].update(bgp={}),lambda b:b.update(site_id='foreign')]:
   b=body();mutate(b)
   with self.assertRaises(AssertionError):m.validate(b,'vgw',m.PINS['vgw'][1])
 def test_unknown_post_saved_no_replay(self):
  b=body();saved={};posts=[]
  def api(path,method='GET',v=None):
   if path.endswith('/auth/me'):return 200,{'id':'user','email_verified':True}
   if path.endswith('/members'):return 200,[{'user_id':'user','status':'active','role':'admin'}]
   if '?limit' in path:return 200,{'items':[]}
   if path.endswith('configuration-check'):return 200,{'valid':True}
   if method=='POST':posts.append(v);raise TimeoutError()
   self.fail(path)
  with self.assertRaises(TimeoutError):m.flow(b,api,lambda n,v:saved.setdefault(n,v),lambda n:saved[n])
  self.assertIn('create-pending.json',saved);self.assertEqual(len(posts),1)
 def test_existing_collision_no_post(self):
  b=body();writes=[]
  def api(path,method='GET',v=None):
   if path.endswith('/auth/me'):return 200,{'id':'u','email_verified':True}
   if path.endswith('/members'):return 200,[{'user_id':'u','status':'active','role':'owner'}]
   if '?limit' in path:return 200,{'items':[{'id':b['id']}]}
   writes.append(path);return 500,{}
  with self.assertRaises(AssertionError):m.flow(b,api,lambda n,v:None,lambda n:None)
  self.assertEqual(writes,[])
 def test_resume_get_only_refuses_enabled(self):
  b=body();calls=[];p={'id':b['id'],'configuration':m.expected(b),'foreign':{}}
  def api(path,method='GET',v=None):calls.append(method);return 200,{'id':b['id'],'org_id':m.ORG,'desired_intent':'enabled','desired_revision':2}
  with self.assertRaises(AssertionError):m.flow(b,api,lambda n,v:None,lambda n:p,True)
  self.assertEqual(calls,['GET'])
if __name__=='__main__':unittest.main()
