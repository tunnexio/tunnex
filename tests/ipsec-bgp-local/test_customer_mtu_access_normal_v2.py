import importlib.util,pathlib,copy,unittest
p=pathlib.Path(__file__).with_name('customer-mtu-access-normal-v2.py');spec=importlib.util.spec_from_file_location('mtu',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Boundary(unittest.TestCase):
 def setUp(self):
  self.r=dict(m.BODY,id='resource');self.g={'id':'grant','src_kind':'cidr','src_cidr':m.SOURCE,'dst_kind':'resource','dst_resource_id':'resource'}
  self.provider={'id':m.PROVIDER,'site_id':m.SITE,'desired_intent':'enabled','desired_revision':2,'local_prefixes':['10.84.2.0/24'],'remote_prefixes':['10.85.0.0/16']}
  self.rules=[];self.resources=[copy.deepcopy(self.r)];self.mutations=[];self.files={m.PREFIX+'resource-result.json':self.r,m.PREFIX+'grant-result.json':self.g,m.PREFIX+'withdraw-result.json':{'id':'grant','absent':True}};self.failed_delete=False
 def save(self,name,value):
  assert name not in self.files,'Unknown outcome must not replay';self.files[name]=copy.deepcopy(value)
 def api(self,path,method='GET',body=None):
  if method=='GET':
   if path.endswith('/policies'):return copy.deepcopy(self.rules)
   if path.endswith('/resources'):return copy.deepcopy(self.resources)
   if path.endswith('/zero-trust-mode'):return {'mode':'enforcing'}
   return copy.deepcopy(self.provider)
  self.mutations.append((path,method,copy.deepcopy(body)))
  if method=='POST':self.rules.append(dict(body,id='grant'));return copy.deepcopy(self.rules[-1])
  if path.endswith('/policies/grant'):
   if not self.failed_delete:self.rules=[v for v in self.rules if v['id']!='grant']
  elif path.endswith('/resources/resource'):self.resources=[]
 def run_action(self,a):m.execute(a,self.api,self.save,self.files.__getitem__)
 def test_exact_cidr_without_source_id(self):
  self.files.pop(m.PREFIX+'grant-result.json');self.run_action('grant');body=self.mutations[0][2];self.assertEqual(body,{'src_kind':'cidr','src_cidr':'10.84.2.10/32','dst_kind':'resource','dst_resource_id':'resource'});self.assertNotIn('src_site_id',body);self.assertNotIn('SourceID',body)
 def test_failed_withdraw_has_no_success_and_no_replay(self):
  self.rules=[self.g];self.failed_delete=True;self.files.pop(m.PREFIX+'withdraw-result.json')
  with self.assertRaises(AssertionError):self.run_action('withdraw')
  self.assertNotIn(m.PREFIX+'withdraw-preservation.json',self.files);self.assertNotIn(m.PREFIX+'withdraw-result.json',self.files)
  with self.assertRaises(AssertionError):self.run_action('withdraw')
  self.assertEqual(len(self.mutations),1)
 def test_foreign_resource_replacement_refused_before_write(self):
  self.resources[0]['cidr']='10.85.2.10/32'
  with self.assertRaises(AssertionError):self.run_action('cleanup-resource')
  self.assertEqual(self.mutations,[])
 def test_foreign_reference_refuses_cleanup(self):
  self.rules=[{'id':'foreign','dst_resource_id':'resource'}]
  with self.assertRaises(AssertionError):self.run_action('cleanup-resource')
  self.assertEqual(self.mutations,[])
 def test_cleanup_exact_resource_preserves_foreign(self):
  other={'id':'foreign','name':'other'};self.resources.append(other)
  original=self.api
  def api(path,method='GET',body=None):
   result=original(path,method,body)
   if method=='DELETE':self.resources=[other]
   return result
  self.api=api;self.run_action('cleanup-resource');self.assertEqual(self.mutations[0][:2],('/api/v1/organizations/'+m.ORG+'/resources/resource','DELETE'));self.assertEqual(self.resources,[other])
 def test_no_cleanup_without_verified_withdrawal(self):
  self.files[m.PREFIX+'withdraw-result.json']['absent']=False
  with self.assertRaises(AssertionError):self.run_action('cleanup-resource')
  self.assertEqual(self.mutations,[])
 def test_foreign_grant_replacement_refuses_withdraw(self):
  self.rules=[dict(self.g,src_cidr='10.84.2.11/32')]
  with self.assertRaises(AssertionError):self.run_action('withdraw')
  self.assertEqual(self.mutations,[])
if __name__=='__main__':unittest.main()
