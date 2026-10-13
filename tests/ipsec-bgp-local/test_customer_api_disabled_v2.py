import copy,importlib.util,pathlib,unittest
ROOT=pathlib.Path(__file__).parent
def module(name,file):
 s=importlib.util.spec_from_file_location(name,ROOT/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
g=module('generator','customer-api-disabled-fixture-generator-v2.py');e=module('executor','customer-api-disabled-fixture-v2.py')
class Tests(unittest.TestCase):
 def fixture(self,profile='vgw-bgp'):
  seed={'provider_id':g.SOURCE_PROVIDER,'org_id':g.ORG,'site_id':g.SITE,'gateway_node_id':g.GW,'public_configuration':g.EXPECTED}
  return g.generate(seed,profile,'a'*64)
 def test_owned_outside_pairs_and_fresh_ranges(self):
  for profile in g.PROFILES:
   f=self.fixture(profile);c=f['body']['configuration'];self.assertEqual([t['outside_address']for t in c['tunnels']],['3.67.173.125','52.58.98.231']if profile.startswith('vgw')else['3.65.241.160','63.189.108.24']);self.assertTrue(all(t['inside_cidr'].startswith('169.254.125.')for t in c['tunnels']));self.assertEqual(c['local_prefixes'],['10.84.2.0/24']);e.binding(f)
 def run_delete(self,changed=False,resume=False):
  f=self.fixture();b=f['body'];writes=[];saved={'result.json':{'passed':True,'id':b['id'],'provider_disabled':True,'enabled_or_rotated':False}}
  finalized=False
  def api(path,method='GET',body=None,extra={}):
   nonlocal finalized
   if method=='DELETE':writes.append((path,extra));finalized=True;return 200,{},{}
   if path.endswith('?limit=100'):return 200,{'items':[],'next_cursor':None},{}
   if path.endswith('/configuration'):return 200,({'configuration_revision':1,'profile_id':'aws-bgp-ipv4-v1'}if finalized else e.public_configuration(b)),{}
   return 200,{'id':b['id'],'org_id':g.ORG,'desired_intent':'deleted'if finalized else'enabled'if changed else'disabled','desired_revision':2 if finalized else 1,'site_id':None if finalized else g.SITE,'gateway_node_id':None if finalized else g.GW,'deleted_at':'now'if finalized else None,'finalized_at':'now'if finalized else None},{}
  def save(n,v):self.assertNotIn(n,saved);saved[n]=v
  if changed:
   with self.assertRaises(AssertionError):e.delete_disabled(f,api,save,saved.__getitem__)
   self.assertEqual(writes,[])
  else:
   e.delete_disabled(f,api,save,saved.__getitem__);self.assertEqual(len(writes),1);self.assertEqual(writes[0][1],{'If-Match':'"1"'});self.assertTrue(saved['delete-finalized.json']['finalized'])
 def test_exact_never_enabled_delete(self):self.run_delete()
 def test_enabled_or_replaced_fixture_refuses_before_delete(self):self.run_delete(changed=True)
 def test_seed_foreign_refuses(self):
  with self.assertRaises(AssertionError):g.generate({},'vgw-static','a'*64)
if __name__=='__main__':unittest.main()
