import importlib.util,pathlib,unittest,uuid
s=importlib.util.spec_from_file_location('m',pathlib.Path(__file__).with_name('customer-api-role-readonly.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Roles(unittest.TestCase):
 def run_role(self,role,mixed=False,wrong=False):
  org,user,provider,foreign=[str(uuid.uuid4())for _ in range(4)];calls=[]
  def api(path,method='GET',body=None):
   calls.append((path,method,body))
   if path.endswith('/auth/me'):return 200,{'id':user,'email_verified':not wrong}
   if path.endswith('/members'):return 200,[{'user_id':user,'role':role,'roles':[role,'admin']if mixed else[role],'status':'active'}]
   if path.endswith('configuration-check'):return (400 if m.ROLES[role]else 403),{'code':'invalid'if m.ROLES[role]else'forbidden'}
   if foreign in path:return 404,{'code':'org_not_found'}
   return 200,{'id':provider}
  result=m.qualify(api,org,provider,user,role,foreign);return result,calls
 def test_role_table_reads_and_validation_only(self):
  for role in m.ROLES:
   r,calls=self.run_role(role);self.assertTrue(r['passed']);self.assertTrue(r['foreign_org_404']);self.assertTrue(all(method=='GET'or(path.endswith('configuration-check')and body=={})for path,method,body in calls))
 def test_mixed_privileged_role_cannot_count_as_member(self):
  with self.assertRaises(AssertionError):self.run_role('member',True)
 def test_unverified_user_refused(self):
  with self.assertRaises(AssertionError):self.run_role('owner',wrong=True)
if __name__=='__main__':unittest.main()
