import importlib.util,pathlib,unittest,uuid
s=importlib.util.spec_from_file_location('m',pathlib.Path(__file__).with_name('customer-normal-principals.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Principals(unittest.TestCase):
 def fixture(self,smtp=False,unknown=False):
  id=str(uuid.uuid4());email='tunnex-customer-member-'+uuid.uuid4().hex+'@example.test';saved={};calls=[];accepted=False
  def api(path,method='GET',body=None):
   nonlocal accepted;calls.append((path,method))
   if path.endswith('email-settings'):return 200,{'enabled':smtp,'revision':0,'source':'installer'}
   if path.endswith('/members'):return 200,[{'user_id':id,'email':email,'role':'member','roles':['member'],'status':'active'}]if accepted else[]
   if path.endswith('/invitations'):
    if unknown:raise TimeoutError('unknown invite')
    return 202,{'delivered':False,'invite_token':'private-test-token'}
   if path.endswith('/accept'):accepted=True;return 200,{'message':'accepted'}
   raise AssertionError(path)
  def save(n,v):self.assertNotIn(n,saved);saved[n]=v
  def login(e,p):return 200,{'id':id,'email':e,'email_verified':True,'cp_admin':False}
  return email,api,save,login,saved,calls
 def test_normal_invite_accept_login_private_token(self):
  e,api,save,login,saved,calls=self.fixture();r=m.create('member',e,'private-password',api,api,login,save);self.assertTrue(r['passed']);self.assertIn('invite-private-result.json',saved);self.assertNotIn('private-test-token',str(r));self.assertNotIn('private-password',str(saved));self.assertTrue(all(method=='GET'or path.endswith('/invitations')or path.endswith('/accept')for path,method in calls))
 def test_enabled_smtp_refuses_before_invitation(self):
  e,api,save,login,saved,calls=self.fixture(True)
  with self.assertRaises(AssertionError):m.create('member',e,'pw',api,api,login,save)
  self.assertFalse(any(method=='POST'for _,method in calls))
 def test_unknown_invite_retains_pending_no_replay(self):
  e,api,save,login,saved,calls=self.fixture(unknown=True)
  with self.assertRaises(TimeoutError):m.create('member',e,'pw',api,api,login,save)
  self.assertIn('invite-pending.json',saved);self.assertEqual(sum(method=='POST'for _,method in calls),1);self.assertNotIn('accept-pending.json',saved)
if __name__=='__main__':unittest.main()
