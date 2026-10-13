import copy,importlib.util,pathlib,unittest,uuid
p=pathlib.Path(__file__).with_name('customer-api-disabled-fixture.py');s=importlib.util.spec_from_file_location('f',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Disabled(unittest.TestCase):
 def fixture(self):
  id=str(uuid.uuid4());site=str(uuid.uuid4());gw=str(uuid.uuid4());body={'id':id,'name':'Customer API disabled fixture test','site_id':site,'gateway_node_id':gw,'tunnel_ids':[str(uuid.uuid4()),str(uuid.uuid4())],'configuration':{'mode':'ipv4-static','local_prefixes':['10.84.2.0/24'],'remote_prefixes':['10.87.1.0/24'],'tunnels':[{'psk':'Synthetic.fixtureSAFE123','outside_address':'8.8.8.8'},{'psk':'Synthetic.fixtureSAFE456','outside_address':'1.1.1.1'}]}};return {'body':body,'owned_config_source_sha256':'a'*64,'expected_org':m.ORG,'expected_site':site,'expected_gateway':gw}
 def fake(self,fixture,unknown=False):
  id=fixture['body']['id'];provider={**{k:fixture['body'][k]for k in ['id','name','site_id','gateway_node_id']},'org_id':m.ORG,'desired_intent':'disabled','desired_revision':1};created=False;calls=[]
  def api(path,method='GET',body=None,headers={}):
   nonlocal created;calls.append((path,method,copy.deepcopy(body),headers))
   if path.endswith('configuration-check'):
    valid=body==fixture['body']['configuration'];return (200,{'valid':True},{})if valid else(400,{'code':'invalid'}, {})
   if '?limit=100'in path:return 200,{'items':[provider]if created else[],'next_cursor':None},{}
   if path.endswith('/configuration'):return 200,m.public_configuration(fixture['body']),{}
   if method=='GET':return 200,provider,{}
   if path.endswith('/intent'):return (409 if headers['If-Match']=='"2"'else 400),{'code':'conflict'},{}
   if method=='POST':
    if created:return 409,{'code':'conflict'},{}
    created=True
    if unknown:raise TimeoutError('unknown create')
    return 201,provider,{'ETag':'"1"'}
   raise AssertionError(path)
  return api,calls
 def test_complete_disabled_path_no_enable_psk_receipts(self):
  f=self.fixture();api,calls=self.fake(f);saved={}
  def save(n,v):self.assertNotIn(n,saved);saved[n]=v
  m.execute(f,api,save,lambda n:saved[n]);self.assertTrue(saved['result.json']['passed']);self.assertNotIn('Synthetic.fixture',str(saved));self.assertTrue(all(not(body and body.get('intent')=='enabled')for _,_,body,_ in calls))
 def test_unknown_create_get_only_resume(self):
  f=self.fixture();api,calls=self.fake(f,True);saved={}
  def save(n,v):self.assertNotIn(n,saved);saved[n]=v
  with self.assertRaises(TimeoutError):m.execute(f,api,save,lambda n:saved[n])
  start=len(calls);m.execute(f,api,save,lambda n:saved[n],True);self.assertTrue(saved['create-reconciled.json']['get_only']);self.assertTrue(all(method=='GET'for _,method,_,_ in calls[start:]))
 def test_live_identity_or_binding_refused_before_requests(self):
  f=self.fixture();f['body']['id']=next(iter(m.LIVE))
  with self.assertRaises(AssertionError):m.binding(f)
  f=self.fixture();f['expected_gateway']=str(uuid.uuid4())
  with self.assertRaises(AssertionError):m.binding(f)
 def test_frozen_configuration_not_mutated(self):
  f=self.fixture();before=copy.deepcopy(f);m.negatives(f['body']['configuration']);m.public_configuration(f['body']);self.assertEqual(f,before)
if __name__=='__main__':unittest.main()
