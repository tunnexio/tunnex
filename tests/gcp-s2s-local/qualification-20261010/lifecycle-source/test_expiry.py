import copy,datetime,json,unittest
import expiry
class Tests(unittest.TestCase):
 def test_actual_frozen_baseline_and_broad_overlap_negative(self):
  historic=json.loads(expiry.HISTORICAL.read_text());templates=json.loads(expiry.TEMPLATES.read_text())['items']
  resources=copy.deepcopy(historic['resources']);policies=copy.deepcopy(historic['policies'])
  expiry.historical_preserved(resources,policies,historic,templates)
  self.assertEqual({x['id']for x in expiry.audit(resources,policies,templates)},{v[1]for v in expiry.OWNED.values()})
  resources[0]['cidr']='10.81.0.0/24';resources[0]['port_low']=1;resources[0]['port_high']=65535
  policies[0]['dst_resource_id']=resources[0]['id'];policies[0]['enabled']=True
  with self.assertRaises(ValueError):expiry.audit(resources,policies,templates)
  with self.assertRaises(ValueError):expiry.historical_preserved(resources,policies,historic,templates)
 def fixture(self):
  bodies=[{'src_kind':'site','src_site_id':'site','dst_kind':'resource','dst_resource_id':'r'+str(i),'expires_at':None}for i in range(2)]
  policies=[dict(b,id='p'+str(i),enabled=True)for i,b in enumerate(bodies)]
  return {'selected':[{'id':'p'+str(i),'body':b}for i,b in enumerate(bodies)],'resources':[],'policies':policies}
 def test_failure_restores_both_and_preserves_originals(self):
  baseline=self.fixture();live=copy.deepcopy(baseline['policies']);calls=[];events=[]
  def req(path,method='GET',body=None):
   calls.append((path,method,body))
   if path=='/resources':return []
   if path=='/policies'and method=='GET':return copy.deepcopy(live)
   if method=='PATCH':
    for p in live:
     if path.endswith('/'+p['id']):p['enabled']=body['enabled'];return copy.deepcopy(p)
   if method=='POST':raise TimeoutError()
   raise ValueError()
  with self.assertRaises(TimeoutError):expiry.lease(req,baseline,events.append,datetime.datetime.now(datetime.timezone.utc))
  self.assertTrue(all(p['enabled']for p in live));self.assertEqual(len([e for e in events if 'restored_original_id'in e]),2)
 def test_restore_semantic_drift_refuses_but_attempts_other(self):
  baseline=self.fixture();live=copy.deepcopy(baseline['policies']);live[0]['dst_resource_id']='foreign';live[1]['enabled']=False;events=[]
  def req(path,method='GET',body=None):
   if method=='PATCH':live[1]['enabled']=True;return live[1]
   return copy.deepcopy(live)
  with self.assertRaises(ValueError):expiry.restore(req,baseline,events.append)
  self.assertTrue(live[1]['enabled']);self.assertEqual(live[0]['dst_resource_id'],'foreign')
 def test_expired_only_cleanup(self):
  body={'expires_at':'2026-10-10T00:00:00Z','src_kind':'site','dst_kind':'resource','dst_resource_id':'r'};now=datetime.datetime(2026,10,10,tzinfo=datetime.timezone.utc);calls=[]
  def req(path,method='GET',body=None):
   calls.append(method);return [dict(event['body'],id='temp')]if method=='GET'else None
  event={'created_temporary_id':'temp','body':body}
  expiry.cleanup(req,[event],lambda v:None,now);self.assertIn('DELETE',calls)
  event['body']['expires_at']='2026-10-10T00:01:00Z';calls.clear()
  with self.assertRaises(ValueError):expiry.cleanup(req,[event],lambda v:None,now)
  self.assertNotIn('DELETE',calls)
if __name__=='__main__':unittest.main()
