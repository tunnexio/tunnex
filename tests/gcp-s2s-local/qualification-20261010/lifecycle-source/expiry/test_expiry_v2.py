import copy,datetime,importlib.util,pathlib,unittest
spec=importlib.util.spec_from_file_location('expiry_v2',pathlib.Path(__file__).with_name('expiry-v2.py'));v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
class Tests(unittest.TestCase):
 def fixture(self):
  b=[{'src_kind':'site','src_site_id':v.SITE,'dst_kind':'resource','dst_resource_id':'r'+str(i),'expires_at':None}for i in range(2)]
  return {'selected':[{'id':'p'+str(i),'body':x}for i,x in enumerate(b)],'resources':[],'policies':[dict(x,id='p'+str(i),enabled=True)for i,x in enumerate(b)]}
 def request(self,baseline,subnets=None,fail_post=False):
  live=copy.deepcopy(baseline['policies']);calls=[]
  if subnets is None:subnets=[{'site_id':v.SITE,'cidr':v.PREFIX,'status':'approved'}]
  def req(path,method='GET',body=None):
   calls.append((path,method,copy.deepcopy(body)))
   if path=='/sites':return [{'id':v.SITE}]
   if path=='/sites/'+v.SITE+'/subnets':return copy.deepcopy(subnets)
   if path=='/resources':return []
   if path=='/policies'and method=='GET':return copy.deepcopy(live)
   if method=='PATCH':
    for p in live:
     if path.endswith('/'+p['id']):p['enabled']=body['enabled'];return copy.deepcopy(p)
   if method=='POST':
    if fail_post:raise TimeoutError()
    # Models actual source-specific unique indexes, regardless of enabled/expiry.
    for p in live:
     if p['src_kind']==body['src_kind']and p['dst_resource_id']==body['dst_resource_id']and (p.get('src_site_id')==body.get('src_site_id')if body['src_kind']=='site'else p.get('src_cidr')==body.get('src_cidr')):raise FileExistsError('unique tuple')
    p=dict(body,id='t'+str(len(live)),enabled=True);live.append(p);return copy.deepcopy(p)
   raise ValueError(path)
  return req,live,calls
 def test_original_site_tuple_conflict_then_distinct_equal_cidr_success(self):
  baseline=self.fixture();req,live,calls=self.request(baseline)
  with self.assertRaises(FileExistsError):req('/policies','POST',dict(baseline['selected'][0]['body'],expires_at='2026-10-10T00:01:30Z'))
  events=[];v.lease(req,baseline,events.append,datetime.datetime(2026,10,10,tzinfo=datetime.timezone.utc))
  self.assertEqual([p['enabled']for p in live[:2]],[False,False]);self.assertEqual(len(live),4)
  for p in live[2:]:self.assertEqual((p['src_kind'],p['src_cidr'],p['src_site_id']),('cidr',v.PREFIX,None))
  self.assertTrue(events[-1]['leased']);v.restore(req,baseline,events.append)
  self.assertEqual(live[:2],baseline['policies']);self.assertEqual(len(live),4)
 def test_source_prefix_drift_refuses_before_any_write(self):
  for rows in [[],[{'site_id':v.SITE,'cidr':'10.70.0.0/16','status':'approved'}],[{'site_id':v.SITE,'cidr':v.PREFIX,'status':'pending'}],[{'site_id':'foreign','cidr':v.PREFIX,'status':'approved'}],[{'site_id':v.SITE,'cidr':v.PREFIX,'status':'approved'}]*2]:
   b=self.fixture();req,live,calls=self.request(b,rows)
   with self.assertRaises(ValueError):v.lease(req,b,lambda _:None,datetime.datetime.now(datetime.timezone.utc))
   self.assertFalse(any(m!='GET'for _,m,_ in calls));self.assertEqual(live,b['policies'])
 def test_existing_disabled_expired_cidr_unique_tuple_refuses_before_writes(self):
  b=self.fixture();b['policies'].append(dict(v.temporary_body(b['selected'][0]['body']),id='old',enabled=False,expires_at='2020-01-01T00:00:00Z'))
  req,live,calls=self.request(b)
  with self.assertRaises(ValueError):v.lease(req,b,lambda _:None,datetime.datetime.now(datetime.timezone.utc))
  self.assertFalse(any(m!='GET'for _,m,_ in calls))
 def test_post_failure_still_restores_both(self):
  b=self.fixture();req,live,calls=self.request(b,fail_post=True);events=[]
  with self.assertRaises(TimeoutError):v.lease(req,b,events.append,datetime.datetime.now(datetime.timezone.utc))
  self.assertEqual(live,b['policies']);self.assertEqual(len([x for x in events if 'restored_original_id'in x]),2)
if __name__=='__main__':unittest.main()
