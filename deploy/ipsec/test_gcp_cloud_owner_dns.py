import copy,datetime,importlib.util,pathlib,unittest
spec=importlib.util.spec_from_file_location('dns',pathlib.Path(__file__).with_name('gcp-cloud-owner-dns.py'));dns=importlib.util.module_from_spec(spec);spec.loader.exec_module(dns)
class DNSPlanTests(unittest.TestCase):
 def manifest(self):return [{'profile':'classic','connection_id':'b79d7eda-920a-40c4-9d05-d8959144ea35','configuration_revision':1}]
 def test_baseline_preserved_and_scoped(self):
  p={'id':'old','legacy_default':False,'name':'baseline','provider_hint':'custom','zone_suffixes':['existing.test'],'endpoints':[{'address':'10.2.0.53','port':53,'transport':'udp'}]};before={'profiles':[p]};original=copy.deepcopy(before);body=dns.build(before,self.manifest());self.assertEqual(before,original);self.assertEqual(body['profiles'][0]['endpoints'],p['endpoints']);self.assertEqual(body['profiles'][1]['ipsec_path']['source_address'],'10.70.0.2');self.assertEqual(body['profiles'][1]['zone_suffixes'],['classic.gcp.s2s-qa.tunnex.app']);self.assertEqual(len(body['profiles'][1]['endpoints']),2)
 def test_replay_legacy_and_bad_revision_refused(self):
  body=dns.build(None,self.manifest())
  for before in ({'profiles':body['profiles']},{'profiles':[{'legacy_default':True}]}):
   with self.assertRaises(ValueError):dns.build(before,self.manifest())
  m=self.manifest();m[0]['configuration_revision']=0
  with self.assertRaises(ValueError):dns.build(None,m)
 def test_actual_revision_and_freshness_gate(self):
  now=datetime.datetime.now(datetime.timezone.utc);m=self.manifest()[0];c={'site_id':dns.SITE,'gateway_node_id':dns.NODE,'desired_intent':'enabled','application_state':'applied','deleted_at':None};cfg={'profile_id':'gcp-classic-static-ipv4-v1','configuration_revision':1};s={'observed_at':now.isoformat(),'tunnels':[{'status':'up'}]};e={'eligible':True,'gcp_classic':{'eligible':True}};dns.verify_live(m,c,cfg,s,e,now)
  for changed in ({'configuration_revision':2},{'profile_id':'gcp-ha-bgp-ipv4-v1'}):
   with self.assertRaises(ValueError):dns.verify_live(m,c,dict(cfg,**changed),s,e,now)
  for status in ({'observed_at':(now-datetime.timedelta(seconds=91)).isoformat(),'tunnels':[{'status':'up'}]},{'observed_at':now.isoformat(),'tunnels':[{'status':'unknown'}]}):
   with self.assertRaises(ValueError):dns.verify_live(m,c,cfg,status,e,now)
if __name__=='__main__':unittest.main()
