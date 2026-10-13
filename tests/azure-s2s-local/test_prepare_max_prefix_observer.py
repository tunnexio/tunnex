import copy
from datetime import datetime,timezone
import importlib.util
from pathlib import Path
import unittest
s=importlib.util.spec_from_file_location('prepare',Path(__file__).with_name('prepare-max-prefix-observer.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class ObserverPreparation(unittest.TestCase):
 def fixture(self):
  ids={k:'11111111-1111-4111-8111-'+str(i).zfill(12) for i,k in enumerate(('org_id','site_id','gateway_id','connection_id'),1)}
  b={**ids,'desired_revision':53,'configuration_revision':2,'maximum_prefixes':1,'namespace_device':4,'namespace_inode':5}
  n={'observed_at':'2026-10-11T01:00:00.1Z','normal_connection':{'id':ids['connection_id'],'profile_id':'azure-active-active-bgp-ipv4-v1','desired_revision':53,'configuration_revision':2,'maximum_prefixes':1,'remote_prefixes':['10.231.0.0/16','10.235.77.0/24'],'desired_intent':'enabled','application_state':'applied','cleanup_state':'not_required'}}
  a={'observed_at':n['observed_at'],'container_id':m.CONTAINER,'image_sha256':m.IMAGE,'node_executable_sha256':m.NODE,'binding':b,'journal_cleanup_desired_revision':53}
  i={'setup':ids,'target':{'id':ids['connection_id']}}
  return n,a,i,datetime(2026,10,11,1,0,1,tzinfo=timezone.utc)
 def test_baseline(self):
  n,a,i,c=self.fixture();self.assertEqual(m.build(n,a,i,'baseline',c)['desired_revision'],53)
 def test_postlimit_no_ready_assumption(self):
  n,a,i,c=self.fixture();n['normal_connection']['application_state']='pending';n['runtime_observation']='not_requested';self.assertEqual(m.build(n,a,i,'post-limit',c)['mode'],'post-limit')
 def test_absence_revision(self):
  n,a,i,c=self.fixture();n['normal_connection'].update(desired_intent='disabled',application_state='not_applied',cleanup_state='retained_guard');self.assertEqual(m.build(n,a,i,'absence',c)['mode'],'absence');a['journal_cleanup_desired_revision']=52
  with self.assertRaises(ValueError):m.build(n,a,i,'absence',c)
 def test_foreign_stale_superseded_refused(self):
  for mutate in (lambda n,a,i:a.update(image_sha256='0'*64),lambda n,a,i:n.update(observed_at='2026-10-11T00:00:00Z'),lambda n,a,i:i['setup'].update(site_id='22222222-2222-4222-8222-222222222222'),lambda n,a,i:a['binding'].update(configuration_revision=3)):
   n,a,i,c=self.fixture();mutate(n,a,i)
   with self.assertRaises(ValueError):m.build(n,a,i,'baseline',c)
if __name__=='__main__':unittest.main()
