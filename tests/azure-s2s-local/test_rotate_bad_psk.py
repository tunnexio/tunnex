import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('rotate_fixture',Path(__file__).with_name('rotate-bad-psk.py'))
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)


class RotationQualification(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.root.chmod(0o700);self.state=self.root/'state.json'
  self.setup={'org_id':'aaaaaaaa-0000-4000-8000-000000000001','site_id':'bbbbbbbb-0000-4000-8000-000000000001','gateway_id':'cccccccc-0000-4000-8000-000000000001'}
  self.allocation={'id':h.CONNECTION,'tunnel_ids':['dddddddd-0000-4000-8000-000000000001','dddddddd-0000-4000-8000-000000000002']}
  self.connection={'id':h.CONNECTION,'org_id':self.setup['org_id'],'site_id':self.setup['site_id'],'gateway_node_id':self.setup['gateway_id'],'desired_revision':30,'desired_intent':'disabled','application_state':'not_applied','cleanup_state':'retained_guard'}
  self.config={'profile_id':h.PROFILE,'configuration_revision':1,'configuration':{'mode':'ipv4-bgp','tunnels':[{},{}],'azure':{},'local_prefixes':['10.233.10.0/24'],'remote_prefixes':['10.231.0.0/16']}}
  self.posts=[];self.fail=False;self.changed=False;self.gets=0
  outer=self
  class Client:
   def call(self,method,path,body=None):
    if method=='GET' and path.endswith('/configuration'):return copy.deepcopy(outer.config)
    if method=='GET':
     outer.gets+=1
     if outer.changed and outer.gets==2:outer.connection['desired_revision']+=1
     return copy.deepcopy(outer.connection)
    if method=='POST':
     saved=json.loads(outer.state.read_text());assert saved['restore_psk']=='owned-good-key-2026';assert saved['stage'].endswith('_sent')
     outer.posts.append(copy.deepcopy(body))
     if outer.fail:raise h.activation.APIError()
     outer.connection['desired_revision']+=1;return copy.deepcopy(outer.connection)
    raise AssertionError('unexpected request')
  self.client=Client()
 def tearDown(self):self.temp.cleanup()
 def operate(self,phase):return h.operate(phase,self.client,'/owned',self.setup,self.allocation,self.state,'owned-good-key-2026','owned-bad-key-2026')
 def test_rollback_persisted_before_atomic_common_key_rotate_and_restore(self):
  result=self.operate('bad');self.assertEqual(result['connection']['desired_revision'],31)
  self.assertEqual(self.posts[0]['expected_desired_revision'],30)
  self.assertEqual([t['tunnel_id'] for t in self.posts[0]['tunnels']],self.allocation['tunnel_ids'])
  self.assertEqual({t['psk'] for t in self.posts[0]['tunnels']},{'owned-bad-key-2026'})
  restored=self.operate('restore');self.assertEqual(restored['connection']['desired_revision'],32)
  self.assertEqual({t['psk'] for t in self.posts[1]['tunnels']},{'owned-good-key-2026'})
  self.assertNotIn('owned-good-key',json.dumps(restored));self.assertNotIn('owned-bad-key',json.dumps(result))
 def test_stale_fresh_get_reservation_prevents_post(self):
  self.changed=True
  with self.assertRaises(ValueError):self.operate('bad')
  self.assertEqual(self.posts,[]);self.assertTrue(self.state.exists())
  with self.assertRaises(ValueError):self.operate('bad')
  self.assertEqual(self.posts,[])
 def test_ambiguous_post_never_repeated_and_reconcile_does_not_acknowledge(self):
  self.fail=True
  with self.assertRaises(ValueError):self.operate('bad')
  self.assertEqual(len(self.posts),1)
  with self.assertRaises(ValueError):self.operate('bad')
  self.connection['desired_revision']+=1
  result=self.operate('reconcile');self.assertEqual(result['classification'],'successor_observed_unattributed');self.assertTrue(result['requires_review'])
  with self.assertRaises(ValueError):self.operate('restore')
  self.assertEqual(len(self.posts),1)
 def test_enabled_pending_or_wrong_binding_refuses(self):
  for key,value in [('desired_intent','enabled'),('cleanup_state','pending'),('site_id','other')]:
   previous=self.connection[key];self.connection[key]=value
   with self.assertRaises(ValueError):self.operate('bad')
   self.connection[key]=previous
  self.assertEqual(self.posts,[])
 def test_saved_configuration_and_current_tunnel_identity_are_bound(self):
  self.operate('bad');self.config['configuration']['remote_prefixes']=['10.250.0.0/24']
  with self.assertRaises(ValueError):self.operate('restore')
  self.assertEqual(len(self.posts),1)
 def test_private_metadata_and_key_bounds(self):
  path=self.root/'key';path.write_text('owned-good-key-2026\n');path.chmod(0o600);self.assertEqual(h.key(path),'owned-good-key-2026')
  for value in ['short','x'*65,'contains\tcontrol']:
   path.write_text(value)
   with self.assertRaises(ValueError):h.key(path)
  path.chmod(0o644)
  with self.assertRaises(ValueError):h.key(path)
  link=self.root/'link';link.symlink_to(path)
  with self.assertRaises(ValueError):h.read(link)


if __name__=='__main__':unittest.main()
