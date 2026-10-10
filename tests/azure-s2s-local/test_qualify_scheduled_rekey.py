import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock,patch
spec=importlib.util.spec_from_file_location('scheduled',Path(__file__).with_name('qualify-scheduled-rekey.py'))
q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)

class SchedulerTests(unittest.TestCase):
 def test_only_parent_timer_changes_for_all_cardinalities(self):
  for count in (1,2):
   original=('    rekey_time = 28800s\n    children {\n      local_ts = 0.0.0.0/0\n      rekey_time = 3000s\n      life_time = 3600s\n    }\n')*count
   accelerated=q.accelerated(original,count)
   normalized=accelerated.replace('rekey_time = 120s','rekey_time = 28800s').replace('rekey_time = 150s','rekey_time = 28800s').replace('\n    rand_time = 0s\n    over_time = 2880s','')
   self.assertEqual(normalized,original)
 def test_unexpected_timers_refused(self):
  with self.assertRaises(ValueError):q.accelerated('rekey_time = 120s',1)
 def test_original_socket_identity_survives_response_timeout(self):
  connection=Mock();connection.sock.getsockname.return_value=('10.233.10.2',43123)
  def fail():
   connection.sock=None
   raise TimeoutError('private endpoint must not appear')
  connection.getresponse.side_effect=fail
  result=q.http_attempt(connection,43123)
  self.assertFalse(result['success']);self.assertEqual(result['local_port_before_attempt'],43123)
  self.assertTrue(result['original_socket_present']);self.assertNotIn('private endpoint',str(result))
  second=q.http_attempt(connection,43123)
  self.assertEqual(second['original_local_port'],43123);self.assertFalse(second['original_socket_present'])
  self.assertEqual(connection.request.call_count,1)
 def test_normal_authority_is_exact_and_read_only(self):
  setup={'org_id':'org','site_id':'site','gateway_id':'gateway'}
  connection={'id':'connection','org_id':'org','site_id':'site','gateway_node_id':'gateway','desired_intent':'enabled','application_state':'applied','deleted_at':None,'finalized_at':None,'desired_revision':34}
  config={'configuration_revision':1,'profile_id':'azure-active-standby-bgp-ipv4-v1','configuration':{'azure':{'ike_version':2}}}
  client=Mock();client.call.side_effect=[connection,config]
  m={'accounts':'accounts','setup':'setup','connection':'connection'}
  with patch.object(q.proof,'private_read',side_effect=[{'owner':{'email':'browser-owner@azure-s2s.local','password':'PRIVATE'}},setup]),patch.object(q.lab,'Client',return_value=client):
   projection=q.api_authority(m)
  self.assertEqual(projection['desired'],34)
  self.assertEqual([call.args[0] for call in client.call.call_args_list],['GET','GET'])
  client.call.reset_mock();client.call.side_effect=[connection,config];m['authority']=dict(projection,desired=33)
  with patch.object(q.proof,'private_read',side_effect=[{'owner':{'email':'browser-owner@azure-s2s.local'}},setup]),patch.object(q.lab,'Client',return_value=client),self.assertRaises(ValueError):q.api_authority(m)
 def test_pending_authority_refuses_before_mutation(self):
  client=Mock();client.call.side_effect=[{'id':'connection','org_id':'org','site_id':'site','gateway_node_id':'gateway','desired_intent':'enabled','application_state':'pending'},{}]
  with patch.object(q.proof,'private_read',side_effect=[{'owner':{'email':'browser-owner@azure-s2s.local'}},{'org_id':'org','site_id':'site','gateway_id':'gateway'}]),patch.object(q.lab,'Client',return_value=client),self.assertRaises(ValueError):q.api_authority({'accounts':'accounts','setup':'setup','connection':'connection'})
  self.assertEqual([call.args[0] for call in client.call.call_args_list],['GET','GET'])
 def test_no_socket_does_not_reconnect(self):
  connection=Mock();connection.sock=None
  self.assertFalse(q.http_attempt(connection,43123)['success']);connection.connect.assert_not_called();connection.request.assert_not_called()

if __name__=='__main__':unittest.main()
