import unittest
import cas
class Tests(unittest.TestCase):
 def test_exact_keyfree_classic_and_advisory_overlap_refusal(self):
  args=('ce137d02-68d6-4d4b-a347-b1d56ffccf53','ac3deba0-573f-41cf-aefc-6f112220a984',[],[],['10.70.0.0/24','10.80.0.0/24','10.81.0.0/24'],True,{'enabled':True},{'eligible':True})
  body=cas.create_plan(*args);self.assertEqual(body['configuration']['remote_prefixes'],['10.82.0.0/24']);self.assertNotIn('psk',body['configuration']['tunnels'][0]);self.assertEqual(len(body['tunnel_ids']),1)
  with self.assertRaises(ValueError):cas.range_preflight(['10.82.0.128/25'],True)
  with self.assertRaises(ValueError):cas.range_preflight([],False)
 def test_inert_owned_peer_distinct_from_active_classic(self):
  self.assertEqual(cas.TEMPLATE['configuration']['tunnels'][0]['outside_address'],'34.131.121.30')
  self.assertNotEqual(cas.TEMPLATE['configuration']['tunnels'][0]['outside_address'],'34.131.214.202')
  self.assertEqual(cas.TEMPLATE['configuration']['remote_prefixes'],['10.82.0.0/24'])
 def test_private_body_clones_keyfree_and_stale_revision_not_replaced(self):
  body=cas.private_create(cas.TEMPLATE,'synthetic-test-only-key')
  self.assertNotIn('psk',cas.TEMPLATE['configuration']['tunnels'][0]);self.assertIn('psk',body['configuration']['tunnels'][0])
  self.assertEqual(cas.rotation_body('ac3deba0-573f-41cf-aefc-6f112220a984','synthetic-test-only-key')['expected_desired_revision'],1)
 def test_cleanup_refuses_active_and_wrongremote(self):
  connection={'id':'ce137d02-68d6-4d4b-a347-b1d56ffccf53','name':cas.NAME,'site_id':cas.SITE,'gateway_node_id':cas.NODE,'desired_intent':'disabled','cleanup_state':'not_required','application_state':'not_applied','desired_revision':2};configuration={'profile_id':'gcp-classic-static-ipv4-v1','configuration':{'remote_prefixes':['10.82.0.0/24']}}
  self.assertEqual(cas.delete_plan(connection,configuration),{'If-Match':'"2"'})
  connection['id']=next(iter(cas.ACTIVE))
  with self.assertRaises(ValueError):cas.delete_plan(connection,configuration)
if __name__=='__main__':unittest.main()
