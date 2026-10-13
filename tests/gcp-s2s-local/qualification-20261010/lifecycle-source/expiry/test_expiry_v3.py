import datetime,importlib.util,pathlib,unittest
spec=importlib.util.spec_from_file_location('expiry_v3',pathlib.Path(__file__).with_name('expiry-v3.py'));v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
class Tests(unittest.TestCase):
 def test_actual_go_five_digit_equals_requested_six_without_rounding(self):
  a={'expires_at':'2026-10-10T17:01:08.39779Z'};b={'expires_at':'2026-10-10T17:01:08.397790Z'}
  self.assertEqual(v.sem(a),v.sem(b));self.assertEqual(v.parse_rfc3339(a['expires_at']).microsecond,397790)
 def test_fraction_lengths_and_lossless_extra_zero_precision(self):
  for digits in ['1','12','123','1234','12345','123456','1234560','12345600','123456000']:
   self.assertEqual(v.parse_rfc3339('2026-10-10T00:00:00.'+digits+'Z').microsecond,int((digits[:6]).ljust(6,'0')))
  self.assertEqual(v.parse_rfc3339('2026-10-10T00:00:00Z').microsecond,0)
 def test_utc_and_offset_equivalence(self):
  self.assertEqual(v.parse_rfc3339('2026-10-10T17:01:08.39779Z'),v.parse_rfc3339('2026-10-10T22:31:08.397790+05:30'))
 def test_malformed_or_lossy_precision_refuses(self):
  for value in [None,'2026-10-10T17:01:08','2026-10-10 17:01:08Z','2026-10-10T17:01:08.Z','2026-10-10T17:01:08.1234561Z','2026-10-10T17:01:08.123456001Z','2026-10-10T17:01:08+05:60','2026-10-10T17:01:08+24:00','2026-13-10T17:01:08Z','2026-10-10T17:01:60Z','2026-10-10T17:01:08.1234560000Z','2026-10-10T17:01:08Zjunk']:
   with self.assertRaises(ValueError):v.parse_rfc3339(value)
 def test_cleanup_deadline_order_does_not_reverse(self):
  now=v.parse_rfc3339('2026-10-10T17:01:08.39779Z');calls=[]
  body={'src_kind':'cidr','src_cidr':v.PREFIX,'dst_kind':'resource','dst_resource_id':'r','expires_at':'2026-10-10T17:01:08.397791Z'}
  event={'created_temporary_id':'temp','body':body}
  def req(path,method='GET',body=None):calls.append(method);return [dict(event['body'],id='temp')]if method=='GET'else None
  with self.assertRaises(ValueError):v.cleanup(req,[event],lambda _:None,now)
  self.assertNotIn('DELETE',calls);calls.clear()
  body['expires_at']='2026-10-10T17:01:08.397789Z';v.cleanup(req,[event],lambda _:None,now);self.assertIn('DELETE',calls)
# Re-run the unchanged CIDR-equivalence, prewrite refusal and restoration cases
# against this version, rather than granting parser-only qualification.
spec2=importlib.util.spec_from_file_location('expiry_v2_cases',pathlib.Path(__file__).with_name('test_expiry_v2.py'))
previous=importlib.util.module_from_spec(spec2);spec2.loader.exec_module(previous);previous.v=v
PreviousAuthorityBoundaryTests=previous.Tests
if __name__=='__main__':unittest.main()
