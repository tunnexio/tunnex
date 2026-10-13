import importlib.util,pathlib,unittest
p=pathlib.Path(__file__).with_name('customer-api-role-negative-matrix.py');spec=importlib.util.spec_from_file_location('matrix',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
 def test_all_write_targets_are_impossible_and_invalid(self):
  for role in m.PRINCIPALS:
   for name,method,path,body,expected in m.cases(role):
    self.assertTrue(m.safe_request(path,method,body));self.assertFalse(any(x in path for x in m.LIVE));self.assertIn(expected,[403,404]);self.assertIn(body,[{},None])
 def test_valid_body_or_live_write_rejected(self):
  for role in m.PRINCIPALS:
   for _,method,path,body,_ in m.cases(role):
    self.assertFalse(m.safe_request(path,method,{'intent':'enabled'}))
    for live in m.LIVE:self.assertFalse(m.safe_request(path.replace(m.ABSENT,live),method,body))if m.ABSENT in path else None
 def test_crossorg_is_distinct_and_reads_only(self):
  self.assertNotEqual(m.ORG,m.FOREIGN)
  for row in m.cases('admin'):self.assertIn(m.FOREIGN,row[2]);self.assertEqual(row[-1],404)
 def test_baseline_changed_configuration_detected(self):
  self.assertNotEqual(m.digest({'revision':1}),m.digest({'revision':2}));self.assertEqual(m.digest({'a':1,'b':2}),m.digest({'b':2,'a':1}))
if __name__=='__main__':unittest.main()
