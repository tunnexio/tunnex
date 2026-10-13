import importlib.util,pathlib,unittest
from unittest import mock
s=importlib.util.spec_from_file_location('r',pathlib.Path(__file__).with_name('run.py'));r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
class Tests(unittest.TestCase):
 def test_missing_final_retains_exact_captured_counts_without_gate(self):
  ns={'line':mock.Mock(side_effect=ValueError('private final snapshot failure'))};exec(r.ORCHESTRATE,ns)
  capture={'capture_complete':True,'counts':{'ens4':{'incoming_exact':1}},'stats':{'ens4':{'drops':0}},'stopped_by_request':True}
  result=ns['read_final_preserving_capture'](object(),capture)
  self.assertEqual(result['counts'],capture['counts']);self.assertEqual(result['stats'],capture['stats']);self.assertTrue(result['final_frame_missing']);self.assertFalse(result['stable_gate']);self.assertNotIn('private final',str(result));self.assertEqual(ns['line'].call_args.args[1],15)
if __name__=='__main__':unittest.main()
