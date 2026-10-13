"""Pure source qualification; never invokes transport or native functions."""
import unittest,pathlib,ast,hashlib
D=pathlib.Path(__file__).parent
R=pathlib.Path('/private/tmp/gcp-native-reader-fixed-stage-v7-diagnostic-20261012/native-fqdn-binding.diagnostic-v1.remote.py')
P=pathlib.Path('/private/tmp/provider-selected-5121-source-prep-20261012-v1/actual-measured-callbacks-v1/native-fqdn-binding.bound-v1.remote.py')
class DiagnosticTests(unittest.TestCase):
 def mapping(self):
  tree=ast.parse(R.read_text());return ast.literal_eval(tree.body[0].value)
 def test_exact_original_predicates_and_calls_preserved(self):
  s=R.read_text().split('\n',1)[1]
  s=s.replace(",'native_refusal_stage':NATIVE_REFUSAL_STAGES.get(str(e),'native_unclassified')",'')
  self.assertEqual(s,P.read_text())
 def test_closed_negative_vocab_and_unknown_suppression(self):
  m=self.mapping();self.assertEqual(len(m),38);self.assertEqual(len(set(m.values())),38)
  self.assertEqual(m['recovery exact SA census'],'native_check_32')
  self.assertEqual(m.get('PRIVATE_RAW_ERROR_VALUE','native_unclassified'),'native_unclassified')
  self.assertTrue(all(v.startswith('native_check_')and v[-2:].isdigit()for v in m.values()))
  tree=ast.parse(R.read_text());emissions=[n for n in ast.walk(tree)if isinstance(n,ast.Dict)and any(isinstance(k,ast.Constant)and k.value=='native_refusal_stage'for k in n.keys)]
  self.assertEqual(len(emissions),1)
 def test_checker_only_native_source_pin_changed(self):
  before=pathlib.Path('/private/tmp/gcp-grant-transition-readiness-20261012/v5/check-selected-transition-v5.py').read_text()
  after=(D/'check-selected-transition-v8.py').read_text()
  after=after.replace('/private/tmp/gcp-native-reader-fixed-stage-v7-diagnostic-20261012/read-native-fqdn-binding.diagnostic-v1.py','/private/tmp/provider-selected-5121-source-prep-20261012-v1/actual-measured-callbacks-v1/read-native-fqdn-binding.bound-v1.py').replace('790e2ae6494c93bb0a35bd93a59278f7f39cb6cd6eb3a75d859955572b8f0195','580a9d40302b941613f41cd8ba640c151e6a297e0588467951bc30f60c08a1c0')
  self.assertEqual(after,before)
if __name__=='__main__':unittest.main()
