"""Source-only parity tests; no transport/native execution."""
import ast,pathlib,unittest,json
P=pathlib.Path('/private/tmp/gcp-native-reader-fixed-stage-v7-diagnostic-20261012/native-fqdn-binding.diagnostic-v1.remote.py')
R=pathlib.Path('/private/tmp/gcp-native-reader-sa-substage-v2-20261012/native-fqdn-binding.sa-substage-v2.remote.py')
D=pathlib.Path('/private/tmp/gcp-native-reader-sa-substage-v2-20261012')
class SATests(unittest.TestCase):
 def test_nine_terms_exact_original_order(self):
  m=json.loads((D/'PREDICATE-PARITY-v2.json').read_text());old=next(x for x in P.read_text().splitlines()if x.startswith(' if len(names)!=3'))
  terms=old[4:].split(':raise ValueError')[0].split(' or ')
  self.assertEqual(terms,m['original_short_circuit_terms']);self.assertEqual(len(terms),9)
  actual=[x for x in R.read_text().splitlines()if ":raise ValueError('recovery exact SA census "in x]
  self.assertEqual([x[4:].split(':raise ValueError')[0]for x in actual],terms)
 def test_surrounding_reads_predicates_unchanged(self):
  s=R.read_text();s='\n'.join(x for x in s.split('\n')if not x.startswith('NATIVE_REFUSAL_STAGES.update('))
  lines=s.splitlines();ix=[i for i,x in enumerate(lines)if ":raise ValueError('recovery exact SA census "in x]
  old=next(x for x in P.read_text().splitlines()if x.startswith(' if len(names)!=3'))
  lines[ix[0]:ix[-1]+1]=[old]
  self.assertEqual('\n'.join(lines)+'\n',P.read_text())
 def test_closed_labels_and_unknown_remain_unclassified(self):
  tree=ast.parse(R.read_text());updates=[n for n in tree.body if isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Attribute)and n.value.func.attr=='update']
  self.assertEqual(len(updates),1);m=ast.literal_eval(updates[0].value.args[0]);self.assertEqual(len(m),9)
  self.assertEqual(m['recovery exact SA census sad_count'],'native_sa_sad_count')
  self.assertNotIn('PRIVATE_ERROR',m);self.assertTrue(all(v.startswith('native_sa_')for v in m.values()))
  self.assertIn("NATIVE_REFUSAL_STAGES.get(str(e),'native_unclassified')",R.read_text())
if __name__=='__main__':unittest.main()
