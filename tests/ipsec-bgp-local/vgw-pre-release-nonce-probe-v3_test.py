import ast,json,pathlib,unittest
source=pathlib.Path(__file__).with_name('vgw-pre-release-nonce-probe-v3.py').read_text()
tree=ast.parse(source)
# Execute only the literal census helper extracted from the observer construction.
helper=next(n.value.left.value for n in ast.walk(tree) if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=='observer_source' for x in n.targets) and isinstance(n.value,ast.BinOp) and isinstance(n.value.left,ast.Constant))
ns={'json':json};exec(helper,ns);empty=ns['empty_xfrm_census']
class EmptyXfrm(unittest.TestCase):
 def test_supported_empty(self):
  for raw in ['', ' \t\r\n','[]','  []\n']:self.assertEqual(empty(raw),[])
 def test_nonempty_and_malformed_refused(self):
  for raw in ['src ::/0 dst ::/0\n dir socketin priority 0','[{}]','{}','null','false','0','[', '[]junk']:
   with self.subTest(raw=raw),self.assertRaises((ValueError,TypeError)):empty(raw)
 def test_check_output_failure_preserved(self):
  # Actual read command still check_output: nonzero may not reach empty parser.
  self.assertIn("return subprocess.check_output(['docker','exec',cid,*args],text=True)",source)
  self.assertIn("xfrm_states=empty_xfrm_census(ex(",source)
  self.assertIn("xfrm_policies=empty_xfrm_census(ex(",source)
if __name__=='__main__':unittest.main()
