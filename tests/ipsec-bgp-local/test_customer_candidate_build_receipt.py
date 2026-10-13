import ast,copy,hashlib,json,pathlib,unittest
ROOT=pathlib.Path(__file__).resolve().parents[2]
PATHS=[ROOT/'tests/ipsec-bgp-local/cloud-enrolled-restart-cycle6-v4.py',ROOT/'tests/ipsec-bgp-local/vgw-pre-release-nonce-probe-v9.py']
FUNCTIONS=[]
for path in PATHS:
 tree=ast.parse(path.read_text());fn=next(x for x in tree.body if isinstance(x,ast.FunctionDef)and x.name=='validate_candidate_receipt');ns={'json':json,'hashlib':hashlib};exec(compile(ast.Module(body=[fn],type_ignores=[]),str(path),'exec'),ns);FUNCTIONS.append((fn,ns[fn.name]))
class TestBuildReceipt(unittest.TestCase):
 def fixture(self):
  raw=(ROOT/'tests/ipsec-bgp-local/.runtime/cloud-customer-worker-v4-rekey/amd64-build-receipt.json').read_bytes();return raw,json.loads(raw)
 def validate(self,raw,obj):
  return FUNCTIONS[0][1](raw,obj['binary_sha256'],obj['source_snapshot_sha256'],hashlib.sha256(raw).hexdigest(),obj['prior_node_sha256'])
 def test_actual_reviewed_receipt(self):
  raw,obj=self.fixture();self.assertTrue(self.validate(raw,obj)['tests_passed'])
 def test_strict_paired_provenance(self):
  for key,value in [('unit_suites_passed',False),('source_before_after_equal',False),('toolchain','go version go1.25.0 darwin/arm64'),('GOOS','darwin'),('GOARCH','arm64'),('CGO_ENABLED','1'),('build_arguments',['build']),('binary_sha256','0'*64)]:
   raw,obj=self.fixture();obj[key]=value;bad=json.dumps(obj).encode()
   with self.subTest(key=key),self.assertRaises(AssertionError):self.validate(bad,obj)
 def test_hash_and_candidate_pairing(self):
  raw,obj=self.fixture();fn=FUNCTIONS[0][1]
  for node,source,receipt,old in [(obj['prior_node_sha256'],obj['source_snapshot_sha256'],hashlib.sha256(raw).hexdigest(),obj['prior_node_sha256']),(obj['binary_sha256'],'b'*64,hashlib.sha256(raw).hexdigest(),obj['prior_node_sha256']),(obj['binary_sha256'],obj['source_snapshot_sha256'],'c'*64,obj['prior_node_sha256']),(obj['binary_sha256'],obj['source_snapshot_sha256'],hashlib.sha256(raw).hexdigest(),'d'*64)]:
   with self.assertRaises(AssertionError):fn(raw,node,source,receipt,old)
 def test_adapter_probe_identical_validator(self):self.assertEqual(ast.dump(FUNCTIONS[0][0],include_attributes=False),ast.dump(FUNCTIONS[1][0],include_attributes=False))
 def test_new_run_preserves_v3(self):self.assertIn("run.name=='cloud-enrolled-restart-21169a9f-cycle6-v4'",PATHS[0].read_text())
if __name__=='__main__':unittest.main()
