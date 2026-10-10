from datetime import datetime,timezone
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('observer_wrapper',Path(__file__).with_name('run-max-prefix-observer.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class WrapperTests(unittest.TestCase):
 def fixture(self):
  b={'mode':'post-limit','org_id':'org','site_id':'site','gateway_id':'gateway','connection_id':'new','desired_revision':53,'configuration_revision':2}
  receipt={**{k:v for k,v in b.items() if k!='mode'},'version':1,'kind':'owned_max_prefix_shutdown_observation','observed_at':datetime.now(timezone.utc).isoformat()}
  line=b'AZURE_MAX_PREFIX_NATIVE_PROOF '+json.dumps(receipt).encode()+b'\n'
  return b,line,b'--- PASS: TestAzureOwnedMaxPrefixNativeProof (1.00s)\n'
 def test_exact_actual_one_pass(self):
  b,line,passed=self.fixture();self.assertEqual(json.loads(m.extract(line+passed,0,b))['connection_id'],'new')
 def test_no_failure_skip_duplicate_foreign_promotion(self):
  b,line,passed=self.fixture()
  for raw,code in ((line+passed,1),(line+passed+b'--- SKIP: test',0),(line+line+passed,0),(line,0),(line.replace(b'"new"',b'"foreign"')+passed,0)):
   with self.assertRaises(ValueError):m.extract(raw,code,b)
 def test_authority_compare_no_readiness_inference(self):
  a={'normal_connection':{'id':'new','application_state':'pending'},'policy_count':0}
  self.assertTrue(m.authority_equal(a,a));self.assertFalse(m.authority_equal(a,{'normal_connection':a['normal_connection'],'policy_count':1}))
 def test_wrong_host_no_commands(self):
  with patch.object(m.os,'geteuid',return_value=0),patch.object(m.socket,'gethostname',return_value='foreign'),patch.object(m,'command') as calls:
   with self.assertRaises(ValueError):m.run(None)
   calls.assert_not_called()
if __name__=='__main__':unittest.main()
