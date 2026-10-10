from datetime import datetime,timezone
import importlib.util
import json
from pathlib import Path
import sys
import os
import tempfile
import hashlib
from types import SimpleNamespace
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
 def test_exact_historical_parent_exception_open_hash_and_other_refusal(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp).resolve();root.chmod(0o700);file=root/'azure-genuine-reboot-proof.json';file.write_bytes(b'pinned');file.chmod(0o600)
   original_stat=Path.stat;original_fstat=os.fstat
   def stat_path(path,*args,**kw):
    st=original_stat(path,*args,**kw)
    return SimpleNamespace(st_uid=1000,st_mode=st.st_mode) if path==root else st
   def fstat(fd):
    st=original_fstat(fd);return SimpleNamespace(**{k:getattr(st,k) for k in ('st_mode','st_size','st_dev','st_ino','st_mtime_ns')},st_uid=0)
   with patch.object(m,'PRIVATE',root),patch.object(m,'PROOF_SHA',hashlib.sha256(b'pinned').hexdigest()),patch.object(Path,'stat',stat_path),patch.object(m.os,'fstat',fstat):
    self.assertEqual(m.read_owned(file,0),b'pinned')
    other=root/'unrelated.json';other.write_bytes(b'pinned');other.chmod(0o600)
    with self.assertRaises(ValueError):m.read_owned(other,0)
    file.write_bytes(b'changed')
    with self.assertRaises(ValueError):m.read_owned(file,0)
 def test_fresh_current_state_not_stale_applied(self):
  spec=importlib.util.spec_from_file_location('prepare_tests',Path(__file__).with_name('test_prepare_max_prefix_observer.py'));fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
  normal,attestation,immutable,clock=fixture.ObserverPreparation().fixture()
  normal['policy_count']=0;fresh=json.loads(json.dumps(normal));fresh['normal_connection']['application_state']='pending'
  self.assertTrue(m.authority_equal(normal,fresh))
  with self.assertRaises(ValueError):m.p.build(fresh,attestation,immutable,'baseline',clock)
  fresh['runtime_observation']='not_requested';self.assertEqual(m.p.build(fresh,attestation,immutable,'post-limit',clock)['mode'],'post-limit')
 def test_same_container_unreviewed_restart_refuses(self):
  value={'Id':m.p.CONTAINER,'Name':'/tunnex-azure-cloud-gateway','Config':{'Labels':{'tunnex.owner':'azure-s2s-01a12505'}},'Image':'sha256:'+m.p.IMAGE,'State':{'Running':True,'Pid':100,'StartedAt':'2026-10-10T23:00:00Z'}}
  with patch.object(m,'command',return_value=json.dumps([value]).encode()) as calls:
   with self.assertRaises(ValueError):m.identity()
   self.assertEqual(calls.call_count,1)
 def test_wrong_host_no_commands(self):
  with patch.object(m.os,'geteuid',return_value=0),patch.object(m.socket,'gethostname',return_value='foreign'),patch.object(m,'command') as calls:
   with self.assertRaises(ValueError):m.run(None)
   calls.assert_not_called()
if __name__=='__main__':unittest.main()
