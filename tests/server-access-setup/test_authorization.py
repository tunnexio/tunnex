import hashlib, importlib.util, os, subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('authorization',ROOT/'packages/apptransport/bootstrap/authorize.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
class Authorization(unittest.TestCase):
 def execute(self,source,actual):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);keys=root/'authorized_keys';keys.write_text('ssh-ed25519 existing-admin-key\nrestrict ssh-ed25519 temporary-key tunnex-enroll-job\n')
   rule=root/'rule';rule.write_text('temporary sudo rule');launcher=root/'launcher.py'
   job=dict(keys=str(keys),owner=os.getuid(),group=os.getgid(),rule=str(rule),launcher=str(launcher),tag='tunnex-enroll-job',expires=9999999999,digest=hashlib.sha256(source).hexdigest(),accounts=[])
   launcher.write_text(a.WRAPPER.replace('JOB = None','JOB = '+repr(job)))
   result=subprocess.run([sys.executable,str(launcher)],input=actual,capture_output=True)
   self.assertEqual(keys.read_text(),'ssh-ed25519 existing-admin-key\n');self.assertFalse(rule.exists());self.assertFalse(launcher.exists());return result
 def test_exact_reviewed_script_only(self):
  source=b"print('reviewed installer ran')\n"
  result=self.execute(source,source);self.assertEqual(result.returncode,0,result.stderr);self.assertIn(b'reviewed installer ran',result.stdout)
 def test_digest_mismatch_refuses_execution_and_cleans_up(self):
  result=self.execute(b"print('reviewed')",b"print('unreviewed root execution')")
  self.assertNotEqual(result.returncode,0);self.assertNotIn(b'unreviewed root execution',result.stdout)
 def test_public_helper_matches_gateway_asset(self):
  self.assertEqual((ROOT/'apps/web/public/tunnex-browser-ssh.py').read_bytes(),(ROOT/'packages/apptransport/bootstrap/helper.py').read_bytes())
if __name__=='__main__':unittest.main()
