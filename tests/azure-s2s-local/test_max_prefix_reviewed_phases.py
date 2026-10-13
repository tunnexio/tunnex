import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
s=importlib.util.spec_from_file_location('phases',Path(__file__).with_name('max-prefix-reviewed-phases.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Phases(unittest.TestCase):
 def args(self,phase):return SimpleNamespace(phase=phase,absence=None,absence_sha256=None,binding=None,psk=None,discovery=None,restored_state=None)
 def test_exact_paths_no_prepare_D(self):
  with patch.object(m,'private_file',side_effect=lambda p:p):
   command=m.argv(self.args('dns-revoke'),m.PRIVATE/'out.json');self.assertIn(str(m.D),command);self.assertNotIn('prepare',command);self.assertIn(str(m.SOURCE/'tests/azure-s2s-local/rebind-profile-dns.py'),command)
 def test_delete_needs_real_digest(self):
  with patch.object(m,'private_file',side_effect=lambda p:p):
   with self.assertRaises(ValueError):m.argv(self.args('delete'),m.PRIVATE/'out.json')
 def test_create_only_private_paths_no_key_value(self):
  a=self.args('create');a.absence=m.PRIVATE/'absence.json';a.absence_sha256='a'*64;a.binding=m.PRIVATE/'binding.json';a.psk=m.PRIVATE/'key';a.discovery=m.PRIVATE/'discovery.json'
  with patch.object(m,'private_file',side_effect=lambda p:p):
   c=m.argv(a,m.PRIVATE/'out.json');self.assertIn('--psk-file',c);self.assertIn(str(m.M),c);self.assertIn('--native-absence',c)
 def test_baseline_new_state_and_lineage(self):
  a=self.args('baseline-prepare');a.restored_state=m.M
  with patch.object(m,'private_file',side_effect=lambda p:p):
   with self.assertRaises(ValueError):m.argv(a,m.PRIVATE/'out.json')
if __name__=='__main__':unittest.main()
