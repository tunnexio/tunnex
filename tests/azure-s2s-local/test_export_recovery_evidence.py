import importlib.util
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('recovery_export',Path(__file__).with_name('export-recovery-evidence.py'))
export=importlib.util.module_from_spec(spec);spec.loader.exec_module(export)


class OwnershipTests(unittest.TestCase):
 def test_main_calls_ownership_gate_before_receipt_reads(self):
  args=['export-recovery-evidence.py','--private-root','/owned/private','--initial-refusal','/package/genuine-reboot-recovery.json','--output','/owned/export.json']
  with patch('sys.argv',args),patch.object(export,'private_root',side_effect=ValueError('ownership refused')) as gate,patch.object(export,'read_private') as reads:
   with self.assertRaisesRegex(ValueError,'ownership refused'):export.main()
   gate.assert_called_once_with(Path('/owned/private'))
   reads.assert_not_called()

 def test_private_directory_accepts_only_root_observer_and_uid1000(self):
  root=Path('/owned/private')
  for uid,mode,observer,accepted in [(1000,0o700,0,True),(0,0o700,0,False),(1001,0o700,0,False),(1000,0o750,0,False),(1000,0o700,1000,False)]:
   with self.subTest(uid=uid,mode=mode,observer=observer),patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=stat.S_IFDIR|mode,st_uid=uid)),patch.object(Path,'resolve',return_value=root),patch.object(export.os,'geteuid',return_value=observer):
    if accepted:self.assertEqual(export.private_root(root),root)
    else:
     with self.assertRaises(ValueError):export.private_root(root)

 def test_symlink_ancestor_refused(self):
  with patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=1000)),patch.object(Path,'resolve',return_value=Path('/different')),patch.object(export.os,'geteuid',return_value=0):
   with self.assertRaises(ValueError):export.private_root(Path('/owned/private'))

 def test_packet_and_api_owners_are_distinct_and_not_broadly_accepted(self):
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'receipt.json';path.write_text('{}')
   for required in (0,1000):
    for actual in (0,1000,1001):
     with self.subTest(required=required,actual=actual),patch.object(export.os,'fstat',return_value=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=actual,st_size=2)):
      if actual==required:self.assertEqual(export.read_private(path,required),{})
      else:
       with self.assertRaises(ValueError):export.read_private(path,required)

 def test_normal_api_reader_is_read_only_and_runs_exact_uid1000(self):
  command=export.current_read_command(Path('/owned/private'))
  self.assertEqual(command[:5],['sudo','-u','#1000','--','python3'])
  self.assertEqual(command[-3:],['read','--private-root','/owned/private'])
  self.assertNotIn('enable',command);self.assertNotIn('disable',command)


if __name__=='__main__':unittest.main()
