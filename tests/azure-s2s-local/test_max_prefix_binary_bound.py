import importlib.util,os,stat,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('observer',Path(__file__).with_name('run-max-prefix-observer.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class BinaryBoundTests(unittest.TestCase):
 def test_exact_binary_above_default_limit_only_explicit_bound(self):
  with tempfile.TemporaryDirectory(dir='/private/tmp') as directory:
   path=Path(directory)/'binary';path.write_bytes(b'x'*m.OBSERVER_BYTES);os.chmod(path,0o600)
   with self.assertRaises(ValueError):m.read_owned(path,os.getuid())
   self.assertEqual(len(m.read_owned(path,os.getuid(),maximum=m.OBSERVER_BYTES,exact_size=m.OBSERVER_BYTES)),m.OBSERVER_BYTES)
   with self.assertRaises(ValueError):m.read_owned(path,os.getuid(),maximum=m.OBSERVER_BYTES,exact_size=m.OBSERVER_BYTES-1)
   with path.open('ab') as stream:stream.write(b'x')
   with self.assertRaises(ValueError):m.read_owned(path,os.getuid(),maximum=m.OBSERVER_BYTES,exact_size=m.OBSERVER_BYTES)
 def test_default_journal_limit_and_owner_symlink_mode_unchanged(self):
  with tempfile.TemporaryDirectory(dir='/private/tmp') as directory:
   path=Path(directory)/'journal';path.write_bytes(b'x'*10485760);os.chmod(path,0o600)
   self.assertEqual(len(m.read_owned(path,os.getuid())),10485760)
   with self.assertRaises(ValueError):m.read_owned(path,os.getuid()+1)
   link=Path(directory)/'link';link.symlink_to(path)
   with self.assertRaises(ValueError):m.read_owned(link,os.getuid())
   os.chmod(path,0o644)
   with self.assertRaises(ValueError):m.read_owned(path,os.getuid())
   os.chmod(path,0o600)
   with path.open('ab') as stream:stream.write(b'x')
   with self.assertRaises(ValueError):m.read_owned(path,os.getuid())
 def test_changed_inode_bracket_refuses(self):
  from types import SimpleNamespace
  with tempfile.TemporaryDirectory(dir='/private/tmp') as directory:
   path=Path(directory)/'binary';path.write_bytes(b'x');os.chmod(path,0o600)
   st=path.stat();changed=SimpleNamespace(st_dev=st.st_dev,st_ino=st.st_ino+1,st_size=st.st_size,st_mtime_ns=st.st_mtime_ns)
   with patch.object(m.os,'fstat',side_effect=[st,changed]):
    with self.assertRaisesRegex(ValueError,'file changed'):m.read_owned(path,os.getuid())
if __name__=='__main__':unittest.main()
