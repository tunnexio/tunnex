import importlib.util
from pathlib import Path
import os
import stat
import tempfile
import unittest
spec=importlib.util.spec_from_file_location('capture',Path(__file__).with_name('acquire-owned-dns-mtls.py'))
capture=importlib.util.module_from_spec(spec);spec.loader.exec_module(capture)
class PrivatePublicationTests(unittest.TestCase):
 def test_exclusive_private_files_and_symlink_refusal(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);target=root/'material.json';capture.private_write(target,b'private')
   self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o600)
   with self.assertRaises(FileExistsError):capture.private_write(target,b'changed')
   self.assertEqual(target.read_bytes(),b'private')
   link=root/'desired.json';link.symlink_to(target)
   with self.assertRaises(OSError):capture.private_write(link,b'changed')
   self.assertEqual(target.read_bytes(),b'private')
