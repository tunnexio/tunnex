import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('gated',Path(__file__).with_name('assemble-gated-restoration.py'))
gated=importlib.util.module_from_spec(spec);spec.loader.exec_module(gated)

class GatedRestorationSafetyTests(unittest.TestCase):
 def test_gate_requires_both_original_inode_and_original_bytes(self):
  with tempfile.TemporaryDirectory() as tmp:
   gate=Path(tmp)/'gate';gate.write_bytes(b'original');identity=gate.stat()
   with gate.open('rb'),patch.object(gated,'private_bytes',side_effect=lambda path,limit:path.read_bytes()):
    gated.same_gate(gate,b'original',identity)
    gate.write_bytes(b'changed')
    with self.assertRaises(ValueError):gated.same_gate(gate,b'original',identity)
    gate.unlink();gate.write_bytes(b'original')
    with self.assertRaises(ValueError):gated.same_gate(gate,b'original',identity)
 def test_receipt_publication_is_exclusive_and_durable(self):
  with tempfile.TemporaryDirectory() as tmp:
   target=Path(tmp)/'receipt';synced=[]
   def write(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
   runner=SimpleNamespace(write_bytes=write,sync_directory=lambda path:synced.append(path))
   with patch.object(gated,'private_bytes',side_effect=lambda path,limit:path.read_bytes()):
    gated.install_receipt(runner,target,b'actual bound receipt')
    self.assertEqual(target.read_bytes(),b'actual bound receipt');self.assertEqual(synced,[target.parent,target.parent])
    self.assertEqual(list(Path(tmp).iterdir()),[target])
    with self.assertRaises(FileExistsError):gated.install_receipt(runner,target,b'foreign')
    self.assertEqual(target.read_bytes(),b'actual bound receipt')
 def test_symlink_receipt_never_overwrites_referent(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);referent=root/'foreign';referent.write_bytes(b'preserve');target=root/'receipt';target.symlink_to(referent)
   runner=SimpleNamespace(write_bytes=lambda path,raw:path.write_bytes(raw),sync_directory=lambda path:None)
   with self.assertRaises(FileExistsError):gated.install_receipt(runner,target,b'new')
   self.assertEqual(referent.read_bytes(),b'preserve');self.assertTrue(target.is_symlink())
 def test_private_read_refuses_symlink_or_nonprivate_mode(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);path=root/'input';path.write_bytes(b'private');path.chmod(0o644)
   with self.assertRaises(ValueError):gated.private_bytes(path,100)
   path.chmod(0o600);link=root/'link';link.symlink_to(path)
   with self.assertRaises(ValueError):gated.private_bytes(link,100)

if __name__=='__main__':unittest.main()
