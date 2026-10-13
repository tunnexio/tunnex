import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import json
import os
spec=importlib.util.spec_from_file_location('adopt',Path(__file__).with_name('adopt-owned-startup-gate.py'))
adopt=importlib.util.module_from_spec(spec);spec.loader.exec_module(adopt)
class GateTests(unittest.TestCase):
 def test_marker_strict(self):
  value=b'actual-owned-controlled-restart:01a12505-6db2-76c3-a5f0-4b8331c22cd7\n'
  self.assertEqual(adopt.marker(value),'01a12505-6db2-76c3-a5f0-4b8331c22cd7')
  for bad in (value+b'x',b'other:'+value,value.replace(b'01a12505',b'INVALID!')):
   with self.assertRaises(ValueError):adopt.marker(bad)
 def test_atomic_conversion_keeps_gate_until_replace(self):
  with tempfile.TemporaryDirectory() as directory:
   gate=Path(directory)/'gate';raw=b'actual-owned-controlled-restart:01a12505-6db2-76c3-a5f0-4b8331c22cd7';gate.write_bytes(raw)
   class Runner:
    def write_bytes(self,path,data):path.write_bytes(data)
    def sync_directory(self,path):pass
   def check():self.assertEqual(gate.read_bytes(),raw)
   with patch.object(adopt.gated,'private_bytes',side_effect=lambda p,n:p.read_bytes()):
    adopt.replace_gate(Runner(),gate,raw,gate.stat(),'a'*64,check)
   self.assertEqual(json.loads(gate.read_bytes()),{'Version':1,'SupervisorRun':adopt.marker(raw),'ContainerID':'a'*64})
 def test_failed_identity_recheck_preserves_original(self):
  with tempfile.TemporaryDirectory() as directory:
   gate=Path(directory)/'gate';raw=b'actual-owned-controlled-restart:01a12505-6db2-76c3-a5f0-4b8331c22cd7';gate.write_bytes(raw)
   class Runner:
    def write_bytes(self,path,data):path.write_bytes(data)
   def refuse():raise ValueError('changed')
   with self.assertRaises(ValueError):adopt.replace_gate(Runner(),gate,raw,gate.stat(),'a'*64,refuse)
   self.assertEqual(gate.read_bytes(),raw)
