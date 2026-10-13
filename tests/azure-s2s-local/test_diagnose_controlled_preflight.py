import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('diagnostic',Path(__file__).with_name('diagnose-controlled-preflight.py'))
diag=importlib.util.module_from_spec(spec);spec.loader.exec_module(diag)
class PathsTests(unittest.TestCase):
 def test_values_and_dynamic_keys_never_print(self):
  before={'Payload':{'Entries':[{'BGP':{'StatusSequence':1,'private-secret-key':'secret-old'}}]}}
  after={'Payload':{'Entries':[{'BGP':{'StatusSequence':2,'private-secret-key':'secret-new'}}]}}
  result=diag.changed_paths(before,after)
  self.assertIn('/Payload/Entries/0/BGP/StatusSequence',result)
  self.assertIn('/Payload/Entries/0/BGP/<map-key>',result)
  self.assertNotIn('secret',str(result));self.assertNotIn('private-secret-key',str(result))
