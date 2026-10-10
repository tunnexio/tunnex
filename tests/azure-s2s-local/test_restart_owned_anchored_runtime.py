import copy
from datetime import datetime,timezone,timedelta
import importlib.util
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('restart',Path(__file__).with_name('restart-owned-anchored-runtime.py'))
restart=importlib.util.module_from_spec(spec);spec.loader.exec_module(restart)
class QualificationTests(unittest.TestCase):
 def test_health_requires_fresh_both_tunnels_peers_and_exact_route(self):
  now=datetime.now(timezone.utc)
  value={'runtime':{'observed_at':now.isoformat(),'tunnels':[{'status':'up'},{'status':'up'}],'bgp':{'peers':[{'state':'established'},{'state':'established'}],'routes':[{'prefix':'10.231.0.0/16'}]}}}
  restart.healthy(value,now)
  for change in (lambda v:v['runtime'].update(observed_at=(now-timedelta(seconds=16)).isoformat()),lambda v:v['runtime']['tunnels'][1].update(status='down'),lambda v:v['runtime']['bgp']['peers'][0].update(state='active'),lambda v:v['runtime']['bgp'].update(routes=[])):
   bad=copy.deepcopy(value);change(bad)
   with self.assertRaises(ValueError):restart.healthy(bad,now)
 def test_baseline_requires_all_protocols_exact_large_source_same_socket(self):
  value={'source_address':'10.233.10.2','udp_payload_bytes':4096,'tcp_large_requested':True,'counters':{},'samples':[]}
  for key in ('fresh_tcp','existing_tcp','fresh_udp','existing_udp'):
   value['counters'][key]={'success':5,'failure':0}
   for i in range(5):value['samples'].append({'kind':key,'success':True,'source_preservation':'preserved','large_same_socket':True,'local_port':40000})
  restart.baseline(value)
  for change in (lambda v:v['counters']['fresh_udp'].update(failure=1),lambda v:v['samples'][-1].update(success=False),lambda v:v['samples'][0].update(source_preservation='changed'),lambda v:v['samples'][5].update(local_port=40001)):
   bad=copy.deepcopy(value);change(bad)
   with self.assertRaises(ValueError):restart.baseline(bad)

class ReceiptArchiveTests(unittest.TestCase):
 def test_unconsumed_receipt_refusal_preserves_file(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);target=root/'receipt';target.write_bytes(b'original')
   class Runner:
    def validate_previous_receipt(self,entry,raw):raise ValueError('not consumed')
   with patch.object(restart.gated,'private_bytes',side_effect=lambda p,n:p.read_bytes()):
    with self.assertRaises(ValueError):restart.archive_receipt(Runner(),{},target,root)
   self.assertEqual(target.read_bytes(),b'original')
   self.assertFalse((root/'previous-receipt.json').exists())
 def test_exact_consumed_receipt_archived_before_removal(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);target=root/'receipt';target.write_bytes(b'consumed')
   class Runner:
    def validate_previous_receipt(self,entry,raw):
     if raw!=b'consumed':raise ValueError('changed')
    def write_bytes(self,path,raw):
     self_assert(target.exists());path.write_bytes(raw)
    def sync_directory(self,path):pass
   self_assert=self.assertTrue
   with patch.object(restart.gated,'private_bytes',side_effect=lambda p,n:p.read_bytes()):restart.archive_receipt(Runner(),{},target,root)
   self.assertFalse(target.exists());self.assertEqual((root/'previous-receipt.json').read_bytes(),b'consumed')

class ParentOwnershipTests(unittest.TestCase):
 def test_exact_ubuntu_private_parent_accepts_and_foreign_parent_refuses(self):
  from types import SimpleNamespace
  import stat
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve();evidence=root/'controlled-namespace-stop-2'
   with patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=1000)):
    restart.evidence_parent(evidence,root)
    with self.assertRaises(ValueError):restart.evidence_parent(root/'other'/'controlled-namespace-stop-2',root)
   for uid,mode in ((0,0o700),(1000,0o755)):
    with patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=stat.S_IFDIR|mode,st_uid=uid)):
     with self.assertRaises(ValueError):restart.evidence_parent(evidence,root)
