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


class RFC3339TimestampTests(unittest.TestCase):
 def test_docker_nanoseconds_preserved_with_python310_parse_input(self):
  value='2026-10-10T13:02:09.667123456Z'
  original=export.datetime
  with patch.object(export,'datetime') as parser:
   parser.fromisoformat.side_effect=original.fromisoformat
   self.assertEqual(export.timestamp(value),value)
   parser.fromisoformat.assert_called_once_with('2026-10-10T13:02:09.667123+00:00')

 def test_short_fractions_are_padded_for_python310(self):
  original=export.datetime
  for fraction in ('1','12','123','1234','12345','123456','1234567','12345678','123456789'):
   value='2026-10-10T13:02:09.'+fraction+'Z'
   with self.subTest(fraction=fraction),patch.object(export,'datetime') as parser:
    parser.fromisoformat.side_effect=original.fromisoformat
    self.assertEqual(export.timestamp(value),value)
    parser.fromisoformat.assert_called_once_with('2026-10-10T13:02:09.'+fraction[:6].ljust(6,'0')+'+00:00')

 def test_fractional_precisions_and_offsets_preserved(self):
  for value in ['2026-10-10T13:02:09Z','2026-10-10T13:02:09.1Z','2026-10-10T13:02:09.123456Z','2026-10-10T13:02:09.123456789+05:30','2026-10-10T13:02:09.123456789-04:00']:
   with self.subTest(value=value):self.assertEqual(export.timestamp(value),value)

 def test_malformed_calendar_precision_timezone_refused(self):
  for value in ['2026-02-30T13:02:09Z','2026-10-10 13:02:09Z','2026-10-10T13:02:09','2026-10-10T13:02:09.Z','2026-10-10T13:02:09.1234567890Z','2026-10-10T13:02:09+24:00','2026-10-10T13:02:09+01:60','2026-10-10T13:02:60Z','2026-10-10T13:02:09ZSECRET']:
   with self.subTest(value=value),self.assertRaisesRegex(ValueError,'timestamp shape'):export.timestamp(value)


class ControlledEvidenceTests(unittest.TestCase):
 def snapshot(self):
  return {'version':1,'container':'a'*64,'boot':'00000000-0000-4000-8000-000000000001','pid':100,'started':'2026-10-10T13:00:00Z','observed_ns':10,'namespace':{'device':1,'inode':2},'journal_raw_sha256':'b'*64,'journal_entries_sha256':'c'*64,'journal':'secret-path'}

 def test_snapshot_projects_only_fixed_identities(self):
  value=export.stop_snapshot(self.snapshot())
  self.assertNotIn('journal',value)
  self.assertEqual(value['pid'],100)

 def test_stop_requires_exact_checks_and_event_binding(self):
  value={'version':1,'kind':'supervisor-confirmed-runtime-stop','snapshot':self.snapshot(),'termination':{'container':'a'*64,'action':'die','time_ns':11},'verified_ns':12,'checks':['exact-stopped-runtime','empty-cgroup','no-namespace-holders-two-passes'],'stopped_journal_raw_sha256':'d'*64}
  self.assertEqual(export.stopped_proof(value)['termination']['time_ns'],11)
  value['checks'].pop()
  with self.assertRaises(ValueError):export.stopped_proof(value)
  value['checks'].append('no-namespace-holders-two-passes');value['termination']['container']='e'*64
  with self.assertRaises(ValueError):export.stopped_proof(value)

 def test_fresh_runtime_refuses_arbitrary_namespace_and_hash(self):
  value={'version':1,'kind':'supervisor-confirmed-fresh-runtime','container':'a'*64,'boot':'00000000-0000-4000-8000-000000000001','namespace':'net:[123]','started_at':'2026-10-10T13:02:00Z','pid':200,'pid_start_ticks':2,'startup_gate_device':1,'startup_gate_inode':2,**{key:'b'*64 for key in ('stop_evidence_sha256','stopped_journal_sha256','current_journal_sha256','startup_gate_sha256')},'raw_journal':'SECRET'}
  self.assertNotIn('raw_journal',export.fresh_runtime(value))
  value['namespace']='arbitrary-string'
  with self.assertRaises(ValueError):export.fresh_runtime(value)
  value['namespace']='net:[123]';value['startup_gate_sha256']='not-a-hash'
  with self.assertRaises(ValueError):export.fresh_runtime(value)

 def test_controlled_subtree_requires_one_bound_accepted_result(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);tree=root/'controlled-namespace-stop-2';tree.mkdir()
   attempt=tree/'assemble-00000000-0000-4000-8000-000000000002';attempt.mkdir();(attempt/'result.json').touch()
   old=self.snapshot()
   stopped={'version':1,'kind':'supervisor-confirmed-runtime-stop','snapshot':old,'termination':{'container':'a'*64,'action':'die','time_ns':11},'verified_ns':12,'checks':['exact-stopped-runtime','empty-cgroup','no-namespace-holders-two-passes'],'stopped_journal_raw_sha256':'d'*64}
   fresh={'version':1,'kind':'supervisor-confirmed-fresh-runtime','container':'a'*64,'boot':old['boot'],'namespace':'net:[123]','started_at':'2026-10-10T13:02:00Z','pid':200,'pid_start_ticks':2,'startup_gate_device':1,'startup_gate_inode':2,**{key:'b'*64 for key in ('stop_evidence_sha256','current_journal_sha256','startup_gate_sha256')},'stopped_journal_sha256':'d'*64}
   values={'before.json':old,'stopped.json':stopped,'fresh-runtime.json':fresh,'result.json':{'stage':'exact_gate_released','observed_at':'2026-10-10T13:02:38Z','runtime_acceptance':'not_observed','secret':'omit'}}
   with patch.object(export,'root_evidence_directory'),patch.object(export,'read_private',side_effect=lambda path:values[path.name]):
    projected=export.controlled_restart(root)
    self.assertNotIn('secret',projected['accepted_installation']['gate_release'])
    self.assertEqual(projected['attempts_without_result'],0)
    fresh['pid']=old['pid']
    with self.assertRaisesRegex(ValueError,'fresh runtime binding'):export.controlled_restart(root)
    fresh['pid']=200
    (attempt/'result.json').unlink()
    with self.assertRaisesRegex(ValueError,'exactly one'):export.controlled_restart(root)

 def test_controlled_receipts_are_fixed_and_optional(self):
  self.assertIn('controlled-recovery-fd6eeaff-packets.json',export.FILES)
  self.assertIn('controlled-healthy-restart-12cfccbb-packets.json',export.FILES)
  with tempfile.TemporaryDirectory() as directory:self.assertEqual(export.controlled_restart(Path(directory)),{'availability':'missing'})


if __name__=='__main__':unittest.main()
