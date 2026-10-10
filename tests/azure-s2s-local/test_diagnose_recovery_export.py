import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('diagnose',Path(__file__).with_name('diagnose-recovery-export.py'))
diag=importlib.util.module_from_spec(spec);spec.loader.exec_module(diag)


class DiagnosticTests(unittest.TestCase):
 def test_missing_packet_elapsed_field_has_fixed_path(self):
  value={key:'fixed' for key in ('source_address','direction','started_at','packet_finished_at')}
  with self.assertRaises(diag.ShapeFailure) as failure:diag.packet_shape(value)
  self.assertEqual(diag.diagnostic(failure.exception),{'category':'missing_required_field','field_path':'packet.packet_run_elapsed_seconds'})

 def test_unexpected_value_and_exception_never_enter_output(self):
  self.assertEqual(diag.diagnostic(KeyError('SECRET'))['field'],'unrecognized_field')
  self.assertNotIn('SECRET',str(diag.diagnostic(ValueError('SECRET'))))
  with self.assertRaises(diag.ShapeFailure) as failure:diag.field({'success':'SECRET'},'success','packet.counters.fresh_tcp',(int,))
  self.assertEqual(diag.diagnostic(failure.exception),{'category':'unexpected_type','field_path':'packet.counters.fresh_tcp.success'})

 def test_bool_is_not_counter_integer(self):
  with self.assertRaises(diag.ShapeFailure):diag.field({'success':True},'success','packet.counters.fresh_tcp',(int,))


if __name__=='__main__':unittest.main()
