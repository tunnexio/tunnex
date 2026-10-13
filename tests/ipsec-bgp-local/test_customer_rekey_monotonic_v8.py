import pathlib,importlib.util,unittest
P=pathlib.Path(__file__).resolve().parent
def load(n):
 s=importlib.util.spec_from_file_location(n,P/n);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
o=load('customer-cloud-rekey-orchestrator-v8.py');stage=load('customer-rekey-stage-v2.py')
class Clock(unittest.TestCase):
 def test_same_gateway_monotonic(self):self.assertTrue(o.fresh_monotonic({'sampler_started_monotonic_ns':101,'sampler_started_ns':-999999},100))
 def test_stale_reordered(self):
  for v in [99,0,False,'101']:
   with self.subTest(v=v),self.assertRaises(AssertionError):o.fresh_monotonic({'sampler_started_monotonic_ns':v},100)
 def test_actual_four_second_correlation_not_authority(self):
  b=stage.clock_bounds(10000000000,14000000000,12000000000);self.assertEqual(b['roundtrip_ns'],4000000000);self.assertEqual(b['offset_lower_ns'],-2000000000);self.assertEqual(b['offset_upper_ns'],2000000000)
 def test_walljump_cannot_change_monotonic(self):
  for wall in [-100000000000,999999999999]:self.assertTrue(o.fresh_monotonic({'sampler_started_monotonic_ns':101,'sampler_started_ns':wall},100))
unittest.main()
