import pathlib,importlib.util,unittest,copy
P=pathlib.Path(__file__).resolve().parent;sp=importlib.util.spec_from_file_location('o',P/'customer-cloud-rekey-orchestrator-v10.py');o=importlib.util.module_from_spec(sp);sp.loader.exec_module(o)
owner={'listener':{'pid':18666,'startticks':'9105301'},'file':'unused'};raw=(P/'.runtime/customer-stream-v9-peer2-20261008-1/growth.stdout').read_bytes();prefix=b'__END__'.join(raw.split(b'__END__')[:18])+b'__END__\n';value=o.progress(prefix,owner)
class Fresh(unittest.TestCase):
 def test_actual_new_growing_owned_sample(self):self.assertIsNotNone(o.fresh_stream_sample(value,15,'44021',True))
 def test_unchanged_index_or_growth_waits(self):
  self.assertIsNone(o.fresh_stream_sample(value,17,'44021',True));q=copy.deepcopy(value);q['samples'][-1]['bytes']=q['samples'][-2]['bytes'];self.assertIsNone(o.fresh_stream_sample(q,15,'44021',True))
 def test_dead_recycled_tuple_refuse(self):
  with self.assertRaises(AssertionError):o.fresh_stream_sample(value,15,'44021',False)
  for field,new in [('listener_startticks','foreign'),('client_ports',['99999'])]:
   q=copy.deepcopy(value);q['samples'][-1][field]=new
   with self.subTest(field=field),self.assertRaises(AssertionError):o.fresh_stream_sample(q,15,'44021',True)
 def test_state_mismatch_refuses_before_freshness(self):
  with self.assertRaises(AssertionError):o.progress(prefix.replace(b'FIN-WAIT-2',b'CLOSE-WAIT',1),owner)
unittest.main()
