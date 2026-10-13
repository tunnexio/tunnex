import importlib.util,pathlib,json,unittest
p=pathlib.Path(__file__).resolve().parent;spec=importlib.util.spec_from_file_location('o',p/'customer-cloud-rekey-orchestrator-v6.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
owner={'listener':{'pid':18666,'startticks':'9105301'},'file':'unused'};raw=(p/'.runtime/customer-stream-v9-peer2-20261008-1/growth.stdout').read_bytes();prefix=b'__END__'.join(raw.split(b'__END__')[:18])+b'__END__\n'
class ReadHalf(unittest.TestCase):
 def test_actual_recorded_halfclosed_progress(self):
  v=m.progress(prefix,owner);self.assertIsNotNone(v);self.assertIn('FIN-WAIT-2',v['socket_scope'])
 def test_wrong_state_pid_tuple_and_inode(self):
  for old,new in [(b'FIN-WAIT-2',b'CLOSE-WAIT'),(b'pid=18666',b'pid=18667'),(b'10.84.2.10:44021',b'10.84.2.10:44022'),(b'131072 66305 304133',b'131072 66305 304134')]:
   q=prefix.replace(old,new,1)
   with self.subTest(old=old),self.assertRaises(AssertionError):m.progress(q,owner)
 def test_below_fifteen(self):
  q=b'__END__'.join(raw.split(b'__END__')[:12])+b'__END__\n';self.assertIsNone(m.progress(q,owner))
unittest.main()
