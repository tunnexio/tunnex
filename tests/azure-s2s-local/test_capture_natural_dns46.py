import importlib.util,pathlib,unittest
spec=importlib.util.spec_from_file_location('capture',pathlib.Path(__file__).with_name('capture-natural-dns46.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Correlation(unittest.TestCase):
 def test_refusal_has_fixed_stage_only(self):
  for value in m.STAGES:
   m.stage(value);self.assertEqual(m.refusal(),{'status':'refused','category':'owned_capture_refused','stage':value})
  with self.assertRaises(ValueError):m.stage('/private/raw exception')
  self.assertNotIn('/private/raw exception',str(m.refusal()))

 def test_exact_udp_and_ambiguity(self):
  end='2026-10-10T21:00:03Z';start=m.stamp(end)-3
  diagnostic={'time':end,'operation':'dns_exchange','socket_ms':3000,'socket_stage':'body','stage':'dns_socket_udp'}
  rpc={'dispatch_utc':'2026-10-10T20:59:59Z','handle_ms':4500}
  flow=('udp','10.231.2.4',40001)
  rows=[{'t':start,'flow':flow,'out':True,'capture_index':0,'dns_id':3,'response':False},{'t':start+.02,'flow':flow,'out':False,'capture_index':1,'dns_id':3,'response':True,'rcode':0}]
  got=m.correlate(rows,[diagnostic],[rpc],True)[0];self.assertTrue(got['noerror_reply_observed']);self.assertTrue(got['opposite_tunnel_reply_observed']);self.assertFalse(got['same_tunnel_reply_observed'])
  self.assertEqual(m.correlate(rows,[diagnostic],[rpc],False)[0]['classification'],'indeterminate')
  rows.append({'t':start,'flow':('udp','10.231.2.20',40002),'out':True,'dns_id':4,'response':False})
  self.assertEqual(m.correlate(rows,[diagnostic],[rpc],True)[0]['classification'],'indeterminate')
 def test_no_rpc_no_correlation(self):
  self.assertEqual(m.correlate([],[],[]),[])
 def test_readiness_exact_interface(self):
  raw=b'tcpdump: listening on tx123, link-type RAW (Raw IP), snapshot length 160 bytes\n'
  self.assertTrue(m.listening_acknowledged(raw,'tx123'))
  self.assertFalse(m.listening_acknowledged(raw,'tx124'))
  with self.assertRaises(ValueError):m.listening_acknowledged(raw+raw,'tx123')
 def test_readiness_waits_for_all_and_refuses_exit(self):
  from unittest.mock import Mock,patch
  processes=[Mock(),Mock()]
  for p in processes:p.poll.return_value=None
  raw=[b'tcpdump: listening on tx1, link-type RAW\n',b'tcpdump: listening on tx2, link-type RAW\n']
  with patch.object(m.time,'time',side_effect=[100.,101.]):
   self.assertEqual(m.await_readiness(processes,['tx1','tx2'],lambda i:raw[i],m.time.monotonic()+1),101.)
  processes[1].poll.return_value=1
  with self.assertRaises(ValueError):m.await_readiness(processes,['tx1','tx2'],lambda i:raw[i],m.time.monotonic()+1)
  with self.assertRaises(ValueError):m.await_readiness(processes,['tx1','tx2'],lambda i:b'',m.time.monotonic()-1)
 def test_capture_loss_and_failure(self):
  log=b'2 packets captured\n2 packets received by filter\n1 packets dropped by kernel\n'
  self.assertEqual(m.capture_health(log,0)['dropped'],1)
  with self.assertRaises(ValueError):m.capture_health(log,1)
  with self.assertRaises(ValueError):m.capture_health(b'',0)
 def test_root_snapshot_rejects_symlink(self):
  import tempfile,os
  with tempfile.TemporaryDirectory() as directory:
   path=pathlib.Path(directory)/'snapshot';path.symlink_to('/etc/hosts')
   with self.assertRaises(ValueError):m.private(str(path))
 def test_live_journal_rejects_noncanonical_path(self):
  with self.assertRaises(ValueError):m.live_journal('/home/ubuntu/../other/journal.json',1,1)
 def test_truncated_pcap_refuses(self):
  with self.assertRaises(ValueError):m.packets(b'bad')
if __name__=='__main__':unittest.main()
