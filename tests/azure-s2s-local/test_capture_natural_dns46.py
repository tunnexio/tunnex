import importlib.util,pathlib,unittest
spec=importlib.util.spec_from_file_location('capture',pathlib.Path(__file__).with_name('capture-natural-dns46.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Correlation(unittest.TestCase):
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
