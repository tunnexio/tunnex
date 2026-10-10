import importlib.util,pathlib,unittest
spec=importlib.util.spec_from_file_location('capture',pathlib.Path(__file__).with_name('capture-natural-dns46.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Correlation(unittest.TestCase):
 def test_exact_udp_and_ambiguity(self):
  end='2026-10-10T21:00:03Z';start=m.stamp(end)-3
  diagnostic={'time':end,'operation':'dns_exchange','socket_ms':3000,'socket_stage':'body','stage':'dns_socket_udp'}
  rpc={'dispatch_utc':'2026-10-10T20:59:59Z','handle_ms':4500}
  flow=('udp','10.231.2.4',40001)
  rows=[{'t':start,'flow':flow,'out':True,'dns_id':3,'response':False},{'t':start+.02,'flow':flow,'out':False,'dns_id':3,'response':True,'rcode':0}]
  got=m.correlate(rows,[diagnostic],[rpc])[0];self.assertTrue(got['noerror_reply_observed'])
  rows.append({'t':start,'flow':('udp','10.231.2.20',40002),'out':True,'dns_id':4,'response':False})
  self.assertEqual(m.correlate(rows,[diagnostic],[rpc])[0]['classification'],'indeterminate')
 def test_no_rpc_no_correlation(self):
  self.assertEqual(m.correlate([],[],[]),[])
 def test_truncated_pcap_refuses(self):
  with self.assertRaises(ValueError):m.packets(b'bad')
if __name__=='__main__':unittest.main()
