import pathlib,importlib.util,unittest
p=pathlib.Path(__file__).with_name('customer-stream-fault-measure.py');s=importlib.util.spec_from_file_location('measure',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Tests(unittest.TestCase):
 def test_socket_observer_covers_fault_not_initial_ten_samples(self):
  c=m.socket_command({'pid':1234,'startticks':'9999','exe':'/usr/bin/nc.openbsd'},44021,'client',240)
  self.assertIn('ss -ntipo',c);self.assertIn('240',c);self.assertIn('270s',c);self.assertIn('44021',c);self.assertIn('/proc/1234/stat',c)
 def test_header_capture_exact_tuple_no_payload_render(self):
  c=m.header_command(44021);self.assertIn('src port 44021',c);self.assertIn('dst port 44021',c);self.assertIn('-S',c);self.assertNotIn(' -A ',c);self.assertNotIn(' -X ',c);self.assertNotIn(' -w ',c)
 def test_no_bad_dir_or_port(self):
  for bad in ['/tmp/foreign','/state/ipsec/bgp-uuid-g1','/state/ipsec/bgp-00000000-0000-4000-8000-000000000001-g0']:
   with self.assertRaises(AssertionError):m.gateway_command(bad)
  for port in [22,'8081',True,65536]:
   with self.assertRaises(AssertionError):m.header_command(port)
 def test_gateway_pins_and_metadata_only(self):
  c=m.gateway_command('/state/ipsec/bgp-44e340c8-1111-4c1b-8a79-368e1b628ba9-g12');self.assertIn(m.CID,c);self.assertIn(m.NODE,c);self.assertIn('nft -j list',c);self.assertIn('show bgp summary json',c);self.assertNotIn('rekey',c);self.assertNotIn('iptables',c)
 def test_client_path_is_existing_private_host(self):
  argv=m.client_ssh('true');self.assertIn('ubuntu@16.170.207.192',argv);self.assertIn('ubuntu@10.84.2.10',argv[-1]);self.assertIn('ProxyCommand',argv[-1])
if __name__=='__main__':unittest.main()
