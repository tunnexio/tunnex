import importlib.util,unittest,socket
from pathlib import Path
from unittest.mock import Mock,patch

def load(name,file):
 s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
probe=load('udp_probe','probe-fqdn-udp.py');api=load('udp_api','qualify-fqdn-udp-api.py')
class UDPTests(unittest.TestCase):
 def test_only_genuine_single_owned_dns_address(self):
  for answers,ok in [(['10.231.1.4'],True),([],False),(['10.231.1.4','8.8.8.8'],False),(['10.231.1.10'],False)]:
   with patch.object(socket,'getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_DGRAM,0,'',(a,8081)) for a in answers]):
    if ok:probe.resolve()
    else:
     with self.assertRaises(ValueError):probe.resolve()
 def test_original_socket_timeout_retains_identity_without_close(self):
  s=Mock();s.getsockname.return_value=('10.233.10.2',42001);s.send.return_value=64;s.recv.side_effect=socket.timeout()
  with patch.object(probe,'resolve'):
   result=probe.sample(s,True,1)
  self.assertFalse(result['success']);self.assertTrue(result['reused_existing_socket']);self.assertEqual(result['local_port'],42001);s.close.assert_not_called()
 def test_overlapping_direct_udp_refuses_but_tcp_does_not(self):
  policies=[{'dst_kind':'resource','dst_resource_id':'r'}];r={'id':'r','cidr':'10.231.1.0/24','protocol':'udp','port_low':8081,'port_high':8081}
  with self.assertRaises(api.lab.LabError):api.refuses_direct_udp(policies,[r])
  api.refuses_direct_udp(policies,[{**r,'protocol':'tcp'}])
  for protocol in ('udp','any',''):
   with self.assertRaises(api.lab.LabError):api.refuses_direct_udp(policies,[{**r,'protocol':protocol,'port_low':0,'port_high':0}])
 def test_no_blanket_or_missing_dns_baseline(self):
  with self.assertRaises(api.lab.LabError):api.protected_ids({'dns_rules':[],'app_rules':[],'reverse_rules':[]})
  self.assertEqual(api.protected_ids({'dns_rules':['1','2','3','4'],'app_rules':[],'reverse_rules':[]}),{'1','2','3','4'})
 def test_bounds(self):
  for args in [(0,1),(61,1),(1,float('nan')),(1,3)]:
   with self.assertRaises(ValueError):probe.bounds(*args)
if __name__=='__main__':unittest.main()
