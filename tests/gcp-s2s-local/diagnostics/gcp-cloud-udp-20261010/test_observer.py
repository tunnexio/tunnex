import importlib.util,pathlib,unittest,socket,struct
from unittest import mock
s=importlib.util.spec_from_file_location('g',pathlib.Path(__file__).with_name('gateway-observer.py'));g=importlib.util.module_from_spec(s);s.loader.exec_module(g)
class Tests(unittest.TestCase):
 def packet(self,payload=b'tnx-gcp-packet-fixed',dst='10.81.0.10',fragment=0,length=None):
  udp=struct.pack('!HHHH',41000,9000,8+len(payload)if length is None else length,0)+payload
  return struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),1,fragment,64,17,0,socket.inet_aton('10.70.0.10'),socket.inet_aton(dst))+udp
 def test_exact_ipv4_offset_zero_without_ethernet(self):
  self.assertEqual(g.match_packet(self.packet(),'fixed'),'exact_nonce')
  self.assertIsNone(g.match_packet(b'\0'*14+self.packet(),'fixed'))
 def test_wrongtuple_nonce_length_fragment(self):
  self.assertIsNone(g.match_packet(self.packet(dst='10.80.0.10'),'fixed'))
  self.assertEqual(g.match_packet(self.packet(),'different'),'other_tuple')
  self.assertEqual(g.match_packet(self.packet(fragment=1),'fixed'),'unsupported_fragment')
  self.assertEqual(g.match_packet(self.packet(length=9),'fixed'),'invalid_udp_length')
  self.assertIsNone(g.match_packet(self.packet()[:-1],'fixed'))
 def test_after_snapshot_failure_preserves_collected_counts(self):
  counts={'ens4':{'incoming_exact':1}};stats={'ens4':{'packets':2,'drops':0}}
  with mock.patch.object(g,'snapshot',side_effect=ValueError('private evidence omitted')):
   r=g.finish_result({},counts,stats,True)
  self.assertEqual(r['counts'],counts);self.assertEqual(r['stats'],stats)
  self.assertTrue(r['stopped_by_request']);self.assertFalse(r['stable_gate'])
  self.assertEqual(r['snapshot_after_error_type'],'ValueError');self.assertNotIn('private evidence',str(r))
 def test_guard_or_sa_turnover_and_capture_drop_refuse_gate(self):
  fields=['boot_id','container_id','image_id','pid','started_at','namespace','delivery_id','contract_version','phase','ownership_digest','generation','links','route','sa_identity','guard']
  before={k:'original' for k in fields}
  for field in ['guard','sa_identity','namespace']:
   after=dict(before);after[field]='changed'
   with mock.patch.object(g,'snapshot',return_value=after):r=g.finish_result(before,{}, {'ens4':{'drops':0}},True)
   self.assertFalse(r['stable_gate'])
  with mock.patch.object(g,'snapshot',return_value=before):
   self.assertTrue(g.finish_result(before,{}, {'ens4':{'drops':0}},True)['stable_gate'])
   self.assertFalse(g.finish_result(before,{}, {'ens4':{'drops':1}},True)['stable_gate'])
if __name__=='__main__':unittest.main()
