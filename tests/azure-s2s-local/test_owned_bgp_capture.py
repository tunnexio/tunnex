import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('owned_capture',Path(__file__).with_name('decode-owned-bgp-capture.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
PREFIX=b'\x18\x0a\xeb\x4d'
OTHER=b'\x18\x0a\xe7\x01'
ATTR=b'\x40\x01\x01\x00'+b'\x40\x02\x04\x02\x01\xff\xeb'+b'\x40\x03\x04\xa9\xfe\x15\x02'

def message(body,kind=2):return bytes([255])*16+struct.pack('!HB',len(body)+19,kind)+body

def update(prefix=PREFIX,withdraw=False):
 if withdraw:return message(struct.pack('!H',len(prefix))+prefix+b'\x00\x00')
 return message(b'\x00\x00'+struct.pack('!H',len(ATTR))+ATTR+prefix)

def frame(payload,seq=100,link=113,peer=21,sport=179,dport=32000,flags=0x18):
 tcp=struct.pack('!HHII',sport,dport,seq,0)+bytes([0x50,flags])+bytes(6)+payload
 ip=b'\x45\x00'+struct.pack('!H',20+len(tcp))+bytes(4)+b'\x40\x06'+bytes(2)+bytes([169,254,peer,2])+bytes([169,254,10,1])+tcp
 if link==113:return bytes(14)+b'\x08\x00'+ip
 if link==276:return b'\x08\x00'+bytes(18)+ip
 if link==1:return bytes(12)+b'\x08\x00'+ip
 return ip

def pcap(packets,link=113,nano=False,endian='<',truncated=False):
 magic={('<',False):b'\xd4\xc3\xb2\xa1',('>',False):b'\xa1\xb2\xc3\xd4',('<',True):b'\x4d\x3c\xb2\xa1',('>',True):b'\xa1\xb2\x3c\x4d'}[endian,nano]
 data=magic+struct.pack(endian+'HHiIII',2,4,0,0,65535,link)
 for index,packet in enumerate(packets):data+=struct.pack(endian+'IIII',1791657600+index,123456789 if nano else 123456,len(packet),len(packet)+int(truncated))+packet
 return data

class Capture(unittest.TestCase):
 def test_candidate_advertise_and_withdraw_all_supported_links_formats(self):
  for link in (1,113,276):
   for endian,nano in (('<',False),('>',False),('<',True),('>',True)):
    first=update();second=update(withdraw=True)
    raw=pcap([frame(first,link=link),frame(second,seq=100+len(first),link=link)],link,nano,endian)
    result=m.decode(raw)
    self.assertEqual([v['action'] for v in result['events']],['advertisement','withdrawal'])
    self.assertEqual(result['bgp_message_count'],2)
    self.assertEqual(result['events'][0]['peer'],'169.254.21.2')
    self.assertEqual(result['events'][0]['observed_at'][-10:],'123456789Z' if nano else '123456000Z')
    self.assertNotIn('payload',result)
 def test_out_of_order_split_and_identical_retransmission(self):
  wire=update();first=frame(wire[:23]);second=frame(wire[23:],seq=123)
  result=m.decode(pcap([second,first,second]))
  self.assertEqual(len(result['events']),1)
  self.assertEqual(result['duplicate_byte_count'],len(wire)-23)
  self.assertEqual(result['events'][0]['observed_at'],m.timestamp(1791657601,123456,False))
 def test_two_actual_peers_both_tcp_initiation_directions(self):
  result=m.decode(pcap([frame(update(),peer=21),frame(update(),peer=22,sport=32001,dport=179)]))
  self.assertEqual({v['peer'] for v in result['events']},m.PEERS)
 def test_non_candidate_update_and_foreign_source_do_not_prove_candidate(self):
  result=m.decode(pcap([frame(update(OTHER)),frame(update(),peer=23)]))
  self.assertEqual(result['events'],[])
  self.assertEqual(result['bgp_message_count'],1)
 def test_conflicting_retransmission_gap_partial_and_midstream_refused(self):
  wire=update()
  scenarios=[ [frame(wire),frame(wire[:-1]+b'\xff')], [frame(wire[:20]),frame(wire[21:],seq=121)], [frame(wire[:-1])], [frame(wire[5:])] ]
  for packets in scenarios:
   with self.subTest(packets=len(packets)),self.assertRaises(ValueError):m.decode(pcap(packets))
 def test_bad_capture_link_truncation_fragment_reset_and_reuse_refused(self):
  fragmented=bytearray(frame(update()));fragmented[16+6]=0x20
  scenarios=[pcap([frame(update())],link=999),pcap([frame(update())],truncated=True),pcap([bytes(fragmented)]),pcap([frame(update(),flags=4)]),pcap([frame(b'',seq=99,flags=2),frame(update()),frame(b'',seq=199,flags=2)])]
  for raw in scenarios:
   with self.subTest(length=len(raw)),self.assertRaises(ValueError):m.decode(raw)
 def test_nlri_attributes_and_bgp_lengths_refuse_malformed(self):
  bad=[message(b'\x00\x00\x00\x00'+PREFIX),message(b'\x00\x00'+struct.pack('!H',len(ATTR))+ATTR+b'\x21'),message(b'\x00\x00'+struct.pack('!H',len(ATTR))+ATTR+b'\x18\x0a'),message(b'\x00\x00\x00\x03\x40\x01\x08'+PREFIX),message(b'abc',4)]
  for wire in bad:
   with self.assertRaises(ValueError):m.decode(pcap([frame(wire)]))
 def test_mp_reach_unreach_ipv4_candidate(self):
  mp=b'\x00\x01\x01\x04\xa9\xfe\x15\x02\x00'+PREFIX
  attrs=ATTR+b'\x80\x0e'+bytes([len(mp)])+mp
  reach=message(b'\x00\x00'+struct.pack('!H',len(attrs))+attrs)
  unreach=b'\x00\x01\x01'+PREFIX
  attrs=b'\x80\x0f'+bytes([len(unreach)])+unreach
  withdraw=message(b'\x00\x00'+struct.pack('!H',len(attrs))+attrs)
  result=m.decode(pcap([frame(reach),frame(withdraw,seq=100+len(reach))]))
  self.assertEqual([v['action'] for v in result['events']],['advertisement','withdrawal'])
 def test_multiple_messages_and_optional_payload_never_exported(self):
  private=b'private-attribute-must-not-export'
  attrs=ATTR+b'\xc0\x63'+bytes([len(private)])+private
  wire=message(b'',4)+message(b'\x00\x00'+struct.pack('!H',len(attrs))+attrs+PREFIX)+message(b'',4)
  result=m.decode(pcap([frame(wire)]))
  self.assertEqual(result['bgp_message_count'],3)
  self.assertEqual(len(result['events']),1)
  self.assertNotIn(private.decode(),str(result))
 def test_main_creates_only_private_typed_new_output(self):
  import contextlib
  import io
  import json
  with tempfile.TemporaryDirectory() as folder:
   folder=Path(folder).resolve();capture=folder/'capture';capture.write_bytes(pcap([frame(update())]));capture.chmod(0o600);output=folder/'projection'
   with patch('sys.argv',['decoder','--capture',str(capture),'--output',str(output)]),contextlib.redirect_stdout(io.StringIO()) as console:m.main()
   self.assertEqual(console.getvalue().strip(),'{"version":1,"capture_projection_written":true}')
   self.assertEqual(output.stat().st_mode&0o777,0o600)
   self.assertEqual(json.loads(output.read_text())['events'][0]['action'],'advertisement')
   with patch('sys.argv',['decoder','--capture',str(capture),'--output',str(output)]),self.assertRaisesRegex(ValueError,'new output'):m.main()
 def test_file_permissions_symlink_and_bounds(self):
  with tempfile.TemporaryDirectory() as folder:
   folder=Path(folder).resolve();file=folder/'capture.pcap';file.write_bytes(pcap([frame(update())]));file.chmod(0o600)
   self.assertEqual(len(m.decode(m.private_input(file))['events']),1)
   link=folder/'link';link.symlink_to(file)
   with self.assertRaises(OSError):m.private_input(link)
   file.chmod(0o644)
   with self.assertRaises(ValueError):m.private_input(file)
   with patch.object(m,'MAX_FILE',24),self.assertRaises(ValueError):m.decode(pcap([frame(update())]))

if __name__=='__main__':unittest.main()
