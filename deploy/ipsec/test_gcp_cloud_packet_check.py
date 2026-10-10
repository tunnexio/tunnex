import importlib.util
import pathlib
import socket
import struct
import unittest
import tempfile
from unittest import mock

spec=importlib.util.spec_from_file_location('packet',pathlib.Path(__file__).with_name('gcp-cloud-packet-check.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class PacketScopeTests(unittest.TestCase):
 def frame(self,proto,port,body,src='10.70.0.10',dst='10.81.0.10',fragment=0):
  if proto==17:transport=struct.pack('!HHHH',50000,port,8+len(body),0)+body
  else:transport=struct.pack('!HHIIHHHH',50000,port,0,0,0x5018,1000,0,0)+body
  ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(transport),1,fragment,64,proto,0,socket.inet_aton(src),socket.inet_aton(dst))
  return b'\0'*12+b'\x08\x00'+ip+transport
 def test_exact_fixed_tuples_and_payload(self):
  nonce='example-owned-nonce'
  udp=self.frame(17,9000,('tnx-gcp-packet-'+nonce).encode())
  self.assertEqual(m.frame_match(udp,'10.81.0.10','udp',nonce),'exact_payload')
  tcp=self.frame(6,8080,('GET /tnx-probe/'+nonce+' HTTP/1.0\r\n').encode())
  self.assertEqual(m.frame_match(tcp,'10.81.0.10','tcp',nonce),'exact_payload')
  for frame in [self.frame(17,53,b'x'),self.frame(17,9000,b'x',src='10.70.0.11'),self.frame(17,9000,b'x',dst='10.80.0.10'),b'bad']:
   self.assertIsNone(m.frame_match(frame,'10.81.0.10','udp',nonce))
  self.assertEqual(m.frame_match(udp,'10.81.0.10','udp','different'),'other_tuple')
  self.assertEqual(m.frame_match(self.frame(17,9000,b'x',fragment=1),'10.81.0.10','udp',nonce),'unsupported')
 def test_pins_and_scope(self):
  for role in [m.CLIENT,*m.TARGETS.values()]:
   argv=m.ssh(role,'read-only command')
   self.assertIn('StrictHostKeyChecking=yes',argv)
   self.assertIn('HostKeyAlias=compute.'+role[1],argv)
   self.assertIn('UserKnownHostsFile='+m.ROOT+role[2],argv)
  self.assertEqual(set(m.TARGETS),{'ha','classic'})
  self.assertEqual(m.CLIENT[3],'10.70.0.10')
 def test_pin_drift_and_unsafe_mode_refused(self):
  with tempfile.TemporaryDirectory() as directory:
   path=pathlib.Path(directory)/m.CLIENT[2]
   wire=b'public synthetic test key wire'
   path.write_text('compute.'+m.CLIENT[1]+' ssh-ed25519 '+m.base64.b64encode(wire).decode()+'\n');path.chmod(0o600)
   fingerprint='SHA256:'+m.base64.b64encode(m.hashlib.sha256(wire).digest()).decode().rstrip('=')
   with mock.patch.object(m,'ROOT',directory+'/'),mock.patch.dict(m.FINGERPRINTS,{m.CLIENT[1]:fingerprint}):
    m.verify_pin(m.CLIENT)
    path.chmod(0o644)
    with self.assertRaises(ValueError):m.verify_pin(m.CLIENT)
    path.chmod(0o600);path.write_text('compute.'+m.CLIENT[1]+' ssh-ed25519 '+m.base64.b64encode(b'drift').decode()+'\n')
    with self.assertRaises(ValueError):m.verify_pin(m.CLIENT)
 def test_duplicate_receipt_refused(self):
  with self.assertRaises(ValueError):m.json.loads('{"accepted":true,"accepted":false}',object_pairs_hook=m.unique)

if __name__=='__main__':unittest.main()
