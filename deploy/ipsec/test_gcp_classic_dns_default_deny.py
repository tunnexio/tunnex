import errno
import importlib.util,pathlib,socket,struct,unittest
from unittest import mock
s=importlib.util.spec_from_file_location('p',pathlib.Path(__file__).with_name('gcp-classic-dns-default-deny.py'));p=importlib.util.module_from_spec(s);s.loader.exec_module(p)
class Tests(unittest.TestCase):
 def test_bounded_udp_negative_exactsource_target_noedns(self):
  sock=mock.MagicMock();sock.__enter__.return_value=sock;sock.recvfrom.side_effect=TimeoutError('bounded')
  with mock.patch.object(p.socket,'socket',return_value=sock):r=p.probe('udp')
  self.assertTrue(r['accepted_negative']);sock.bind.assert_called_once_with(('10.70.0.2',0))
  wire,target=sock.sendto.call_args.args;self.assertEqual(target,('10.81.0.2',53));self.assertEqual(struct.unpack('!6H',wire[:12])[2:],(1,0,0,0))
 def test_response_not_negative_and_unknown_error_refuses(self):
  sock=mock.MagicMock();sock.__enter__.return_value=sock;sock.recvfrom.return_value=(b'response',('10.81.0.2',53))
  with mock.patch.object(p.socket,'socket',return_value=sock):self.assertFalse(p.probe('udp')['accepted_negative'])
  sock.recvfrom.side_effect=OSError('unattributed failure')
  with mock.patch.object(p.socket,'socket',return_value=sock):
   with self.assertRaises(OSError):p.probe('udp')
 def test_administrative_refusal_retains_exact_stage_not_negative_proof(self):
  for protocol,operation,stage in [('udp','bind','bind'),('udp','sendto','send'),('udp','recvfrom','recv'),('tcp','connect','connect'),('tcp','sendall','write'),('tcp','recv','read')]:
   sock=mock.MagicMock();sock.__enter__.return_value=sock;getattr(sock,operation).side_effect=PermissionError(errno.EPERM,'not logged')
   with mock.patch.object(p.socket,'socket',return_value=sock):r=p.probe(protocol)
   self.assertEqual((r['outcome'],r['errno'],r['stage']),('administrative_refusal',errno.EPERM,stage));self.assertFalse(r['accepted_negative']);self.assertNotIn('response_length',r)
 def test_unknown_permission_errno_refuses(self):
  sock=mock.MagicMock();sock.__enter__.return_value=sock;sock.sendto.side_effect=PermissionError(errno.EIO,'not logged')
  with mock.patch.object(p.socket,'socket',return_value=sock):
   with self.assertRaises(PermissionError):p.probe('udp')
if __name__=='__main__':unittest.main()
