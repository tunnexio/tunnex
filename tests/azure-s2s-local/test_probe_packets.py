import errno
import importlib.util
from pathlib import Path
import socket
import unittest

spec=importlib.util.spec_from_file_location('probe_packets',Path(__file__).with_name('probe-packets.py'))
probe=importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

class Datagram:
 def __init__(self,send_error=None,receive_error=None):
  self.send_error=send_error;self.receive_error=receive_error;self.received=False
 def send(self,payload):
  if self.send_error:raise self.send_error
  self.payload=payload;return len(payload)
 def recv(self,size):
  self.received=True
  if self.receive_error:raise self.receive_error
  return self.payload
 def getsockname(self):return ('10.233.10.2',40000)

class UDPReceiptTests(unittest.TestCase):
 def test_df_rejection_distinguishes_local_send_and_gateway_receive_error(self):
  for stage in ('send','receive'):
   connection=Datagram(**{stage+'_error':OSError(errno.EMSGSIZE,'private error text')})
   result=probe.udp_echo(connection,b'x'*1362)
   self.assertFalse(result['success']);self.assertEqual(result['udp_error_stage'],stage)
   self.assertEqual(result['error_code'],'udp_message_too_large');self.assertEqual(result['socket_errno'],errno.EMSGSIZE)
   self.assertEqual('sent_bytes' in result,stage=='receive')
   self.assertEqual(connection.received,stage=='receive')
   self.assertNotIn('private',str(result))
 def test_receive_timeout_is_not_mtu_rejection(self):
  result=probe.udp_echo(Datagram(receive_error=socket.timeout('private')),b'x'*64)
  self.assertEqual(result['udp_error_stage'],'receive');self.assertEqual(result['error_code'],'udp_timeout')
  self.assertNotIn('socket_errno',result);self.assertEqual(result['sent_bytes'],64)
 def test_unknown_errno_and_message_are_not_exposed(self):
  result=probe.udp_echo(Datagram(send_error=OSError(12345,'private')),b'x')
  self.assertEqual(result['error_code'],'udp_socket_error');self.assertNotIn('socket_errno',result)
  self.assertNotIn('private',str(result))
 def test_success_receipt_keeps_exact_echo_evidence(self):
  result=probe.udp_echo(Datagram(),b'x'*4096)
  self.assertTrue(result['success']);self.assertEqual(result['echo_bytes'],4096)
  self.assertTrue(result['echo_exact_match']);self.assertEqual(result['local_port'],40000)

if __name__=='__main__':unittest.main()
