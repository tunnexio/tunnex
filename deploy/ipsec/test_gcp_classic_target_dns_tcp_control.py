import importlib.util,pathlib,unittest
from unittest import mock
s=importlib.util.spec_from_file_location('p',pathlib.Path(__file__).with_name('gcp-classic-target-dns-tcp-control.py'));p=importlib.util.module_from_spec(s);s.loader.exec_module(p)
class Tests(unittest.TestCase):
 def test_exact_local_source_and_single_connect_timeout_retained(self):
  sock=mock.MagicMock();sock.getsockname.return_value=(p.SOURCE,46000);sock.connect.side_effect=TimeoutError('not emitted');r=[]
  with self.assertRaises(TimeoutError):p.query(sock,r.append)
  sock.bind.assert_called_once_with(('10.81.0.10',0));sock.connect.assert_called_once_with(('10.81.0.2',53));sock.sendall.assert_not_called();self.assertEqual(r[-1]['stage'],'tcp_connect');self.assertTrue(r[-1]['failed'])
 def test_total_deadline_never_reset_by_progress(self):
  sock=mock.MagicMock();sock.getsockname.return_value=(p.SOURCE,46000);sock.recv.side_effect=[b'\x00\x0c',b'abcd',b'efgh',b'ijkl']
  with mock.patch.object(p.time,'monotonic',side_effect=[0,0,0,1,2,3,4.1]):
   with self.assertRaises(TimeoutError):p.query(sock,lambda x:None)
  self.assertEqual(sock.recv.call_count,3)
if __name__=='__main__':unittest.main()
